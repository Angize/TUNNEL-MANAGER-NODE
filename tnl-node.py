#!/usr/bin/env python3

import base64
import errno
import hashlib
import hmac
import ipaddress
import itertools
import json
import os
import select
import shlex
import py_compile
import re
import secrets
import shutil
import socket
import struct
import subprocess
import sys
import threading
import time
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor, wait as futures_wait
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

CONFIG_DIR = "/opt/tunnel"
NODE_CONF = os.path.join(CONFIG_DIR, "node.conf")
LOG = os.path.join(CONFIG_DIR, "node-agent.log")
SERVICE_FILE = "/etc/systemd/system/tnl-node.service"
SELF_PATH = os.path.realpath(__file__)
INSTALLED = os.path.join(CONFIG_DIR, "tnl-node.py")

CORE_BIN = os.path.join(CONFIG_DIR, "tnl-core")
_core_lock = threading.Lock()
_core_sha_cache = {"mtime": None, "sha": ""}
_core_sha_lock = threading.Lock()
OBFS_DATA_PAD_MAX = 64

NAME_RE = re.compile(r"^[A-Za-z0-9_]+$")
IFACE_RE = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.@-]*$")

MAX_CONNS = 64
_conn_sem = threading.BoundedSemaphore(MAX_CONNS)
_apply_lock = threading.Lock()
_restart_pending = threading.Event()
_central_cb = None
_central_cb_lock = threading.Lock()
_last_reported_ips = None
CHECKIN_GAP = 20


def load_conf():
    with open(NODE_CONF) as f:
        return json.load(f)


def save_conf(conf):
    os.makedirs(CONFIG_DIR, exist_ok=True)
    tmp = NODE_CONF + ".tmp"
    with open(tmp, "w") as f:
        json.dump(conf, f, indent=2)
    os.chmod(tmp, 0o600)
    os.replace(tmp, NODE_CONF)


def run(args, timeout=60):
    try:
        p = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
        return p.returncode, p.stdout, p.stderr
    except subprocess.TimeoutExpired:
        return 124, "", "timeout"
    except FileNotFoundError as e:
        return 127, "", str(e)


def must(args, timeout=60):
    rc, out, err = run(args, timeout=timeout)
    if rc != 0:
        raise RuntimeError((err or out or ("rc=" + str(rc))).strip() + "  [" + " ".join(args) + "]")
    return rc, out, err


def logline(msg):
    try:
        with open(LOG, "a") as f:
            f.write(f"[{int(time.time())}] {msg}\n")
    except Exception:
        pass


def is_ipv4(s):
    try:
        return isinstance(ipaddress.ip_address(s), ipaddress.IPv4Address)
    except Exception:
        return False


def _as_bool(v):
    return v is True or (isinstance(v, str) and v.strip().lower() in ("1", "true", "yes", "on"))


def valid_cidr(s, want6):
    if "/" not in str(s):
        return False
    try:
        return ipaddress.ip_network(s, strict=False).version == (6 if want6 else 4)
    except Exception:
        return False


def ip2int(s):
    return int(ipaddress.IPv4Address(s))


def derive_tunnel_ip(ttype, subnet, host):
    parts = subnet.split("/")
    base = parts[0]
    prefix = parts[1] if len(parts) > 1 else ("64" if ttype == "sit" else "24")
    net = ipaddress.ip_network(f"{base}/{prefix}", strict=False)
    return f"{net.network_address + host}/{net.prefixlen}"


def raw_configs():
    out = []
    if not os.path.isdir(CONFIG_DIR):
        return out
    for fn in sorted(os.listdir(CONFIG_DIR)):
        if fn.endswith(".json") and fn != "node.conf":
            c = read_config(fn[:-5])
            if c and c.get("name"):
                out.append(c)
    return out


def public_configs():
    out = []
    for c in raw_configs():
        c = dict(c)
        c.pop("psk", None)
        out.append(c)
    return out


def read_config(name):
    if not NAME_RE.match(name or ""):
        return None
    path = os.path.join(CONFIG_DIR, name + ".json")
    if not os.path.isfile(path):
        return None
    try:
        with open(path) as f:
            return json.load(f)
    except Exception:
        return None


def write_config(name, obj):
    if not NAME_RE.match(name):
        raise ValueError("bad name")
    path = os.path.join(CONFIG_DIR, name + ".json")
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        json.dump(obj, f, indent=2)
    os.chmod(tmp, 0o600)
    os.replace(tmp, path)


def used_ids():
    ids = set()
    for c in raw_configs():
        try:
            ids.add(int(c.get("id")))
        except Exception:
            pass
    return ids


def unique_name(ttype, tid):
    name = f"core{tid}" if ttype == "core" else f"native{tid}"
    if os.path.exists(os.path.join(CONFIG_DIR, name + ".json")):
        return None
    rc, _, _ = run(["ip", "link", "show", name])
    return name if rc != 0 else None


def list_ifaces():
    rc, out, _ = run(["ip", "-o", "link", "show"])
    res = []
    for line in out.splitlines():
        parts = line.split(": ")
        if len(parts) < 2:
            continue
        name = parts[1].split("@")[0].strip()
        if re.match(r"^(eth|ens|eno|enp|enx)[0-9a-z]*$", name):
            res.append(name)
    return res


def iface_ips(iface):
    if not IFACE_RE.match(iface):
        return []
    rc, out, _ = run(["ip", "-4", "-o", "addr", "show", "dev", iface, "scope", "global"])
    ips = []
    for line in out.splitlines():
        parts = line.split()
        for i, tok in enumerate(parts):
            if tok == "inet" and i + 1 < len(parts):
                ips.append(parts[i + 1].split("/")[0])
    return ips


def all_ips():
    return {i: iface_ips(i) for i in list_ifaces()}


def local_ips_flat():
    return [ip for ips in all_ips().values() for ip in ips]


def default_iface():
    rc, out, _ = run(["ip", "route"])
    for line in out.splitlines():
        if line.startswith("default"):
            parts = line.split()
            if "dev" in parts:
                return parts[parts.index("dev") + 1]
    ifs = list_ifaces()
    return ifs[0] if ifs else None


def iface_for_ip(ip):
    for i, ips in all_ips().items():
        if ip and ip in ips:
            return i
    return default_iface()


def primary_ip():
    dev = default_iface()
    if dev:
        ips = iface_ips(dev)
        if ips:
            return ips[0]
    for i in list_ifaces():
        ips = iface_ips(i)
        if ips:
            return ips[0]
    return None


def base_mtu(dev=None):
    asked = dev
    dev = dev or default_iface()
    if dev and IFACE_RE.match(dev):
        rc, out, _ = run(["ip", "link", "show", dev])
        m = re.search(r"\bmtu (\d+)", out) if rc == 0 else None
        if m:
            return int(m.group(1))
    if asked:
        raise RuntimeError("MTUِ اینترفیسِ «" + str(asked) + "» خوانده نشد — تونل از همین لینک خارج می‌شود")
    return 1500


def _modprobe(*mods):
    for m in mods:
        run(["modprobe", m])


def enable_ip_forward():
    run(["sysctl", "-w", "net.ipv4.ip_forward=1"])
    try:
        lines = []
        if os.path.isfile("/etc/sysctl.conf"):
            with open("/etc/sysctl.conf") as f:
                lines = [ln for ln in f if not ln.strip().startswith("net.ipv4.ip_forward")]
        lines.append("net.ipv4.ip_forward=1\n")
        with open("/etc/sysctl.conf", "w") as f:
            f.writelines(lines)
    except Exception:
        pass


TUNING_DROPIN = "/etc/sysctl.d/99-angize-tuning.conf"
TUNING_MODLOAD = "/etc/modules-load.d/angize-bbr.conf"
TUNING_PREV = os.path.join(CONFIG_DIR, "tuning_prev.json")
KERNEL_TUNING = [
    ("net.core.default_qdisc", "fq"),
    ("net.core.rmem_max", "16777216"),
    ("net.core.wmem_max", "16777216"),
    ("net.core.netdev_max_backlog", "16384"),
    ("net.ipv4.tcp_rmem", "4096 131072 16777216"),
    ("net.ipv4.tcp_wmem", "4096 65536 16777216"),
    ("net.ipv4.tcp_mtu_probing", "1"),
]


def _sysctl_get(key):
    try:
        with open("/proc/sys/" + key.replace(".", "/")) as f:
            return " ".join(f.read().split())
    except Exception:
        return ""


def _bbr_available():
    if "bbr" in _sysctl_get("net.ipv4.tcp_available_congestion_control").split():
        return True
    run(["modprobe", "tcp_bbr"])
    return "bbr" in _sysctl_get("net.ipv4.tcp_available_congestion_control").split()


def tuning_active():
    return os.path.isfile(TUNING_PREV)


def tuning_status():
    return {
        "active": tuning_active(),
        "cc": _sysctl_get("net.ipv4.tcp_congestion_control"),
        "qdisc": _sysctl_get("net.core.default_qdisc"),
        "bbr_available": _bbr_available(),
    }


def apply_kernel_tuning():
    if not tuning_active():
        prev = {"cc": _sysctl_get("net.ipv4.tcp_congestion_control"),
                "qdisc": _sysctl_get("net.core.default_qdisc")}
        err = _atomic_write_json(TUNING_PREV, prev)
        if err:
            logline(f"kernel tuning: could not save originals, NOT applying: {err}")
            return err
    knobs = list(KERNEL_TUNING)
    bbr = _bbr_available()
    if bbr:
        knobs.append(("net.ipv4.tcp_congestion_control", "bbr"))
    else:
        logline("kernel tuning: bbr unavailable — leaving the default congestion control")
    for k, v in knobs:
        run(["sysctl", "-w", f"{k}={v}"])
    if bbr:
        try:
            with open(TUNING_MODLOAD, "w", encoding="utf-8") as f:
                f.write("tcp_bbr\n")
        except Exception as e:
            logline(f"kernel tuning modules-load: {e}")
    try:
        body = ["# Angize node tuning (part B) - managed by tnl-node; toggle from the panel to revert.\n"]
        body += [f"{k} = {v}\n" for k, v in knobs]
        with open(TUNING_DROPIN, "w", encoding="utf-8") as f:
            f.writelines(body)
    except Exception as e:
        logline(f"kernel tuning persist: {e}")
    return None


def revert_kernel_tuning():
    if not tuning_active():
        for p in (TUNING_DROPIN, TUNING_MODLOAD):
            try:
                if os.path.isfile(p):
                    os.remove(p)
            except Exception:
                pass
        return
    prev = {}
    try:
        with open(TUNING_PREV, encoding="utf-8") as f:
            prev = json.load(f)
    except Exception:
        prev = {}
    cc, qdisc = prev.get("cc"), prev.get("qdisc")
    if cc:
        run(["sysctl", "-w", f"net.ipv4.tcp_congestion_control={cc}"])
    if qdisc:
        run(["sysctl", "-w", f"net.core.default_qdisc={qdisc}"])
    for p in (TUNING_DROPIN, TUNING_MODLOAD, TUNING_PREV):
        try:
            if os.path.isfile(p):
                os.remove(p)
        except Exception as e:
            logline(f"kernel tuning revert rm {p}: {e}")


def _up_netdev(name, cfg, overhead, v6=False):
    addr = ["ip", "-6", "addr", "add", cfg["tunnel_ip"], "dev", name] if v6 else ["ip", "addr", "add", cfg["tunnel_ip"], "dev", name]
    must(addr)
    must(["ip", "link", "set", name, "up"])
    must(["ip", "link", "set", "dev", name, "mtu", str(base_mtu(cfg.get("iface")) - overhead)])


def build_vxlan(cfg):
    name = cfg["name"]
    _modprobe("vxlan")
    run(["ip", "link", "del", name])
    dstport = int(cfg.get("port") or 4789)
    must(["ip", "link", "add", name, "type", "vxlan", "id", str(cfg["id"]),
         "local", cfg["local_ip"], "remote", cfg["remote_ip"], "dstport", str(dstport)])
    _up_netdev(name, cfg, 50)


def build_gre(cfg):
    name = cfg["name"]
    _modprobe("ip_gre")
    run(["ip", "link", "del", name])
    must(["ip", "link", "add", name, "type", "gre",
         "local", cfg["local_ip"], "remote", cfg["remote_ip"], "key", str(cfg["id"])])
    _up_netdev(name, cfg, 28)


def build_sit(cfg):
    name = cfg["name"]
    run(["ip", "link", "del", name])
    must(["ip", "tunnel", "add", name, "mode", "sit", "remote", cfg["remote_ip"],
         "local", cfg["local_ip"], "ttl", "255"])
    _up_netdev(name, cfg, 20, v6=True)


def build_ipip(cfg):
    name = cfg["name"]
    _modprobe("ipip")
    run(["ip", "link", "del", name])
    must(["ip", "tunnel", "add", name, "mode", "ipip", "remote", cfg["remote_ip"],
         "local", cfg["local_ip"], "ttl", "255"])
    _up_netdev(name, cfg, 20)


def _l2tp_ids(cfg):
    tid = int(cfg["id"])
    port = int(cfg.get("port") or (20000 + tid))
    return tid, port


def build_l2tp(cfg):
    name = cfg["name"]
    tid, port = _l2tp_ids(cfg)
    _modprobe("l2tp_eth", "l2tp_netlink")
    run(["ip", "l2tp", "del", "session", "tunnel_id", str(tid), "session_id", str(tid)])
    run(["ip", "l2tp", "del", "tunnel", "tunnel_id", str(tid)])
    run(["ip", "link", "del", name])
    must(["ip", "l2tp", "add", "tunnel", "tunnel_id", str(tid), "peer_tunnel_id", str(tid),
         "encap", "udp", "local", cfg["local_ip"], "remote", cfg["remote_ip"],
         "udp_sport", str(port), "udp_dport", str(port)])
    must(["ip", "l2tp", "add", "session", "name", name, "tunnel_id", str(tid),
         "session_id", str(tid), "peer_session_id", str(tid)])
    _up_netdev(name, cfg, 54)


def _fou_port(cfg):
    return int(cfg.get("port") or 20000)


def build_fou(cfg):
    name = cfg["name"]
    port = _fou_port(cfg)
    _modprobe("fou", "ipip")
    run(["ip", "link", "del", name])
    run(["ip", "fou", "add", "port", str(port), "ipproto", "4"])
    must(["ip", "link", "add", "name", name, "type", "ipip", "remote", cfg["remote_ip"],
         "local", cfg["local_ip"], "ttl", "255", "encap", "fou",
         "encap-sport", "auto", "encap-dport", str(port)])
    _up_netdev(name, cfg, 28)


def _ipsec_params(cfg):
    tid = int(cfg["id"])
    psk = str(cfg.get("psk") or "")
    enc = hashlib.sha256((psk + "|enc").encode()).hexdigest()
    auth = hashlib.sha256((psk + "|auth").encode()).hexdigest()
    spi_lo, spi_hi = 0x10000 + tid, 0x20000 + tid
    local_smaller = ip2int(cfg["local_ip"]) < ip2int(cfg["remote_ip"])
    spi_out, spi_in = (spi_lo, spi_hi) if local_smaller else (spi_hi, spi_lo)
    return tid, enc, auth, spi_out, spi_in


def _ipsec_clear(cfg):
    name = cfg["name"]
    tid = int(cfg["id"])
    for spi in (0x10000 + tid, 0x20000 + tid):
        run(["ip", "xfrm", "state", "deleteall", "proto", "esp", "spi", hex(spi)])
    for dirn in ("out", "in", "fwd"):
        run(["ip", "xfrm", "policy", "deleteall", "dir", dirn, "if_id", str(tid)])
    run(["ip", "link", "del", name])


def build_ipsec(cfg):
    name, local, remote = cfg["name"], cfg["local_ip"], cfg["remote_ip"]
    tid, enc, auth, spi_out, spi_in = _ipsec_params(cfg)
    if not cfg.get("psk"):
        raise ValueError("ipsec needs a psk")
    _modprobe("esp4", "xfrm_interface")
    _ipsec_clear(cfg)
    common = ["proto", "esp", "mode", "tunnel", "reqid", str(tid),
              "enc", "cbc(aes)", "0x" + enc, "auth", "hmac(sha256)", "0x" + auth, "if_id", str(tid)]
    must(["ip", "xfrm", "state", "add", "src", local, "dst", remote, "spi", hex(spi_out)] + common)
    must(["ip", "xfrm", "state", "add", "src", remote, "dst", local, "spi", hex(spi_in)] + common)
    for dirn, s, dst in (("out", local, remote), ("in", remote, local), ("fwd", remote, local)):
        must(["ip", "xfrm", "policy", "add", "dir", dirn, "if_id", str(tid),
             "tmpl", "src", s, "dst", dst, "proto", "esp", "reqid", str(tid), "mode", "tunnel"])
    phys = iface_for_ip(local) or default_iface()
    must(["ip", "link", "add", name, "type", "xfrm", "dev", phys, "if_id", str(tid)])
    _up_netdev(name, cfg, 80)


def _core_arch():
    m = os.uname().machine
    return {"x86_64": "amd64", "amd64": "amd64", "aarch64": "arm64", "arm64": "arm64"}.get(m, "amd64")


def _core_ref():
    try:
        return str(load_conf().get("core_version") or "").strip()
    except Exception:
        return ""


def _installed_core_sha():
    try:
        st = os.stat(CORE_BIN)
        with _core_sha_lock:
            if _core_sha_cache["mtime"] != st.st_mtime:
                with open(CORE_BIN, "rb") as f:
                    _core_sha_cache["sha"] = hashlib.sha256(f.read()).hexdigest()
                _core_sha_cache["mtime"] = st.st_mtime
            return _core_sha_cache["sha"]
    except Exception:
        return ""


def _ensure_core():
    if not os.path.isfile(CORE_BIN):
        raise RuntimeError("core not installed on this node (push it from the panel)")


def _core_port(cfg):
    return int(cfg.get("port") or 20000)


RAW_HEADER_LEN = {"bare": 0, "ipip": 0, "etherip": 2, "ipcomp": 4, "gre": 4, "icmp": 8, "udp": 8,
                  "esp": 8, "l2tpv3": 8, "tcp": 32, "ah": 24}
MAX_WORKERS = 8
QUEUEING_TRANSPORTS = ("raw", "udp")

_TUNING_INT_KEYS = ("dead_retest_secs",
                    "min_liveness_secs")

_TUNING_LIST_KEYS = ("suspect_backoff", "ladder_revive")


def _core_tuning(tn):
    if not isinstance(tn, dict):
        return {}
    out = {}
    for k in _TUNING_INT_KEYS:
        try:
            v = int(tn.get(k) or 0)
        except (TypeError, ValueError):
            continue
        if v > 0:
            out[k] = v
    for k in _TUNING_LIST_KEYS:
        raw = tn.get(k)
        if not isinstance(raw, (list, tuple)):
            continue
        steps = []
        for x in raw:
            try:
                iv = int(x)
            except (TypeError, ValueError):
                continue
            if iv > 0:
                steps.append(iv)
        if steps:
            out[k] = steps
    return out


def _ordered_pool(primary, extras):
    seen, ordered = set(), []
    for x in [primary] + [str(v) for v in (extras or [])]:
        ip = str(x).strip().split(":", 1)[0].strip()
        if ip and ip not in seen:
            seen.add(ip)
            ordered.append(ip)
    return ordered


def _core_config(cfg):
    name = cfg["name"]
    port = _core_port(cfg)
    cipher = str(cfg.get("cipher") or "auto")
    crypto_on = bool(cfg.get("psk")) and cipher != "none"
    transport = str(cfg.get("transport") or "udp").lower()
    raw_profile = str(cfg.get("raw_profile") or "bare").lower()
    obfs = bool(cfg.get("obfs")) and crypto_on
    if transport == "raw":
        outer = 20 + RAW_HEADER_LEN.get(raw_profile, 0)
    elif transport == "spoof":
        outer = 20
    elif transport == "ws":
        outer = 40 + 14
    else:
        outer = 40 if transport == "tcp" else 28
    stream = transport in ("tcp", "ws")
    if obfs:
        framing = (2 if stream else 0) + 3 + OBFS_DATA_PAD_MAX
    else:
        framing = 4 if stream else 2
    overhead = outer + framing
    if crypto_on:
        overhead += (40 if cipher == "xchacha20-poly1305" else 28) + 12
    if transport in ("udp", "raw", "spoof") and bool(cfg.get("fec")):
        overhead += 13
    mtu = max(576, base_mtu(cfg.get("iface")) - overhead)
    if transport == "dns":
        mtu = 1280
    corecfg = {
        "role": cfg.get("role"),
        "mode": "packet",
        "profile": "core",
        "transport": transport,
        "obfs": obfs,
        "tun_name": name,
        "tun_addr": cfg["tunnel_ip"],
        "mtu": mtu,
        "crypto": {"enabled": crypto_on, "psk": cfg.get("psk", ""), "cipher": cipher},
    }
    _tn = _core_tuning(cfg.get("tuning"))
    if _tn:
        corecfg["tuning"] = _tn
    _sb = int(cfg.get("sock_buf") or 0)
    if _sb:
        corecfg["sock_buf"] = _sb
    if bool(cfg.get("cover")) and transport == "tcp" and crypto_on:
        corecfg["cover"] = True
        sni = str(cfg.get("cover_sni") or "").strip()
        if sni:
            corecfg["cover_sni"] = sni
    corecfg["status_path"] = _cfg_path(name, ".status")
    if transport == "raw" and str(cfg.get("role")) == "server":
        _psrc = [str(x).strip() for x in (cfg.get("peer_src_ips") or []) if is_ipv4(str(x).strip())]
        if _psrc:
            corecfg["peer_src_ips"] = _psrc
    if transport == "raw":
        corecfg["raw_profile"] = raw_profile
        try:
            _rp = int(cfg.get("raw_proto") or 0)
        except (TypeError, ValueError):
            _rp = 0
        if raw_profile == "bare" and 1 <= _rp <= 255:
            corecfg["raw_proto"] = _rp
        try:
            _rport = int(cfg.get("raw_port") or 0)
        except (TypeError, ValueError):
            _rport = 0
        if raw_profile in ("udp", "tcp") and 1 <= _rport <= 65535:
            corecfg["raw_port"] = _rport
        try:
            _rsport = int(cfg.get("raw_sport") or 0)
        except (TypeError, ValueError):
            _rsport = 0
        if raw_profile in ("udp", "tcp") and _as_bool(cfg.get("raw_sport_random")):
            corecfg["raw_sport_random"] = True
        elif raw_profile in ("udp", "tcp") and 1 <= _rsport <= 65535:
            corecfg["raw_sport"] = _rsport
        try:
            _rrot = int(cfg.get("raw_sport_rotate") or 0)
        except (TypeError, ValueError):
            _rrot = 0
        if raw_profile == "udp" and 1 <= _rrot <= 64:
            corecfg["raw_sport_rotate"] = _rrot
            try:
                _rdp = int(cfg.get("raw_dports") or 0)
            except (TypeError, ValueError):
                _rdp = 0
            if 1 <= _rdp <= 8:
                corecfg["raw_dports"] = _rdp
    try:
        _ptries = int(cfg.get("port_tries") or 0)
    except (TypeError, ValueError):
        _ptries = 0
    if 1 <= _ptries <= 50:
        corecfg["port_tries"] = _ptries
    if transport in QUEUEING_TRANSPORTS:
        try:
            _wk = int(cfg.get("workers") or 0)
        except (TypeError, ValueError):
            _wk = 0
        if 2 <= _wk <= MAX_WORKERS and not bool(cfg.get("fec")):
            corecfg["workers"] = _wk
    if transport == "spoof":
        try:
            _rp = int(cfg.get("raw_proto") or 0)
        except (TypeError, ValueError):
            _rp = 0
        if 1 <= _rp <= 255:
            corecfg["raw_proto"] = _rp
    if transport == "dns":
        corecfg["dns_zone"] = str(cfg.get("dns_zone") or "").strip().lower()
        if cfg.get("role") == "client":
            corecfg["dns_resolvers"] = [str(x).strip() for x in (cfg.get("dns_resolvers") or []) if str(x).strip()]
    if transport == "ws":
        if cfg.get("ws_host"):
            corecfg["ws_host"] = str(cfg["ws_host"])
        if cfg.get("ws_path"):
            corecfg["ws_path"] = str(cfg["ws_path"])
        cdn = str(cfg.get("cdn_carrier") or "ws").strip().lower()
        if cdn in ("http", "grpc"):
            corecfg["cdn_carrier"] = cdn

            if cfg.get("role") == "client":
                _shape = ("http_streams",)
                if cdn == "http":
                    _shape = ("http_up_workers", "http_up_batch_kb", "http_up_rate", "http_streams")
            elif cdn == "http":
                _shape = ("http_up_workers", "http_up_batch_kb")
            else:
                _shape = ()
            for _k in _shape:
                try:
                    _v = int(cfg.get(_k) or 0)
                except (TypeError, ValueError):
                    _v = 0
                if _v > 0:
                    corecfg[_k] = _v
        if bool(cfg.get("ws_tls")) and cfg.get("role") == "client":
            corecfg["ws_tls"] = True
            if bool(cfg.get("sni_split")):
                corecfg["sni_split"] = True
                sp = int(cfg.get("split_pos") or 0)
                if sp:
                    corecfg["split_pos"] = max(0, min(1400, sp))
                mode = str(cfg.get("sni_mode") or "").strip().lower()
                if mode in ("disorder", "fake"):
                    corecfg["sni_mode"] = mode
                    st = int(cfg.get("split_ttl") or 0)
                    if st:
                        corecfg["split_ttl"] = max(0, min(255, st))
            ech = str(cfg.get("ws_ech") or "").strip()
            if ech:
                corecfg["ws_ech"] = ech
            ips = [str(x).strip() for x in (cfg.get("ws_edge_ips") or []) if str(x).strip()]
            snis = [s for s in (cfg.get("ws_edge_snis") or []) if isinstance(s, dict) and str(s.get("host") or "").strip()]
            if ips and snis:
                corecfg["ws_edge_ips"] = ips
                corecfg["ws_edge_snis"] = [{"host": str(s["host"]).strip(),
                                         "ech": str(s.get("ech") or "").strip(),
                                         "path": str(s.get("path") or "").strip()} for s in snis]
                _wrs = cfg.get("ws_rotate_secs")
                corecfg["ws_rotate_secs"] = 600 if _wrs is None else max(0, min(28800, int(_wrs)))
    if transport in ("udp", "raw", "spoof") and bool(cfg.get("fec")):
        corecfg["fec"] = True
        corecfg["fec_data"] = int(cfg.get("fec_data") or 10)
        corecfg["fec_parity"] = int(cfg.get("fec_parity") or 3)
    if bool(cfg.get("gso")):
        corecfg["gso"] = True
    if transport == "spoof" and crypto_on:
        spoof_src = str(cfg.get("spoof_src") or "").strip()
        spoof_dst = str(cfg.get("spoof_dst") or "").strip()
        if cfg.get("role") == "client":
            if spoof_src:
                corecfg["spoof_src_ip"] = spoof_src
            if spoof_dst:
                corecfg["spoof_dst_ip"] = spoof_dst
        else:
            if spoof_dst:
                corecfg["spoof_dst_ip"] = spoof_dst
            corecfg["real_peer_ip"] = cfg["remote_ip"]
    if transport in ("raw", "spoof", "tcp", "ws") and cfg.get("role") == "client" and bool(cfg.get("fake_desync")):
        corecfg["fake_desync"] = True
        corecfg["fake_ttl"] = max(1, min(255, int(cfg.get("fake_ttl") or 4)))
        corecfg["fake_count"] = max(1, min(64, int(cfg.get("fake_count") or 2)))
        mode = str(cfg.get("fake_mode") or "ttl").strip().lower()
        corecfg["fake_mode"] = mode if mode in ("ttl", "badsum", "both") else "ttl"
    if transport in ("udp", "tcp", "raw") and str(cfg.get("role")) == "client":
        ordered = _ordered_pool(str(cfg.get("remote_ip") or ""), cfg.get("peer_ips"))
        if len(ordered) >= 2:
            corecfg["peer_ips"] = [f"{ip}:{port}" if transport in ("udp", "tcp") else ip for ip in ordered]
            corecfg["peer_rotate_secs"] = max(0, int(cfg.get("peer_rotate_secs") or 0))
        _src_sel = [str(x).strip() for x in (cfg.get("src_ips") or []) if str(x).strip()]
        sord = _ordered_pool(str(cfg.get("local_ip") or ""), _src_sel)
        if _src_sel and sord:
            corecfg["src_ips"] = sord
            corecfg.setdefault("peer_rotate_secs", max(0, int(cfg.get("peer_rotate_secs") or 0)))
    if cfg.get("role") == "server":
        lip = cfg.get("local_ip") or "0.0.0.0"
        pool_ips = [str(x).strip() for x in (cfg.get("listen_ips") or []) if str(x).strip()]
        pooled = bool(cfg.get("pool_listen"))
        if transport == "dns":
            corecfg["listen"] = f"{lip}:53"
        elif pooled and transport in ("udp", "tcp") and pool_ips:
            corecfg["listen"] = f"{pool_ips[0]}:{port}"
            corecfg["listen_ips"] = [f"{ip}:{port}" for ip in pool_ips]
        elif pooled and transport == "raw":
            corecfg["listen"] = f"0.0.0.0:{port}"
        else:
            corecfg["listen"] = f"{lip}:{port}"
    elif transport == "dns":
        pass
    else:
        dial, dport = cfg["remote_ip"], port
        edge = str(cfg.get("edge_ip") or "").strip()
        if transport == "ws" and edge:
            h, sep, p = edge.rpartition(":")
            if sep and p.isdigit():
                dial, dport = h, int(p)
            else:
                dial, dport = edge, (443 if bool(cfg.get("ws_tls")) else 80)
        corecfg["peer"] = f"{dial}:{dport}"
        lip = str(cfg.get("local_ip") or "").strip()
        if lip:
            corecfg["bind_ip"] = lip
    return corecfg


def _core_unit(name):
    return "tnl-cor-" + name


def _core_last_error(name, lines=40):
    unit = _core_unit(name)
    args = ["journalctl", "-u", unit, "-n", str(int(lines)), "--no-pager", "-o", "cat"]
    _, inv, _ = run(["systemctl", "show", "-p", "InvocationID", "--value", unit], timeout=10)
    inv = inv.strip()
    if inv:
        args.append("_SYSTEMD_INVOCATION_ID=" + inv)
    rc, out, _ = run(args, timeout=10)
    if rc != 0 or not out:
        return ""
    tag = "tnl-core: "
    for ln in reversed(out.splitlines()):
        i = ln.find(tag)
        if i >= 0:
            msg = ln[i + len(tag):].strip()
            if msg:
                return msg[:300]
    return ""


def _netdev_missing_reason(name, ttype):
    if run(["ip", "link", "show", name])[0] == 0:
        return ""
    if ttype == "core":
        if _core_running(name):
            return ("هستهٔ tnl-core در حال اجراست ولی اینترفیسِ «" + name + "» هنوز بالا نیامده — "
                    "احتمالاً استارتِ کند؛ چند لحظه بعد دوباره امتحان کن")
        why = _core_last_error(name)
        if why:
            return "هستهٔ tnl-core بالا نیامد — پیامِ خودش: " + why
    need = {"vxlan": "vxlan", "gre": "ip_gre", "sit": "sit", "ipip": "ipip",
            "l2tpv3": "l2tp_eth", "fou": "fou و ipip", "ipsec": "xfrm_interface",
            "core": "هستهٔ tnl-core"}.get(ttype, ttype)
    return f"اینترفیسِ {ttype} ساخته نشد — «{need}» روی این نود نصب/فعال نیست"


def _core_running(name):
    _, out, _ = run(["systemctl", "is-active", _core_unit(name)], timeout=10)
    return out.strip() in ("active", "activating")


def _cfg_path(name, suffix=""):
    return os.path.join(CONFIG_DIR, "core-" + name + suffix)


_tmp_seq = itertools.count(1)


def _atomic_write_json(path, obj):
    d, base = os.path.split(path)
    tmp = os.path.join(d, ".%s.%d.tmp" % (base, next(_tmp_seq)))
    try:
        with open(tmp, "w") as f:
            json.dump(obj, f)
        os.replace(tmp, path)
    except OSError as e:
        try:
            os.remove(tmp)
        except OSError:
            pass
        return str(e)
    return None


def _core_status_paths(name):
    base = _cfg_path(name, ".status")
    return (base, base + ".verdict", base + ".verdict.taken",
            base + ".pin", base + ".pin.taken", base + ".echcmd")


def _read_core_cfg(name):
    try:
        with open(_cfg_path(name, ".json")) as f:
            cc = json.load(f)
    except (OSError, ValueError):
        return {}
    return cc if isinstance(cc, dict) else {}


def _is_ws_pool(name):
    cc = _read_core_cfg(name)
    return bool(cc.get("ws_edge_ips"))


def _is_ws_single(name):
    cc = _read_core_cfg(name)
    return bool(cc.get("ws_host") and cc.get("status_path")) and not cc.get("ws_edge_ips")


def _is_peer_pool(name):
    cc = _read_core_cfg(name)
    return bool(cc.get("peer_ips") or cc.get("src_ips"))


def build_core(cfg):
    name = cfg["name"]
    _ensure_core()
    corecfg = _core_config(cfg)
    path = _cfg_path(name, ".json")
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        json.dump(corecfg, f, indent=2)
    os.chmod(tmp, 0o600)
    os.replace(tmp, path)
    _core_relaunch(name)


def _core_relaunch(name):
    unit = _core_unit(name)
    run(["systemctl", "stop", unit])
    run(["systemctl", "reset-failed", unit])
    _sweep_owned_rules(name)
    for p in _core_status_paths(name):
        try:
            os.remove(p)
        except OSError:
            pass
    run(["systemd-run", "--unit", unit, "--collect",
         "-p", "Restart=always", "-p", "RestartSec=3",
         CORE_BIN, "--config", _cfg_path(name, ".json")])
    for _ in range(80):
        if os.path.exists("/sys/class/net/" + name):
            return True
        time.sleep(0.1)
    return False


RULE_OWNER_PREFIX = "tnl:"


def _sweep_owned_rules(name):
    if not NAME_RE.match(name or ""):
        return 0
    tag = '--comment "%s%s"' % (RULE_OWNER_PREFIX, name)
    removed = 0
    for table in ("filter", "raw", "mangle", "nat"):
        try:
            out = subprocess.run(["iptables-save", "-t", table], capture_output=True, text=True, timeout=10)
        except (OSError, subprocess.SubprocessError):
            continue
        if out.returncode != 0:
            continue
        for line in out.stdout.splitlines():
            if not line.startswith("-A ") or tag not in line:
                continue
            try:
                args = shlex.split(line)
            except ValueError:
                continue
            args[0] = "-D"
            run(["iptables", "-t", table] + args)
            removed += 1
    if removed:
        logline("%s: swept %d orphaned firewall rule(s) tagged %s%s" % (name, removed, RULE_OWNER_PREFIX, name))
    return removed


def _core_stop(name):
    unit = _core_unit(name)
    run(["systemctl", "stop", unit])
    run(["systemctl", "reset-failed", unit])
    _sweep_owned_rules(name)
    for p in _core_status_paths(name):
        try:
            os.remove(p)
        except OSError:
            pass


def _core_teardown(cfg):
    name = cfg.get("name", "")
    if not NAME_RE.match(name):
        return
    _core_stop(name)
    try:
        os.remove(_cfg_path(name, ".json"))
    except OSError:
        pass


def _set_link_state(cfg, enabled):
    name = cfg.get("name", "")
    if not NAME_RE.match(name):
        raise ValueError("bad name")
    if cfg.get("type") == "core":
        if enabled:
            build_core(cfg)
            why = _netdev_missing_reason(name, "core")
            if why:
                raise RuntimeError(why)
        else:
            _core_stop(name)
            if _core_running(name):
                raise RuntimeError("واحدِ هستهٔ «" + name + "» با وجودِ stop هنوز در حال اجراست")
    else:
        must(["ip", "link", "set", name, "up" if enabled else "down"])


def _pf_match(cfg, iface, proto, lp):
    m = ["-i", iface, "-p", proto, "--dport", lp]
    lip = cfg.get("listen_ip") or ""
    if is_ipv4(lip):
        m += ["-d", lip]
    return m


def _pf_acct_rules(cfg):
    lp, nm = str(cfg.get("listen_port", "")), cfg.get("name", "")
    if not (lp.isdigit() and NAME_RE.match(nm)):
        return []
    scope = []
    iface = cfg.get("iface") or ""
    if IFACE_RE.match(iface):
        scope = ["-i", iface]
    ct = ["-m", "conntrack"]
    lip = cfg.get("listen_ip") or ""
    if is_ipv4(lip):
        ct += ["--ctorigdst", lip]
    ct += ["--ctorigdstport", lp]
    out = []
    for dirn, ctdir in (("in", "ORIGINAL"), ("out", "REPLY")):
        out.append(scope + ct + ["--ctdir", ctdir, "-m", "comment", "--comment",
                                 f"pfacct:{nm}:{dirn}", "-j", "RETURN"])
    return out


def _ipt_add_missing(table, chain, rule):
    rc, _, _ = run(["iptables", "-t", table, "-C", chain] + rule)
    if rc != 0:
        run(["iptables", "-t", table, "-A", chain] + rule)


def _ipt_ins_missing(table, chain, rule):
    rc, _, _ = run(["iptables", "-t", table, "-C", chain] + rule)
    if rc != 0:
        run(["iptables", "-t", table, "-I", chain, "1"] + rule)


def _ipt_del_all(table, chain, rule, tries=64):
    for _ in range(tries):
        rc, _, _ = run(["iptables", "-t", table, "-C", chain] + rule)
        if rc != 0:
            break
        run(["iptables", "-t", table, "-D", chain] + rule)


def _pf_acct_build(cfg):
    run(["iptables", "-t", "mangle", "-N", "PFACCT"])
    _ipt_add_missing("mangle", "PREROUTING", ["-j", "PFACCT"])
    for r in _pf_acct_rules(cfg):
        _ipt_add_missing("mangle", "PFACCT", r)


def _pf_acct_teardown(cfg):
    for r in _pf_acct_rules(cfg):
        _ipt_del_all("mangle", "PFACCT", r)


def _read_pf_net(cfgs):
    names = {c.get("name") for c in cfgs if c.get("type") == "portfw" and c.get("name")}
    if not names:
        return {}
    rc, out, _ = run(["iptables-save", "-c", "-t", "mangle"])
    if rc != 0:
        return {}
    res = {}
    for line in out.splitlines():
        if "pfacct:" not in line:
            continue
        mb = re.match(r"\[(\d+):(\d+)\]", line)
        mc = re.search(r"pfacct:([A-Za-z0-9_.-]+):(in|out)", line)
        if not (mb and mc) or mc.group(1) not in names:
            continue
        e = res.setdefault(mc.group(1), [0, 0])
        e[0 if mc.group(2) == "in" else 1] += int(mb.group(2))
    return res


def build_portfw(cfg):
    iface = cfg["iface"]
    lp, dp = str(cfg["listen_port"]), str(cfg["dst_port"])
    if not (IFACE_RE.match(iface) and lp.isdigit() and dp.isdigit()):
        return
    ips = [ip for ip in cfg.get("dst_ips", []) if is_ipv4(ip)]
    if not ips:
        return
    enable_ip_forward()
    idx = int(cfg.get("current_index", 0) or 0)
    if idx >= len(ips):
        idx = 0
    active = ips[idx]
    for proto in ("tcp", "udp"):
        match = _pf_match(cfg, iface, proto, lp)
        for ip in ips:
            _ipt_del_all("nat", "PREROUTING", match + ["-j", "DNAT", "--to-destination", f"{ip}:{dp}"])
        run(["iptables", "-t", "nat", "-A", "PREROUTING"] + match
            + ["-j", "DNAT", "--to-destination", f"{active}:{dp}"])
    for proto in ("tcp", "udp"):
        for ip in ips:
            _ipt_del_all("nat", "POSTROUTING",
                         ["-d", ip, "-p", proto, "--dport", dp, "-o", iface, "-j", "MASQUERADE"])
        run(["iptables", "-t", "nat", "-A", "POSTROUTING", "-d", active, "-p", proto,
            "--dport", dp, "-o", iface, "-j", "MASQUERADE"])
    _pf_acct_build(cfg)


def apply_config(cfg):
    t = cfg.get("type")
    if t == "vxlan":
        build_vxlan(cfg)
    elif t == "gre":
        build_gre(cfg)
    elif t == "sit":
        build_sit(cfg)
    elif t == "ipip":
        build_ipip(cfg)
    elif t == "l2tpv3":
        build_l2tp(cfg)
    elif t == "fou":
        build_fou(cfg)
    elif t == "ipsec":
        build_ipsec(cfg)
    elif t == "core":
        build_core(cfg)
    elif t == "portfw":
        build_portfw(cfg)
    if t != "portfw" and not cfg.get("enabled", True):
        _set_link_state(cfg, False)


def teardown_config(cfg):
    ttype, name, tid = cfg.get("type"), cfg.get("name", ""), str(cfg.get("id", ""))
    if not NAME_RE.match(name):
        return
    if ttype in ("vxlan", "gre", "sit", "ipip"):
        run(["ip", "link", "del", name])
    elif ttype == "l2tpv3":
        if tid.isdigit():
            run(["ip", "l2tp", "del", "session", "tunnel_id", tid, "session_id", tid])
            run(["ip", "l2tp", "del", "tunnel", "tunnel_id", tid])
        run(["ip", "link", "del", name])
    elif ttype == "fou":
        run(["ip", "link", "del", name])
        port = _fou_port(cfg)
        if not any(c.get("name") != name and c.get("type") == "fou" and _fou_port(c) == port for c in raw_configs()):
            run(["ip", "fou", "del", "port", str(port), "ipproto", "4"])
    elif ttype == "ipsec":
        _ipsec_clear(cfg)
    elif ttype == "core":
        _core_teardown(cfg)
    elif ttype == "portfw":
        _pf_acct_teardown(cfg)
        iface, lp, dp = cfg.get("iface", ""), str(cfg.get("listen_port", "")), str(cfg.get("dst_port", ""))
        if IFACE_RE.match(iface) and lp.isdigit() and dp.isdigit():
            for proto in ("tcp", "udp"):
                match = _pf_match(cfg, iface, proto, lp)
                for ip in cfg.get("dst_ips", []):
                    if not is_ipv4(ip):
                        continue
                    _ipt_del_all("nat", "PREROUTING",
                                 match + ["-j", "DNAT", "--to-destination", f"{ip}:{dp}"])
            for proto in ("tcp", "udp"):
                for ip in cfg.get("dst_ips", []):
                    if not is_ipv4(ip):
                        continue
                    _ipt_del_all("nat", "POSTROUTING",
                                 ["-d", ip, "-p", proto, "--dport", dp, "-o", iface, "-j", "MASQUERADE"])


def apply_all():
    rc, rout, _ = run(["ip", "-4", "route"])
    has_default = any(l.startswith("default") for l in rout.splitlines())
    pip = primary_ip() if has_default else None
    locals_now = local_ips_flat()
    for cfg in raw_configs():
        if cfg.get("type") not in ("portfw", None):
            li = cfg.get("local_ip")
            if li and pip and li not in locals_now:
                cfg["local_ip"] = pip
                write_config(cfg["name"], cfg)
                logline(f"self-healed local_ip of {cfg['name']} -> {pip}")
        try:
            apply_config(cfg)
        except Exception as e:
            logline(f"apply {cfg.get('name')} failed: {e}")


def rotate_once():
    now = int(time.time())
    for cfg in raw_configs():
        if cfg.get("type") != "portfw":
            continue
        try:
            interval = int(cfg.get("switch_interval", 0) or 0)
        except Exception:
            interval = 0
        ips = [ip for ip in cfg.get("dst_ips", []) if is_ipv4(ip)]
        if interval <= 0 or len(ips) < 2:
            continue
        if now - int(cfg.get("last_switch", 0) or 0) < interval:
            continue
        cfg["current_index"] = (int(cfg.get("current_index", 0) or 0) + 1) % len(ips)
        cfg["last_switch"] = now
        write_config(cfg["name"], cfg)
        build_portfw(cfg)
        logline(f"rotated {cfg['name']} -> index {cfg['current_index']}")


def rotation_loop():
    while True:
        time.sleep(30)
        try:
            with _apply_lock:
                if _restart_pending.is_set():
                    continue
                rotate_once()
        except Exception as e:
            logline(f"rotate loop: {e}")


def peer_of(tunnel_ip, ttype):
    addr = tunnel_ip.split("/")[0]
    prefix = tunnel_ip.split("/")[1] if "/" in tunnel_ip else ("64" if ttype == "sit" else "24")
    net = ipaddress.ip_network(f"{addr}/{prefix}", strict=False)
    mine = int(ipaddress.ip_address(addr)) - int(net.network_address)
    return str(net.network_address + (3 - mine))


PROBE_PORT = 9
SYN_RTO = 1.0
PROBE_WAIT = 0.8
PROBE_COUNT = 20
PROBE_MIN_PCT = 15
PROBE_MIN_PCT_RANGE = (5, 100)
SWEEP_SLOW = 3.0
SWEEP_FAST = 1.0
RED_SWEEPS = 2
_SO_BINDTODEVICE = getattr(socket, "SO_BINDTODEVICE", 25)
_ANSWERED = (0, errno.ECONNREFUSED)
_PENDING = (errno.EINPROGRESS, errno.EWOULDBLOCK, errno.EALREADY)


def tun_probe(iface, tunnel_ip, ttype, count=PROBE_COUNT):
    self_ip = tunnel_ip.split("/")[0]
    peer = peer_of(tunnel_ip, ttype)
    fam = socket.AF_INET6 if ttype == "sit" else socket.AF_INET
    hits = sent = 0
    best = None

    def faster(prev, secs):
        ms = round(secs * 1000, 1)
        return ms if prev is None else min(prev, ms)

    waiting = {}
    for _ in range(max(1, count)):
        try:
            s = socket.socket(fam, socket.SOCK_STREAM)
        except OSError:
            break
        try:
            s.setblocking(False)
            s.setsockopt(socket.SOL_SOCKET, _SO_BINDTODEVICE, iface.encode() + b"\x00")
            s.bind((self_ip, 0))
            t0 = time.monotonic()
            err = s.connect_ex((peer, PROBE_PORT))
        except OSError:
            s.close()
            break
        if err in _ANSWERED:
            sent += 1
            hits += 1
            best = faster(best, time.monotonic() - t0)
            s.close()
        elif err in _PENDING:
            sent += 1
            waiting[s] = t0
        else:
            s.close()

    if sent * 2 < max(1, count):
        for s in waiting:
            s.close()
        return 0, 0, None

    deadline = time.monotonic() + PROBE_WAIT
    while waiting:
        left = deadline - time.monotonic()
        if left <= 0:
            break
        try:
            ready = select.select([], list(waiting), [], left)[1]
        except OSError:
            break
        if not ready:
            break
        now = time.monotonic()
        for s in ready:
            t0 = waiting.pop(s, None)
            try:
                if s.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR) in _ANSWERED:
                    hits += 1
                    best = faster(best, now - t0)
            except OSError:
                pass
            s.close()
    for s in waiting:
        s.close()
    return hits, sent, best


def probe_min_pct(cfg):
    lo, hi = PROBE_MIN_PCT_RANGE
    try:
        v = int(cfg.get("probe_min_pct"))
    except (TypeError, ValueError):
        return PROBE_MIN_PCT
    return max(lo, min(hi, v))


def carrying(hits, sent, pct):
    return hits * 100 >= sent * pct


_verdict_lock = threading.Lock()
_verdict = {}


def settle(name, ok):
    with _verdict_lock:
        st = _verdict.setdefault(name, {"pub": None, "bad": 0})
        if ok:
            st["pub"], st["bad"] = True, 0
        else:
            st["bad"] += 1
            if not (st["pub"] is True and st["bad"] < RED_SWEEPS):
                st["pub"] = False
        return st["pub"]


def _read_path_state(name):
    try:
        with open(_cfg_path(name, ".status")) as f:
            st = json.load(f)
    except (OSError, ValueError):
        return 0, False
    if not isinstance(st, dict):
        return 0, False
    try:
        epoch = int(st.get("epoch") or 0)
    except (TypeError, ValueError):
        return 0, False
    return epoch, bool(st.get("ready"))


def _condemned(st, kind, key):
    return bool(key) and any(h["key"] == key and h["kind"] == kind and h["state"] != "healthy"
                             for h in st["health"])


def _report_carrying(name, edge, epoch):
    st = _read_status(name)
    pair = st["pair"]
    low, high = pair["low"], pair["high"]
    if not edge and not (_condemned(st, pair["low_kind"], low) or _condemned(st, pair["high_kind"], high)):
        return
    err = _atomic_write_json(_cfg_path(name, ".status.verdict"),
                             {"cmd": "ok", "low": low, "high": high, "epoch": epoch})
    carrying = f"{low or '?'} / {high or '?'} are carrying" if low or high else "the path is carrying"
    logline(f"{name}: probe found traffic crossing — told the core {carrying}"
            + (f" [{err}]" if err else ""))


def pool_failover(name, alive, crossed, epoch, session_up, stable):
    if str(_read_core_cfg(name).get("role") or "") != "client":
        return
    counted = stable and not crossed
    low, high = "", ""
    if counted:
        pair = _read_status(name)["pair"]
        low, high = pair["low"], pair["high"]
    with _verdict_lock:
        st = _verdict.setdefault(name, {"pub": None, "bad": 0})
        was_red, st["red"] = st.get("red", False), alive is False
        if crossed:
            st["on"], st["onbad"] = None, 0
        elif counted:
            if st.get("on") != (low, high):
                st["on"], st["onbad"] = (low, high), 0
            st["onbad"] += 1
        onbad = st.get("onbad", 0)
    if alive is not False:
        if crossed and session_up:
            _report_carrying(name, was_red and alive is True, epoch)
        return
    if not counted or onbad < RED_SWEEPS:
        return
    err = _atomic_write_json(_cfg_path(name, ".status.verdict"),
                             {"cmd": "fail", "low": low, "high": high, "epoch": epoch})
    asked = (f"fail {low or '?'} / {high or '?'}" if low or high
             else "spend a free step — this tunnel has no endpoint to burn")
    logline(f"{name}: probe found nothing crossing — asked the core to {asked}"
            + (f" [{err}]" if err else ""))


LIVE_WINDOW = 12.0
_flow_lock = threading.Lock()
_flow_state = {}
def _iface_ctr(name, which):
    try:
        with open("/sys/class/net/" + name + "/statistics/" + which + "_bytes") as f:
            return int(f.read().strip())
    except Exception:
        return None


def _prune_iface_state(names):
    with _flow_lock:
        for nm in [n for n in _flow_state if n not in names]:
            _flow_state.pop(nm, None)
    with _verdict_lock:
        for nm in [n for n in _verdict if n not in names]:
            _verdict.pop(nm, None)


def _flow_sample(name):
    now = time.monotonic()
    with _flow_lock:
        rx, tx = _iface_ctr(name, "rx"), _iface_ctr(name, "tx")
        if rx is None or tx is None:
            return None, None
        prev = _flow_state.get(name)
        rxp = prev.get("rxp") if prev else None
        txp = prev.get("txp") if prev else None
        if prev is not None:
            if rx > prev["rx"]:
                rxp = now
            elif rx < prev["rx"]:
                rxp = None
            if tx > prev["tx"]:
                txp = now
            elif tx < prev["tx"]:
                txp = None
        _flow_state[name] = {"rx": rx, "tx": tx, "rxp": rxp, "txp": txp}
    still = lambda p: None if p is None else max(0.0, now - p)
    return still(rxp), still(txp)


def health_of(cfg):
    ttype, name = cfg.get("type"), cfg.get("name", "")
    if ttype == "portfw":
        iface, lp, dp = cfg.get("iface", ""), str(cfg.get("listen_port", "")), str(cfg.get("dst_port", ""))
        ips = [ip for ip in cfg.get("dst_ips", []) if is_ipv4(ip)]
        idx = int(cfg.get("current_index", 0) or 0)
        if idx >= len(ips):
            idx = 0
        active = ips[idx] if ips else ""
        rule = False
        if active and IFACE_RE.match(iface) and lp.isdigit() and dp.isdigit():
            rule = True
            for proto in ("tcp", "udp"):
                match = _pf_match(cfg, iface, proto, lp)
                rc, _, _ = run(["iptables", "-t", "nat", "-C", "PREROUTING"] + match
                               + ["-j", "DNAT", "--to-destination", f"{active}:{dp}"])
                if rc != 0:
                    rule = False
                    break
        reachable = False
        if active and dp.isdigit():
            try:
                socket.create_connection((active, int(dp)), timeout=2).close()
                reachable = True
            except ConnectionRefusedError:
                reachable = True
            except Exception:
                reachable = False
        return {"active": active, "rule": rule, "reachable": reachable, "up": rule}
    up = os.path.exists("/sys/class/net/" + name)
    rx_still, tx_still = _flow_sample(name) if up else (None, None)
    alive, rtt, loss, crossed = None, None, None, None
    tip = cfg.get("tunnel_ip", "")
    if up and tip and tip != "N/A":
        epoch_before, ready_before = _read_path_state(name)
        hits, sent, rtt = tun_probe(name, tip, ttype)
        if sent:
            loss = round((sent - hits) * 100.0 / sent, 1)
            crossed = carrying(hits, sent, probe_min_pct(cfg))
            alive = settle(name, crossed)
            epoch, ready = _read_path_state(name)
            pool_failover(name, alive, crossed, epoch_before, ready_before and ready,
                          epoch == epoch_before)
    return {"up": up, "alive": alive, "dead": alive is False, "rtt_ms": rtt, "loss_pct": loss,
            "crossed": crossed, "rx_still": rx_still, "tx_still": tx_still, "live_win": int(LIVE_WINDOW)}


def _cpu_snap():
    with open("/proc/stat") as f:
        v = [int(x) for x in f.readline().split()[1:]]
    idle = v[3] + (v[4] if len(v) > 4 else 0)
    return sum(v), idle


_cpu_prev = None
_cpu_last = 0.0
_cpu_lock = threading.Lock()


def _cpu_pct():
    global _cpu_prev, _cpu_last
    with _cpu_lock:
        cur = _cpu_snap()
        prev = _cpu_prev
        if prev is None:
            time.sleep(0.1)
            prev, cur = cur, _cpu_snap()
        elif cur[0] - prev[0] <= 0:
            return _cpu_last
        _cpu_prev = cur
        t2, i2 = cur
        t1, i1 = prev
        dt = t2 - t1
        if dt <= 0:
            return _cpu_last
        _cpu_last = round((1 - (i2 - i1) / dt) * 100, 1)
        return _cpu_last


def _read_os():
    with open("/etc/os-release") as f:
        for line in f:
            if line.startswith("PRETTY_NAME="):
                return line.split("=", 1)[1].strip().strip('"')
    return None


def _proc_net_dev():
    out = {}
    with open("/proc/net/dev") as f:
        for line in f:
            if ":" not in line:
                continue
            name, rest = line.split(":", 1)
            cols = rest.split()
            try:
                out[name.strip()] = [int(cols[0]), int(cols[8])]
            except (IndexError, ValueError):
                continue
    return out


def _read_net(cfgs):
    raw = _proc_net_dev()
    net = {}
    for c in cfgs:
        t, nm = c.get("type"), c.get("name")
        if t == "portfw" or not nm:
            continue
        v = raw.get(nm)
        if v:
            net[nm] = v
    trx = ttx = 0
    seen = False
    for ifn in list_ifaces():
        v = raw.get(ifn)
        if v:
            trx += v[0]
            ttx += v[1]
            seen = True
    if seen:
        net["_node"] = [trx, ttx]
    return net


def read_stats():
    st = {"cpus": os.cpu_count()}
    try:
        with open("/proc/uptime") as f:
            st["uptime"] = int(float(f.read().split()[0]))
    except Exception:
        pass
    try:
        with open("/proc/loadavg") as f:
            st["load"] = f.read().split()[:3]
    except Exception:
        pass
    try:
        mt = ma = 0
        with open("/proc/meminfo") as f:
            for line in f:
                if line.startswith("MemTotal:"):
                    mt = int(line.split()[1])
                elif line.startswith("MemAvailable:"):
                    ma = int(line.split()[1])
        st["mem_total_mb"] = mt // 1024
        st["mem_used_mb"] = (mt - ma) // 1024
    except Exception:
        pass
    try:
        st["os"] = _read_os()
    except Exception:
        pass
    try:
        s = os.statvfs("/")
        total = s.f_blocks * s.f_frsize
        avail = s.f_bavail * s.f_frsize
        used = (s.f_blocks - s.f_bfree) * s.f_frsize
        st["disk_total_mb"] = total // (1024 * 1024)
        st["disk_used_mb"] = used // (1024 * 1024)
        st["disk_pct"] = round(used / (used + avail) * 100, 1) if (used + avail) else 0.0
    except Exception:
        pass
    try:
        st["cpu_pct"] = _cpu_pct()
    except Exception:
        pass
    return st


HEALTH_WORKERS = 64
HEALTH_DEADLINE = 12
_health_cache = {}
_health_lock = threading.Lock()
_health_inflight = {}


_sweep_due = {}


def _sweep_gap(res):
    return SWEEP_FAST if (res or {}).get("crossed") is False else SWEEP_SLOW


def _health_harvest(names):
    with _health_lock:
        for nm in names:
            f = _health_inflight.get(nm)
            if f is None or not f.done():
                _health_cache.setdefault(nm, {"up": None})
                continue
            _health_inflight.pop(nm, None)
            try:
                _health_cache[nm] = f.result()
            except Exception:
                _health_cache.setdefault(nm, {"up": None})
            _sweep_due[nm] = time.monotonic() + _sweep_gap(_health_cache.get(nm))
        for nm in [n for n in _health_cache if n not in names]:
            _health_cache.pop(nm, None)


def health_refresh_once(ex):
    cfgs = raw_configs()
    if not cfgs:
        with _health_lock:
            _health_cache.clear()
        _health_inflight.clear()
        _sweep_due.clear()
        _prune_iface_state(set())
        return
    names = {c["name"] for c in cfgs}
    _health_harvest(names)
    for nm in [n for n in _health_inflight if n not in names]:
        _health_inflight.pop(nm, None)
    for nm in [n for n in _sweep_due if n not in names]:
        _sweep_due.pop(nm, None)
    now = time.monotonic()
    for c in cfgs:
        if c["name"] in _health_inflight or _sweep_due.get(c["name"], 0.0) > now:
            continue
        _health_inflight[c["name"]] = ex.submit(health_of, c)
    futures_wait(set(_health_inflight.values()), timeout=HEALTH_DEADLINE)
    _health_harvest(names)
    _prune_iface_state(names)


def health_loop():
    ex = ThreadPoolExecutor(max_workers=HEALTH_WORKERS)
    while True:
        try:
            health_refresh_once(ex)
        except Exception as e:
            logline(f"health loop: {e}")
        time.sleep(SWEEP_FAST)


def _require(d, keys):
    for k in keys:
        if k not in d or d[k] in (None, ""):
            raise ValueError(f"missing field: {k}")


def _req_name(d):
    _require(d, ["name"])
    name = str(d["name"])
    if not NAME_RE.match(name):
        raise ValueError("bad name")
    return name


def _self_sha():
    try:
        with open(INSTALLED, "rb") as f:
            return hashlib.sha256(f.read()).hexdigest()
    except OSError:
        return ""


_SELF_SHA = _self_sha()


REQ_CTR_STEP = 256
REQ_CTR_WINDOW = 4096
_REQ_CTR_MASK = (1 << REQ_CTR_WINDOW) - 1

_req_ctr_lock = threading.Lock()
_req_ctr = 0
_req_seen = 0
_req_ctr_hwm = 0


def _seed_req_ctr():
    global _req_ctr, _req_seen, _req_ctr_hwm
    try:
        v = int(load_conf().get("req_ctr") or 0)
    except Exception:
        v = 0
    with _req_ctr_lock:
        _req_ctr = _req_ctr_hwm = v
        _req_seen = _REQ_CTR_MASK


def _persist_req_ctr(hwm):
    with _apply_lock:
        try:
            conf = load_conf()
            if int(conf.get("req_ctr") or 0) < hwm:
                conf["req_ctr"] = hwm
                save_conf(conf)
        except Exception as e:
            logline(f"req_ctr persist: {e}")


def _accept_ctr(ctr):
    global _req_ctr, _req_seen, _req_ctr_hwm
    hwm = None
    with _req_ctr_lock:
        if ctr > _req_ctr:
            step = ctr - _req_ctr
            _req_seen = 1 if step >= REQ_CTR_WINDOW else ((_req_seen << step) | 1) & _REQ_CTR_MASK
            _req_ctr = ctr
            if ctr >= _req_ctr_hwm:
                _req_ctr_hwm = hwm = ctr + REQ_CTR_STEP
        else:
            bit = _req_ctr - ctr
            if bit >= REQ_CTR_WINDOW or (_req_seen >> bit) & 1:
                return False
            _req_seen |= 1 << bit
    if hwm is not None:
        threading.Thread(target=_persist_req_ctr, args=(hwm,), daemon=True).start()
    return True


def _sig_msg(method, path, ctr, body_sha):
    return "%s\n%s\n%s\n%s" % (method, path, ctr, body_sha)


def _sig_ok(secret, method, path, ctr, body_sha, sig_b64):
    try:
        want = hmac.new(secret.encode("utf-8"),
                        _sig_msg(method, path, ctr, body_sha).encode("utf-8"),
                        hashlib.sha256).digest()
        got = base64.b64decode(sig_b64, validate=True)
    except Exception:
        return False
    return hmac.compare_digest(want, got)


def note_central(ip, port, tls):
    global _central_cb
    try:
        p = int(port)
    except (TypeError, ValueError):
        return
    if not (1 <= p <= 65535):
        return
    cb = (ip, p, bool(tls))
    with _central_cb_lock:
        if _central_cb == cb:
            return
        _central_cb = cb
    _save_central_cb(cb)


def _save_central_cb(cb):
    with _apply_lock:
        try:
            conf = load_conf()
            want = [cb[0], cb[1], cb[2]]
            if conf.get("central_cb") == want:
                return
            conf["central_cb"] = want
            save_conf(conf)
        except Exception as e:
            logline(f"central_cb persist: {e}")


def _seed_central_cb():
    global _central_cb
    try:
        cb = load_conf().get("central_cb")
    except Exception:
        return
    if not (isinstance(cb, list) and len(cb) == 3):
        return
    try:
        p = int(cb[1])
    except (TypeError, ValueError):
        return
    if is_ipv4(str(cb[0])) and 1 <= p <= 65535:
        with _central_cb_lock:
            _central_cb = (str(cb[0]), p, bool(cb[2]))


def central_origin():
    cb = get_central()
    if not cb:
        return ""
    return "%s://%s:%d" % ("https" if cb[2] else "http", cb[0], cb[1])


def get_central():
    with _central_cb_lock:
        return _central_cb


def do_checkin():
    cb = get_central()
    if not cb:
        return False
    try:
        conf = load_conf()
    except Exception:
        return False
    tok = conf.get("token", "")
    claim = {"fp": hashlib.sha256(tok.encode()).hexdigest(), "ips": all_ips(),
             "port": conf.get("port"), "hostname": socket.gethostname(),
             "ctr": int(time.time() * 1000)}
    claim["sig"] = base64.b64encode(hmac.new(
        tok.encode(), json.dumps(claim, sort_keys=True, separators=(",", ":")).encode(),
        hashlib.sha256).digest()).decode()
    body = json.dumps(claim).encode()
    url = central_origin() + "/api/checkin"
    req = urllib.request.Request(url, data=body, method="POST",
                                 headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=8) as r:
            return bool(json.loads(r.read().decode()).get("ok"))
    except Exception:
        return False


def checkin_loop():
    global _last_reported_ips
    while True:
        time.sleep(CHECKIN_GAP)
        try:
            flat = sorted(local_ips_flat())
            if flat and flat != _last_reported_ips:
                if do_checkin():
                    _last_reported_ips = flat
        except Exception as e:
            logline(f"checkin: {e}")


def op_ping(d):
    cfgs = public_configs()
    stats = read_stats()
    try:
        net = _read_net(cfgs)
        for k, v in _read_pf_net(cfgs).items():
            net["pf:" + k] = v
        stats["net"] = net
    except Exception:
        pass
    return {"ok": True, "agent": "tnl-node", "version": 1, "ready": True,
            "central": central_origin(),
            "hostname": socket.gethostname(), "ips": all_ips(), "sha256": _SELF_SHA,
            "tunnels": len([c for c in cfgs if c.get("type") != "portfw"]),
            "portfw": len([c for c in cfgs if c.get("type") == "portfw"]),
            "core_ver": _core_ref(), "core_sha": _installed_core_sha()[:12], "arch": _core_arch(),
            "stats": stats}


def op_list(d):
    cfgs = public_configs()
    with _health_lock:
        hc = dict(_health_cache)
    pools = {}
    sports = {}
    rots = {}
    for c in cfgs:
        nm = c.get("name") or ""
        if not nm:
            continue
        st = _read_status(nm)
        pair = st["pair"]
        dst = pair["low"] if pair["low_kind"] == "dst" else ""
        src = pair["high"] if pair["high_kind"] == "src" else ""
        if dst or src:
            pools[nm] = {"dst": dst, "src": src}
        if st["path"]["sport"]:
            sports[nm] = st["path"]["sport"]
        elif st["rot"]["sport"]:
            sports[nm] = st["rot"]["sport"]
        if st["rot"]["every"]:
            rots[nm] = st["rot"]
    return {"configs": cfgs, "health": {c["name"]: hc.get(c["name"], {"up": None}) for c in cfgs},
            "pools": pools, "sports": sports, "rots": rots}


def op_tunnel(d):
    _require(d, ["type", "self_ip", "peer_ip", "subnet", "host"])
    ttype = d["type"]
    if ttype not in ("vxlan", "gre", "sit", "ipip", "l2tpv3", "fou", "ipsec", "core"):
        raise ValueError("bad type")
    self_ip, peer_ip = d["self_ip"], d["peer_ip"]
    if not is_ipv4(self_ip) or not is_ipv4(peer_ip):
        raise ValueError("bad ip")
    if ip2int(self_ip) == ip2int(peer_ip):
        raise ValueError("self and peer IP are identical")
    if self_ip not in local_ips_flat():
        raise ValueError(f"{self_ip} is not a local IP on this node")
    subnet = d["subnet"]
    if not valid_cidr(subnet, want6=(ttype == "sit")):
        raise ValueError("bad subnet")
    tid = int(d.get("id") or 0)
    if not 1 <= tid <= 65535:
        raise ValueError("id out of range (1-65535)")
    host = int(d["host"])
    if host not in (1, 2):
        raise ValueError("host must be 1 (server) or 2 (client)")
    iface = d.get("iface") or iface_for_ip(self_ip)
    if not iface or not IFACE_RE.match(iface):
        raise ValueError("no local interface for that IP")
    name = d.get("name") or unique_name(ttype, tid)
    if not name or not NAME_RE.match(name):
        raise ValueError("bad name")
    tunnel_ip = derive_tunnel_ip(ttype, subnet, host)
    obj = {"name": name, "type": ttype, "id": tid, "iface": iface,
           "remote_ip": peer_ip, "tunnel_ip": tunnel_ip, "local_ip": self_ip}
    old = read_config(name)
    obj["enabled"] = _as_bool(d.get("enabled", (old or {}).get("enabled", True)))
    if d.get("probe_min_pct") not in (None, ""):
        _lo, _hi = PROBE_MIN_PCT_RANGE
        obj["probe_min_pct"] = max(_lo, min(_hi, int(d["probe_min_pct"])))
    if ttype == "core":
        _tn = _core_tuning(d.get("tuning"))
        if _tn:
            obj["tuning"] = _tn
    if ttype == "core" and d.get("sock_buf") not in (None, ""):
        _sb = int(d["sock_buf"])
        obj["sock_buf"] = -1 if _sb < 0 else min(_sb, 64 << 20)
    if ttype in ("l2tpv3", "fou", "core", "vxlan"):
        if d.get("port") not in (None, ""):
            port = int(d["port"])
            if not 1 <= port <= 65535:
                raise ValueError("bad port")
            obj["port"] = port
    if ttype == "ipsec":
        psk = str(d.get("psk") or "").strip()
        if len(psk) < 32:
            raise ValueError("ipsec needs a psk")
        obj["psk"] = psk
    if ttype == "core":
        role = d.get("role")
        if role not in ("server", "client"):
            raise ValueError("core needs role server|client")
        obj["role"] = role
        cipher = str(d.get("cipher") or "auto").strip().lower()
        if cipher not in ("auto", "aes-256-gcm", "aes-128-gcm", "chacha20-poly1305", "xchacha20-poly1305", "none"):
            raise ValueError("bad core cipher")
        obj["cipher"] = cipher
        transport = str(d.get("transport") or "udp").strip().lower()
        if transport not in ("udp", "tcp", "raw", "spoof", "ws", "dns"):
            raise ValueError("bad core transport")
        obj["transport"] = transport

        def _clean_pool(key):
            out = [str(x).strip() for x in (d.get(key) or []) if str(x).strip()]
            if len(out) > 64:
                raise ValueError(key + " pool too large (>64)")
            for ip in out:
                if not is_ipv4(ip):
                    raise ValueError("bad " + key + " entry (must be an IPv4 address)")
            return out

        if transport == "dns":
            zone = str(d.get("dns_zone") or "").strip().lower()
            if not zone or len(zone) > 253 or not re.match(r"^(?!-)[A-Za-z0-9-]{1,63}(?:\.(?!-)[A-Za-z0-9-]{1,63})+$", zone):
                raise ValueError("bad dns_zone")
            obj["dns_zone"] = zone
            resolvers = []
            for r in (d.get("dns_resolvers") or []):
                rs = str(r).strip()
                if not rs:
                    continue
                if rs.count(":") == 1:
                    host, _, port = rs.partition(":")
                    if not (port.isdigit() and 1 <= int(port) <= 65535):
                        raise ValueError("bad dns_resolvers port (1..65535)")
                else:
                    host = rs
                if not is_ipv4(host):
                    raise ValueError("bad dns_resolvers entry (must be IPv4 or IPv4:port)")
                resolvers.append(rs)
            if not str(d.get("psk") or "").strip() or cipher == "none":
                raise ValueError("ترنسپورت dns به رمزنگاری (psk) نیاز دارد — نشست داخلِ کوئری‌های DNS با AEAD رمز و احراز می‌شود")
            if role == "client" and not resolvers:
                raise ValueError("کلاینتِ dns به حداقل یک resolverِ معتبر (IPv4) نیاز دارد")
            if resolvers:
                obj["dns_resolvers"] = resolvers
        if transport == "ws":
            wh = str(d.get("ws_host") or "").strip()
            if wh:
                if not re.match(r"^[A-Za-z0-9.-]{1,253}$", wh):
                    raise ValueError("bad ws_host")
                obj["ws_host"] = wh
            wp = str(d.get("ws_path") or "").strip()
            if wp:
                if len(wp) > 1024 or not re.match(r"^/[\x21-\x7e]*$", wp):
                    raise ValueError("bad ws_path")
                obj["ws_path"] = wp
            _cdn = str(d.get("cdn_carrier") or "").strip().lower()
            if _cdn:
                if _cdn not in ("ws", "http", "grpc"):
                    raise ValueError("bad cdn_carrier")
                if _cdn != "ws":
                    obj["cdn_carrier"] = _cdn
                _up_max = {"http_up_workers": 16, "http_up_batch_kb": 512, "http_up_rate": 1000,
                           "http_streams": 16}
                for _k in ("http_up_workers", "http_up_batch_kb", "http_up_rate", "http_streams"):
                    if _k in d:
                        try:
                            _v = int(d.get(_k) or 0)
                        except (TypeError, ValueError):
                            raise ValueError("bad %s" % _k)
                        if _v < 0 or _v > _up_max[_k]:
                            raise ValueError("%s باید بین 0 و %d باشد (0 = پیش‌فرض)" % (_k, _up_max[_k]))
                        if _v:
                            obj[_k] = _v
            if _as_bool(d.get("ws_tls")):
                obj["ws_tls"] = True
                _has_pool = bool(d.get("ws_edge_ips")) and bool(d.get("ws_edge_snis"))
                if role == "client" and not obj.get("ws_host") and not _has_pool:
                    raise ValueError("ws_tls به ws_host نیاز دارد (SNI/دامنهٔ فرانت‌کننده)")
                ech = str(d.get("ws_ech") or "").strip()
                if ech:
                    if len(ech) > 4096 or not re.match(r"^[A-Za-z0-9+/=]+$", ech):
                        raise ValueError("bad ws_ech")
                    obj["ws_ech"] = ech
                if _as_bool(d.get("sni_split")):
                    obj["sni_split"] = True
                    sp = int(d.get("split_pos") or 0)
                    if sp < 0 or sp > 1400:
                        raise ValueError("bad split_pos")
                    if sp:
                        obj["split_pos"] = sp
                    _sm = str(d.get("sni_mode") or "").strip().lower()
                    if _sm in ("disorder", "fake"):
                        obj["sni_mode"] = _sm
                        st = int(d.get("split_ttl") or 0)
                        if st < 0 or st > 255:
                            raise ValueError("bad split_ttl")
                        if st:
                            obj["split_ttl"] = st
                pips = [str(x).strip() for x in (d.get("ws_edge_ips") or []) if str(x).strip()]
                psnis = d.get("ws_edge_snis") or []
                if pips or psnis:
                    if len(pips) > 64 or len(psnis) > 64:
                        raise ValueError("ws edge pool too large")
                    npips = []
                    for ip in pips:
                        h = ip.rpartition(":")[0] if ":" in ip else ip
                        p = ip.rpartition(":")[2] if ":" in ip else "443"
                        if not is_ipv4(h) or not (p.isdigit() and 1 <= int(p) <= 65535):
                            raise ValueError("bad ws_edge_ip (must be IPv4:port)")
                        npips.append("%s:%s" % (h, p))
                    pips = npips
                    clean_snis = []
                    for s in psnis:
                        if not isinstance(s, dict):
                            raise ValueError("bad ws_edge_sni")
                        h = str(s.get("host") or "").strip()
                        if not re.match(r"^[A-Za-z0-9.\-]{1,253}$", h):
                            raise ValueError("bad ws_edge_sni host")
                        se = str(s.get("ech") or "").strip()
                        if se and (len(se) > 4096 or not re.match(r"^[A-Za-z0-9+/=]+$", se)):
                            raise ValueError("bad ws_edge_sni ech")
                        sp = str(s.get("path") or "").strip()
                        if sp and (len(sp) > 1024 or not re.match(r"^/[\x21-\x7e]*$", sp)):
                            raise ValueError("bad ws_edge_sni path")
                        clean_snis.append({"host": h, "ech": se, "path": sp})
                    if pips and clean_snis:
                        obj["ws_edge_ips"] = pips
                        obj["ws_edge_snis"] = clean_snis
                        _rs = d.get("ws_rotate_secs")
                        obj["ws_rotate_secs"] = max(0, min(28800, int(_rs))) if _rs is not None else 600
            edge = str(d.get("edge_ip") or "").strip()
            if edge:
                host = edge.rpartition(":")[0] or edge
                if not re.match(r"^[A-Za-z0-9.\-]{1,253}$", host):
                    raise ValueError("bad edge_ip")
                obj["edge_ip"] = edge
        if transport == "raw":
            profile = str(d.get("raw_profile") or "bare").strip().lower()
            if profile not in RAW_HEADER_LEN:
                raise ValueError("bad raw_profile")
            obj["raw_profile"] = profile
            if profile == "bare":
                rproto = int(d.get("raw_proto") or 0)
                if rproto and not (1 <= rproto <= 255):
                    raise ValueError("bad raw_proto")
                if rproto:
                    obj["raw_proto"] = rproto
            if profile in ("udp", "tcp"):
                rport = int(d.get("raw_port") or 0)
                if rport and not (1 <= rport <= 65535):
                    raise ValueError("bad raw_port")
                if rport:
                    obj["raw_port"] = rport
                rsport = int(d.get("raw_sport") or 0)
                if rsport and not (1 <= rsport <= 65535):
                    raise ValueError("bad raw_sport")
                if rsport and _as_bool(d.get("raw_sport_random")):
                    raise ValueError("raw_sport and raw_sport_random are exclusive")
                if _as_bool(d.get("raw_sport_random")):
                    obj["raw_sport_random"] = True
                elif rsport:
                    obj["raw_sport"] = rsport
                rrot = int(d.get("raw_sport_rotate") or 0)
                if rrot and profile != "udp":
                    raise ValueError("raw_sport_rotate is the udp profile only")
                if rrot and not (1 <= rrot <= 64):
                    raise ValueError("bad raw_sport_rotate")
                if rrot and (rsport or _as_bool(d.get("raw_sport_random"))):
                    raise ValueError("raw_sport_rotate excludes raw_sport and raw_sport_random")
                if rrot:
                    obj["raw_sport_rotate"] = rrot
                rdp = int(d.get("raw_dports") or 0)
                if rdp and not rrot:
                    raise ValueError("raw_dports needs raw_sport_rotate")
                if rdp and not (1 <= rdp <= 8):
                    raise ValueError("bad raw_dports")
                if rdp:
                    obj["raw_dports"] = rdp
        ptries = int(d.get("port_tries") or 0)
        if ptries and not (1 <= ptries <= 50):
            raise ValueError("bad port_tries")
        if ptries:
            obj["port_tries"] = ptries
        if transport in QUEUEING_TRANSPORTS:
            wk = int(d.get("workers") or 0)
            if wk and not (1 <= wk <= MAX_WORKERS):
                raise ValueError("bad workers")
            if wk > 1:
                obj["workers"] = wk
        if transport == "spoof":
            rproto = int(d.get("raw_proto") or 0)
            if rproto and not (1 <= rproto <= 255):
                raise ValueError("bad raw_proto")
            if rproto:
                obj["raw_proto"] = rproto
        if transport in ("udp", "raw", "spoof") and _as_bool(d.get("fec")):
            if obj.get("raw_sport_rotate"):
                raise ValueError("raw_sport_rotate and fec are exclusive (the FEC send path snapshots the source port)")
            obj["fec"] = True
            fd = int(d.get("fec_data") or 10)
            fp = int(d.get("fec_parity") or 3)
            if fd < 1 or fp < 1 or fd + fp > 255:
                raise ValueError("fec_data/fec_parity out of range (>=1, sum<=255)")
            obj["fec_data"] = fd
            obj["fec_parity"] = fp
        if transport in ("udp", "tcp", "raw") and role == "client":
            pips = _clean_pool("peer_ips")
            sips = _clean_pool("src_ips")
            if pips or sips:
                if pips:
                    obj["peer_ips"] = pips
                if sips:
                    obj["src_ips"] = sips
                _prs = d.get("peer_rotate_secs")
                obj["peer_rotate_secs"] = max(0, min(86400, int(_prs))) if _prs is not None else 0
        if transport in ("udp", "tcp", "raw") and role == "server" and _as_bool(d.get("pool_listen")):
            obj["pool_listen"] = True
            if transport in ("udp", "tcp"):
                lips = _clean_pool("listen_ips")
                if lips:
                    obj["listen_ips"] = lips
        if transport == "raw" and role == "server":
            psrc = _clean_pool("peer_src_ips")
            if psrc:
                obj["peer_src_ips"] = psrc
        psk = str(d.get("psk") or "").strip()
        if psk:
            if len(psk) < 16:
                raise ValueError("core psk too short (>=16)")
            obj["psk"] = psk
        obfs = _as_bool(d.get("obfs"))
        if obfs and (not psk or cipher == "none"):
            raise ValueError("obfs requires a psk and encryption")
        obj["obfs"] = obfs
        if transport == "raw" and (not psk or cipher == "none"):
            raise ValueError("ترنسپورت raw به رمزنگاری (psk) نیاز دارد — هر فریم با AEAD رمز و احراز می‌شود")
        if transport == "spoof" and (not psk or cipher == "none"):
            raise ValueError("ترنسپورت spoof به رمزنگاری (psk) نیاز دارد — هر فریمِ هدرجعلی با AEAD احراز می‌شود")
        if _as_bool(d.get("cover")) and transport == "tcp":
            obj["cover"] = True
            sni = str(d.get("cover_sni") or "").strip()
            if not sni:
                raise ValueError("پوشش TLS به cover_sni نیاز دارد (نام دامنه‌ای که ارائه می‌شود)")
            if not re.match(r"^[A-Za-z0-9.-]{1,253}$", sni):
                raise ValueError("bad cover_sni")
            obj["cover_sni"] = sni
        if _as_bool(d.get("gso")):
            obj["gso"] = True
        if _as_bool(d.get("fake_desync")):
            if transport not in ("raw", "spoof", "tcp", "ws"):
                raise ValueError("fake_desync is supported on the raw, spoof, tcp and ws carriers (not udp)")
            obj["fake_desync"] = True
            ttl = int(d.get("fake_ttl") or 4)
            if ttl < 1 or ttl > 255:
                raise ValueError("fake_ttl out of range (1..255)")
            obj["fake_ttl"] = ttl
            cnt = int(d.get("fake_count") or 2)
            if cnt < 1 or cnt > 64:
                raise ValueError("fake_count out of range (1..64)")
            obj["fake_count"] = cnt
            mode = str(d.get("fake_mode") or "ttl").strip().lower()
            if mode not in ("ttl", "badsum", "both"):
                raise ValueError("bad fake_mode")
            obj["fake_mode"] = mode
        if transport == "spoof":
            ss = str(d.get("spoof_src") or "").strip()
            sd = str(d.get("spoof_dst") or "").strip()
            if ss:
                if not is_ipv4(ss):
                    raise ValueError("bad spoof_src")
                obj["spoof_src"] = ss
            if sd:
                if not is_ipv4(sd):
                    raise ValueError("bad spoof_dst")
                obj["spoof_dst"] = sd
            if not ss and not sd:
                raise ValueError("ترنسپورت spoof حداقل به یکی از spoof_src / spoof_dst نیاز دارد")
    if old and old.get("type") != "portfw":
        teardown_config(old)
    write_config(name, obj)

    def _fail(msg):
        teardown_config(obj)
        if old and old.get("type") != "portfw" and NAME_RE.match(old.get("name", "")):
            write_config(name, old)
            restored = True
            try:
                apply_config(old)
            except Exception:
                restored = False
            old_async_tun = old.get("type") == "core"
            if restored and (not old.get("enabled", True) or old_async_tun or run(["ip", "link", "show", name])[0] == 0):
                return {"ok": False, "msg": msg, "restored": True}
        try:
            os.remove(os.path.join(CONFIG_DIR, name + ".json"))
        except OSError:
            pass
        return {"ok": False, "msg": msg, "restored": False}

    try:
        apply_config(obj)
    except Exception as e:
        return _fail(str(e))
    if not obj.get("enabled", True):
        return {"ok": True, "name": name, "tunnel_ip": tunnel_ip}
    why = _netdev_missing_reason(name, ttype)
    if why:
        return _fail(why)
    return {"ok": True, "name": name, "tunnel_ip": tunnel_ip}


def op_portfw(d):
    _require(d, ["listen_port", "dst_port", "dst_ips"])
    iface = d.get("iface") or default_iface()
    if not iface or not IFACE_RE.match(iface):
        raise ValueError("no interface")
    lp, dp = str(d["listen_port"]), str(d["dst_port"])
    if not (lp.isdigit() and 1 <= int(lp) <= 65535 and dp.isdigit() and 1 <= int(dp) <= 65535):
        raise ValueError("bad port")
    ips = d["dst_ips"] if isinstance(d["dst_ips"], list) else str(d["dst_ips"]).split(",")
    ips = [x.strip() for x in ips if x.strip()]
    if not ips or not all(is_ipv4(x) for x in ips):
        raise ValueError("bad destination IP")
    listen_ip = str(d.get("listen_ip") or "").strip()
    if listen_ip:
        if not is_ipv4(listen_ip):
            raise ValueError("bad listen IP")
        if listen_ip not in local_ips_flat():
            raise ValueError(f"{listen_ip} is not a local IP on this node")
        liface = iface_for_ip(listen_ip)
        if liface and IFACE_RE.match(liface):
            iface = liface
    interval = 0 if len(ips) == 1 else int(d.get("interval_min", 5)) * 60
    for c in raw_configs():
        if (c.get("type") == "portfw" and c.get("iface") == iface and str(c.get("listen_port")) == lp
                and str(c.get("listen_ip") or "") == listen_ip):
            raise ValueError(f"port {lp} on {iface}{' (' + listen_ip + ')' if listen_ip else ''} is already forwarded (delete it first)")
    tid = int(d.get("id") or 0) or (max(used_ids(), default=41) + 1)
    name = f"portfw{tid}"
    if os.path.exists(os.path.join(CONFIG_DIR, name + ".json")):
        raise ValueError("no free name")
    obj = {"name": name, "type": "portfw", "id": tid, "iface": iface, "listen_port": lp,
           "listen_ip": listen_ip, "dst_ips": ips, "dst_port": dp, "switch_interval": interval,
           "current_index": 0, "last_switch": int(time.time())}
    write_config(name, obj)
    try:
        build_portfw(obj)
    except Exception as e:
        return {"ok": False, "msg": str(e)}
    return {"ok": True, "name": name}


def op_portfw_edit(d):
    _require(d, ["name"])
    old = read_config(d["name"])
    if not old or old.get("type") != "portfw":
        raise ValueError("not found")
    iface = d.get("iface") or old.get("iface") or default_iface()
    if not iface or not IFACE_RE.match(iface):
        raise ValueError("no interface")
    lp = str(d["listen_port"]) if d.get("listen_port") not in (None, "") else str(old.get("listen_port"))
    dp = str(d["dst_port"]) if d.get("dst_port") not in (None, "") else str(old.get("dst_port"))
    if not (lp.isdigit() and 1 <= int(lp) <= 65535 and dp.isdigit() and 1 <= int(dp) <= 65535):
        raise ValueError("bad port")
    if d.get("dst_ips") not in (None, ""):
        ips = d["dst_ips"] if isinstance(d["dst_ips"], list) else str(d["dst_ips"]).split(",")
        ips = [x.strip() for x in ips if x.strip()]
    else:
        ips = list(old.get("dst_ips", []))
    if not ips or not all(is_ipv4(x) for x in ips):
        raise ValueError("bad destination IP")
    rot = d.get("rotate")
    if rot is None:
        interval = (int(d["interval_min"]) * 60 if d.get("interval_min") not in (None, "")
                    else int(old.get("switch_interval", 0) or 0))
    else:
        interval = int(d.get("interval_min", 5)) * 60 if rot else 0
    if len(ips) < 2:
        interval = 0
    if "listen_ip" in d:
        listen_ip = str(d.get("listen_ip") or "").strip()
        if listen_ip:
            if not is_ipv4(listen_ip):
                raise ValueError("bad listen IP")
            if listen_ip not in local_ips_flat():
                raise ValueError(f"{listen_ip} is not a local IP on this node")
            liface = iface_for_ip(listen_ip)
            if liface and IFACE_RE.match(liface):
                iface = liface
    else:
        listen_ip = str(old.get("listen_ip") or "")
    for c in raw_configs():
        if (c.get("name") != old["name"] and c.get("type") == "portfw"
                and c.get("iface") == iface and str(c.get("listen_port")) == lp
                and str(c.get("listen_ip") or "") == listen_ip):
            raise ValueError(f"port {lp} on {iface} is already forwarded")
    teardown_config(old)
    idx = int(old.get("current_index", 0) or 0)
    if idx >= len(ips):
        idx = 0
    obj = {"name": old["name"], "type": "portfw", "id": old.get("id"), "iface": iface,
           "listen_port": lp, "listen_ip": listen_ip, "dst_ips": ips, "dst_port": dp,
           "switch_interval": interval, "current_index": idx, "last_switch": int(time.time())}
    write_config(old["name"], obj)
    try:
        build_portfw(obj)
    except Exception as e:
        return {"ok": False, "msg": str(e)}
    return {"ok": True, "name": old["name"]}


def op_portfw_next(d):
    _require(d, ["name"])
    cfg = read_config(d["name"])
    if not cfg or cfg.get("type") != "portfw":
        raise ValueError("not found")
    ips = [ip for ip in cfg.get("dst_ips", []) if is_ipv4(ip)]
    if len(ips) < 2:
        raise ValueError("need >=2 destinations to rotate")
    cfg["current_index"] = (int(cfg.get("current_index", 0) or 0) + 1) % len(ips)
    cfg["last_switch"] = int(time.time())
    write_config(cfg["name"], cfg)
    build_portfw(cfg)
    return {"ok": True, "active": ips[cfg["current_index"]]}


def op_delete(d):
    _require(d, ["name"])
    cfg = read_config(d["name"])
    if not cfg:
        return {"ok": True, "already": True}
    teardown_config(cfg)
    try:
        os.remove(os.path.join(CONFIG_DIR, d["name"] + ".json"))
    except FileNotFoundError:
        pass
    return {"ok": True}


def op_link_enable(d):
    _require(d, ["name"])
    name = d["name"]
    if not NAME_RE.match(name):
        raise ValueError("bad name")
    enabled = _as_bool(d.get("enabled", True))
    cfg = read_config(name)
    if not cfg or cfg.get("type") == "portfw":
        return {"ok": True, "already": True}
    cfg["enabled"] = enabled
    try:
        _set_link_state(cfg, enabled)
    except Exception as e:
        return {"ok": False, "msg": str(e)}
    write_config(name, cfg)
    return {"ok": True, "enabled": enabled}


def op_core_restart(d):
    name = _req_name(d)
    cfg = read_config(name)
    if not cfg:
        raise ValueError("tunnel not found")
    if cfg.get("type") != "core":
        raise ValueError("only a core tunnel has a process to restart")
    if not _as_bool(cfg.get("enabled", True)):
        return {"ok": False, "msg": "تونل غیرفعال است"}
    if not os.path.exists(_cfg_path(name, ".json")):
        return {"ok": False, "msg": "کانفیگِ هسته روی این نود نیست — تونل را بازسازی کن"}
    if not _core_relaunch(name):
        return {"ok": False, "msg": "هسته بالا نیامد (اینترفیس ظاهر نشد)"}
    return {"ok": True}


def op_wipe(d):
    for c in raw_configs():
        try:
            teardown_config(c)
            os.remove(os.path.join(CONFIG_DIR, c["name"] + ".json"))
        except Exception:
            pass
    try:
        revert_kernel_tuning()
    except Exception as e:
        logline(f"wipe: kernel tuning revert failed: {e}")
    _restart_pending.set()
    script = ("sleep 1; systemctl stop tnl-node 2>/dev/null; systemctl disable tnl-node 2>/dev/null; "
              "rm -f " + SERVICE_FILE + "; systemctl daemon-reload 2>/dev/null; rm -rf " + CONFIG_DIR)
    subprocess.Popen(["sh", "-c", script], start_new_session=True, stdin=subprocess.DEVNULL,
                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    logline("node wiped by panel request")
    return {"ok": True, "wiped": True}


def op_check(d):
    _require(d, ["name"])
    cfg = read_config(d["name"])
    if not cfg:
        raise ValueError("not found")
    with _health_lock:
        health = dict(_health_cache.get(cfg["name"]) or {"up": None})
    return {"ok": True, "health": health}


def _ss_proc(line):
    m = re.search(r'users:\(\("([^"]+)"', line)
    return m.group(1) if m else ""


def _norm_ip(x):
    return str(x or "").strip().strip("[]")


_WILD = ("0.0.0.0", "::", "*", "")


def _decode_hexip(h):
    h = h.strip()
    if set(h) <= {"0"}:
        return "0.0.0.0"
    if len(h) == 8:
        try:
            b = bytes.fromhex(h)
            return "%d.%d.%d.%d" % (b[3], b[2], b[1], b[0])
        except ValueError:
            return None
    return None


def _port_busy_proc(port, proto, tip=None):
    files = ("/proc/net/tcp", "/proc/net/tcp6") if proto == "tcp" else ("/proc/net/udp", "/proc/net/udp6")
    for path in files:
        try:
            with open(path) as f:
                next(f, None)
                for row in f:
                    parts = row.split()
                    if len(parts) < 4:
                        continue
                    local, st = parts[1], parts[3]
                    if proto == "tcp" and st != "0A":
                        continue
                    hexaddr, _, hexport = local.rpartition(":")
                    try:
                        if int(hexport, 16) != int(port):
                            continue
                    except ValueError:
                        continue
                    if tip is None:
                        return True
                    lip = _decode_hexip(hexaddr)
                    if lip is None or lip in _WILD or lip == tip:
                        return True
        except (OSError, StopIteration):
            continue
    return False


def _port_busy(port, proto, ip=None):
    proto = "tcp" if str(proto).lower() == "tcp" else "udp"
    flag = "-t" if proto == "tcp" else "-u"
    tip = _norm_ip(ip) or None
    rc, out, _ = run(["ss", "-H", "-l", "-n", "-p", flag])
    if rc == 0:
        for line in out.splitlines():
            f = line.split()
            if len(f) < 4:
                continue
            local = f[3]
            if ":" not in local:
                continue
            host, _, lport = local.rpartition(":")
            if lport != str(port):
                continue
            lhost = _norm_ip(host)
            if tip is None or lhost in _WILD or lhost == tip:
                return True, _ss_proc(line)
        return False, ""
    return _port_busy_proc(port, proto, tip), ""


SPEED_CHUNK = 1 << 16
SPEED_MAX_SECS = 30
SPEED_MAX_STREAMS = 8
SPEED_ZERO = bytes(SPEED_CHUNK)


def _tun_ip4(name):
    rc, out, _ = run(["ip", "-o", "-4", "addr", "show", name])
    m = re.search(r"inet (\d+\.\d+\.\d+\.\d+)", out) if rc == 0 else None
    if not m:
        raise ValueError("interface %s has no IPv4 address" % name)
    return m.group(1)


def _speed_rule(name, ip, port):
    return ["-i", name, "-p", "tcp", "-d", ip, "--dport", str(port),
            "-m", "comment", "--comment", RULE_OWNER_PREFIX + name, "-j", "ACCEPT"]


def _speed_conn(c, secs):
    try:
        c.settimeout(secs + 15)
        mode = c.recv(1)
        if mode == b"U":
            got = 0
            while True:
                b = c.recv(SPEED_CHUNK)
                if not b:
                    break
                got += len(b)
            c.sendall(struct.pack(">Q", got))
        elif mode == b"D":
            end = time.time() + secs
            while time.time() < end:
                c.sendall(SPEED_ZERO)
    except (OSError, struct.error):
        pass
    finally:
        try:
            c.close()
        except OSError:
            pass


def _speed_serve(s, rule, secs):
    end = time.time() + secs * 2 + 30
    s.settimeout(2.0)
    try:
        while time.time() < end:
            try:
                c, _ = s.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            threading.Thread(target=_speed_conn, args=(c, secs), daemon=True).start()
    finally:
        try:
            s.close()
        except OSError:
            pass
        _ipt_del_all("filter", "INPUT", rule)


def _speed_dir(mode, ip, port, src, secs, streams):
    got = [0] * streams
    span = [None] * streams

    def one(i):
        try:
            c = socket.create_connection((ip, port), timeout=10, source_address=(src, 0))
        except OSError:
            return
        try:
            c.settimeout(secs + 15)
            c.sendall(mode)
            t0 = time.time()
            end = t0 + secs
            if mode == b"U":
                while time.time() < end:
                    c.sendall(SPEED_ZERO)
                span[i] = (t0, time.time())
                c.shutdown(socket.SHUT_WR)
                head = b""
                while len(head) < 8:
                    b = c.recv(8 - len(head))
                    if not b:
                        return
                    head += b
                got[i] = struct.unpack(">Q", head)[0]
            else:
                while time.time() < end:
                    b = c.recv(SPEED_CHUNK)
                    if not b:
                        break
                    got[i] += len(b)
                span[i] = (t0, time.time())
        except (OSError, struct.error):
            pass
        finally:
            try:
                c.close()
            except OSError:
                pass

    th = [threading.Thread(target=one, args=(i,)) for i in range(streams)]
    for x in th:
        x.start()
    for x in th:
        x.join(secs + 30)
    live = [s for s in span if s]
    if not live:
        return 0.0, 0
    el = max(0.001, max(b for _, b in live) - min(a for a, _ in live))
    return round(sum(got) * 8 / 1e6 / el, 1), len(live)


def op_speedtest(d):
    name = str(d.get("name") or "")
    if not NAME_RE.match(name):
        raise ValueError("bad name")
    secs = min(SPEED_MAX_SECS, max(3, int(d.get("secs") or 8)))
    mode = str(d.get("mode") or "")
    if mode == "serve":
        ip = _tun_ip4(name)
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((ip, 0))
        s.listen(SPEED_MAX_STREAMS * 2)
        port = s.getsockname()[1]
        rule = _speed_rule(name, ip, port)
        _ipt_ins_missing("filter", "INPUT", rule)
        threading.Thread(target=_speed_serve, args=(s, rule, secs), daemon=True).start()
        return {"ok": True, "ip": ip, "port": port, "secs": secs}
    if mode == "run":
        ip = str(d.get("peer_ip") or "")
        port = int(d.get("port") or 0)
        if not is_ipv4(ip) or not 1 <= port <= 65535:
            raise ValueError("bad peer")
        streams = min(SPEED_MAX_STREAMS, max(1, int(d.get("streams") or 4)))
        src = _tun_ip4(name)
        up, nup = _speed_dir(b"U", ip, port, src, secs, streams)
        down, ndown = _speed_dir(b"D", ip, port, src, secs, streams)
        if not nup and not ndown:
            raise ValueError("nothing reached %s:%d over %s -- the far end is not listening or the "
                             "tunnel is not carrying" % (ip, port, name))
        return {"ok": True, "secs": secs, "streams": streams, "up_mbit": up, "down_mbit": down,
                "up_streams": nup, "down_streams": ndown}
    raise ValueError("bad mode")


def op_portcheck(d):
    _require(d, ["port"])
    try:
        port = int(d["port"])
    except (TypeError, ValueError):
        raise ValueError("bad port")
    if not 1 <= port <= 65535:
        raise ValueError("port out of range")
    proto = "tcp" if str(d.get("proto", "udp")).lower() == "tcp" else "udp"
    ip = _norm_ip(d.get("ip")) or None
    if ip and not re.match(r"^[0-9A-Fa-f:.]{1,45}$", ip):
        raise ValueError("bad ip")
    busy, who = _port_busy(port, proto, ip)
    return {"ok": True, "busy": busy, "who": who, "port": port, "proto": proto, "ip": ip or ""}


def op_edge_status(d):
    st = _read_status(_req_name(d))
    return {"ok": True,
            "active": st["active"],
            "pair": st["pair"],
            "health": [h for h in st["health"] if h["kind"] in ("ip", "sni")],
            "events": st["events"],
            "ts": st["ts"],
            "now": int(time.time())}


_PEER_ADDR_RE = re.compile(r"^[0-9A-Fa-f:.]{1,64}$")


def _port_or_zero(v):
    try:
        n = int(v or 0)
    except (TypeError, ValueError):
        return 0
    return n if 1 <= n <= 65535 else 0


def _read_status(name):
    empty = {"active": "", "epoch": 0, "ready": False, "health": [], "events": [], "ts": 0,
             "pair": {"low": "", "high": "", "low_kind": "", "high_kind": ""},
             "rot": {"sport": 0, "dport": 0, "dports": 0, "every": 0, "lo": 0, "hi": 0, "drawn": 0},
             "path": {"src": "", "sport": 0, "dst": "", "dport": 0}}
    try:
        with open(_cfg_path(name, ".status")) as f:
            st = json.load(f)
    except (OSError, ValueError):
        return empty
    if not isinstance(st, dict):
        return empty
    health = []
    for h in (st.get("health") or [])[:256]:
        if not isinstance(h, dict) or not h.get("key"):
            continue
        health.append({"key": str(h.get("key")), "kind": str(h.get("kind") or ""),
                       "state": str(h.get("state") or "healthy"),
                       "fails": int(h.get("fails") or 0),
                       "next_retest_unix": int(h.get("next_retest_unix") or 0),
                       "pin": bool(h.get("pin"))})
    events = []
    for e in (st.get("events") or [])[:64]:
        if not isinstance(e, dict):
            continue
        events.append({"seq": int(e.get("seq") or 0), "ts": int(e.get("ts") or 0),
                       "kind": str(e.get("kind") or ""), "code": str(e.get("code") or ""),
                       "detail": str(e.get("detail") or "")})
    pair = st.get("pair") if isinstance(st.get("pair"), dict) else {}
    pk = st.get("path") if isinstance(st.get("path"), dict) else {}
    rt = st.get("rot") if isinstance(st.get("rot"), dict) else {}
    return {"active": str(st.get("active") or ""), "epoch": int(st.get("epoch") or 0),
            "ready": bool(st.get("ready")), "health": health, "events": events,
            "ts": int(st.get("ts") or 0),
            "pair": {"low": str(pair.get("low") or ""), "high": str(pair.get("high") or ""),
                     "low_kind": str(pair.get("low_kind") or ""),
                     "high_kind": str(pair.get("high_kind") or "")},
            "rot": {"sport": _port_or_zero(rt.get("sport")),
                    "dport": _port_or_zero(rt.get("dport")),
                    "dports": max(0, min(8, int(rt.get("dports") or 0))),
                    "every": max(0, min(64, int(rt.get("every") or 0))),
                    "lo": _port_or_zero(rt.get("lo")), "hi": _port_or_zero(rt.get("hi")),
                    "drawn": max(0, int(rt.get("drawn") or 0))},
            "path": {"src": str(pk.get("src") or ""), "sport": _port_or_zero(pk.get("sport")),
                     "dst": str(pk.get("dst") or ""), "dport": _port_or_zero(pk.get("dport"))}}


def _axis_rows(st, kind):
    ok = lambda v: bool(v) and bool(_PEER_ADDR_RE.match(v))
    rows = [h for h in st["health"] if h["kind"] == kind]
    if kind in ("dst", "src"):
        rows = [h for h in rows if ok(h["key"])]
    return rows


def _axis_section(st, kind, active):
    rows = _axis_rows(st, kind)
    pin = next((h["key"] for h in rows if h["pin"]), "")
    return {"active": active, "addrs": [h["key"] for h in rows][:64],
            "health": [{k: h[k] for k in ("key", "state", "fails", "next_retest_unix")} for h in rows],
            "pin": pin, "ts": st["ts"]}


def op_peer_status(d):
    st = _read_status(_req_name(d))
    pair = st["pair"]
    return {"ok": True, "now": int(time.time()),
            "dst": _axis_section(st, "dst", pair["low"] if pair["low_kind"] == "dst" else ""),
            "src": _axis_section(st, "src", pair["high"] if pair["high_kind"] == "src" else "")}


PINBOX_MAX = 64 * 1024


def _write_pin(name, kind, key, cmd=""):
    if not NAME_RE.match(name):
        raise ValueError("bad name")
    key = str(key or "").strip()
    if not key or len(key) > 255:
        raise ValueError("مقدارِ ورودی نامعتبر است")
    body = {"kind": kind, "key": key}
    if cmd:
        body["cmd"] = cmd
    path = _cfg_path(name, ".status.pin")
    try:
        if os.path.getsize(path) > PINBOX_MAX:
            return {"ok": False, "error": "صفِ فرمان پر است — هستهٔ این تونل فرمان‌ها را برنمی‌دارد"}
    except OSError:
        pass
    try:
        with open(path, "a") as f:
            f.write(json.dumps(body) + "\n")
    except OSError as e:
        return {"ok": False, "error": str(e)}
    return {"ok": True}


def op_peer_select(d):
    _require(d, ["name", "key"])
    name = str(d["name"])
    if not _is_peer_pool(name):
        return {"ok": False, "error": "این تونل استخرِ آی‌پی ندارد"}
    return _write_pin(name, "src" if str(d.get("side")) == "src" else "dst", d.get("key"))


def op_pool_select(d):
    _require(d, ["name", "kind", "key"])
    name = str(d["name"])
    if not _is_ws_pool(name):
        return {"ok": False, "error": "این تونل استخرِ لبه ندارد"}
    return _write_pin(name, "sni" if str(d.get("kind")) == "sni" else "ip", d.get("key"))


def op_retest_now(d):
    _require(d, ["name", "kind", "key"])
    name = str(d["name"])
    kind = str(d.get("kind") or "")
    if kind not in ("dst", "src", "ip", "sni"):
        raise ValueError("محورِ نامعتبر")
    if kind in ("ip", "sni") and not _is_ws_pool(name):
        return {"ok": False, "error": "این تونل استخرِ لبه ندارد"}
    if kind in ("dst", "src") and not _is_peer_pool(name):
        return {"ok": False, "error": "این تونل استخرِ آی‌پی ندارد"}
    return _write_pin(name, kind, d.get("key"), cmd="retest")


CORE_VER_RE = re.compile(r"^(?!.*\.\.)[A-Za-z0-9._-]{1,40}$")
CORE_SHA_RE = re.compile(r"^[0-9a-f]{64}$")

FETCH_MAX_AGENT = 262144
FETCH_MAX_CORE = 64 << 20
FETCH_BUDGET = 150
FETCH_CHUNK = 256 * 1024
FETCH_TRIES = 6


def _is_central_origin(u):
    with _central_cb_lock:
        cb = _central_cb
    if not cb or cb[2]:
        return False
    try:
        p = urllib.parse.urlsplit(u)
        return p.hostname == cb[0] and int(p.port or 80) == int(cb[1])
    except ValueError:
        return False


def _resumes_at(resp, offset):
    if resp.status != 206:
        return False
    m = re.match(r"\s*bytes\s+(\d+)-", resp.headers.get("Content-Range", "") or "")
    return bool(m) and int(m.group(1)) == offset


def _fetch_url(url, max_bytes, timeout=45, budget=FETCH_BUDGET):
    u = str(url or "").strip()
    low = u.lower()
    if low.startswith("http://"):
        if not _is_central_origin(u):
            raise ValueError("update url must be https (plaintext is allowed only for the panel's own origin)")
    elif not low.startswith("https://"):
        raise ValueError("update url must be https")
    deadline = time.monotonic() + budget
    chunks, got, want, err = [], 0, 0, None
    done = False
    for _ in range(FETCH_TRIES):
        if done or time.monotonic() >= deadline:
            break
        hdrs = {"User-Agent": "tnl-node"}
        if got:
            hdrs["Range"] = "bytes=%d-" % got
        req = urllib.request.Request(u, headers=hdrs)
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r:
                if got and not _resumes_at(r, got):
                    chunks, got = [], 0
                try:
                    n = int(r.headers.get("Content-Length") or 0)
                except (TypeError, ValueError):
                    n = 0
                want = got + n if n else want
                while got <= max_bytes:
                    if time.monotonic() > deadline:
                        raise ValueError("download gave up after %ds with %d of %d bytes"
                                         % (budget, got, want))
                    c = r.read1(FETCH_CHUNK)
                    if not c:
                        done = not want or got >= want
                        break
                    chunks.append(c)
                    got += len(c)
            err = None
        except Exception as e:
            err = e
    if err is not None and not done:
        raise err
    buf = b"".join(chunks)
    if len(buf) > max_bytes:
        raise ValueError("downloaded file is larger than %d bytes" % max_bytes)
    if not buf:
        raise ValueError("downloaded file is empty")
    if want and len(buf) != want:
        raise ValueError("download truncated: got %d of %d bytes" % (len(buf), want))
    return buf


def _verify_update_sig(msg, sig_b64):
    try:
        pub = str(load_conf().get("update_pubkey") or "").strip()
    except Exception:
        return False
    if not pub:
        return False
    if not sig_b64:
        return False
    try:
        sig = base64.b64decode(sig_b64, validate=True)
    except Exception:
        return False
    kp, sp = os.path.join(CONFIG_DIR, ".upd_pub.pem"), os.path.join(CONFIG_DIR, ".upd_sig.bin")
    try:
        with open(kp, "w") as f:
            f.write(pub)
        with open(sp, "wb") as f:
            f.write(sig)
        p = subprocess.run(["openssl", "dgst", "-sha256", "-verify", kp, "-signature", sp],
                           input=msg, capture_output=True)
        return p.returncode == 0 and b"Verified OK" in (p.stdout or b"")
    except Exception:
        return False
    finally:
        for pth in (kp, sp):
            try:
                os.remove(pth)
            except OSError:
                pass


def op_set_update_key(d):
    pub = str(d.get("pubkey") or "").strip()
    if "PUBLIC KEY" not in pub or len(pub) > 8192:
        raise ValueError("bad pubkey")
    conf = load_conf()
    cur = str(conf.get("update_pubkey") or "").strip()
    if cur and cur != pub:
        return {"ok": False, "msg": "update key already set (re-provision over SSH to change)"}
    if not cur:
        conf["update_pubkey"] = pub
        save_conf(conf)
    return {"ok": True, "already": bool(cur)}


CORE_STAGED = CORE_BIN + ".new"


def _release_checksum(url):
    txt = _fetch_url(str(url) + ".sha256", 4096, timeout=20).decode("utf-8", "replace")
    sha = (txt.split() or [""])[0].strip().lower()
    if not CORE_SHA_RE.match(sha):
        raise ValueError("the release published no usable checksum")
    return sha


def _granted_sha(d):
    want = str(d.get("sha256") or "").strip().lower()
    if want:
        if not CORE_SHA_RE.match(want):
            raise ValueError("bad sha256")
        if not _verify_update_sig(want.encode(), d.get("sig")):
            return "", {"ok": False, "code": "bad_signature"}
        return want, None
    url = str(d.get("url") or "").strip()
    if not url:
        raise ValueError("bad sha256")
    if not _verify_update_sig(url.encode(), d.get("sig")):
        return "", {"ok": False, "code": "bad_signature"}
    try:
        return _release_checksum(url), None
    except Exception as e:
        return "", {"ok": False, "code": "checksum_unavailable", "msg": str(e)[:140]}


def _core_bytes(d):
    want, bad = _granted_sha(d)
    if bad:
        return None, want, bad
    if d.get("data") is None and d.get("url"):
        try:
            raw = _fetch_url(d["url"], FETCH_MAX_CORE)
        except Exception as e:
            return None, want, {"ok": False, "code": "download_failed", "msg": str(e)[:140]}
    else:
        _require(d, ["data"])
        try:
            raw = base64.b64decode(d["data"], validate=True)
        except Exception:
            raise ValueError("bad base64 payload")
    if len(raw) < 100000:
        return None, want, {"ok": False, "code": "too_small"}
    if hashlib.sha256(raw).hexdigest() != want:
        return None, want, {"ok": False, "code": "sha_mismatch"}
    return raw, want, None


def _core_label(d):
    label = str(d.get("version") or "custom").strip() or "custom"
    return label if CORE_VER_RE.match(label) else "custom"


def op_core_put(d):
    raw, want, bad = _core_bytes(d)
    if bad:
        return bad
    if os.path.isfile(CORE_BIN) and _installed_core_sha() == want:
        conf = load_conf()
        label = _core_label(d)
        if conf.get("core_version") != label:
            conf["core_version"] = label
            save_conf(conf)
        return {"ok": True, "code": "same", "core_sha": want[:12]}
    with _core_lock:
        tmp = CORE_STAGED + ".tmp"
        with open(tmp, "wb") as f:
            f.write(raw)
        os.chmod(tmp, 0o755)
        os.replace(tmp, CORE_STAGED)
    return {"ok": True, "code": "staged", "core_sha": want[:12]}


def op_core_apply(d):
    want, bad = _granted_sha(d)
    if bad:
        return bad
    with _core_lock:
        if not os.path.isfile(CORE_STAGED):
            if os.path.isfile(CORE_BIN) and _installed_core_sha() == want:
                return {"ok": True, "code": "same", "core_sha": want[:12], "restarted": 0}
            return {"ok": False, "code": "nothing_staged"}
        with open(CORE_STAGED, "rb") as f:
            got = hashlib.sha256(f.read()).hexdigest()
        if got != want:
            os.remove(CORE_STAGED)
            return {"ok": False, "code": "sha_mismatch"}
        os.replace(CORE_STAGED, CORE_BIN)
    label = _core_label(d)
    conf = load_conf()
    conf["core_version"] = label
    save_conf(conf)
    restarted, failed = 0, []
    for c in raw_configs():
        if c.get("type") != "core" or not c.get("enabled", True):
            continue
        try:
            build_core(c)
            restarted += 1
        except Exception as e:
            failed.append({"name": c.get("name"), "msg": str(e)[:120]})
    logline("core %s applied (sha %s); relaunched %d tunnel(s)" % (label, want[:12], restarted))
    return {"ok": True, "code": "applied", "version": label, "core_sha": want[:12],
            "restarted": restarted, "failed": failed}


def op_apply(d):
    apply_all()
    return {"ok": True}


def op_update(d):
    src = d.get("code")
    if src is None and d.get("url"):
        if not CORE_SHA_RE.match(str(d.get("sha256") or "").strip().lower()):
            return {"ok": False, "msg": "url mode needs the sha256 of the agent to install"}
        try:
            raw = _fetch_url(d["url"], FETCH_MAX_AGENT)
        except Exception as e:
            return {"ok": False, "msg": "download failed: " + str(e)[:140]}
        try:
            src = raw.decode()
        except UnicodeDecodeError:
            return {"ok": False, "msg": "downloaded agent is not utf-8 text"}
    if not isinstance(src, str) or not src.strip():
        raise ValueError("empty code")
    h = hashlib.sha256(src.encode()).hexdigest()
    if d.get("sha256") and d["sha256"] != h:
        return {"ok": False, "msg": "checksum mismatch"}
    if not _verify_update_sig(h.encode(), d.get("sig")):
        return {"ok": False, "msg": "signature verification failed (panel key)"}
    if h == _SELF_SHA:
        return {"ok": True, "sha256": h, "restarting": False, "already": True}
    try:
        compile(src, "tnl-node.py", "exec")
    except SyntaxError as e:
        return {"ok": False, "msg": "rejected (syntax): " + str(e)}
    tmp = INSTALLED + ".new"
    try:
        with open(tmp, "w") as f:
            f.write(src)
        os.chmod(tmp, 0o755)
        py_compile.compile(tmp, doraise=True)
    except Exception as e:
        try:
            os.remove(tmp)
        except OSError:
            pass
        return {"ok": False, "msg": "rejected: " + str(e)[:140]}
    try:
        with open(INSTALLED, "rb") as f:
            disk_sha = hashlib.sha256(f.read()).hexdigest()
    except OSError:
        disk_sha = ""
    if disk_sha and disk_sha == _SELF_SHA:
        try:
            shutil.copy2(INSTALLED, INSTALLED + ".bak")
        except OSError:
            pass
    os.replace(tmp, INSTALLED)
    logline(f"agent updated -> sha {h[:12]}, restarting")
    _restart_pending.set()
    subprocess.Popen(["sh", "-c", "sleep 1; systemctl restart tnl-node"],
                     start_new_session=True, stdin=subprocess.DEVNULL,
                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    m = re.search(r'"version":\s*(\d+)', src)
    return {"ok": True, "version": int(m.group(1)) if m else None, "sha256": h, "restarting": True}


def op_spoof_probe(d):
    try:
        _ensure_core()
    except Exception as e:
        return {"ok": False, "reason": "core binary unavailable on this node: %s" % e}
    rc, out, err = run([CORE_BIN, "--probe-spoof"], timeout=15)
    if rc != 0:
        return {"ok": False, "reason": (err or out or "probe failed").strip()}
    try:
        p = json.loads(out.strip())
    except Exception:
        return {"ok": False, "reason": "unreadable probe output"}
    p.setdefault("ok", False)
    return p


_EGRESS = {}
_EGRESS_LOCK = threading.Lock()
_EGRESS_MAX = 32
_PROBE_TAGS = (b"BAS", b"SRC", b"DST")


def _egress_checksum(b):
    if len(b) % 2:
        b += b"\x00"
    s = 0
    for i in range(0, len(b), 2):
        s += (b[i] << 8) | b[i + 1]
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff


def _egress_build_ip4(src, dst, proto, payload, ttl=64):
    total = 20 + len(payload)
    h = bytearray(total)
    h[0] = 0x45
    struct.pack_into("!H", h, 2, total)
    h[8] = ttl
    h[9] = proto
    h[12:16] = socket.inet_aton(src)
    h[16:20] = socket.inet_aton(dst)
    struct.pack_into("!H", h, 10, _egress_checksum(bytes(h[:20])))
    h[20:] = payload
    return bytes(h)


def _egress_payload(tag, nonce):
    return tag + nonce.encode("ascii", "ignore")[:32]


def _egress_route_local(peer):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect((peer, 9))
            ip = s.getsockname()[0]
        finally:
            s.close()
        return ip if is_ipv4(ip) else None
    except OSError:
        return None


def op_spoof_egress_listen(d):
    nonce = str(d.get("nonce") or "").strip()
    if not re.match(r"^[0-9a-f]{8,32}$", nonce):
        raise ValueError("bad nonce")
    proto = int(d.get("proto") or 253)
    if not 1 <= proto <= 255:
        raise ValueError("bad proto")
    decoy = str(d.get("decoy") or "").strip()
    if decoy and not is_ipv4(decoy):
        raise ValueError("bad decoy")
    window = min(20, max(2, int(d.get("window") or 8)))
    token = secrets.token_hex(8)

    def capture():
        saw = {"baseline": False, "src": False, "dst": False}
        observed = {}
        fd = None
        try:
            fd = socket.socket(socket.AF_PACKET, socket.SOCK_DGRAM, socket.htons(0x0800))
            fd.settimeout(1.0)
            end = time.time() + window
            nb = nonce.encode("ascii")
            while time.time() < end:
                try:
                    pkt, addr = fd.recvfrom(2048)
                except socket.timeout:
                    continue
                except OSError:
                    break
                if len(addr) >= 3 and addr[2] == 4:
                    continue
                if len(pkt) < 20 or (pkt[0] >> 4) != 4 or pkt[9] != proto:
                    continue
                ihl = (pkt[0] & 0x0f) * 4
                body = pkt[ihl:ihl + 3 + len(nb)]
                if len(body) < 3 + len(nb) or body[3:3 + len(nb)] != nb:
                    continue
                tag = body[:3]
                src = socket.inet_ntoa(pkt[12:16])
                dst = socket.inet_ntoa(pkt[16:20])
                if tag == b"BAS":
                    saw["baseline"] = True
                elif tag == b"SRC":
                    saw["src"] = True
                    observed["src_seen_from"] = src
                elif tag == b"DST" and (not decoy or dst == decoy):
                    saw["dst"] = True
                    observed["dst_seen"] = dst
                if saw["baseline"] and saw["src"] and (saw["dst"] or not decoy):
                    break
        except OSError as e:
            observed["error"] = str(e)
        finally:
            if fd is not None:
                fd.close()
            with _EGRESS_LOCK:
                _EGRESS[token] = {"done": True, "saw": saw, "observed": observed}

    with _EGRESS_LOCK:
        if len(_EGRESS) >= _EGRESS_MAX:
            for k in [k for k, v in list(_EGRESS.items()) if v.get("done")][: _EGRESS_MAX // 2]:
                _EGRESS.pop(k, None)
        _EGRESS[token] = {"done": False}
    threading.Thread(target=capture, daemon=True).start()
    return {"ok": True, "token": token, "window": window}


def op_spoof_egress_send(d):
    nonce = str(d.get("nonce") or "").strip()
    if not re.match(r"^[0-9a-f]{8,32}$", nonce):
        raise ValueError("bad nonce")
    proto = int(d.get("proto") or 253)
    if not 1 <= proto <= 255:
        raise ValueError("bad proto")
    peer = str(d.get("peer") or "").strip()
    if not is_ipv4(peer):
        raise ValueError("bad peer")
    real_src = str(d.get("real_src") or "").strip()
    if not real_src:
        real_src = _egress_route_local(peer) or ""
    if not real_src or real_src not in local_ips_flat():
        raise ValueError("real_src must be one of this node's own IPs (route-local lookup failed)")
    forged_src = str(d.get("forged_src") or "").strip()
    if forged_src and not is_ipv4(forged_src):
        raise ValueError("bad forged_src")
    decoy_dst = str(d.get("decoy_dst") or "").strip()
    if decoy_dst and not is_ipv4(decoy_dst):
        raise ValueError("bad decoy_dst")

    plan = [("BAS", real_src, peer)]
    if forged_src:
        plan.append(("SRC", forged_src, peer))
    if decoy_dst:
        plan.append(("DST", real_src, decoy_dst))

    fd = None
    sent = []
    try:
        fd = socket.socket(socket.AF_INET, socket.SOCK_RAW, proto)
        fd.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        fd.settimeout(2.0)
        sa = (peer, 0)
        for tag, s, dstip in plan:
            pkt = _egress_build_ip4(s, dstip, proto, _egress_payload(tag.encode(), nonce))
            for _ in range(3):
                try:
                    fd.sendto(pkt, sa)
                except OSError as e:
                    return {"ok": False, "error": "send failed (%s): %s" % (tag, e)}
                time.sleep(0.05)
            sent.append(tag.lower())
    except OSError as e:
        return {"ok": False, "error": "raw socket: %s (needs root / CAP_NET_RAW)" % e}
    finally:
        if fd is not None:
            fd.close()
    return {"ok": True, "sent": sent}


def op_spoof_egress_result(d):
    token = str(d.get("token") or "").strip()
    with _EGRESS_LOCK:
        r = _EGRESS.get(token)
    if r is None:
        return {"ok": False, "error": "unknown or expired token"}
    return {"ok": True, **r}


def op_ech_update(d):
    _require(d, ["name", "snis"])
    name = str(d["name"])
    if not NAME_RE.match(name):
        raise ValueError("bad name")
    if not (_is_ws_pool(name) or _is_ws_single(name)):
        return {"ok": False, "error": "این تونل ws نیست"}
    snis = d.get("snis") or {}
    if not isinstance(snis, dict):
        raise ValueError("bad snis")
    clean = {}
    for h, e in snis.items():
        e = str(e or "").strip()
        if e and len(e) <= 4096 and re.match(r"^[A-Za-z0-9+/=]+$", e):
            clean[str(h)[:255]] = e
    if not clean:
        return {"ok": False, "error": "no valid ech"}
    path = _cfg_path(name, ".status.echcmd")
    err = _atomic_write_json(path, {"snis": clean})
    if err:
        return {"ok": False, "error": err}
    return {"ok": True, "hosts": list(clean.keys())}


def op_kernel_tune(d):
    action = str(d.get("action") or "status").lower()
    if action == "apply":
        err = apply_kernel_tuning()
        if err:
            return {"ok": False, "error": "could not save tuning state; nothing changed"}
        st = tuning_status()
    elif action == "revert":
        revert_kernel_tuning()
        st = tuning_status()
    else:
        st = tuning_status()
    st["ok"] = True
    return st


OPS = {"ping": op_ping, "list": op_list, "check": op_check, "tunnel": op_tunnel,
       "portfw": op_portfw, "portfw-edit": op_portfw_edit, "portfw-next": op_portfw_next,
       "delete": op_delete, "apply": op_apply, "update": op_update, "wipe": op_wipe,
       "portcheck": op_portcheck, "speedtest": op_speedtest, "edge-status": op_edge_status,
       "peer-status": op_peer_status,
       "peer-select": op_peer_select, "pool-select": op_pool_select, "retest-now": op_retest_now,
       "ech-update": op_ech_update,
       "core-put": op_core_put, "core-apply": op_core_apply,
       "spoof-probe": op_spoof_probe,
       "spoof-egress-listen": op_spoof_egress_listen, "spoof-egress-send": op_spoof_egress_send,
       "spoof-egress-result": op_spoof_egress_result,
       "set-update-key": op_set_update_key,
       "kernel-tune": op_kernel_tune,
       "link-enable": op_link_enable, "core-restart": op_core_restart}
READ_ONLY = {"ping", "list", "check", "portcheck", "spoof-probe", "edge-status", "peer-status"}

WIRE = {
    "pg": "ping", "ls": "list", "ck": "check", "mk": "tunnel", "dl": "delete", "ap": "apply",
    "up": "update", "wz": "wipe", "pf": "portfw", "pe": "portfw-edit", "pn": "portfw-next",
    "pc": "portcheck", "sd": "speedtest", "es": "edge-status", "ps": "peer-status", "pl": "peer-select",
    "qs": "pool-select", "rt": "retest-now", "eu": "ech-update",
    "cp": "core-put", "ca": "core-apply", "sp": "spoof-probe", "sl": "spoof-egress-listen", "ss": "spoof-egress-send",
    "sr": "spoof-egress-result", "sk": "set-update-key", "kt": "kernel-tune", "le": "link-enable",
    "cr": "core-restart",
}


class Handler(BaseHTTPRequestHandler):
    server_version = "tnl-node"
    timeout = 30

    def log_message(self, *a):
        pass

    def setup(self):
        BaseHTTPRequestHandler.setup(self)
        self._sem_held = _conn_sem.acquire(blocking=False)

    def finish(self):
        try:
            BaseHTTPRequestHandler.finish(self)
        finally:
            if getattr(self, "_sem_held", False):
                _conn_sem.release()
                self._sem_held = False

    def handle(self):
        if not getattr(self, "_sem_held", False):
            try:
                body = b'{"error":"server busy, retry shortly"}'
                self.wfile.write(b"HTTP/1.1 503 Service Unavailable\r\n"
                                 b"Content-Type: application/json\r\n"
                                 b"Content-Length: " + str(len(body)).encode() + b"\r\n"
                                 b"Connection: close\r\n\r\n" + body)
            except Exception:
                pass
            return
        BaseHTTPRequestHandler.handle(self)

    def _authed(self, method):
        want = self.server.conf.get("token", "")
        if not want:
            return ""
        sig = self.headers.get("X-Sig", "")
        if not sig:
            return ""
        return "sig" if _sig_ok(want, method, self.path, self.headers.get("X-Ctr", ""),
                                self.headers.get("X-Body", ""), sig) else ""

    def _send(self, code, body):
        data = json.dumps(body).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(data)

    def _body(self, cap=1048576):
        try:
            n = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            n = 0
        n = min(max(n, 0), cap)
        raw = self.rfile.read(n) if n > 0 else b""
        self._raw = raw
        try:
            obj = json.loads(raw.decode()) if raw else {}
        except Exception:
            return {}
        return obj if isinstance(obj, dict) else {}

    def _body_matches_sig(self):
        raw = getattr(self, "_raw", b"")
        try:
            return hmac.compare_digest(self.headers.get("X-Body", "") or "",
                                       hashlib.sha256(raw).hexdigest() if raw else "")
        except Exception:
            return False

    def _handle(self, method):
        self._handle_locked(method)

    def _handle_locked(self, method):
        path = self.path.split("?", 1)[0]
        if not path.startswith("/api/"):
            self._send(404, {"error": "not found"})
            return
        cmd = WIRE.get(path[5:], "")
        how = self._authed(method)
        if not how:
            self._send(401, {"error": "bad or missing node token"})
            return
        if how == "sig":
            try:
                ctr = int(self.headers.get("X-Ctr", ""))
            except (TypeError, ValueError):
                ctr = -1
            if not _accept_ctr(ctr):
                with _req_ctr_lock:
                    cur = _req_ctr
                self._send(409, {"error": "stale counter", "ctr": cur})
                return
        cp = self.headers.get("X-Central-Port")
        if cp:
            ch = str(self.headers.get("X-Central-Host", "")).strip()
            note_central(ch if is_ipv4(ch) else self.client_address[0], cp,
                         str(self.headers.get("X-Central-TLS", "")).strip() not in ("", "0"))
        if cmd not in OPS:
            self._send(404, {"error": "unknown endpoint"})
            return
        if cmd not in READ_ONLY and method != "POST":
            self._send(405, {"error": "use POST"})
            return
        cap = 33554432 if cmd == "core-put" else 1048576
        d = self._body(cap) if method == "POST" else {}
        if how == "sig" and not self._body_matches_sig():
            self._send(401, {"error": "body does not match the signature"})
            return
        try:
            if cmd in READ_ONLY:
                res = OPS[cmd](d)
            else:
                if _restart_pending.is_set():
                    self._send(503, {"error": "agent is restarting, retry shortly"})
                    return
                with _apply_lock:
                    if _restart_pending.is_set():
                        self._send(503, {"error": "agent is restarting, retry shortly"})
                        return
                    res = OPS[cmd](d)
            self._send(200, res)
        except ValueError as e:
            self._send(400, {"error": str(e)})
        except Exception as e:
            logline(f"op {cmd} error: {e}")
            self._send(500, {"error": "internal error (see node-agent.log)"})

    def do_GET(self):
        self._handle("GET")

    def do_POST(self):
        self._handle("POST")


SERVICE = "tnl-node.service"


def svc(*a):
    run(["systemctl", *a, SERVICE])


def service_active():
    return run(["systemctl", "is-active", "--quiet", SERVICE])[0] == 0


def install_deps():
    print("[*] Installing dependencies (iptables, openssl)...")
    env = dict(os.environ, DEBIAN_FRONTEND="noninteractive")
    try:
        subprocess.run(["apt-get", "update", "-qq"], env=env, timeout=300)
        subprocess.run(["apt-get", "install", "-yqq", "iptables", "openssl"], env=env, timeout=600)
    except Exception as e:
        print(f"[!] apt failed: {e}")
    print("[✔] dependencies ready (native tunnels — no OpenvSwitch needed).")


def write_service():
    with open(SERVICE_FILE, "w") as f:
        f.write(f"""[Unit]
Description=tnl node agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/bin/env python3 {INSTALLED} --serve
Restart=on-failure
RestartSec=3

[Install]
WantedBy=multi-user.target
""")
    run(["systemctl", "daemon-reload"])


def _prepare_install():
    os.makedirs(CONFIG_DIR, exist_ok=True)
    os.chmod(CONFIG_DIR, 0o700)
    if os.path.realpath(SELF_PATH) != INSTALLED:
        shutil.copy2(SELF_PATH, INSTALLED)
        os.chmod(INSTALLED, 0o755)
    return load_conf() if os.path.isfile(NODE_CONF) else {}


def _finish_install(conf):
    if not conf.get("token"):
        conf["token"] = secrets.token_urlsafe(32)
    save_conf(conf)
    install_deps()
    write_service()
    svc("enable")
    svc("restart")
    print("[✔] node agent installed and started.")


def do_install():
    conf = _prepare_install()
    conf["port"] = int(input(f"Agent port [{conf.get('port', 8099)}]: ").strip() or conf.get("port", 8099))
    _finish_install(conf)
    do_show()


def do_auto_install(port):
    conf = _prepare_install()
    try:
        conf["port"] = int(str(port).strip())
    except Exception:
        conf["port"] = conf.get("port", 8099)
    if not 1 <= conf["port"] <= 65535:
        conf["port"] = 8099
    _finish_install(conf)
    print("TNL_INSTALL_OK")
    print(f"TNL_NODE_PORT={conf['port']}")
    print(f"TNL_NODE_TOKEN={conf['token']}")


def do_show():
    if not os.path.isfile(NODE_CONF):
        print("Not configured yet - run Install first.")
        return
    conf = load_conf()
    print("\n=== register this node in the central panel ===")
    print(f"  host  : {primary_ip() or 'this-node-ip'}")
    print(f"  port  : {conf.get('port', 8099)}")
    print(f"  token : {conf.get('token')}")
    print("================================================\n")


def change_port():
    conf = load_conf() if os.path.isfile(NODE_CONF) else {}
    p = input(f"New agent port [{conf.get('port', 8099)}]: ").strip()
    if not p:
        return
    conf["port"] = int(p)
    save_conf(conf)
    if os.path.isfile(SERVICE_FILE):
        svc("restart")
    print(f"[✔] port set to {conf['port']} - open it to the central server only.")


def regen_token():
    if input("Regenerate token? the old one stops working [y/N]: ").strip().lower() != "y":
        return
    conf = load_conf() if os.path.isfile(NODE_CONF) else {}
    conf["token"] = secrets.token_urlsafe(32)
    save_conf(conf)
    if os.path.isfile(SERVICE_FILE):
        svc("restart")
    print("[✔] new token - update it in the central panel:")
    do_show()


def uninstall():
    if input("Uninstall the agent? [y/N]: ").strip().lower() != "y":
        return
    svc("stop")
    svc("disable")
    try:
        os.remove(SERVICE_FILE)
    except FileNotFoundError:
        pass
    run(["systemctl", "daemon-reload"])
    print("[✔] agent service removed (tunnels & configs kept).")
    if input("Also delete node.conf (token/port)? [y/N]: ").strip().lower() == "y":
        try:
            os.remove(NODE_CONF)
        except FileNotFoundError:
            pass
        print("[✔] node.conf removed.")


def do_restart():
    if not os.path.isfile(SERVICE_FILE):
        print("Not installed yet - run Install first.")
        return
    print("[*] restarting the agent (tunnels rebuild on boot, brief blip)...")
    svc("restart")
    print("[✔] restarted, agent active." if service_active()
          else "[!] restarted but not active - check Status / logs.")


def status():
    exists = os.path.isfile(SERVICE_FILE)
    conf = load_conf() if os.path.isfile(NODE_CONF) else {}
    cfgs = raw_configs()
    print()
    print(f"  service : {'active' if service_active() else ('installed, stopped' if exists else 'not installed')}")
    print(f"  port    : {conf.get('port', '-')}")
    print(f"  token   : {'set' if conf.get('token') else 'none'}")
    print(f"  tunnels : {len([c for c in cfgs if c.get('type') != 'portfw'])}")
    print(f"  portfw  : {len([c for c in cfgs if c.get('type') == 'portfw'])}")
    print(f"  host IP : {primary_ip() or '?'}")
    print()


def menu():
    if os.geteuid() != 0:
        print("Run as root (sudo).")
        sys.exit(1)
    os.makedirs(CONFIG_DIR, exist_ok=True)
    while True:
        exists = os.path.isfile(SERVICE_FILE)
        st = "active" if service_active() else ("stopped" if exists else "not installed")
        print(f"\n=== tnl-node . agent setup   [{st}] ===")
        print("  1) Install / reinstall (deps + service)")
        print("  2) Show connection info (host/port/token)")
        print("  3) Restart service (apply an updated file)")
        print("  4) Change port")
        print("  5) Regenerate token")
        print("  6) Status")
        print("  7) Uninstall")
        print("  8) Exit")
        c = input("choice: ").strip()
        try:
            if c == "1":
                do_install()
            elif c == "2":
                do_show()
            elif c == "3":
                do_restart()
            elif c == "4":
                change_port()
            elif c == "5":
                regen_token()
            elif c == "6":
                status()
            elif c == "7":
                uninstall()
            elif c == "8":
                break
            else:
                print("invalid.")
        except Exception as e:
            print(f"[!] {e}")


def serve():
    if not os.path.isfile(NODE_CONF):
        print("Not configured. Run the setup menu:  sudo python3 tnl-node.py")
        sys.exit(1)
    if os.geteuid() != 0:
        print("Run as root (sudo).")
        sys.exit(1)
    conf = load_conf()
    try:
        os.chmod(CONFIG_DIR, 0o700)
    except Exception:
        pass
    for _ in range(30):
        rc, out, _ = run(["ip", "-4", "route"])
        if any(l.startswith("default") for l in out.splitlines()):
            break
        time.sleep(1)
    try:
        apply_all()
    except Exception as e:
        logline(f"startup apply_all: {e}")
    threading.Thread(target=rotation_loop, daemon=True).start()
    threading.Thread(target=health_loop, daemon=True).start()
    _seed_central_cb()
    _seed_req_ctr()
    threading.Thread(target=checkin_loop, daemon=True).start()
    httpd = ThreadingHTTPServer(("0.0.0.0", int(conf.get("port", 8099))), Handler)
    httpd.conf = conf
    print(f"tnl-node agent on http://0.0.0.0:{conf.get('port', 8099)}/  (self-contained, token-auth)")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass


def main():
    arg = sys.argv[1] if len(sys.argv) > 1 else ""
    if arg == "--serve":
        serve()
    elif arg == "--install":
        if os.geteuid() != 0:
            print("Run as root (sudo).")
            sys.exit(1)
        do_install()
    elif arg == "--auto-install":
        if os.geteuid() != 0:
            print("Run as root (sudo).")
            sys.exit(1)
        do_auto_install(sys.argv[2] if len(sys.argv) > 2 else "8099")
    elif arg == "--show":
        do_show()
    else:
        menu()


if __name__ == "__main__":
    main()
