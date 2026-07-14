#!/usr/bin/env python3
# tnl-node — self-contained node agent for the tnl central control plane.
#
# Installed on every NODE server. It is FULLY self-contained: it builds tunnels itself
# (VXLAN/GRE via OpenvSwitch, SIT, iptables port-forwards), re-applies them on boot,
# and rotates port-forward destinations — all in-process. No tnl.sh, no reload.sh, no jq,
# no menu. Every operation is driven by the central panel over a token-authenticated API.
#
# Node dependencies: python3, iproute2 (ip), iptables. All tunnels are native kernel netdevs
# (VXLAN/GRE/SIT/IPIP/L2TPv3/FOU/IPsec) — no OpenvSwitch required.
#
# Usage:
#   sudo python3 tnl-node.py --install         # set port + generate token, install+start the service
#   sudo python3 tnl-node.py --auto-install P  # non-interactive install on port P (panel SSH provisioning)
#   sudo python3 tnl-node.py --show            # print host / port / token for the central panel
#   sudo python3 tnl-node.py               # run (used by systemd): re-applies configs, then serves
#
# Auth: every request must carry header  X-Node-Token: <token>  (constant-time compared).
# Plain HTTP — expose the agent port to the central server only (trusted network / VPN).

import base64
import hashlib
import hmac
import ipaddress
import json
import os
import py_compile
import re
import secrets
import shutil
import socket
import subprocess
import sys
import threading
import time
import urllib.request
from concurrent.futures import ThreadPoolExecutor, wait as futures_wait
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

CONFIG_DIR = "/opt/tunnel"
NODE_CONF = os.path.join(CONFIG_DIR, "node.conf")
LOG = os.path.join(CONFIG_DIR, "node-agent.log")
SERVICE_FILE = "/etc/systemd/system/tnl-node.service"
SELF_PATH = os.path.realpath(__file__)
INSTALLED = os.path.join(CONFIG_DIR, "tnl-node.py")  # stable path the systemd unit points at

# The custom Go data-plane core (packet/core): a static binary the PANEL delivers by pushing verified
# bytes to the node (op core-install). The node never downloads it itself — nodes may have no internet
# (e.g. an Iran node), so the panel is the single source and stages/relays the binary. The node only
# verifies the pushed sha256 and supervises the binary via systemd-run.
CORE_BIN = os.path.join(CONFIG_DIR, "tnl-core")
_core_lock = threading.Lock()  # serialize replace of the shared core binary
_core_sha_cache = {"mtime": None, "sha": ""}  # avoid re-hashing the 3 MB binary on every ping
OBFS_DATA_PAD_MAX = 64   # must match the core's obfsDataPadMax so the MTU budget covers worst-case padding

NAME_RE = re.compile(r"^[A-Za-z0-9_]+$")
IFACE_RE = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.@-]*$")  # no leading '-' → can't be mistaken for a CLI flag (arg-injection guard)

MAX_CONNS = 64                  # cap concurrent request handlers so an unauth slowloris can't exhaust root threads
_conn_sem = threading.BoundedSemaphore(MAX_CONNS)
_apply_lock = threading.Lock()  # serialize all state mutations (API writes + rotation thread)
_restart_pending = threading.Event()  # set once op_update swaps the binary → reject NEW mutating ops until the bounce
_central_cb = None              # (ip, port) the panel last reached us from → where we call back /api/checkin
_central_cb_lock = threading.Lock()
_last_reported_ips = None       # last IP set we successfully checked in with (skip redundant check-ins)
CHECKIN_GAP = 20                # seconds between our own IP-change checks

# ----------------------------------------------------------------------------- config

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

# ----------------------------------------------------------------------------- helpers

def run(args, timeout=60):
    try:
        p = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
        return p.returncode, p.stdout, p.stderr
    except subprocess.TimeoutExpired:
        return 124, "", "timeout"
    except FileNotFoundError as e:
        return 127, "", str(e)


def must(args, timeout=60):
    """Run a build command that MUST succeed. run() never raises, so a failed `ip`/`ip xfrm` command
    used to be swallowed silently — the netdev could still exist (so op_tunnel's netdev-exists verify
    passed) while the tunnel was half-built (missing address, no ESP SA) and carried no traffic yet
    reported ok. Raising here routes the real failure (stderr) through op_tunnel's apply_config catch,
    which restores the previous build and returns ok:false with the reason. Use it ONLY for commands
    that must succeed on a freshly-torn-down device — NOT for idempotent teardown (`ip link del`, xfrm
    `deleteall`) or already-present-is-fine registrations (`ip fou add`), which stay on run()."""
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
    """Coerce an API value to a real bool WITHOUT the bool("false")==True trap: genuine JSON
    booleans pass through (True stays True, False/None stay False) and a stringly-typed flag only
    counts as True for an explicit truthy token. Use for every security/toggle flag read off the wire."""
    return v is True or (isinstance(v, str) and v.strip().lower() in ("1", "true", "yes", "on"))


def valid_cidr(s, want6):
    if "/" not in str(s):   # a bare IP has no prefix: ip_network() treats it as /32, but derive_tunnel_ip needs the slash
        return False
    try:
        return ipaddress.ip_network(s, strict=False).version == (6 if want6 else 4)
    except Exception:
        return False


def ip2int(s):
    return int(ipaddress.IPv4Address(s))


def derive_tunnel_ip(ttype, local_ip, remote_ip, subnet):
    """Same rule as the fleet: smaller public IP => .1, larger => .2 (never a custom host)."""
    parts = subnet.split("/")
    base = parts[0]
    prefix = parts[1] if len(parts) > 1 else ("64" if ttype == "sit" else "24")   # never IndexError on a prefix-less subnet
    host = "1" if ip2int(local_ip) < ip2int(remote_ip) else "2"
    if ttype == "sit":
        # build the host address with ipaddress so full-form / non-'::'-terminated v6 subnets
        # don't yield a malformed double-'::' string that `ip -6 addr add` silently rejects
        net = ipaddress.ip_network(f"{base}/{prefix}", strict=False)
        return f"{net.network_address + int(host)}/{net.prefixlen}"
    return f"{base.rsplit('.', 1)[0]}.{host}/{prefix}"

# ----------------------------------------------------------------------------- config IO

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
        c.pop("remote_password", None)  # never expose secrets over the API
        c.pop("psk", None)              # IPsec pre-shared key stays on the node
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
    name = f"{ttype}{tid}"
    if os.path.exists(os.path.join(CONFIG_DIR, name + ".json")):
        return None
    rc, _, _ = run(["ip", "link", "show", name])
    return name if rc != 0 else None

# ----------------------------------------------------------------------------- network

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
    """MTU of the underlay a tunnel egresses on. Pass the tunnel's own `iface` to sample THAT link
    (PPPoE 1492 / IPv6-min 1280 uplinks differ from the default route); no arg falls back to the
    default-route iface as before."""
    dev = dev or default_iface()
    if dev and IFACE_RE.match(dev):
        rc, out, _ = run(["ip", "link", "show", dev])
        m = re.search(r"\bmtu (\d+)", out)
        if m:
            return int(m.group(1))
    return 1500

# ----------------------------------------------------------------------------- build / teardown

def _modprobe(*mods):
    """Best-effort load of the kernel modules a tunnel type needs. The new `ip link add type ...` and
    `ip l2tp` netlink APIs do NOT auto-load their modules (unlike the old `ip tunnel add`), so an FOU or
    L2TPv3 build silently fails to create its netdev on any node where the module isn't already resident."""
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


def _purge_ovs(cfg):
    """One-time migration from the old OpenvSwitch scheme: an already-provisioned node may still have an OVS
    bridge named like the tunnel plus its veth pair, which would squat the netdev name. Best-effort removal —
    ovs-vsctl is gone on fresh nodes (run() just returns 127), harmless on nodes that still have it."""
    name, tid = cfg.get("name", ""), str(cfg.get("id", ""))
    run(["ovs-vsctl", "--if-exists", "del-br", name])
    if tid.isdigit():
        run(["ip", "link", "del", f"veth{tid}a"])
        run(["ip", "link", "del", f"veth{tid}b"])


def build_vxlan(cfg):
    """Native kernel VXLAN (UDP 4789) — point-to-point to the peer, tunnel IP assigned directly.
    No OpenvSwitch/veth: one netdev per tunnel, same as ipip/sit. VNI == tunnel id (symmetric both ends)."""
    name = cfg["name"]
    _modprobe("vxlan")   # `ip link add type vxlan` does not auto-load the module
    _purge_ovs(cfg)      # migrate: clear any OVS bridge/veth left by the old scheme so the name is free
    run(["ip", "link", "del", name])
    dstport = int(cfg.get("port") or 4789)   # UDP port is now settable (default 4789) — e.g. to dodge a filter
    must(["ip", "link", "add", name, "type", "vxlan", "id", str(cfg["id"]),
         "local", cfg["local_ip"], "remote", cfg["remote_ip"], "dstport", str(dstport)])
    must(["ip", "addr", "add", cfg["tunnel_ip"], "dev", name])
    must(["ip", "link", "set", name, "up"])
    run(["ip", "link", "set", "dev", name, "mtu", str(base_mtu(cfg.get("iface")) - 50)])  # IP20+UDP8+VXLAN8+innerEth14


def build_gre(cfg):
    """Native kernel GRE (proto 47) — point-to-point, tunnel IP assigned directly. GRE key == tunnel id."""
    name = cfg["name"]
    _modprobe("ip_gre")   # `ip link add type gre` does not auto-load the module
    _purge_ovs(cfg)       # migrate: clear any OVS bridge/veth left by the old scheme so the name is free
    run(["ip", "link", "del", name])
    must(["ip", "link", "add", name, "type", "gre",
         "local", cfg["local_ip"], "remote", cfg["remote_ip"], "key", str(cfg["id"])])
    must(["ip", "addr", "add", cfg["tunnel_ip"], "dev", name])
    must(["ip", "link", "set", name, "up"])
    run(["ip", "link", "set", "dev", name, "mtu", str(base_mtu(cfg.get("iface")) - 28)])  # IP20+GRE4+key4


def build_sit(cfg):
    name = cfg["name"]
    run(["ip", "link", "del", name])
    must(["ip", "tunnel", "add", name, "mode", "sit", "remote", cfg["remote_ip"],
         "local", cfg["local_ip"], "ttl", "255"])
    must(["ip", "-6", "addr", "add", cfg["tunnel_ip"], "dev", name])
    must(["ip", "link", "set", name, "up"])
    run(["ip", "link", "set", "dev", name, "mtu", str(base_mtu(cfg.get("iface")) - 28 - 20)])


def build_ipip(cfg):
    """IPv4-in-IPv4 — the lightest L3 tunnel (20-byte overhead). Same shape as SIT but v4."""
    name = cfg["name"]
    _modprobe("ipip")
    run(["ip", "link", "del", name])
    must(["ip", "tunnel", "add", name, "mode", "ipip", "remote", cfg["remote_ip"],
         "local", cfg["local_ip"], "ttl", "255"])
    must(["ip", "addr", "add", cfg["tunnel_ip"], "dev", name])
    must(["ip", "link", "set", name, "up"])
    run(["ip", "link", "set", "dev", name, "mtu", str(base_mtu(cfg.get("iface")) - 20)])


def _l2tp_ids(cfg):
    tid = int(cfg["id"])
    port = int(cfg.get("port") or (20000 + tid))
    return tid, port


def build_l2tp(cfg):
    """L2TPv3 pseudowire over UDP — NAT-friendly, picks its own UDP port. Symmetric ids/ports on both
    ends (same tunnel_id/session_id/port each side), so a point-to-point pair matches without coordination."""
    name = cfg["name"]
    tid, port = _l2tp_ids(cfg)
    _modprobe("l2tp_eth", "l2tp_netlink")   # l2tp_eth pulls l2tp_core; without it the session netdev never appears
    run(["ip", "l2tp", "del", "session", "tunnel_id", str(tid), "session_id", str(tid)])
    run(["ip", "l2tp", "del", "tunnel", "tunnel_id", str(tid)])
    run(["ip", "link", "del", name])
    must(["ip", "l2tp", "add", "tunnel", "tunnel_id", str(tid), "peer_tunnel_id", str(tid),
         "encap", "udp", "local", cfg["local_ip"], "remote", cfg["remote_ip"],
         "udp_sport", str(port), "udp_dport", str(port)])
    must(["ip", "l2tp", "add", "session", "name", name, "tunnel_id", str(tid),
         "session_id", str(tid), "peer_session_id", str(tid)])
    must(["ip", "addr", "add", cfg["tunnel_ip"], "dev", name])
    must(["ip", "link", "set", name, "up"])
    run(["ip", "link", "set", "dev", name, "mtu", str(base_mtu(cfg.get("iface")) - 54)])


def _fou_port(cfg):
    return int(cfg.get("port") or (20000 + int(cfg["id"])))


def build_fou(cfg):
    """IPIP wrapped in Foo-over-UDP — an L3 tunnel that rides UDP so it crosses NAT and lets you pick the
    port. The FOU listener decapsulates ipip-in-udp on our port; the ipip link encaps to the peer's port."""
    name = cfg["name"]
    port = _fou_port(cfg)
    _modprobe("fou", "ipip")   # ipip is REQUIRED: `ip link add type ipip encap fou` won't auto-load it
    run(["ip", "link", "del", name])
    run(["ip", "fou", "add", "port", str(port), "ipproto", "4"])  # decap listener (harmless if already there)
    must(["ip", "link", "add", "name", name, "type", "ipip", "remote", cfg["remote_ip"],
         "local", cfg["local_ip"], "ttl", "255", "encap", "fou",
         "encap-sport", "auto", "encap-dport", str(port)])
    must(["ip", "addr", "add", cfg["tunnel_ip"], "dev", name])
    must(["ip", "link", "set", name, "up"])
    run(["ip", "link", "set", "dev", name, "mtu", str(base_mtu(cfg.get("iface")) - 28)])


def _ipsec_params(cfg):
    """Deterministic ESP parameters for one side. Keys come from the shared psk (distinct enc/auth keys);
    SPIs derive from the tunnel id; direction (which SPI is outbound) is decided by comparing the two
    public IPs so both ends agree without extra coordination. if_id binds the SAs to the xfrm interface."""
    tid = int(cfg["id"])
    psk = str(cfg.get("psk") or "")
    enc = hashlib.sha256((psk + "|enc").encode()).hexdigest()          # 32 bytes -> aes-256
    auth = hashlib.sha256((psk + "|auth").encode()).hexdigest()        # 32 bytes -> hmac(sha256)
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
    """Route-based IPsec via an xfrm interface + static-key ESP (no IKE daemon). Traffic routed into the
    xfrm device is tagged with if_id, matched by the policies, and ESP-encapsulated to the peer."""
    name, local, remote = cfg["name"], cfg["local_ip"], cfg["remote_ip"]
    tid, enc, auth, spi_out, spi_in = _ipsec_params(cfg)
    if not cfg.get("psk"):
        raise ValueError("ipsec needs a psk")
    _modprobe("esp4", "xfrm_interface")   # defensive: xfrm usually auto-loads, but make the netdev creation deterministic
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
    must(["ip", "addr", "add", cfg["tunnel_ip"], "dev", name])
    must(["ip", "link", "set", name, "up"])
    run(["ip", "link", "set", "dev", name, "mtu", str(base_mtu(cfg.get("iface")) - 80)])


def _core_arch():
    m = os.uname().machine
    return {"x86_64": "amd64", "amd64": "amd64", "aarch64": "arm64", "arm64": "arm64"}.get(m, "amd64")


def _core_ref():
    """The core version installed on this node — the label the panel stamped when it pushed the binary
    (a release tag or "custom"), or "" when no binary has been installed yet."""
    try:
        return str(load_conf().get("core_version") or "").strip()
    except Exception:
        return ""


def _installed_core_sha():
    """sha256 of the installed binary, cached by mtime so ping doesn't re-hash 3 MB each time."""
    try:
        st = os.stat(CORE_BIN)
        if _core_sha_cache["mtime"] != st.st_mtime:
            with open(CORE_BIN, "rb") as f:
                _core_sha_cache["sha"] = hashlib.sha256(f.read()).hexdigest()
            _core_sha_cache["mtime"] = st.st_mtime
        return _core_sha_cache["sha"]
    except Exception:
        return ""


def _ensure_core():
    """The core binary is delivered ONLY by the panel, which pushes verified bytes via the core-install
    op. The node NEVER downloads it itself (nodes may have no internet — e.g. an Iran node). If the
    binary is missing, raise a clear, panel-detectable error so the panel's tunnel-build path relays the
    staged binary and retries; if the panel has nothing staged, the operator sees "core not installed"."""
    if not os.path.isfile(CORE_BIN):
        raise RuntimeError("core not installed on this node (push it from the panel)")


def _core_port(cfg):
    return int(cfg.get("port") or (20000 + int(cfg["id"])))


_TUNING_INT_KEYS = ("dead_retest_secs", "pin_ttl_secs", "data_fail_threshold", "data_good_window_secs",
                    "idle_mult", "idle_min_secs", "session_stale_mult", "session_stale_min_secs",
                    "ping_loss_threshold", "min_liveness_secs", "probe_timeout_secs", "flux_rotate_default_secs")


def _core_tuning(tn):
    """Sanitize the panel's operational-timing overrides into a type-clean JSON object for the core:
    positive ints for the scalar knobs, a list of positive ints for suspect_backoff. Drop anything
    malformed or non-positive (the core treats absent/zero as "keep default"). Returns {} when there
    is nothing to pass, so the core config omits `tuning` entirely and every timing stays at default."""
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
    sb = tn.get("suspect_backoff")
    if isinstance(sb, (list, tuple)):
        steps = []
        for x in sb:
            try:
                iv = int(x)
            except (TypeError, ValueError):
                continue
            if iv > 0:
                steps.append(iv)
        if steps:
            out["suspect_backoff"] = steps
    return out


def _core_config(cfg):
    """Pure: build the JSON the core binary consumes from a stored tunnel config. The tun device is
    named after the config so /proc/net/dev accounting and `ip link show <name>` health work unchanged.
    Crypto is on whenever a psk is present; the psk never leaves the node (public_configs pops it)."""
    name = cfg["name"]
    port = _core_port(cfg)
    cipher = str(cfg.get("cipher") or "auto")   # match the panel's default so the MTU/crypto sizing agrees
    crypto_on = bool(cfg.get("psk")) and cipher != "none"  # a psk with cipher=none is NOT encryption
    transport = str(cfg.get("transport") or "udp").lower()
    raw_profile = str(cfg.get("raw_profile") or "bip").lower()
    obfs = bool(cfg.get("obfs")) and crypto_on   # obfs is meaningless without the AEAD key
    # MTU budget = outer headers + core framing + obfs padding + AEAD (nonce+tag) + wire mask salt.
    flux_carrier = str(cfg.get("flux_carrier") or "udp").lower()
    if transport == "raw":
        # IP20 + the profile's carrier header (bip/ipip add none; gre 4; icmp/udp 8; tcp 20).
        outer = 20 + {"bip": 0, "ipip": 0, "gre": 4, "icmp": 8, "udp": 8, "tcp": 20}.get(raw_profile, 0)
    elif transport == "flux":
        # IP20 + the carrier header: udp adds an 8-byte UDP header; stun adds UDP + a
        # 20-byte STUN header; the raw carrier adds none.
        outer = 20 + {"udp": 8, "stun": 28}.get(flux_carrier, 0)
    elif transport == "ws":
        outer = 40 + 14        # IP20 + TCP20 + up to a 14-byte WebSocket frame header
    else:
        outer = 40 if transport == "tcp" else 28        # IP20 + TCP20 | IP20 + UDP8
    stream = transport in ("tcp", "ws")   # ws is TCP-family: length-prefixed frames, same 2-byte prefix as tcp
    if obfs:
        framing = (2 if stream else 0) + 3 + OBFS_DATA_PAD_MAX  # masked-len + [type,len] + max pad
    else:
        framing = 4 if stream else 2        # (len)+magic+type | magic+type
    overhead = outer + framing
    if crypto_on:
        # AEAD nonce+tag, plus the 12-byte per-frame mask salt the core prepends (v2 wire).
        overhead += (40 if cipher == "xchacha20-poly1305" else 28) + 12
    # FEC (datagram carriers: udp/raw/flux) prepends an 11-byte block header + a 2-byte
    # shard-len to every data shard, so it costs 13 bytes of usable payload per packet.
    if transport in ("udp", "raw", "flux") and bool(cfg.get("fec")):
        overhead += 13
    # The TUN MTU must never EXCEED the carrier budget, or datagram carriers fragment/black-hole on a
    # small underlay (PPPoE 1492 / IPv6-min 1280): floor 1280 could hand out MORE than base-overhead.
    # Sample the tunnel's own egress iface, and clamp only at a safe small minimum, never raising above budget.
    mtu = max(576, base_mtu(cfg.get("iface")) - overhead)
    corecfg = {
        "role": cfg.get("role"),
        "mode": "packet",
        "profile": "core",
        "transport": transport,
        "obfs": obfs,
        "tun_name": name,
        "tun_addr": cfg["tunnel_ip"],
        "tun_peer": peer_of(cfg["tunnel_ip"], "core"),
        "mtu": mtu,
        "keepalive": max(5, min(120, int(cfg.get("keepalive") or 15))),   # honor a configured value (clamped 5..120s); 15 default
        "crypto": {"enabled": crypto_on, "psk": cfg.get("psk", ""), "cipher": cipher},
    }
    # Per-tunnel self-heal deadline (client): tightens the carrier's dead-detection window so this tunnel
    # heals faster than the default. 0/unset = default formula; the core clamps a set value to >=2×keepalive.
    _da = int(cfg.get("dead_after_secs") or 0)
    if _da:
        corecfg["dead_after_secs"] = max(10, min(300, _da))
    # Operator-tuned operational timings (self-heal / pool-health): pass the panel's `tuning` object
    # through to the core, which clamps every value. Keep it type-clean here (ints, and an int list for
    # the backoff schedule) so a malformed field can't reach the core config; the core defaults any
    # field we omit. Applies to both roles (idle/ping-loss are server-side too).
    _tn = _core_tuning(cfg.get("tuning"))
    if _tn:
        corecfg["tuning"] = _tn
    # TLS cover (HTTPS camouflage) — TCP only; carries an optional SNI to present.
    if bool(cfg.get("cover")) and transport == "tcp" and crypto_on:
        corecfg["cover"] = True
        sni = str(cfg.get("cover_sni") or "").strip()
        if sni:
            corecfg["cover_sni"] = sni
    # Datagram transports (udp/raw/flux) have no ws edge pool, but the CLIENT still writes a
    # precise self-heal event ring (stale-detect / recovery) to a status file we expose back to the
    # panel's system log — same file name the pool uses, so op_edge_status reads it unchanged. This
    # is `status_path` (NOT `ws_status_path`), so _is_ws_pool keeps telling a pool core apart from a
    # plain datagram core (only the pool has SIGHUP/SIGUSR handlers).
    if transport in ("udp", "raw", "flux") and str(cfg.get("role")) == "client":
        corecfg["status_path"] = os.path.join(CONFIG_DIR, "core-" + name + ".status")
    # peer_src_ips (raw/flux SERVER): the client's source pool. These carriers receive via a raw/
    # AF_PACKET socket that sees every host and pre-filter by the learned peer source, so a rotated
    # client source is otherwise dropped pre-crypto and never re-learned (the tunnel dies on a source
    # rotation until a rebuild). Handing the server the client's known sources lets a rotated-but-
    # expected source reach crypto and re-bind. udp/tcp bind per-source and re-learn on their own.
    if transport in ("raw", "flux") and str(cfg.get("role")) == "server":
        _psrc = [str(x).strip() for x in (cfg.get("peer_src_ips") or []) if is_ipv4(str(x).strip())]
        if _psrc:
            corecfg["peer_src_ips"] = _psrc
    if transport == "raw":
        corecfg["raw_profile"] = raw_profile
    if transport == "flux":
        # flux is a distinct transport (not a raw_profile): carrier, shape profile,
        # epoch length and a manual epoch offset are all it needs — both ends derive
        # the rotating shape from the PSK + clock (+ offset), no on-wire negotiation.
        corecfg["flux_carrier"] = flux_carrier
        corecfg["flux_rotate_secs"] = int(cfg.get("flux_rotate_secs") or 600)
        corecfg["flux_shape"] = str(cfg.get("flux_shape") or "random").lower()
        off = int(cfg.get("flux_epoch_offset") or 0)
        if off:
            corecfg["flux_epoch_offset"] = off
    if transport == "ws":
        # WebSocket carrier (CDN-frontable): Host/SNI, path, and whether the client
        # speaks wss (TLS to the CDN edge). The server stays plain — the CDN terminates TLS.
        if cfg.get("ws_host"):
            corecfg["ws_host"] = str(cfg["ws_host"])
        if cfg.get("ws_path"):
            corecfg["ws_path"] = str(cfg["ws_path"])
        # xhttp mode: carry the stream over a GET(down)+POST(up) HTTP request pair instead
        # of a WebSocket upgrade, so it passes a CDN/account that blocks WebSocket. Both
        # roles need the flag (server serves the xhttp endpoint, client dials it); the same
        # fronting fields (ws_host/ws_tls/ws_ech/ws_path) apply. Not combined with the pool.
        xhttp = bool(cfg.get("ws_xhttp"))
        if xhttp:
            corecfg["ws_xhttp"] = True
            # xhttp upstream style: "packet" (packet-up, default — many short POSTs, most
            # CDN-compatible), "stream" (stream-one, a single full-duplex request; needs HTTP/2,
            # hence ws_tls), or "grpc" (stream-one dressed as a real gRPC call so a CDN reaches the
            # origin over h2c and streams instead of buffering; also needs ws_tls). Forward for both
            # roles; the core server auto-detects the client's style but the client must be told.
            xmode = str(cfg.get("ws_xhttp_mode") or "").strip().lower()
            if xmode in ("packet", "stream", "grpc"):
                corecfg["ws_xhttp_mode"] = xmode
        # Only the CLIENT speaks wss (TLS to the CDN edge); the server stays plain — the CDN
        # terminates TLS and forwards the WebSocket to the origin. Never emit ws_tls server-side.
        if bool(cfg.get("ws_tls")) and cfg.get("role") == "client":
            corecfg["ws_tls"] = True
            # SNI fragmentation: split the wss ClientHello so the cleartext SNI crosses a TCP segment
            # boundary — a stateless SNI-blocklist DPI can't match the full hostname. Cheap complement
            # to ECH (which hides the SNI entirely). Applies to both single-edge and pool ws/xhttp.
            # split_pos is the byte offset into the ClientHello (0 = auto: middle of the hostname).
            if bool(cfg.get("sni_split")):
                corecfg["sni_split"] = True
                sp = int(cfg.get("split_pos") or 0)
                if sp:
                    corecfg["split_pos"] = max(0, min(1400, sp))
                # mode: "split" (in-order) or "disorder" (low-TTL head desyncs a reassembling DPI).
                mode = str(cfg.get("sni_mode") or "").strip().lower()
                if mode in ("disorder", "fake"):
                    corecfg["sni_mode"] = mode
                    st = int(cfg.get("split_ttl") or 0)
                    if st:
                        corecfg["split_ttl"] = max(0, min(255, st))
            # ECH: encrypt the SNI so an SNI-blocklisting censor can't see the real domain.
            # The panel fetches the base64 ECHConfigList from the domain's HTTPS record over
            # DoH (clean internet) and hands it to us; we just forward it to the core. Client
            # + wss only (it rides the TLS ClientHello). Empty = no ECH.
            ech = str(cfg.get("ws_ech") or "").strip()
            if ech:
                corecfg["ws_ech"] = ech
            # Edge pool: the panel sends clean edge-IP + SNI lists (each SNI with its own
            # ECH/path) plus the rotation settings. A non-empty pool overrides the single
            # ws_host/ws_ech/edge above — the core cycles (IP × SNI) and burns blocked ones,
            # writing its live state to a status file we expose back to the panel.
            ips = [str(x).strip() for x in (cfg.get("ws_edge_ips") or []) if str(x).strip()]
            snis = [s for s in (cfg.get("ws_edge_snis") or []) if isinstance(s, dict) and str(s.get("host") or "").strip()]
            if ips and snis:  # rotating pool — works for both the ws and xhttp carriers
                corecfg["ws_edge_ips"] = ips
                corecfg["ws_edge_snis"] = [{"host": str(s["host"]).strip(),
                                         "ech": str(s.get("ech") or "").strip(),
                                         "path": str(s.get("path") or "").strip()} for s in snis]
                _wrs = cfg.get("ws_rotate_secs")   # 0 = rotation OFF (failover-only); a truthiness `or 600` would wrongly force 600
                corecfg["ws_rotate_secs"] = 600 if _wrs is None else max(0, min(28800, int(_wrs)))
                corecfg["ws_auto_burn"] = bool(cfg.get("ws_auto_burn"))
                corecfg["ws_warm_standby"] = bool(cfg.get("ws_warm_standby"))  # make-before-break failover
                corecfg["ws_status_path"] = os.path.join(CONFIG_DIR, "core-" + name + ".status")
    # FEC (forward error correction): reconstructs lost carrier datagrams from parity so a
    # throttled/high-loss link stays usable. Datagram carriers only (udp/raw/flux) — on
    # tcp/ws it's wasted (TCP is already reliable), so it's only forwarded for those three.
    if transport in ("udp", "raw", "flux") and bool(cfg.get("fec")):
        corecfg["fec"] = True
        corecfg["fec_data"] = int(cfg.get("fec_data") or 10)
        corecfg["fec_parity"] = int(cfg.get("fec_parity") or 3)
    if bool(cfg.get("gso")):     # TUN segmentation offload — local throughput optimization
        corecfg["gso"] = True
    # IP spoofing (raw bip + crypto only): forge the outer source and/or the destination (a decoy).
    # The client puts the decoy in the header dst while still routing to the real server; the server
    # then receives those frames via AF_PACKET and answers AS the decoy, so it must be told the
    # client's real IP (remote_ip) to reply to — the forged source hides it from the wire.
    if transport == "raw" and raw_profile == "bip" and crypto_on:
        spoof_src = str(cfg.get("spoof_src") or "").strip()
        spoof_dst = str(cfg.get("spoof_dst") or "").strip()
        if cfg.get("role") == "client":
            if spoof_src:
                corecfg["spoof_src_ip"] = spoof_src
            if spoof_dst:
                corecfg["spoof_dst_ip"] = spoof_dst
        else:  # server
            if spoof_dst:
                corecfg["spoof_dst_ip"] = spoof_dst
            if spoof_src or spoof_dst:
                corecfg["real_peer_ip"] = cfg["remote_ip"]
    # Fake-packet desync (client): the core emits decoy packets to mis-sync a stateful DPI without
    # touching the real session. raw/flux forge whole IPv4 packets; tcp/ws INJECT decoy TCP segments
    # on the kernel connection's 4-tuple (AF_PACKET). Plain udp has no such hook. Decoys are separate
    # packets, not extra per-frame overhead, so they cost no MTU budget.
    if transport in ("raw", "flux", "tcp", "ws") and cfg.get("role") == "client" and bool(cfg.get("fake_desync")):
        corecfg["fake_desync"] = True
        corecfg["fake_ttl"] = max(1, min(255, int(cfg.get("fake_ttl") or 4)))
        corecfg["fake_count"] = max(1, min(64, int(cfg.get("fake_count") or 2)))
        mode = str(cfg.get("fake_mode") or "ttl").strip().lower()
        corecfg["fake_mode"] = mode if mode in ("ttl", "badsum", "both") else "ttl"
    # Destination rotation pool (client, direct transports udp/tcp/raw/flux): cycle the foreign node's
    # IPs and burn a blocked one. Build the pool with the primary remote_ip FIRST (so the pool's
    # starting endpoint matches the single `peer` the core also dials), dedup, then format per
    # transport: udp/tcp dial "ip:port" (every endpoint shares the tunnel's core port), raw/flux
    # address a bare IP (the core ignores any port there). A pool of >=2 overrides the single peer;
    # the core writes its live active/burned state to a dedicated file we expose via op_peer_status.
    if transport in ("udp", "tcp", "raw", "flux") and str(cfg.get("role")) == "client":
        prim = str(cfg.get("remote_ip") or "").strip()
        seen, ordered = set(), []
        for x in [prim] + [str(v) for v in (cfg.get("peer_ips") or [])]:
            ip = x.strip().split(":", 1)[0].strip()   # bare IPv4 (drop any accidental :port)
            if ip and ip not in seen:
                seen.add(ip)
                ordered.append(ip)
        if len(ordered) >= 2:
            corecfg["peer_ips"] = [f"{ip}:{port}" if transport in ("udp", "tcp") else ip for ip in ordered]
            corecfg["peer_rotate_secs"] = max(0, int(cfg.get("peer_rotate_secs") or 0))
            corecfg["peer_auto_burn"] = bool(cfg.get("peer_auto_burn"))
            corecfg["peer_status_path"] = os.path.join(CONFIG_DIR, "core-" + name + ".peerpool")
        # Source rotation pool (client): this node's OWN IPs to send FROM, cycled alongside peer_ips.
        # Prepend local_ip so the pool's start matches the client's default source; bare IPv4 for every
        # carrier (a source is never "ip:port"). A pool of >=2 activates source rotation in the core.
        sprim = str(cfg.get("local_ip") or "").strip()
        sseen, sord = set(), []
        for x in [sprim] + [str(v) for v in (cfg.get("src_ips") or [])]:
            ip = x.strip().split(":", 1)[0].strip()
            if ip and ip not in sseen:
                sseen.add(ip)
                sord.append(ip)
        if len(sord) >= 2:
            corecfg["src_ips"] = sord
            corecfg.setdefault("peer_rotate_secs", max(0, int(cfg.get("peer_rotate_secs") or 0)))
            corecfg.setdefault("peer_auto_burn", bool(cfg.get("peer_auto_burn")))
            # The source pool writes its own live state / pin cmd file so the panel can show and pin both
            # sides (destination = .peerpool, source = .srcpool).
            corecfg["src_status_path"] = os.path.join(CONFIG_DIR, "core-" + name + ".srcpool")
    if cfg.get("role") == "server":
        # Bind to THIS node's physical IP for the tunnel, not 0.0.0.0. With multiple IPs on the
        # host this is required for the raw transport: a raw (portless) socket bound to 0.0.0.0
        # replies from the primary IP, so a second tunnel on a secondary IP would send from the
        # wrong source and the client (which filters by peer IP) drops every reply. Binding to the
        # exact listen IP makes the reply source correct and also cleanly demuxes by destination IP.
        lip = cfg.get("local_ip") or "0.0.0.0"
        # EXCEPTION — under a destination rotation pool the client dials THIS server across several of
        # its selected IPs. Bind EACH one explicitly (the core opens one socket/listener per IP) instead
        # of 0.0.0.0, for two reasons: (1) a UDP reply then egresses from the exact IP the client dialed
        # — a single 0.0.0.0 socket would reply from the host's primary IP and the client, which filters
        # by peer IP, would drop it; (2) the server accepts only on the pool IPs, not every host IP.
        # listen stays the first IP as a friendly anchor; listen_ips drives the actual binds. (raw/flux
        # receive via AF_PACKET regardless of dest IP, so pool_listen is a no-op there.)
        pool_ips = [str(x).strip() for x in (cfg.get("listen_ips") or []) if str(x).strip()]
        if bool(cfg.get("pool_listen")) and transport in ("udp", "tcp") and pool_ips:
            corecfg["listen"] = f"{pool_ips[0]}:{port}"
            corecfg["listen_ips"] = [f"{ip}:{port}" for ip in pool_ips]
        else:
            corecfg["listen"] = f"{lip}:{port}"
    else:
        # The client dials the peer. For a ws link fronted through a CDN, edge_ip
        # overrides the dial target to the CDN edge (host or host:port) while ws_host
        # stays the fronting domain; the CDN routes on to the real origin. The core is
        # unaware — it just dials whatever peer it is given.
        dial, dport = cfg["remote_ip"], port
        edge = str(cfg.get("edge_ip") or "").strip()
        if transport == "ws" and edge:
            h, sep, p = edge.rpartition(":")
            if sep and p.isdigit():
                dial, dport = h, int(p)
            else:
                dial = edge
        corecfg["peer"] = f"{dial}:{dport}"
        # Pin the client's outbound source to THIS node's own IP (local_ip is validated to be a
        # local address in op_tunnel). On a host with several IPs the kernel would otherwise egress
        # from its primary IP; binding makes the peer/CDN see this node's registered IP. The core
        # applies it only for the TCP-family carriers (tcp/ws/xhttp) and ignores it otherwise.
        lip = str(cfg.get("local_ip") or "").strip()
        if lip:
            corecfg["bind_ip"] = lip
    # Single-edge ws/xhttp (not a pool): the CLIENT core writes the same self-heal event ring the
    # datagram carriers do — e.g. an in-band ECH self-heal — to a status file we expose to the panel.
    # Use status_path (NOT ws_status_path) so _is_ws_pool keeps treating it as a non-pool core (a
    # single-edge ws core installs no SIGHUP/SIGUSR handlers, so a pool-only signal would kill it).
    if (transport == "ws" and str(cfg.get("role")) == "client"
            and "ws_status_path" not in corecfg):
        corecfg["status_path"] = os.path.join(CONFIG_DIR, "core-" + name + ".status")
    return corecfg


def _core_unit(name):
    return "tnl-cor-" + name


def _core_status_paths(name):
    """The core's live status files for tunnel `name`: the self-heal/ws-pool status and its select-edge
    command sidecar, plus the direct-transport destination and source pool status files and their own pin
    command sidecars. Callers only iterate to clean them up, so listing all of them here means a rebuild/
    teardown never leaves stale pool state — or a leftover pin command — behind."""
    base = os.path.join(CONFIG_DIR, "core-" + name + ".status")
    peer = os.path.join(CONFIG_DIR, "core-" + name + ".peerpool")
    src = os.path.join(CONFIG_DIR, "core-" + name + ".srcpool")
    return base, base + ".cmd", peer, peer + ".cmd", src, src + ".cmd"


def _is_ws_pool(name):
    """True if the running core for `name` is a ws edge-pool client — the ONLY core that installs
    SIGHUP/SIGUSR handlers. Signaling any other core falls through to Go's default signal
    disposition and TERMINATES the tunnel, so pool-only ops (probe-now / rotate) must guard on this."""
    try:
        with open(os.path.join(CONFIG_DIR, "core-" + name + ".json")) as f:
            cc = json.load(f)
    except (OSError, ValueError):
        return False
    return bool(cc.get("ws_status_path") or cc.get("ws_edge_ips"))


def _is_peer_pool(name):
    """True if the running core for `name` is a direct-transport pool client (a destination and/or
    source rotation pool). Such a core installs a SIGHUP handler (probe-now) exactly like the ws pool,
    so pool-only ops must guard on this — signaling a plain core would fall through to Go's default
    disposition and TERMINATE the tunnel."""
    try:
        with open(os.path.join(CONFIG_DIR, "core-" + name + ".json")) as f:
            cc = json.load(f)
    except (OSError, ValueError):
        return False
    return bool(cc.get("peer_status_path") or cc.get("src_status_path"))


def build_core(cfg):
    """Fetch/verify the core binary, write its per-tunnel config, and (re)launch it under a transient
    systemd unit with Restart=always. Then wait for the TUN to appear so op_tunnel's verify sees it."""
    name = cfg["name"]
    _ensure_core()
    # Drop any stale status + select-edge sidecar from a previous core with this name, so a rebuild
    # never shows a stale pool state or replays a leftover "pin this edge" command on first tick.
    for p in _core_status_paths(name):
        try:
            os.remove(p)
        except OSError:
            pass
    corecfg = _core_config(cfg)
    path = os.path.join(CONFIG_DIR, "core-" + name + ".json")
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        json.dump(corecfg, f, indent=2)
    os.chmod(tmp, 0o600)          # holds the psk -> keep it private like node.conf
    os.replace(tmp, path)
    unit = _core_unit(name)
    run(["systemctl", "stop", unit])
    run(["systemctl", "reset-failed", unit])
    run(["systemd-run", "--unit", unit, "--collect",
         "-p", "Restart=always", "-p", "RestartSec=3",
         CORE_BIN, "--config", path])
    for _ in range(80):          # up to 8s: must exceed RestartSec=3 so one restart cycle
        if run(["ip", "link", "show", name])[0] == 0:   # (a slow/first-launch core) isn't misread as failure
            break
        time.sleep(0.1)


def _core_teardown(cfg):
    name = cfg.get("name", "")
    if not NAME_RE.match(name):
        return
    unit = _core_unit(name)
    run(["systemctl", "stop", unit])       # kills the core -> its non-persistent TUN disappears
    run(["systemctl", "reset-failed", unit])
    try:
        os.remove(os.path.join(CONFIG_DIR, "core-" + name + ".json"))
    except OSError:
        pass
    for p in _core_status_paths(name):   # don't leave a dead tunnel's pool state as "live"
        try:
            os.remove(p)
        except OSError:
            pass


def _set_link_state(cfg, enabled):
    """Bring a tunnel's data path up or down WITHOUT tearing the config down. For a core tunnel the
    TUN is owned by the core process (and Restart=always would fight an `ip link down`), so we stop the
    unit to disable and (re)build it to enable. Plain kernel tunnels just toggle the netdev's admin state."""
    name = cfg.get("name", "")
    if not NAME_RE.match(name):
        return
    if cfg.get("type") == "core":
        if enabled:
            build_core(cfg)
        else:
            unit = _core_unit(name)
            run(["systemctl", "stop", unit])
            run(["systemctl", "reset-failed", unit])
            for p in _core_status_paths(name):   # a stopped core has no live pool state -> don't leave stale
                try:                              # status the panel would render as "live" (and never a leftover pin cmd)
                    os.remove(p)
                except OSError:
                    pass
    else:
        run(["ip", "link", "set", name, "up" if enabled else "down"])


def _pf_match(cfg, iface, proto, lp):
    """PREROUTING match args for this forward; a listen_ip pins the rule to ONE local IP (multi-IP hosts)."""
    m = ["-i", iface, "-p", proto, "--dport", lp]
    lip = cfg.get("listen_ip") or ""
    if is_ipv4(lip):
        m += ["-d", lip]
    return m


def _pf_acct_rules(cfg):
    """Two per-forward byte-accounting rules for the PFACCT mangle chain: one for each conntrack
    direction, keyed on the connection's ORIGINAL destination (listen_ip:listen_port). Keying on the
    original tuple — not the rotating DNAT target — is what lets the counters survive rotation. The
    'in' rule counts client->listen bytes (rx/down), 'out' counts the reply back to the client (tx/up)."""
    lp, nm = str(cfg.get("listen_port", "")), cfg.get("name", "")
    if not (lp.isdigit() and NAME_RE.match(nm)):
        return []
    scope = []
    iface = cfg.get("iface") or ""
    if IFACE_RE.match(iface):   # scope to the listen iface like the DNAT does, so two same-port forwards on
        scope = ["-i", iface]   # different ifaces don't collide (shared -j RETURN) or count each other's traffic
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


def _pf_acct_build(cfg):
    """(Re)ensure this forward's accounting rules exist — idempotent, so the per-rotation build_portfw
    call never resets the counters. Rules live in a dedicated PFACCT chain hung off mangle PREROUTING."""
    run(["iptables", "-t", "mangle", "-N", "PFACCT"])  # create once; errors harmlessly if it exists
    rc, _, _ = run(["iptables", "-t", "mangle", "-C", "PREROUTING", "-j", "PFACCT"])
    if rc != 0:
        run(["iptables", "-t", "mangle", "-A", "PREROUTING", "-j", "PFACCT"])
    for r in _pf_acct_rules(cfg):
        rc, _, _ = run(["iptables", "-t", "mangle", "-C", "PFACCT"] + r)
        if rc != 0:
            run(["iptables", "-t", "mangle", "-A", "PFACCT"] + r)


def _pf_acct_teardown(cfg):
    for r in _pf_acct_rules(cfg):
        for _ in range(64):
            rc, _, _ = run(["iptables", "-t", "mangle", "-C", "PFACCT"] + r)
            if rc != 0:
                break
            run(["iptables", "-t", "mangle", "-D", "PFACCT"] + r)


def _read_pf_net(cfgs):
    """{portfw_name: [rx_bytes, tx_bytes]} from the PFACCT chain's rule counters (cumulative, both
    directions). Parsed from `iptables-save -c` output: each rule is prefixed with [packets:bytes]."""
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
    for proto in ("tcp", "udp"):   # forward BOTH protocols — VPN endpoints (WireGuard/OpenVPN-UDP) are UDP
        match = _pf_match(cfg, iface, proto, lp)
        for ip in ips:  # flush every candidate rule first
            for _ in range(64):
                rc, _, _ = run(["iptables", "-t", "nat", "-C", "PREROUTING"] + match
                               + ["-j", "DNAT", "--to-destination", f"{ip}:{dp}"])
                if rc != 0:
                    break
                run(["iptables", "-t", "nat", "-D", "PREROUTING"] + match
                    + ["-j", "DNAT", "--to-destination", f"{ip}:{dp}"])
        run(["iptables", "-t", "nat", "-A", "PREROUTING"] + match
            + ["-j", "DNAT", "--to-destination", f"{active}:{dp}"])
    for proto in ("tcp", "udp"):   # SNAT ONLY the forwarded flow (dst+port), not all egress on the iface
        for ip in ips:             # flush every candidate first so a rotation leaves no stale masq rule
            for _ in range(64):
                rc, _, _ = run(["iptables", "-t", "nat", "-C", "POSTROUTING", "-d", ip, "-p", proto,
                               "--dport", dp, "-o", iface, "-j", "MASQUERADE"])
                if rc != 0:
                    break
                run(["iptables", "-t", "nat", "-D", "POSTROUTING", "-d", ip, "-p", proto,
                    "--dport", dp, "-o", iface, "-j", "MASQUERADE"])
        run(["iptables", "-t", "nat", "-A", "POSTROUTING", "-d", active, "-p", proto,
            "--dport", dp, "-o", iface, "-j", "MASQUERADE"])
    for _ in range(16):   # remove any legacy broad `-o iface MASQUERADE` this forward may have left (now per-flow)
        rc, _, _ = run(["iptables", "-t", "nat", "-C", "POSTROUTING", "-o", iface, "-j", "MASQUERADE"])
        if rc != 0:
            break
        run(["iptables", "-t", "nat", "-D", "POSTROUTING", "-o", iface, "-j", "MASQUERADE"])
    _pf_acct_build(cfg)   # idempotent byte counters (rx/tx) that survive rotation


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
    # A tunnel the operator turned OFF is still built (so edit/rebuild/boot reconstruct it correctly)
    # but its data path is left DOWN until re-enabled. portfw has no admin on/off.
    if t != "portfw" and not cfg.get("enabled", True):
        _set_link_state(cfg, False)


def teardown_config(cfg):
    ttype, name, tid = cfg.get("type"), cfg.get("name", ""), str(cfg.get("id", ""))
    if not NAME_RE.match(name):
        return
    if ttype in ("vxlan", "gre", "sit", "ipip"):
        run(["ip", "link", "del", name])
        if ttype in ("vxlan", "gre"):
            _purge_ovs(cfg)   # also clear a pre-migration OVS bridge/veth, if this node still has one
    elif ttype == "l2tpv3":
        if tid.isdigit():
            run(["ip", "l2tp", "del", "session", "tunnel_id", tid, "session_id", tid])
            run(["ip", "l2tp", "del", "tunnel", "tunnel_id", tid])
        run(["ip", "link", "del", name])
    elif ttype == "fou":
        run(["ip", "link", "del", name])
        port = _fou_port(cfg)
        # drop the FOU decap listener only if no OTHER fou tunnel still needs this port (compare by name —
        # raw_configs() reloads from disk, so identity checks fail; the config file may still exist here)
        if not any(c.get("name") != name and c.get("type") == "fou" and _fou_port(c) == port for c in raw_configs()):
            run(["ip", "fou", "del", "port", str(port), "ipproto", "4"])
    elif ttype == "ipsec":
        _ipsec_clear(cfg)
    elif ttype == "core":
        _core_teardown(cfg)
    elif ttype == "portfw":
        _pf_acct_teardown(cfg)   # drop the byte counters (keyed on name/listen_port, independent of iface)
        iface, lp, dp = cfg.get("iface", ""), str(cfg.get("listen_port", "")), str(cfg.get("dst_port", ""))
        if IFACE_RE.match(iface) and lp.isdigit() and dp.isdigit():
            for proto in ("tcp", "udp"):
                match = _pf_match(cfg, iface, proto, lp)  # same match the rule was built with (incl. listen_ip)
                for ip in cfg.get("dst_ips", []):
                    if not is_ipv4(ip):
                        continue
                    for _ in range(64):
                        rc, _, _ = run(["iptables", "-t", "nat", "-C", "PREROUTING"] + match
                                       + ["-j", "DNAT", "--to-destination", f"{ip}:{dp}"])
                        if rc != 0:
                            break
                        run(["iptables", "-t", "nat", "-D", "PREROUTING"] + match
                            + ["-j", "DNAT", "--to-destination", f"{ip}:{dp}"])
            for proto in ("tcp", "udp"):   # remove the per-flow MASQUERADE rules this forward installed
                for ip in cfg.get("dst_ips", []):   # (each is scoped to its own dst+port, so no cross-forward guard needed)
                    if not is_ipv4(ip):
                        continue
                    for _ in range(64):
                        rc, _, _ = run(["iptables", "-t", "nat", "-C", "POSTROUTING", "-d", ip, "-p", proto,
                                       "--dport", dp, "-o", iface, "-j", "MASQUERADE"])
                        if rc != 0:
                            break
                        run(["iptables", "-t", "nat", "-D", "POSTROUTING", "-d", ip, "-p", proto,
                            "--dport", dp, "-o", iface, "-j", "MASQUERADE"])


def apply_all():
    """Boot/reconcile: self-heal each tunnel's local_ip, then (re)build every config."""
    rc, rout, _ = run(["ip", "-4", "route"])
    has_default = any(l.startswith("default") for l in rout.splitlines())
    pip = primary_ip() if has_default else None  # don't self-heal to a guessed IP when routing is down
    locals_now = local_ips_flat()
    for cfg in raw_configs():
        if cfg.get("type") not in ("portfw", None):   # every node<->node tunnel carries a local_ip to self-heal
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
                if _restart_pending.is_set():   # don't start a rotate build in the restart shutdown window
                    continue
                rotate_once()
        except Exception as e:
            logline(f"rotate loop: {e}")

# ----------------------------------------------------------------------------- health / stats

def peer_of(tunnel_ip, ttype):
    self_ip = tunnel_ip.split("/")[0]
    if ttype == "sit":
        base = self_ip.rpartition(":")[0]
        return base + ":2" if self_ip.rsplit(":", 1)[1] == "1" else base + ":1"
    base, last = self_ip.rsplit(".", 1)
    return f"{base}.2" if last == "1" else f"{base}.1"


def health_of(cfg, thorough=False):
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
            # Check the SAME rules build_portfw installs: BOTH protocols, and the -d listen_ip
            # pin (via _pf_match). Hand-rolling the match with just "-p tcp" and no -d meant a
            # listen_ip-pinned forward's -C never matched, so it was reported DOWN forever even
            # while it carried traffic (and the udp DNAT was never verified at all).
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
                reachable = True   # host answered with RST -> IP is reachable, the port just isn't TCP-listening
            except Exception:      # (normal for a UDP forward: WireGuard/OpenVPN-UDP). timeout/other -> unreachable
                reachable = False
        return {"active": active, "rule": rule, "reachable": reachable, "up": rule}
    up = False
    with _apply_lock:  # serialize with a rebuild (mutations hold this) so we don't read the brief
        rc, _, _ = run(["ip", "link", "show", name])   # mid-teardown gap as a transient false 'down'
    if rc == 0:
        up = True
    ping = None
    peer = rtt = loss = None
    tip = cfg.get("tunnel_ip", "")
    if tip and tip != "N/A":
        peer = peer_of(tip, ttype)
        cnt, wait = ("4", "2") if thorough else ("1", "1")  # on-demand check pings harder for accuracy
        cmd = (["ping", "-6", "-c", cnt, "-W", wait, peer] if ttype == "sit"
               else ["ping", "-c", cnt, "-W", wait, peer])
        rc3, out3, _ = run(cmd, timeout=14)
        ml = re.search(r"(\d+(?:\.\d+)?)% packet loss", out3)
        if ml:
            loss = float(ml.group(1))
        mr = re.search(r"=\s*[\d.]+/([\d.]+)/", out3)  # rtt min/avg/max/mdev = a/b/c/d ms -> avg
        if mr:
            rtt = float(mr.group(1))
        ping = (loss < 100) if loss is not None else (rc3 == 0)
    return {"up": up, "peer_ping": ping, "peer": peer, "rtt_ms": rtt, "loss_pct": loss}


def _cpu_snap():
    with open("/proc/stat") as f:
        v = [int(x) for x in f.readline().split()[1:]]
    idle = v[3] + (v[4] if len(v) > 4 else 0)  # idle + iowait
    return sum(v), idle


def _cpu_pct():
    """Live CPU utilisation over a short 100ms window (stateless, so concurrent callers never clash)."""
    t1, i1 = _cpu_snap()
    time.sleep(0.1)
    t2, i2 = _cpu_snap()
    dt = t2 - t1
    return round((1 - (i2 - i1) / dt) * 100, 1) if dt > 0 else 0.0


def _read_os():
    """Human OS name from /etc/os-release (PRETTY_NAME) — read live like the other stats."""
    with open("/etc/os-release") as f:
        for line in f:
            if line.startswith("PRETTY_NAME="):
                return line.split("=", 1)[1].strip().strip('"')
    return None


def _proc_net_dev():
    """{ifname: [rx_bytes, tx_bytes]} for every interface, from ONE read of /proc/net/dev."""
    out = {}
    with open("/proc/net/dev") as f:
        for line in f:
            if ":" not in line:
                continue
            name, rest = line.split(":", 1)
            cols = rest.split()
            try:
                out[name.strip()] = [int(cols[0]), int(cols[8])]  # rx_bytes, tx_bytes
            except (IndexError, ValueError):
                continue
    return out


def _read_net(cfgs):
    """Per-tunnel + whole-node RX/TX byte counters. Every tunnel is a single kernel netdev named
    after its config (the OpenvSwitch/veth data path was removed). Keyed by config name; portfw excluded."""
    raw = _proc_net_dev()
    net = {}
    for c in cfgs:
        t, nm = c.get("type"), c.get("name")
        if t == "portfw" or not nm:
            continue
        v = raw.get(nm)   # every tunnel is now its own netdev (named after the config); counters live there
        if v:
            net[nm] = v
    # whole-node throughput = sum over ALL physical NICs, not the momentary default-route iface: a
    # default-route flap must not make the central subtract two unrelated netdev counters (phantom spike).
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
        avail = s.f_bavail * s.f_frsize                 # free space for an unprivileged user (df's Avail)
        used = (s.f_blocks - s.f_bfree) * s.f_frsize    # df's Used — excludes the root-reserved blocks
        st["disk_total_mb"] = total // (1024 * 1024)
        st["disk_used_mb"] = used // (1024 * 1024)
        st["disk_pct"] = round(used / (used + avail) * 100, 1) if (used + avail) else 0.0  # df's Use%
    except Exception:
        pass
    try:
        st["cpu_pct"] = _cpu_pct()
    except Exception:
        pass
    return st

# ----------------------------------------------------------------------------- health cache
# A background thread keeps a health snapshot so op_list is O(1) even on a hub node with hundreds
# of tunnels — the slow peer-pings / port-connects never happen on the central's request path.

HEALTH_WORKERS = 64   # sized so even a hub node with hundreds of tunnels sweeps within the deadline
HEALTH_DEADLINE = 12  # a sweep never blocks past this; slow probes keep their last-known value
_health_cache = {}
_health_lock = threading.Lock()


def health_refresh_once(ex):
    cfgs = raw_configs()
    if not cfgs:
        with _health_lock:
            _health_cache.clear()
        return
    futs = {ex.submit(health_of, c): c["name"] for c in cfgs}
    done, _ = futures_wait(set(futs), timeout=HEALTH_DEADLINE)
    with _health_lock:
        prev = dict(_health_cache)
        newc = {}
        for f, name in futs.items():
            if f in done:
                try:
                    newc[name] = f.result()
                except Exception:
                    newc[name] = prev.get(name, {"up": None})
            else:
                newc[name] = prev.get(name, {"up": None})  # probe too slow this round: keep last-known
        _health_cache.clear()
        _health_cache.update(newc)


def health_loop():
    ex = ThreadPoolExecutor(max_workers=HEALTH_WORKERS)  # persistent; stragglers can't block the loop
    while True:
        try:
            health_refresh_once(ex)
        except Exception as e:
            logline(f"health loop: {e}")
        time.sleep(8)

# ----------------------------------------------------------------------------- API ops

def _require(d, keys):
    for k in keys:
        if k not in d or d[k] in (None, ""):
            raise ValueError(f"missing field: {k}")


def _self_sha():
    """sha256 of the on-disk agent this process is running — computed once at startup."""
    try:
        with open(INSTALLED, "rb") as f:
            return hashlib.sha256(f.read()).hexdigest()
    except OSError:
        return ""


_SELF_SHA = _self_sha()


# ----------------------------------------------------------------------------- central check-in
# The panel reaches us at host:port (from its registry). If our public IP changes, the panel can no
# longer find us — so we phone home. We learn the panel's callback from its INCOMING requests (it
# stamps X-Central-Port; the source IP is where it reached us from). Because our check-in POSTs the
# node's bearer token, we must NOT hand that callback to just any authenticated caller: the source IP
# is bound to the panel — pinned on first contact (persisted to node.conf) or set explicitly via
# `central_allow` — so a stolen/shared token replayed from another host cannot redirect our token.
# When our IP set changes we POST /api/checkin so the panel can fix our host and heal the tunnels.

def _ip_in_allow(ip, allow):
    """True if ip matches any host/CIDR in `allow` (a str list or a comma/space-separated string)."""
    if isinstance(allow, str):
        allow = re.split(r"[,\s]+", allow.strip())
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    for entry in allow or []:
        entry = str(entry).strip()
        if not entry:
            continue
        try:
            if "/" in entry:
                if a in ipaddress.ip_network(entry, strict=False):
                    return True
            elif a == ipaddress.ip_address(entry):
                return True
        except ValueError:
            continue
    return False


def _central_ip_ok(ip):
    """Gate which source IP may become our check-in callback. An explicit `central_allow`
    (host/CIDR list) in node.conf wins; otherwise the panel IP is pinned on first contact and
    persisted, so a later token-bearing request from a DIFFERENT host cannot hijack the callback
    and exfiltrate our token."""
    # Fast, LOCK-FREE read path — runs for EVERY request (incl. read-only ping/list). Only the
    # rare first-contact TOFU write needs _apply_lock; never take it on the steady-state path,
    # or a slow core build (holding _apply_lock ~8-16s) would make every health ping block and
    # the panel read the node as down mid-build.
    try:
        conf = load_conf()
    except Exception:
        return False
    allow = conf.get("central_allow")
    if allow:
        return _ip_in_allow(ip, allow)
    pinned = conf.get("central_ip")
    if pinned:
        return ip == pinned
    # No pin yet: a persist IS required. Take _apply_lock only now and RE-CHECK under it (a
    # concurrent request may have pinned meanwhile) so we can't lose a write / clobber a peer's.
    with _apply_lock:
        try:
            conf = load_conf()
        except Exception:
            return False
        allow = conf.get("central_allow")
        if allow:
            return _ip_in_allow(ip, allow)
        pinned = conf.get("central_ip")
        if pinned:
            return ip == pinned
        try:                   # trust-on-first-use: remember the first panel IP we ever learn
            conf["central_ip"] = ip
            save_conf(conf)
        except Exception:
            pass
        return True


def note_central(ip, port):
    global _central_cb
    try:
        p = int(port)
    except (TypeError, ValueError):
        return
    if not (1 <= p <= 65535):  # X-Central-Port is fully attacker-controlled — bound it
        return
    # _central_ip_ok is lock-free on the common read path and takes _apply_lock ITSELF only for the
    # rare first-contact TOFU write (re-checking under the lock to stay race-safe). Don't wrap it here,
    # or every request — including read-only pings — would serialize behind a long core build.
    if not _central_ip_ok(ip):
        return
    with _central_cb_lock:
        _central_cb = (ip, p)


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
    body = json.dumps({"token": conf.get("token", ""), "ips": all_ips(),
                       "hostname": socket.gethostname()}).encode()
    url = f"http://{cb[0]}:{cb[1]}/api/checkin"
    req = urllib.request.Request(url, data=body, method="POST",
                                 headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=8) as r:
            return bool(json.loads(r.read().decode()).get("ok"))
    except Exception:
        return False


def checkin_loop():
    """Watch our own IPs; when the set changes (or was never reported), keep phoning home until acked."""
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
        net = _read_net(cfgs)   # per-tunnel + node byte counters (skipped if unreadable — never fails ping)
        for k, v in _read_pf_net(cfgs).items():   # per-portfw counters, namespaced so they never collide
            net["pf:" + k] = v
        stats["net"] = net
    except Exception:
        pass
    return {"ok": True, "agent": "tnl-node", "version": 26, "ready": True,
            "hostname": socket.gethostname(), "ips": all_ips(), "sha256": _SELF_SHA,
            "tunnels": len([c for c in cfgs if c.get("type") != "portfw"]),
            "portfw": len([c for c in cfgs if c.get("type") == "portfw"]),
            "core_ver": _core_ref(), "core_sha": _installed_core_sha()[:12], "arch": _core_arch(),
            "stats": stats}


def op_list(d):
    cfgs = public_configs()  # O(1): configs are read fresh, health comes from the background snapshot
    with _health_lock:
        hc = dict(_health_cache)
    # For a direct-transport IP-rotation client, surface the CURRENTLY-ACTIVE pool endpoint per tunnel
    # (destination + source), so the panel's fleet view shows the live IP the tunnel is really on at load
    # time — without a separate per-tunnel status call. Only pooled tunnels have these files; the rest are
    # absent (empty), so this is a cheap best-effort read of a couple of small files per config.
    pools = {}
    for c in cfgs:
        nm = c.get("name") or ""
        if not nm:
            continue
        dst = _read_peer_pool(nm, ".peerpool")["active"]
        src = _read_peer_pool(nm, ".srcpool")["active"]
        if dst or src:
            pools[nm] = {"dst": dst, "src": src}
    return {"configs": cfgs, "health": {c["name"]: hc.get(c["name"], {"up": None}) for c in cfgs}, "pools": pools}


def op_tunnel(d):
    """Create ONE side of a node<->node tunnel (central calls this on both nodes)."""
    _require(d, ["type", "self_ip", "peer_ip", "subnet"])
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
    if not 1 <= tid <= 254:
        raise ValueError("id out of range (1-254)")
    iface = d.get("iface") or iface_for_ip(self_ip)
    if not iface or not IFACE_RE.match(iface):
        raise ValueError("no local interface for that IP")
    name = d.get("name") or unique_name(ttype, tid)
    if not name or not NAME_RE.match(name):
        raise ValueError("bad name")
    tunnel_ip = derive_tunnel_ip(ttype, self_ip, peer_ip, subnet)
    obj = {"name": name, "type": ttype, "id": tid, "iface": iface,
           "remote_ip": peer_ip, "tunnel_ip": tunnel_ip, "local_ip": self_ip}
    _prev = read_config(name)   # preserve the operator's on/off across a rebuild that doesn't restate it
    obj["enabled"] = _as_bool(d.get("enabled", (_prev or {}).get("enabled", True)))
    if ttype == "core" and d.get("keepalive") not in (None, ""):   # optional; whitelist so a set value survives (else _core_config falls back to 15)
        obj["keepalive"] = max(5, min(120, int(d["keepalive"])))
    # dead_after_secs (core, optional): per-tunnel self-heal deadline. Whitelist so a set value survives;
    # 0/unset leaves the core's default formula. Store within the same 10..300 range the core validates.
    if ttype == "core" and d.get("dead_after_secs") not in (None, ""):
        _da = int(d["dead_after_secs"])
        obj["dead_after_secs"] = 0 if _da <= 0 else max(10, min(300, _da))
    if ttype in ("l2tpv3", "fou", "core", "vxlan"):   # optional UDP port; l2tp/fou/core blank->from id, vxlan blank->4789
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
        if transport not in ("udp", "tcp", "raw", "flux", "ws"):
            raise ValueError("bad core transport")
        obj["transport"] = transport
        if transport == "ws":         # WebSocket carrier (CDN-frontable): persist Host/path/TLS
            wh = str(d.get("ws_host") or "").strip()
            if wh:
                if not re.match(r"^[A-Za-z0-9.-]{1,253}$", wh):
                    raise ValueError("bad ws_host")
                obj["ws_host"] = wh
            wp = str(d.get("ws_path") or "").strip()
            if wp:
                if len(wp) > 1024 or not re.match(r"^/[\x21-\x7e]*$", wp):   # start with /, printable, no CR/LF/space/ctrl
                    raise ValueError("bad ws_path")
                obj["ws_path"] = wp
            # xhttp mode (GET-down + POST-up instead of a WebSocket upgrade) — passes a CDN
            # that blocks WebSocket. Independent of ws_tls (server side is plain HTTP either
            # way); whitelist it here so it survives persistence (dropping = silently reverts
            # to a plain WebSocket, which the WS-block rule then kills).
            if _as_bool(d.get("ws_xhttp")):
                obj["ws_xhttp"] = True
                # xhttp upstream style: packet-up (default), stream-one, or grpc. Whitelist it so
                # the choice survives persistence (dropping = silently reverts to packet-up).
                xm = str(d.get("ws_xhttp_mode") or "").strip().lower()
                if xm in ("packet", "stream", "grpc"):
                    obj["ws_xhttp_mode"] = xm
            if _as_bool(d.get("ws_tls")):
                obj["ws_tls"] = True
                # The core rejects ws_tls on a single-edge client without ws_host (it is the TLS
                # SNI / fronting domain); catch it here with a precise error instead of a late
                # "interface not created". A rotating edge POOL carries its own per-SNI hosts, so
                # ws_host is NOT required in that mode — only demand it for the single edge.
                _has_pool = bool(d.get("ws_edge_ips")) and bool(d.get("ws_edge_snis"))
                if role == "client" and not obj.get("ws_host") and not _has_pool:
                    raise ValueError("ws_tls به ws_host نیاز دارد (SNI/دامنهٔ فرانت‌کننده)")
                # ECH: base64 ECHConfigList that hides the SNI. The panel fetches it from the
                # domain's HTTPS record over DoH and sends it here; whitelist it so it survives
                # (forgetting = silently dropped, and the SNI leaks). Client + wss only.
                ech = str(d.get("ws_ech") or "").strip()
                if ech:
                    if len(ech) > 4096 or not re.match(r"^[A-Za-z0-9+/=]+$", ech):
                        raise ValueError("bad ws_ech")
                    obj["ws_ech"] = ech
                # SNI fragmentation: split the wss ClientHello so the cleartext SNI crosses a TCP
                # segment boundary (a cheap complement to ECH). Whitelist it so it survives
                # persistence — forgetting it means _core_config never sees the key and the split
                # silently never happens. split_pos is the byte offset (0 = auto: middle of the host).
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
                # Edge pool: clean IP + SNI lists (each SNI {host,ech,path}) + rotation. Whitelist
                # them so the rotation config survives (dropping = the pool silently collapses to
                # the single edge). Validate every entry — these reach the core config verbatim.
                pips = [str(x).strip() for x in (d.get("ws_edge_ips") or []) if str(x).strip()]
                psnis = d.get("ws_edge_snis") or []
                if pips or psnis:
                    if len(pips) > 64 or len(psnis) > 64:
                        raise ValueError("ws edge pool too large")
                    for ip in pips:
                        h = ip.rpartition(":")[0] or ip
                        if not re.match(r"^[A-Za-z0-9.\-]{1,253}$", h):
                            raise ValueError("bad ws_edge_ip")
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
                        _rs = d.get("ws_rotate_secs")   # 0 = rotation off (failover-only) — a truthiness `or 600` would wrongly force 600
                        obj["ws_rotate_secs"] = max(0, min(28800, int(_rs))) if _rs is not None else 600
                        obj["ws_auto_burn"] = _as_bool(d.get("ws_auto_burn"))
                        obj["ws_warm_standby"] = _as_bool(d.get("ws_warm_standby"))  # make-before-break failover
            edge = str(d.get("edge_ip") or "").strip()   # CDN edge the client dials instead of the origin
            if edge:
                host = edge.rpartition(":")[0] or edge
                if not re.match(r"^[A-Za-z0-9.\-]{1,253}$", host):
                    raise ValueError("bad edge_ip")
                obj["edge_ip"] = edge
        if transport == "raw":        # raw-IP carrier: which protocol the sealed frame is wrapped in
            profile = str(d.get("raw_profile") or "bip").strip().lower()
            if profile not in ("bip", "ipip", "gre", "icmp", "udp", "tcp"):
                raise ValueError("bad raw_profile")
            obj["raw_profile"] = profile
        if transport == "flux":       # polymorphic moving-target carrier: persist carrier/shape/epoch
            carrier = str(d.get("flux_carrier") or "udp").strip().lower()
            if carrier not in ("udp", "raw", "stun"):
                raise ValueError("bad flux_carrier")
            obj["flux_carrier"] = carrier
            rot = int(d.get("flux_rotate_secs") or 600)
            if rot < 10 or rot > 86400:
                raise ValueError("flux_rotate_secs out of range (10..86400)")
            obj["flux_rotate_secs"] = rot
            shape = str(d.get("flux_shape") or "random").strip().lower()
            if shape not in ("random", "quic", "video", "webrtc"):
                raise ValueError("bad flux_shape")
            obj["flux_shape"] = shape
            obj["flux_epoch_offset"] = int(d.get("flux_epoch_offset") or 0)  # manual "rotate now" bump
        # FEC (forward error correction) — repairs lost carrier datagrams from parity, on the
        # datagram carriers only (udp/raw/flux). Persisting these in the whitelist is mandatory:
        # an un-whitelisted key is silently dropped from the stored config and never reaches the core.
        if transport in ("udp", "raw", "flux") and _as_bool(d.get("fec")):
            obj["fec"] = True
            fd = int(d.get("fec_data") or 10)
            fp = int(d.get("fec_parity") or 3)
            if fd < 1 or fp < 1 or fd + fp > 255:
                raise ValueError("fec_data/fec_parity out of range (>=1, sum<=255)")
            obj["fec_data"] = fd
            obj["fec_parity"] = fp
        # Destination rotation pool (client, direct transports udp/tcp/raw/flux): the panel sends the
        # foreign node's IPs to cycle through so a single blocked server IP doesn't kill the tunnel —
        # the direct-transport analogue of the ws edge pool. Whitelisting these is mandatory (an
        # un-whitelisted key is silently dropped and never reaches the core). Each must be a plain
        # IPv4: the pool swaps the dial destination with no DNS step, and raw/flux are IPv4-only.
        # Meaningless on ws (its own edge pool) or a server (it listens), so restrict to a direct
        # client. Stored as bare IPs; _core_config appends the port for udp/tcp and leaves raw/flux bare.
        if transport in ("udp", "tcp", "raw", "flux") and role == "client":
            def _clean_pool(key):
                out = [str(x).strip() for x in (d.get(key) or []) if str(x).strip()]
                if len(out) > 64:
                    raise ValueError(key + " pool too large (>64)")
                for ip in out:
                    if not is_ipv4(ip):
                        raise ValueError("bad " + key + " entry (must be an IPv4 address)")
                return out
            pips = _clean_pool("peer_ips")   # destination pool: the SERVER's IPs the client dials
            sips = _clean_pool("src_ips")     # source pool: this client node's OWN IPs to send FROM
            if pips or sips:
                if pips:
                    obj["peer_ips"] = pips
                if sips:
                    obj["src_ips"] = sips
                _prs = d.get("peer_rotate_secs")   # 0 = failover-only; a truthiness `or N` would wrongly force N
                obj["peer_rotate_secs"] = max(0, min(86400, int(_prs))) if _prs is not None else 0
                obj["peer_auto_burn"] = _as_bool(d.get("peer_auto_burn"))
        # pool_listen (server side, udp/tcp): the client rotates the destination across THIS server's
        # selected IPs, so the server binds EACH of them explicitly (one socket/listener per IP) rather
        # than 0.0.0.0 — see _core_config for why (correct UDP reply source + accept only on pool IPs).
        # listen_ips carries that selected set as bare IPv4 (the port is appended in _core_config).
        # Whitelisting both keys is mandatory (an un-whitelisted key is dropped and never reaches core).
        # raw/flux receive via AF_PACKET (every dest IP already), so the flag is a no-op there.
        if transport in ("udp", "tcp") and role == "server" and _as_bool(d.get("pool_listen")):
            obj["pool_listen"] = True
            lips = [str(x).strip() for x in (d.get("listen_ips") or []) if str(x).strip()]
            if len(lips) > 64:
                raise ValueError("listen_ips pool too large (>64)")
            for ip in lips:
                if not is_ipv4(ip):
                    raise ValueError("bad listen_ips entry (must be an IPv4 address)")
            if lips:
                obj["listen_ips"] = lips
        # peer_src_ips (server side, raw/flux): the client's SOURCE pool. raw/flux servers see every host
        # on the wire and pre-filter by the learned source, so a rotated client source is dropped pre-
        # crypto and never re-learned without this. Whitelisting is mandatory (un-whitelisted keys are
        # dropped and never reach the core). udp/tcp bind per-source and re-learn naturally.
        if transport in ("raw", "flux") and role == "server":
            psrc = [str(x).strip() for x in (d.get("peer_src_ips") or []) if str(x).strip()]
            if len(psrc) > 64:
                raise ValueError("peer_src_ips pool too large (>64)")
            for ip in psrc:
                if not is_ipv4(ip):
                    raise ValueError("bad peer_src_ips entry (must be an IPv4 address)")
            if psrc:
                obj["peer_src_ips"] = psrc
        psk = str(d.get("psk") or "").strip()
        if psk:                       # crypto is optional but recommended; when set it must be strong enough
            if len(psk) < 16:
                raise ValueError("core psk too short (>=16)")
            obj["psk"] = psk          # popped from public_configs, so it never leaves the node
        obfs = _as_bool(d.get("obfs"))    # anti-DPI: needs the AEAD key, so a psk (and a real cipher) is required
        if obfs and (not psk or cipher == "none"):
            raise ValueError("obfs requires a psk and encryption")
        obj["obfs"] = obfs
        # flux derives its rotating shape from the PSK and authenticates the shape-independent
        # decode with the AEAD, so crypto is mandatory — reject early rather than let the core fail.
        if transport == "flux" and (not psk or cipher == "none"):
            raise ValueError("flux requires a psk and encryption")
        # The raw transport authenticates+encrypts every raw IP packet with the AEAD, so the core
        # rejects it without crypto; validate here so the failure is precise, not "interface not created".
        if transport == "raw" and (not psk or cipher == "none"):
            raise ValueError("ترنسپورت raw به رمزنگاری (psk) نیاز دارد — هر فریم با AEAD رمز و احراز می‌شود")
        # TLS cover (HTTPS camouflage) — persist it so _core_config can forward it to the core.
        if _as_bool(d.get("cover")) and transport == "tcp":
            obj["cover"] = True
            sni = str(d.get("cover_sni") or "").strip()
            # The core rejects cover without a cover_sni (the SNI it presents / borrows a real cert for),
            # so require it up front rather than fail later with the generic "interface not created".
            if not sni:
                raise ValueError("پوشش TLS به cover_sni نیاز دارد (نام دامنه‌ای که ارائه می‌شود)")
            if not re.match(r"^[A-Za-z0-9.-]{1,253}$", sni):   # hostname charset, like ws_host
                raise ValueError("bad cover_sni")
            obj["cover_sni"] = sni
        if _as_bool(d.get("gso")):        # TUN segmentation offload (throughput); Linux only, harmless if unsupported
            obj["gso"] = True
        # Fake-packet desync: persist the decoy knobs so _core_config can forward them. Supported on
        # raw/flux (forge IPv4) and tcp/ws (inject decoy TCP segments); not on plain udp. Whitelisting
        # is mandatory — an un-whitelisted key is silently dropped from the stored config and never
        # reaches the core (this is exactly the bug spoofing hit).
        if _as_bool(d.get("fake_desync")):
            if transport not in ("raw", "flux", "tcp", "ws"):
                raise ValueError("fake_desync is supported on the raw, flux, tcp and ws carriers (not udp)")
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
        # IP spoofing (raw bip only): persist the forged source and/or decoy destination so _core_config
        # can wire them per role. Without this the fields never reach the stored cfg and spoofing is a no-op.
        if transport == "raw" and obj.get("raw_profile") == "bip":
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
    old = read_config(name)   # in-place rebuild: fully tear the previous build down first so nothing tied to a
    if old and old.get("type") != "portfw":   # now-overwritten field (e.g. FOU's old UDP-port decap listener) leaks
        teardown_config(old)
    write_config(name, obj)

    def _fail(msg):
        # The new build failed. Tear it down, then ROLL BACK to the previously-working config
        # instead of deleting the tunnel outright: a transient build/verify blip (e.g. a core
        # cold-start slower than the TUN wait) must not permanently destroy a tunnel that was
        # healthy before this edit. Only drop the file if there was no prior build to restore,
        # or the restore itself also fails.
        teardown_config(obj)
        if old and old.get("type") != "portfw" and NAME_RE.match(old.get("name", "")):
            write_config(name, old)
            restored = True
            try:
                apply_config(old)
            except Exception:
                restored = False
            # A disabled tunnel legitimately has no netdev, so its restore succeeds as long as
            # apply_config didn't throw; only require the netdev to exist when it should be UP.
            if restored and (not old.get("enabled", True) or run(["ip", "link", "show", name])[0] == 0):
                return {"ok": False, "msg": msg, "restored": True}
        try:
            os.remove(os.path.join(CONFIG_DIR, name + ".json"))
        except OSError:
            pass
        return {"ok": False, "msg": msg, "restored": False}

    try:
        apply_config(obj)
    except Exception as e:
        # apply blew up (e.g. core download/checksum failure): the old build is already gone
        # and this config was just written, so undo the partial build and restore the old one.
        return _fail(str(e))
    # A tunnel the operator turned OFF has its data path down BY DESIGN — for a core tunnel that
    # means apply_config stopped the unit and its non-persistent TUN is absent, so a netdev-exists
    # check would read as a build failure and _fail would delete the (perfectly good) config. Skip
    # the check for a disabled tunnel: a successful apply_config IS the success signal here.
    if not obj.get("enabled", True):
        return {"ok": True, "name": name, "tunnel_ip": tunnel_ip}
    # builds run `ip` via run() which never raises on failure, so verify the netdev really exists
    rc, _, _ = run(["ip", "link", "show", name])   # every type is a plain kernel netdev now
    if rc != 0:
        need = {"vxlan": "vxlan", "gre": "ip_gre", "sit": "sit", "ipip": "ipip",
                "l2tpv3": "l2tp_eth", "fou": "fou و ipip", "ipsec": "xfrm_interface",
                "core": "هستهٔ tnl-core"}[ttype]
        return _fail(f"اینترفیسِ {ttype} ساخته نشد — «{need}» روی این نود نصب/فعال نیست")
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
    listen_ip = str(d.get("listen_ip") or "").strip()  # optional: pin to ONE local IP (multi-IP hosts)
    if listen_ip:
        if not is_ipv4(listen_ip):
            raise ValueError("bad listen IP")
        if listen_ip not in local_ips_flat():
            raise ValueError(f"{listen_ip} is not a local IP on this node")
        liface = iface_for_ip(listen_ip)  # bind the rule to the iface that actually carries this IP
        if liface and IFACE_RE.match(liface):
            iface = liface
    interval = 0 if len(ips) == 1 else int(d.get("interval_min", 5)) * 60
    for c in raw_configs():
        if (c.get("type") == "portfw" and c.get("iface") == iface and str(c.get("listen_port")) == lp
                and str(c.get("listen_ip") or "") == listen_ip):  # same port on a DIFFERENT local IP is fine
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
    """Edit an existing port-forward IN PLACE (keeps its name): ports, dst IPs, rotation on/off, listen IP."""
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
        interval = 0  # rotation only means something with >=2 destinations
    if "listen_ip" in d:  # a new listen-IP pin was sent (multi-IP host): validate and re-derive the iface
        listen_ip = str(d.get("listen_ip") or "").strip()
        if listen_ip:
            if not is_ipv4(listen_ip):
                raise ValueError("bad listen IP")
            if listen_ip not in local_ips_flat():
                raise ValueError(f"{listen_ip} is not a local IP on this node")
            liface = iface_for_ip(listen_ip)  # bind to the iface that actually carries the new IP
            if liface and IFACE_RE.match(liface):
                iface = liface
    else:
        listen_ip = str(old.get("listen_ip") or "")  # no new pin sent: the old pin survives the edit
    for c in raw_configs():  # a DIFFERENT forward must not already own this iface+listen_port+listen_ip
        if (c.get("name") != old["name"] and c.get("type") == "portfw"
                and c.get("iface") == iface and str(c.get("listen_port")) == lp
                and str(c.get("listen_ip") or "") == listen_ip):
            raise ValueError(f"port {lp} on {iface} is already forwarded")
    teardown_config(old)  # clear the OLD iptables rules (old iface/port/ips) before writing the new set
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
    """Manually advance a port-forward to its NEXT destination right now."""
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
        return {"ok": True, "already": True}   # idempotent: nothing to tear down (lets central retry a partial delete cleanly)
    teardown_config(cfg)
    try:
        os.remove(os.path.join(CONFIG_DIR, d["name"] + ".json"))
    except FileNotFoundError:
        pass
    return {"ok": True}


def op_link_enable(d):
    """Turn a tunnel's data path on or off without rebuilding it. Persists the state so edit/rebuild/boot
    keep it, and brings the interface up/down now (core: (re)start/stop the core unit; others: ip link up/down)."""
    _require(d, ["name"])
    name = d["name"]
    if not NAME_RE.match(name):
        raise ValueError("bad name")
    enabled = _as_bool(d.get("enabled", True))
    cfg = read_config(name)
    if not cfg or cfg.get("type") == "portfw":
        return {"ok": True, "already": True}   # nothing to toggle (idempotent)
    cfg["enabled"] = enabled
    write_config(name, cfg)
    _set_link_state(cfg, enabled)
    return {"ok": True, "enabled": enabled}


def op_wipe(d):
    """Full self-destruct requested by the panel. Tear down every tunnel/portfw in-process, then
    (detached, after this 200 flushes) stop+remove the service and delete /opt/tunnel entirely —
    configs, node.conf/token and the installed binary. Nothing of this node remains."""
    for c in raw_configs():
        try:
            teardown_config(c)
            os.remove(os.path.join(CONFIG_DIR, c["name"] + ".json"))
        except Exception:
            pass
    _restart_pending.set()  # reject any new mutating op during the shutdown window
    script = ("sleep 1; systemctl stop tnl-node 2>/dev/null; systemctl disable tnl-node 2>/dev/null; "
              "rm -f " + SERVICE_FILE + "; systemctl daemon-reload 2>/dev/null; rm -rf " + CONFIG_DIR)
    subprocess.Popen(["sh", "-c", script], start_new_session=True, stdin=subprocess.DEVNULL,
                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    logline("node wiped by panel request")
    return {"ok": True, "wiped": True}


def op_check(d):
    """On-demand health probe for ONE config — a thorough live peer-ping over the tunnel."""
    _require(d, ["name"])
    cfg = read_config(d["name"])
    if not cfg:
        raise ValueError("not found")
    return {"ok": True, "health": health_of(cfg, thorough=True)}


def _ss_proc(line):
    """Pull the occupying process name out of an `ss -p` line: users:(("nginx",pid=..))."""
    m = re.search(r'users:\(\("([^"]+)"', line)
    return m.group(1) if m else ""


def _norm_ip(x):
    """Bare IP: drop [] and whitespace. '' for none/wildcard placeholders."""
    return str(x or "").strip().strip("[]")


_WILD = ("0.0.0.0", "::", "*", "")


def _decode_hexip(h):
    """Decode a /proc/net local address hex string to a dotted/normal IP for comparison.
    IPv4 is 8 hex chars little-endian; the all-zero form (any length) is the wildcard '::'.
    Returns None when it can't decode (caller then treats the socket conservatively)."""
    h = h.strip()
    if set(h) <= {"0"}:
        return "0.0.0.0"
    if len(h) == 8:
        try:
            b = bytes.fromhex(h)
            return "%d.%d.%d.%d" % (b[3], b[2], b[1], b[0])  # little-endian
        except ValueError:
            return None
    return None  # IPv6 (non-zero) — don't attempt, let the caller be conservative


def _port_busy_proc(port, proto, tip=None):
    """Fallback when `ss` is unavailable: scan /proc/net/{tcp,tcp6}|{udp,udp6}. No process name.
    TCP listeners have st==0A. When tip is given, only a matching-IP or wildcard bind conflicts;
    an undecodable listener IP is treated conservatively (busy) so two tunnels never silently
    collide. Returns bool."""
    files = ("/proc/net/tcp", "/proc/net/tcp6") if proto == "tcp" else ("/proc/net/udp", "/proc/net/udp6")
    for path in files:
        try:
            with open(path) as f:
                next(f, None)  # header
                for row in f:
                    parts = row.split()
                    if len(parts) < 4:
                        continue
                    local, st = parts[1], parts[3]
                    if proto == "tcp" and st != "0A":   # only LISTEN sockets conflict for TCP
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
    """Is `port` already listening on this node for the given proto? Sees ALL processes
    (Xray/nginx/x-ui/…), not just our tunnels. When `ip` is given, only a bind on that same IP
    or a wildcard (0.0.0.0/::) counts — so several ws tunnels can share a port across the host's
    different IPs. Returns (busy, who)."""
    proto = "tcp" if str(proto).lower() == "tcp" else "udp"
    flag = "-t" if proto == "tcp" else "-u"
    tip = _norm_ip(ip) or None
    rc, out, _ = run(["ss", "-H", "-l", "-n", "-p", flag])
    if rc == 0:
        for line in out.splitlines():
            f = line.split()
            if len(f) < 4:
                continue
            local = f[3]   # State Recv-Q Send-Q Local:Port Peer:Port [users:(...)]
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


def op_portcheck(d):
    """READ_ONLY: report whether {port, proto} is already in use on this node so the panel
    can block a create/edit that would collide with an existing service or tunnel."""
    _require(d, ["port"])
    try:
        port = int(d["port"])
    except (TypeError, ValueError):
        raise ValueError("bad port")
    if not 1 <= port <= 65535:
        raise ValueError("port out of range")
    proto = "tcp" if str(d.get("proto", "udp")).lower() == "tcp" else "udp"
    ip = _norm_ip(d.get("ip")) or None  # optional: only conflict on this bind IP (or a wildcard)
    if ip and not re.match(r"^[0-9A-Fa-f:.]{1,45}$", ip):
        raise ValueError("bad ip")
    busy, who = _port_busy(port, proto, ip)
    return {"ok": True, "busy": busy, "who": who, "port": port, "proto": proto, "ip": ip or ""}


def op_edge_status(d):
    """READ_ONLY: return the ws edge pool's live status (active edge + auto-burned IP/SNI
    lists) the core writes for tunnel {name}, so the panel can surface and persist the burns.
    Empty status when the tunnel has no pool or the core hasn't written the file yet."""
    _require(d, ["name"])
    name = str(d["name"])
    if not NAME_RE.match(name):
        raise ValueError("bad name")
    path = os.path.join(CONFIG_DIR, "core-" + name + ".status")
    try:
        with open(path) as f:
            st = json.load(f)
    except (OSError, ValueError):
        return {"ok": True, "active": "", "burned_ips": [], "burned_snis": [], "health": [], "ts": 0}
    health = []
    for h in (st.get("health") or [])[:256]:
        if not isinstance(h, dict):
            continue
        health.append({
            "key": str(h.get("key") or ""),
            "kind": "sni" if str(h.get("kind")) == "sni" else "ip",
            "state": str(h.get("state") or "healthy"),
            "fails": int(h.get("fails") or 0),
            "next_retest_unix": int(h.get("next_retest_unix") or 0),
        })
    events = []
    for e in (st.get("events") or [])[:64]:
        if not isinstance(e, dict):
            continue
        events.append({
            "seq": int(e.get("seq") or 0),
            "ts": int(e.get("ts") or 0),
            "kind": str(e.get("kind") or ""),
            "code": str(e.get("code") or ""),
            "detail": str(e.get("detail") or ""),
        })
    return {"ok": True,
            "active": str(st.get("active") or ""),
            "burned_ips": [str(x) for x in (st.get("burned_ips") or [])][:64],
            "burned_snis": [str(x) for x in (st.get("burned_snis") or [])][:64],
            "health": health,
            "events": events,
            "ts": int(st.get("ts") or 0),
            # The core stamps next_retest_unix on the NODE's clock, so return the node's "now"
            # too — the panel counts down against this, not its own (possibly skewed) clock, and
            # can flag a stale file (now - ts large) as offline.
            "now": int(time.time())}


_PEER_ADDR_RE = re.compile(r"^[0-9A-Fa-f:.]{1,64}$")  # a pool endpoint is only ever an IPv4/IPv6/ip:port


def _read_peer_pool(name, suffix):
    """Parse one direct-transport pool status file (suffix '.peerpool' = destination, '.srcpool' =
    source) into the normalized shape the panel reads: active endpoint, the full list, the flat burned
    list, the per-endpoint health FSM (state / fails / retest countdown), and any operator pin. Empty
    (but well-formed) when the file is missing — the pool doesn't exist or the core hasn't written yet."""
    empty = {"active": "", "addrs": [], "burned": [], "health": [], "pin": "", "ts": 0}
    try:
        with open(os.path.join(CONFIG_DIR, "core-" + name + suffix)) as f:
            st = json.load(f)
    except (OSError, ValueError):
        return empty
    # A pool endpoint is always a bare IP or ip:port; drop anything else so a malformed file can't feed
    # a non-IP string to the panel's live view (defense-in-depth — the panel re-validates too).
    ok = lambda s: bool(s) and bool(_PEER_ADDR_RE.match(s))
    health = []
    for h in (st.get("health") or [])[:64]:
        if not isinstance(h, dict):
            continue
        key = str(h.get("key") or "")
        if not ok(key):
            continue
        health.append({
            "key": key,
            "state": str(h.get("state") or "healthy"),
            "fails": int(h.get("fails") or 0),
            "next_retest_unix": int(h.get("next_retest_unix") or 0),
        })
    active = str(st.get("active") or "")
    pin = str(st.get("pin") or "")
    return {
        "active": active if ok(active) else "",
        "addrs": [x for x in (str(v) for v in (st.get("addrs") or [])) if ok(x)][:64],
        "burned": [x for x in (str(v) for v in (st.get("burned") or [])) if ok(x)][:64],
        "health": health,
        "pin": pin if ok(pin) else "",
        "ts": int(st.get("updated_unix") or 0),
    }


def op_peer_status(d):
    """READ_ONLY: return the direct-transport pools' live state for tunnel {name} — both the DESTINATION
    pool (the server IPs the client dials) and the SOURCE pool (this node's own egress IPs) — so the
    panel can show which IP is active, which got blocked (suspect vs dead, with the retest countdown),
    and any manual pin. Empty sections when the tunnel has no such pool or the core hasn't written yet.
    The core stamps next_retest_unix on the NODE's clock, so `now` is returned for the panel to count
    down against (and to flag a stale file as offline)."""
    _require(d, ["name"])
    name = str(d["name"])
    if not NAME_RE.match(name):
        raise ValueError("bad name")
    dst = _read_peer_pool(name, ".peerpool")
    src = _read_peer_pool(name, ".srcpool")
    # Top-level fields mirror the destination pool for backward compatibility with the old reader.
    return {"ok": True, "now": int(time.time()), "dst": dst, "src": src,
            "active": dst["active"], "addrs": dst["addrs"], "burned": dst["burned"], "ts": dst["ts"]}


def op_peer_select(d):
    """Live 'pin this IP' for a direct-transport pool: drop a JSON command file the running core polls
    (<status>.cmd) so it jumps its rotation to THIS specific endpoint and re-points onto it — no rebuild,
    TUN stays up. side 'src' pins the source pool (<name>.srcpool.cmd); anything else the destination
    pool (<name>.peerpool.cmd). Backs the panel's per-IP pin button."""
    _require(d, ["name", "key"])
    name = str(d["name"])
    if not NAME_RE.match(name):
        raise ValueError("bad name")
    if not _is_peer_pool(name):
        return {"ok": False, "error": "این تونل استخرِ آی‌پی ندارد"}
    key = str(d.get("key") or "").strip()
    if not key or len(key) > 64:
        raise ValueError("مقدارِ آی‌پی نامعتبر است")
    suffix = ".srcpool" if str(d.get("side")) == "src" else ".peerpool"
    path = os.path.join(CONFIG_DIR, "core-" + name + suffix + ".cmd")
    # Write atomically (tmp + replace): the core polls this file once per second and removes it, so a
    # half-written file would be read+deleted and the pin SILENTLY LOST. os.replace is atomic.
    tmp = path + ".tmp"
    try:
        with open(tmp, "w") as f:
            json.dump({"key": key}, f)
        os.replace(tmp, path)
    except OSError as e:
        try:
            os.remove(tmp)
        except OSError:
            pass
        return {"ok": False, "error": str(e)}
    return {"ok": True}


def op_peer_probe_now(d):
    """Live 'probe now' for a direct-transport pool: SIGHUP tells the running core to retest EVERY
    suspect/dead endpoint immediately (re-admit it to the live rotation) instead of waiting out the
    backoff, so a lifted block heals at once. No rebuild, TUN stays up."""
    _require(d, ["name"])
    name = str(d["name"])
    if not NAME_RE.match(name):
        raise ValueError("bad name")
    if not _is_peer_pool(name):   # a non-pool core has no SIGHUP handler -> the signal would kill it
        return {"ok": False, "error": "این تونل استخرِ آی‌پی ندارد"}
    rc, out, err = run(["systemctl", "kill", "-s", "SIGHUP", _core_unit(name)])
    if rc != 0:
        return {"ok": False, "error": (err or out or "").strip() or ("سیگنال به هسته نرسید (" + name + ")")}
    return {"ok": True}


def op_pool_select(d):
    """Live 'pin this edge' for a ws edge pool: drop a JSON command file the running core polls
    (<status>.cmd) so it jumps its rotation to THIS specific IP/SNI and re-dials onto it — no
    rebuild, TUN stays up. Backs the panel's per-edge select button."""
    _require(d, ["name", "kind", "key"])
    name = str(d["name"])
    if not NAME_RE.match(name):
        raise ValueError("bad name")
    if not _is_ws_pool(name):
        return {"ok": False, "error": "این تونل استخرِ لبه ندارد"}
    kind = "sni" if str(d.get("kind")) == "sni" else "ip"
    key = str(d.get("key") or "").strip()
    if not key or len(key) > 255:
        raise ValueError("مقدارِ لبه نامعتبر است")
    path = os.path.join(CONFIG_DIR, "core-" + name + ".status.cmd")
    # Write atomically (tmp + replace): the core polls this file once per second and removes it,
    # so a half-written file would be read+deleted and the pin SILENTLY LOST. os.replace is atomic.
    tmp = path + ".tmp"
    try:
        with open(tmp, "w") as f:
            json.dump({"kind": kind, "key": key}, f)
        os.replace(tmp, path)
    except OSError as e:
        try:
            os.remove(tmp)
        except OSError:
            pass
        return {"ok": False, "error": str(e)}
    return {"ok": True}


def op_pool_probe_now(d):
    """Live 'probe now' for a ws edge pool: SIGHUP tells the running core to retest EVERY
    suspect/dead edge immediately (cheap TLS-only probes) instead of waiting out the backoff,
    so a lifted block heals at once. No rebuild, TUN stays up."""
    _require(d, ["name"])
    name = str(d["name"])
    if not NAME_RE.match(name):
        raise ValueError("bad name")
    if not _is_ws_pool(name):   # a non-pool core has no SIGHUP handler -> the signal would kill it
        return {"ok": False, "error": "این تونل استخرِ لبه ندارد"}
    rc, out, err = run(["systemctl", "kill", "-s", "SIGHUP", _core_unit(name)])
    if rc != 0:
        return {"ok": False, "error": (err or out or "").strip() or ("سیگنال به هسته نرسید (" + name + ")")}
    return {"ok": True}


CORE_VER_RE = re.compile(r"^(?!.*\.\.)[A-Za-z0-9._-]{1,40}$")  # negative-lookahead rejects any '..' → no path traversal in the release URL
CORE_SHA_RE = re.compile(r"^[0-9a-f]{64}$")


def _verify_update_sig(msg, sig_b64):
    """Verify an RSA-SHA256 signature (base64) over `msg` (bytes) with the panel PUBLIC key stored in
    node.conf['update_pubkey'], via openssl. Returns True when NO key is provisioned yet (legacy /
    pre-rollout node — behave exactly as before) or the signature verifies; False when a key IS set but
    the signature is missing/invalid. This is what stops a stolen token from pushing malicious root code:
    only the panel (holding the matching private key) can produce a valid signature. Callers run under
    _apply_lock, so the fixed temp paths below are never used concurrently."""
    try:
        pub = str(load_conf().get("update_pubkey") or "").strip()
    except Exception:
        return False
    if not pub:
        return True   # backward-compat: node not yet provisioned with a key -> accept unsigned as before
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
    """Provision the panel's update-signing PUBLIC key (PEM). FIRST-SET ONLY: once a key is stored it
    can only be changed by re-installing over SSH — so a token holder can't swap in their own key and
    then sign malicious updates. Idempotent when the identical key is re-sent."""
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


def op_core_install(d):
    """Install a raw core binary pushed from the panel (base64), not a published release. Verify its
    sha256, swap it in atomically, pin the node to a custom label, then rebuild the core tunnels so they
    relaunch on it. NEVER install a binary whose checksum does not verify (it runs as root)."""
    _require(d, ["data", "sha256"])
    want = str(d.get("sha256") or "").strip().lower()
    if not CORE_SHA_RE.match(want):
        raise ValueError("bad sha256")
    try:
        raw = base64.b64decode(d["data"], validate=True)
    except Exception:
        raise ValueError("bad base64 payload")
    if len(raw) < 100000:                         # an core binary is ~3 MB; anything tiny is a mistake, never install it
        return {"ok": False, "msg": "binary too small"}
    got = hashlib.sha256(raw).hexdigest()
    if got != want:
        return {"ok": False, "msg": "checksum mismatch"}   # transport truncation guard — never install unverified bytes
    if not _verify_update_sig(want.encode(), d.get("sig")):   # authenticity: only the panel's key may authorize a root binary
        return {"ok": False, "msg": "signature verification failed (panel key)"}
    label = str(d.get("version") or "custom").strip() or "custom"
    if not CORE_VER_RE.match(label):
        label = "custom"
    # Already the exact binary? Then this is a no-op: do NOT swap and do NOT restart the
    # running core tunnels (a re-push of the same version must not blip live tunnels).
    if os.path.isfile(CORE_BIN) and _installed_core_sha() == got:
        conf = load_conf()
        if conf.get("core_version") != label:
            conf["core_version"] = label
            save_conf(conf)
        return {"ok": True, "unchanged": True, "version": label, "core_sha": got[:12], "restarted": 0}
    with _core_lock:
        tmp = CORE_BIN + ".new"
        with open(tmp, "wb") as f:
            f.write(raw)
        os.chmod(tmp, 0o755)
        os.replace(tmp, CORE_BIN)               # atomic swap on the same fs — no half-written window
    conf = load_conf()
    conf["core_version"] = label
    save_conf(conf)
    restarted, errs = 0, []
    for c in raw_configs():                        # relaunch every core tunnel on the freshly-installed binary
        if c.get("type") == "core":
            if not c.get("enabled", True):
                continue                           # a tunnel the operator turned OFF stays down — an install must not silently re-enable it
            try:
                build_core(c)
                restarted += 1
            except Exception as e:
                errs.append(f"{c.get('name')}: {e}")
    logline(f"core installed from upload ({label}, sha {got[:12]}); rebuilt {restarted} core tunnel(s)")
    return {"ok": True, "version": label, "core_sha": got[:12], "restarted": restarted, "errors": errs}


def op_apply(d):
    apply_all()
    return {"ok": True}


def op_update(d):
    """Replace this agent with new source pushed from the panel. VALIDATE-BEFORE-SWAP is the brick guard:
    a bad upload is rejected and the currently-running file is left untouched. Restart is fired by the
    handler AFTER this 200 is flushed, so the central's push call gets its {ok:true} before the bounce."""
    _require(d, ["code"])
    src = d["code"]
    if not isinstance(src, str) or not src.strip():
        raise ValueError("empty code")
    h = hashlib.sha256(src.encode()).hexdigest()
    if d.get("sha256") and d["sha256"] != h:            # transport truncation guard (a truncated prefix could still compile)
        return {"ok": False, "msg": "checksum mismatch"}
    if not _verify_update_sig(h.encode(), d.get("sig")):   # authenticity: only the panel's key may authorize new agent code
        return {"ok": False, "msg": "signature verification failed (panel key)"}
    if h == _SELF_SHA:                                   # already running this exact code -> no-op, do NOT restart
        return {"ok": True, "sha256": h, "restarting": False, "already": True}
    try:
        compile(src, "tnl-node.py", "exec")             # in-memory compile gate — nothing on disk touched yet
    except SyntaxError as e:
        return {"ok": False, "msg": "rejected (syntax): " + str(e)}
    tmp = INSTALLED + ".new"
    try:
        with open(tmp, "w") as f:
            f.write(src)
        os.chmod(tmp, 0o755)
        py_compile.compile(tmp, doraise=True)           # deep gate from disk — catches a truncated/partial write
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
    if disk_sha and disk_sha == _SELF_SHA:               # back up ONLY when disk still = the code we're actually running
        try:                                             # (a genuine known-good) — never clobber .bak with an un-restarted swap
            shutil.copy2(INSTALLED, INSTALLED + ".bak")
        except OSError:
            pass
    os.replace(tmp, INSTALLED)                           # atomic swap on the same filesystem — no half-written window
    logline(f"agent updated -> sha {h[:12]}, restarting")
    # Fire the bounce HERE — right after the swap commits, while still under _apply_lock (held by _handle).
    # This makes the restart independent of whether the 200 write to the client succeeds (a broken pipe used to
    # skip it and strand the node on stale in-memory code), and _restart_pending stops any new build from starting
    # in the shutdown window. sleep 1 lets the 200 flush first; detached (setsid) so it survives the restart.
    _restart_pending.set()
    subprocess.Popen(["sh", "-c", "sleep 1; systemctl restart tnl-node"],
                     start_new_session=True, stdin=subprocess.DEVNULL,
                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    m = re.search(r'"version":\s*(\d+)', src)
    return {"ok": True, "version": int(m.group(1)) if m else None, "sha256": h, "restarting": True}


def op_spoof_probe(d):
    """Ask the core binary whether IP spoofing (decoy) can run on THIS node. Reports local
    capability only (CAP_NET_RAW + AF_PACKET) — it cannot prove the upstream datacenter will
    forward a forged source, which only shows up if a real tunnel fails to establish. The panel
    uses {ok, reason} to enable/disable the spoofing controls and show why."""
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


OPS = {"ping": op_ping, "list": op_list, "check": op_check, "tunnel": op_tunnel,
       "portfw": op_portfw, "portfw-edit": op_portfw_edit, "portfw-next": op_portfw_next,
       "delete": op_delete, "apply": op_apply, "update": op_update, "wipe": op_wipe,
       "portcheck": op_portcheck, "edge-status": op_edge_status,
       "peer-status": op_peer_status,
       "peer-select": op_peer_select, "peer-probe-now": op_peer_probe_now,
       "pool-probe-now": op_pool_probe_now, "pool-select": op_pool_select,
       "core-install": op_core_install, "spoof-probe": op_spoof_probe,
       "set-update-key": op_set_update_key,
       "link-enable": op_link_enable}
READ_ONLY = {"ping", "list", "check", "portcheck", "spoof-probe", "edge-status", "peer-status"}

# ----------------------------------------------------------------------------- HTTP

class Handler(BaseHTTPRequestHandler):
    server_version = "tnl-node"
    timeout = 30   # socket timeout on slow header/body reads → a pre-auth slowloris can't pin a root thread forever

    def log_message(self, *a):
        pass

    # MAX_CONNS is enforced at the CONNECTION level (here), not per parsed request: ThreadingHTTPServer
    # spawns a thread per accepted TCP connection BEFORE any header is read, so a slowloris dribbling
    # headers used to tie up threads bounded only by the 30s socket timeout. We try-acquire _conn_sem the
    # moment the connection is set up; if the cap is already reached we refuse instantly in handle()
    # (no header read at all), so the thread exits immediately and can never be pinned by a slow client.
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
        if not getattr(self, "_sem_held", False):   # over the connection cap → refuse without reading headers
            try:
                body = b'{"error":"server busy, retry shortly"}'
                self.wfile.write(b"HTTP/1.1 503 Service Unavailable\r\n"
                                 b"Content-Type: application/json\r\n"
                                 b"Content-Length: " + str(len(body)).encode() + b"\r\n"
                                 b"Connection: close\r\n\r\n" + body)
            except Exception:
                pass
            return
        BaseHTTPRequestHandler.handle(self)   # normal (keep-alive) request loop, holding one permit

    def _authed(self):
        tok = self.headers.get("X-Node-Token", "")
        want = self.server.conf.get("token", "")
        if not tok or not want:
            return False
        try:
            # compare on bytes: a non-ASCII X-Node-Token would make compare_digest(str, str) raise
            # TypeError (→ connection reset). Encoding first keeps it constant-time and fail-closed.
            return hmac.compare_digest(tok.encode("utf-8"), want.encode("utf-8"))
        except Exception:
            return False

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
        n = min(max(n, 0), cap)   # default 1MB — headroom for a pushed agent source (JSON-escaped); raised for core uploads
        raw = self.rfile.read(n) if n > 0 else b""
        try:
            obj = json.loads(raw.decode()) if raw else {}
        except Exception:
            return {}
        return obj if isinstance(obj, dict) else {}   # a top-level array/string/number must not reach ops as non-dict

    def _handle(self, method):
        # The _conn_sem permit is already held for the whole connection (see setup()/handle()), so the
        # number of connections that ever reach here is bounded — no per-request acquire needed.
        self._handle_locked(method)

    def _handle_locked(self, method):
        path = self.path.split("?", 1)[0]
        if not path.startswith("/api/"):
            self._send(404, {"error": "not found"})
            return
        cmd = path[5:]
        if not self._authed():
            self._send(401, {"error": "bad or missing node token"})
            return
        cp = self.headers.get("X-Central-Port")
        if cp:
            note_central(self.client_address[0], cp)  # learn where to call /api/checkin back from
        if cmd not in OPS:
            self._send(404, {"error": "unknown endpoint"})
            return
        if cmd not in READ_ONLY and method != "POST":
            self._send(405, {"error": "use POST"})
            return
        # core-install carries a base64-encoded core binary (~3MB raw → ~4MB base64); a 1MB cap
        # would truncate it and fail the JSON parse, so raise the cap for that op only.
        cap = 20971520 if cmd == "core-install" else 1048576
        d = self._body(cap) if method == "POST" else {}
        try:
            if cmd in READ_ONLY:
                res = OPS[cmd](d)
            else:
                if _restart_pending.is_set():   # an update already swapped the binary — don't start a build in the shutdown window
                    self._send(503, {"error": "agent is restarting, retry shortly"})
                    return
                with _apply_lock:
                    if _restart_pending.is_set():   # re-check under the lock: op_update may have just committed
                        self._send(503, {"error": "agent is restarting, retry shortly"})
                        return
                    res = OPS[cmd](d)
            self._send(200, res)   # op_update already scheduled its own bounce (see op_update); nothing to fire here
        except ValueError as e:
            self._send(400, {"error": str(e)})
        except Exception as e:
            logline(f"op {cmd} error: {e}")
            self._send(500, {"error": "internal error (see node-agent.log)"})

    def do_GET(self):
        self._handle("GET")

    def do_POST(self):
        self._handle("POST")

# ----------------------------------------------------------------------------- install / main

SERVICE = "tnl-node.service"


def svc(*a):
    run(["systemctl", *a, SERVICE])


def service_active():
    return run(["systemctl", "is-active", "--quiet", SERVICE])[0] == 0


def install_deps():
    # Native tunnels only need iproute2 (already present) + iptables for port-forwards. VXLAN/GRE/… are
    # kernel modules loaded on demand; OpenvSwitch is no longer required.
    print("[*] Installing dependencies (iptables)...")
    env = dict(os.environ, DEBIAN_FRONTEND="noninteractive")
    try:
        subprocess.run(["apt-get", "update", "-qq"], env=env, timeout=300)
        subprocess.run(["apt-get", "install", "-yqq", "iptables"], env=env, timeout=600)
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


def do_install():
    os.makedirs(CONFIG_DIR, exist_ok=True)
    os.chmod(CONFIG_DIR, 0o700)
    if os.path.realpath(SELF_PATH) != INSTALLED:  # copy to a stable path so the unit never breaks if moved
        shutil.copy2(SELF_PATH, INSTALLED)
        os.chmod(INSTALLED, 0o755)
    conf = load_conf() if os.path.isfile(NODE_CONF) else {}
    conf["port"] = int(input(f"Agent port [{conf.get('port', 8099)}]: ").strip() or conf.get("port", 8099))
    if not conf.get("token"):
        conf["token"] = secrets.token_urlsafe(32)
    save_conf(conf)
    install_deps()
    write_service()
    svc("enable")
    svc("restart")
    print("[✔] node agent installed and started.")
    do_show()


def do_auto_install(port):
    """Non-interactive install for the central panel's SSH auto-provisioning.
    Prints machine-parseable markers the panel greps for (token/port)."""
    os.makedirs(CONFIG_DIR, exist_ok=True)
    os.chmod(CONFIG_DIR, 0o700)
    if os.path.realpath(SELF_PATH) != INSTALLED:
        shutil.copy2(SELF_PATH, INSTALLED)
        os.chmod(INSTALLED, 0o755)
    conf = load_conf() if os.path.isfile(NODE_CONF) else {}
    try:
        conf["port"] = int(str(port).strip())
    except Exception:
        conf["port"] = conf.get("port", 8099)
    if not 1 <= conf["port"] <= 65535:
        conf["port"] = 8099
    if not conf.get("token"):
        conf["token"] = secrets.token_urlsafe(32)
    save_conf(conf)
    install_deps()
    write_service()
    svc("enable")
    svc("restart")
    print("[✔] node agent installed and started.")
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
    for _ in range(30):  # wait for a default route, then rebuild all tunnels (boot persistence)
        rc, out, _ = run(["ip", "-4", "route"])
        if any(l.startswith("default") for l in out.splitlines()):
            break
        time.sleep(1)
    try:
        apply_all()
    except Exception as e:
        logline(f"startup apply_all: {e}")
    threading.Thread(target=rotation_loop, daemon=True).start()
    threading.Thread(target=health_loop, daemon=True).start()  # keep the health snapshot fresh (O(1) op_list)
    threading.Thread(target=checkin_loop, daemon=True).start()  # phone home to the panel if our IP changes
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
