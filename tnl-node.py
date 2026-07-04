#!/usr/bin/env python3
# tnl-node — self-contained node agent for the tnl central control plane.
#
# Installed on every NODE server. It is FULLY self-contained: it builds tunnels itself
# (VXLAN/GRE via OpenvSwitch, SIT, iptables port-forwards), re-applies them on boot,
# and rotates port-forward destinations — all in-process. No tnl.sh, no reload.sh, no jq,
# no menu. Every operation is driven by the central panel over a token-authenticated API.
#
# Node dependencies: python3, iproute2 (ip), iptables, and openvswitch-switch (for VXLAN/GRE).
#
# Usage:
#   sudo python3 tnl-node.py --install         # set port + generate token, install+start the service
#   sudo python3 tnl-node.py --auto-install P  # non-interactive install on port P (panel SSH provisioning)
#   sudo python3 tnl-node.py --show            # print host / port / token for the central panel
#   sudo python3 tnl-node.py               # run (used by systemd): re-applies configs, then serves
#
# Auth: every request must carry header  X-Node-Token: <token>  (constant-time compared).
# Plain HTTP — expose the agent port to the central server only (trusted network / VPN).

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

NAME_RE = re.compile(r"^[A-Za-z0-9_]+$")
IFACE_RE = re.compile(r"^[A-Za-z0-9_.@-]+$")

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


def valid_cidr(s, want6):
    try:
        return ipaddress.ip_network(s, strict=False).version == (6 if want6 else 4)
    except Exception:
        return False


def ip2int(s):
    return int(ipaddress.IPv4Address(s))


def derive_tunnel_ip(ttype, local_ip, remote_ip, subnet):
    """Same rule as the fleet: smaller public IP => .1, larger => .2 (never a custom host)."""
    base, prefix = subnet.split("/")[0], subnet.split("/")[1]
    host = "1" if ip2int(local_ip) < ip2int(remote_ip) else "2"
    if ttype == "sit":
        base = base[:-2] if base.endswith("::") else base.rstrip(":")
        return f"{base}::{host}/{prefix}"
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


def base_mtu():
    dev = default_iface()
    if dev:
        rc, out, _ = run(["ip", "link", "show", dev])
        m = re.search(r"\bmtu (\d+)", out)
        if m:
            return int(m.group(1))
    return 1500

# ----------------------------------------------------------------------------- build / teardown

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


def _ovs_veth(cfg, overhead):
    tid, name = str(cfg["id"]), cfg["name"]
    va, vb = f"veth{tid}a", f"veth{tid}b"
    run(["ip", "link", "add", va, "type", "veth", "peer", "name", vb])
    run(["ovs-vsctl", "add-port", name, va])
    run(["ip", "addr", "add", cfg["tunnel_ip"], "dev", vb])
    run(["ip", "link", "set", va, "up"])
    run(["ip", "link", "set", vb, "up"])
    mtu = str(base_mtu() - 28 - overhead)
    run(["ip", "link", "set", "dev", va, "mtu", mtu])
    run(["ip", "link", "set", "dev", vb, "mtu", mtu])


def build_vxlan(cfg):
    tid, name = str(cfg["id"]), cfg["name"]
    run(["ip", "link", "del", f"veth{tid}a"])
    run(["ip", "link", "del", f"veth{tid}b"])
    run(["ovs-vsctl", "--if-exists", "del-br", name])
    run(["ovs-vsctl", "add-br", name])
    port = f"vx{tid}"  # tunnel port name must differ from the bridge name (name == vxlan{tid})
    run(["ovs-vsctl", "add-port", name, port, "--", "set", "interface", port,
         "type=vxlan", f"options:remote_ip={cfg['remote_ip']}", f"options:local_ip={cfg['local_ip']}",
         f"options:key={tid}", "options:dst_port=4789", "options:csum=true"])
    _ovs_veth(cfg, 50)


def build_gre(cfg):
    tid, name = str(cfg["id"]), cfg["name"]
    run(["ip", "link", "del", f"veth{tid}a"])
    run(["ip", "link", "del", f"veth{tid}b"])
    run(["ovs-vsctl", "--if-exists", "del-br", name])
    run(["ovs-vsctl", "add-br", name])
    port = f"gr{tid}"  # tunnel port name must differ from the bridge name (name == gre{tid})
    run(["ovs-vsctl", "add-port", name, port, "--", "set", "interface", port,
         "type=gre", f"options:remote_ip={cfg['remote_ip']}", f"options:local_ip={cfg['local_ip']}",
         f"options:key={tid}"])
    _ovs_veth(cfg, 24)


def build_sit(cfg):
    name = cfg["name"]
    run(["ip", "link", "del", name])
    run(["ip", "tunnel", "add", name, "mode", "sit", "remote", cfg["remote_ip"],
         "local", cfg["local_ip"], "ttl", "255"])
    run(["ip", "-6", "addr", "add", cfg["tunnel_ip"], "dev", name])
    run(["ip", "link", "set", name, "up"])
    run(["ip", "link", "set", "dev", name, "mtu", str(base_mtu() - 28 - 20)])


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
        for ip in ips:  # flush every candidate rule first
            for _ in range(64):
                rc, _, _ = run(["iptables", "-t", "nat", "-C", "PREROUTING", "-i", iface, "-p", proto,
                                "--dport", lp, "-j", "DNAT", "--to-destination", f"{ip}:{dp}"])
                if rc != 0:
                    break
                run(["iptables", "-t", "nat", "-D", "PREROUTING", "-i", iface, "-p", proto,
                     "--dport", lp, "-j", "DNAT", "--to-destination", f"{ip}:{dp}"])
        run(["iptables", "-t", "nat", "-A", "PREROUTING", "-i", iface, "-p", proto,
             "--dport", lp, "-j", "DNAT", "--to-destination", f"{active}:{dp}"])
    rc, _, _ = run(["iptables", "-t", "nat", "-C", "POSTROUTING", "-o", iface, "-j", "MASQUERADE"])
    if rc != 0:
        run(["iptables", "-t", "nat", "-A", "POSTROUTING", "-o", iface, "-j", "MASQUERADE"])


def apply_config(cfg):
    t = cfg.get("type")
    if t == "vxlan":
        build_vxlan(cfg)
    elif t == "gre":
        build_gre(cfg)
    elif t == "sit":
        build_sit(cfg)
    elif t == "portfw":
        build_portfw(cfg)


def teardown_config(cfg):
    ttype, name, tid = cfg.get("type"), cfg.get("name", ""), str(cfg.get("id", ""))
    if not NAME_RE.match(name):
        return
    if ttype in ("vxlan", "gre"):
        if tid.isdigit():
            run(["ip", "link", "del", f"veth{tid}a"])
            run(["ip", "link", "del", f"veth{tid}b"])
        run(["ovs-vsctl", "--if-exists", "del-br", name])
    elif ttype == "sit":
        run(["ip", "link", "del", name])
    elif ttype == "portfw":
        iface, lp, dp = cfg.get("iface", ""), str(cfg.get("listen_port", "")), str(cfg.get("dst_port", ""))
        if IFACE_RE.match(iface) and lp.isdigit() and dp.isdigit():
            for proto in ("tcp", "udp"):
                for ip in cfg.get("dst_ips", []):
                    if not is_ipv4(ip):
                        continue
                    for _ in range(64):
                        rc, _, _ = run(["iptables", "-t", "nat", "-C", "PREROUTING", "-i", iface, "-p", proto,
                                        "--dport", lp, "-j", "DNAT", "--to-destination", f"{ip}:{dp}"])
                        if rc != 0:
                            break
                        run(["iptables", "-t", "nat", "-D", "PREROUTING", "-i", iface, "-p", proto,
                             "--dport", lp, "-j", "DNAT", "--to-destination", f"{ip}:{dp}"])
            rc, out, _ = run(["iptables", "-t", "nat", "-S", "PREROUTING"])
            if not [l for l in out.splitlines() if re.search(rf"-i {re.escape(iface)} -p (?:tcp|udp) .*-j DNAT", l)]:
                for _ in range(16):
                    rc, _, _ = run(["iptables", "-t", "nat", "-C", "POSTROUTING", "-o", iface, "-j", "MASQUERADE"])
                    if rc != 0:
                        break
                    run(["iptables", "-t", "nat", "-D", "POSTROUTING", "-o", iface, "-j", "MASQUERADE"])


def apply_all():
    """Boot/reconcile: self-heal each tunnel's local_ip, then (re)build every config."""
    rc, rout, _ = run(["ip", "-4", "route"])
    has_default = any(l.startswith("default") for l in rout.splitlines())
    pip = primary_ip() if has_default else None  # don't self-heal to a guessed IP when routing is down
    locals_now = local_ips_flat()
    for cfg in raw_configs():
        if cfg.get("type") in ("vxlan", "gre", "sit"):
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
            rc, _, _ = run(["iptables", "-t", "nat", "-C", "PREROUTING", "-i", iface, "-p", "tcp",
                            "--dport", lp, "-j", "DNAT", "--to-destination", f"{active}:{dp}"])
            rule = rc == 0
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
    rc, _, _ = run(["ip", "link", "show", name])
    if rc == 0:
        if ttype in ("vxlan", "gre"):
            rc2, out2, _ = run(["ovs-vsctl", "list-br"])
            up = name in out2.split()
        else:
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


def _default_iface_name():
    """Default-route interface from /proc/net/route (pure file read, no subprocess)."""
    with open("/proc/net/route") as f:
        next(f, None)  # header row
        for line in f:
            p = line.split()
            if len(p) > 3 and p[1] == "00000000" and int(p[3], 16) & 2:  # RTF_GATEWAY
                return p[0]
    return None


def _read_net(cfgs):
    """Per-tunnel + whole-node RX/TX byte counters. sit -> the config name is the netdev;
    vxlan/gre -> veth{id}b (the tunnel_ip-bearing leg). Keyed by config name; portfw excluded."""
    raw = _proc_net_dev()
    net = {}
    for c in cfgs:
        t, nm, tid = c.get("type"), c.get("name"), str(c.get("id"))
        if t == "portfw" or not nm:
            continue
        iface = nm if t == "sit" else "veth" + tid + "b"
        v = raw.get(iface)
        if v:
            net[nm] = v
    pi = _default_iface_name()
    if pi and pi in raw:
        net["_node"] = raw[pi]
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
# longer find us — so we phone home. We learn the panel's address purely from its INCOMING requests
# (it stamps X-Central-Port; the source IP is the address it reached us from), never at install time.
# When our IP set changes we POST /api/checkin so the panel can fix our host and heal the tunnels.

def note_central(ip, port):
    global _central_cb
    try:
        p = int(port)
    except (TypeError, ValueError):
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
        stats["net"] = _read_net(cfgs)   # per-tunnel + node byte counters (skipped if unreadable — never fails ping)
    except Exception:
        pass
    return {"ok": True, "agent": "tnl-node", "version": 6, "ready": True,
            "hostname": socket.gethostname(), "ips": all_ips(), "sha256": _SELF_SHA,
            "ovs": run(["ovs-vsctl", "--version"])[0] == 0,
            "tunnels": len([c for c in cfgs if c.get("type") != "portfw"]),
            "portfw": len([c for c in cfgs if c.get("type") == "portfw"]),
            "stats": stats}


def op_list(d):
    cfgs = public_configs()  # O(1): configs are read fresh, health comes from the background snapshot
    with _health_lock:
        hc = dict(_health_cache)
    return {"configs": cfgs, "health": {c["name"]: hc.get(c["name"], {"up": None}) for c in cfgs}}


def op_tunnel(d):
    """Create ONE side of a node<->node tunnel (central calls this on both nodes)."""
    _require(d, ["type", "self_ip", "peer_ip", "subnet"])
    ttype = d["type"]
    if ttype not in ("vxlan", "gre", "sit"):
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
    write_config(name, obj)
    try:
        apply_config(obj)
    except Exception as e:
        return {"ok": False, "msg": str(e)}
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
    interval = 0 if len(ips) == 1 else int(d.get("interval_min", 5)) * 60
    for c in raw_configs():
        if c.get("type") == "portfw" and c.get("iface") == iface and str(c.get("listen_port")) == lp:
            raise ValueError(f"port {lp} on {iface} is already forwarded (delete it first)")
    tid = int(d.get("id") or 0) or (max(used_ids(), default=41) + 1)
    name = f"portfw{tid}"
    if os.path.exists(os.path.join(CONFIG_DIR, name + ".json")):
        raise ValueError("no free name")
    obj = {"name": name, "type": "portfw", "id": tid, "iface": iface, "listen_port": lp,
           "dst_ips": ips, "dst_port": dp, "switch_interval": interval,
           "current_index": 0, "last_switch": int(time.time())}
    write_config(name, obj)
    try:
        build_portfw(obj)
    except Exception as e:
        return {"ok": False, "msg": str(e)}
    return {"ok": True, "name": name}


def op_portfw_edit(d):
    """Edit an existing port-forward IN PLACE (keeps its name): ports, dst IPs, rotation on/off."""
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
    for c in raw_configs():  # a DIFFERENT forward must not already own this iface+listen_port
        if (c.get("name") != old["name"] and c.get("type") == "portfw"
                and c.get("iface") == iface and str(c.get("listen_port")) == lp):
            raise ValueError(f"port {lp} on {iface} is already forwarded")
    teardown_config(old)  # clear the OLD iptables rules (old iface/port/ips) before writing the new set
    idx = int(old.get("current_index", 0) or 0)
    if idx >= len(ips):
        idx = 0
    obj = {"name": old["name"], "type": "portfw", "id": old.get("id"), "iface": iface,
           "listen_port": lp, "dst_ips": ips, "dst_port": dp, "switch_interval": interval,
           "current_index": idx, "last_switch": int(time.time())}
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


OPS = {"ping": op_ping, "list": op_list, "check": op_check, "tunnel": op_tunnel,
       "portfw": op_portfw, "portfw-edit": op_portfw_edit, "portfw-next": op_portfw_next,
       "delete": op_delete, "apply": op_apply, "update": op_update, "wipe": op_wipe}
READ_ONLY = {"ping", "list", "check"}

# ----------------------------------------------------------------------------- HTTP

class Handler(BaseHTTPRequestHandler):
    server_version = "tnl-node"

    def log_message(self, *a):
        pass

    def _authed(self):
        tok = self.headers.get("X-Node-Token", "")
        want = self.server.conf.get("token", "")
        return bool(tok) and bool(want) and hmac.compare_digest(tok, want)

    def _send(self, code, body):
        data = json.dumps(body).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(data)

    def _body(self):
        try:
            n = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            n = 0
        n = min(max(n, 0), 1048576)   # 1MB — headroom for a pushed agent source (JSON-escaped)
        raw = self.rfile.read(n) if n > 0 else b""
        try:
            obj = json.loads(raw.decode()) if raw else {}
        except Exception:
            return {}
        return obj if isinstance(obj, dict) else {}   # a top-level array/string/number must not reach ops as non-dict

    def _handle(self, method):
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
        d = self._body() if method == "POST" else {}
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
    print("[*] Installing dependencies (openvswitch-switch, iptables)...")
    env = dict(os.environ, DEBIAN_FRONTEND="noninteractive")
    try:
        subprocess.run(["apt-get", "update", "-qq"], env=env, timeout=300)
        subprocess.run(["apt-get", "install", "-yqq", "openvswitch-switch", "iptables"], env=env, timeout=600)
    except Exception as e:
        print(f"[!] apt failed: {e}")
    print("[✔] openvswitch ready." if run(["ovs-vsctl", "--version"])[0] == 0
          else "[!] openvswitch not available - VXLAN/GRE need it (SIT still works).")


def write_service():
    with open(SERVICE_FILE, "w") as f:
        f.write(f"""[Unit]
Description=tnl node agent
After=network-online.target openvswitch-switch.service
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
