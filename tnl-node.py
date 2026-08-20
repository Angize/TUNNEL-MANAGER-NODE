#!/usr/bin/env python3
# tnl-node — self-contained node agent for the tnl central control plane.
#
# Installed on every NODE server. It builds tunnels itself (native kernel netdevs, iptables
# port-forwards), re-applies them on boot and rotates port-forward destinations, all in-process. Every
# operation is driven by the central panel over a token-authenticated API. Needs python3, iproute2
# and iptables; every tunnel is a native kernel netdev.
#
# Usage:
#   sudo python3 tnl-node.py --install         # set port + generate token, install+start the service
#   sudo python3 tnl-node.py --auto-install P  # non-interactive install on port P (panel provisioning)
#   sudo python3 tnl-node.py --show            # print host / port / token for the central panel
#   sudo python3 tnl-node.py                   # run (used by systemd): re-apply configs, then serve
#
# Auth: the panel SIGNS every request -- X-Ctr + X-Body + X-Sig, an HMAC keyed on this node's token
# over the method, path, counter and body hash. The token itself never crosses the wire, in either
# direction, and a captured request cannot be replayed. Plain HTTP -- expose the agent port to the
# central server only.

import base64
import errno
import hashlib
import hmac
import ipaddress
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
INSTALLED = os.path.join(CONFIG_DIR, "tnl-node.py")  # stable path the systemd unit points at

# The custom Go data-plane core (packet/core): a static binary the PANEL delivers by pushing verified
# bytes to the node (op core-install). The node never downloads it itself — nodes may have no internet
# (e.g. an Iran node), so the panel is the single source and stages/relays the binary. The node only
# verifies the pushed sha256 and supervises the binary via systemd-run.
CORE_BIN = os.path.join(CONFIG_DIR, "tnl-core")
_core_lock = threading.Lock()  # serialize replace of the shared core binary
_core_sha_cache = {"mtime": None, "sha": ""}  # avoid re-hashing the 3 MB binary on every ping
_core_sha_lock = threading.Lock()  # guard the mtime/sha cache RMW (ping loop vs install thread)
OBFS_DATA_PAD_MAX = 64   # must match the core's obfsDataPadMax so the MTU budget covers worst-case padding

NAME_RE = re.compile(r"^[A-Za-z0-9_]+$")
IFACE_RE = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.@-]*$")  # no leading '-' → can't be mistaken for a CLI flag (arg-injection guard)

MAX_CONNS = 64                  # cap concurrent request handlers so an unauth slowloris can't exhaust root threads
_conn_sem = threading.BoundedSemaphore(MAX_CONNS)
_apply_lock = threading.Lock()  # serialize all state mutations (API writes + rotation thread)
_restart_pending = threading.Event()  # set once op_update swaps the binary → reject NEW mutating ops until the bounce
_central_cb = None              # (ip, port, tls) the panel announces → where we call back /api/checkin
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


def derive_tunnel_ip(ttype, subnet, host):
    """This end's overlay address. `host` is 1 or 2 and comes from the PANEL, which gives .1 to the
    server and .2 to the client; the node does not choose. Deriving it here from the two public IPs made
    the overlay address depend on which provider handed out the larger address, and the two ends had to
    agree on that by luck rather than by being told."""
    parts = subnet.split("/")
    base = parts[0]
    prefix = parts[1] if len(parts) > 1 else ("64" if ttype == "sit" else "24")   # never IndexError on a prefix-less subnet
    # ONE branch for both families: host 1 and 2 are the first two addresses of the network, whatever its
    # size. v4 used to string-splice the last octet, which only worked while every tunnel owned a whole
    # /24 -- it would have silently produced an address outside a /30.
    net = ipaddress.ip_network(f"{base}/{prefix}", strict=False)
    return f"{net.network_address + host}/{net.prefixlen}"

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
    name = f"core{tid}" if ttype == "core" else f"native{tid}"
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
    default-route iface.

    A NAMED dev that cannot be read RAISES. Falling back to 1500 there hands the tunnel an MTU its
    underlay cannot carry, and nothing downstream can tell that apart from a genuine 1500 link. With
    no dev asked for there is nothing better than 1500, so that fallback stays."""
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


# --- Host network tuning; the core-side SO_*BUF is the other half of the throughput work ---
# OPT-IN, operator-triggered from the panel — NOT at install or startup, because it changes host-wide
# behaviour. BBR does not collapse on the loss and RTT of the Iran path the way CUBIC does, fq gives it
# pacing, and the raised ceilings let the TCP carriers autotune. TUNING_PREV is what revert restores.
TUNING_DROPIN = "/etc/sysctl.d/99-angize-tuning.conf"
TUNING_MODLOAD = "/etc/modules-load.d/angize-bbr.conf"  # ensure tcp_bbr is loaded before systemd-sysctl at boot
TUNING_PREV = os.path.join(CONFIG_DIR, "tuning_prev.json")  # original CC+qdisc, for a faithful revert
KERNEL_TUNING = [
    ("net.core.default_qdisc", "fq"),
    ("net.core.rmem_max", "16777216"),
    ("net.core.wmem_max", "16777216"),
    ("net.core.netdev_max_backlog", "16384"),
    ("net.ipv4.tcp_rmem", "4096 131072 16777216"),
    ("net.ipv4.tcp_wmem", "4096 65536 16777216"),
    ("net.ipv4.tcp_mtu_probing", "1"),  # PLPMTUD: survive an ICMP-black-holed path without a stall
]


def _sysctl_get(key):
    """Read a sysctl value (whitespace-normalised) or '' on failure."""
    try:
        with open("/proc/sys/" + key.replace(".", "/")) as f:
            return " ".join(f.read().split())
    except Exception:
        return ""


def _bbr_available():
    """True if bbr can be selected. Reports from the kernel's available-CC list, loading the
    tcp_bbr module first ONLY when it is not already present — so on a built-in / already-loaded
    kernel this is a pure read (no fork), and a status poll stays cheap and side-effect-free."""
    if "bbr" in _sysctl_get("net.ipv4.tcp_available_congestion_control").split():
        return True
    run(["modprobe", "tcp_bbr"])
    return "bbr" in _sysctl_get("net.ipv4.tcp_available_congestion_control").split()


def tuning_active():
    """True when tuning is currently applied. Keyed on the saved-originals file (TUNING_PREV), not
    the persist drop-in: TUNING_PREV is written before any live change and removed only by revert,
    so it is a reliable 'is on' marker even if the drop-in failed to write or was deleted by hand."""
    return os.path.isfile(TUNING_PREV)


def tuning_status():
    """Snapshot for the panel button: whether tuning is on, the live CC+qdisc, and whether bbr
    can be selected. bbr_available goes through _bbr_available() (which modprobes tcp_bbr first) so
    the button reflects what apply would actually achieve — otherwise a box whose bbr module is not
    yet loaded would report false and the panel would wrongly disable an enable that would succeed."""
    return {
        "active": tuning_active(),
        "cc": _sysctl_get("net.ipv4.tcp_congestion_control"),
        "qdisc": _sysctl_get("net.core.default_qdisc"),
        "bbr_available": _bbr_available(),
    }


def apply_kernel_tuning():
    """Apply the host tuning live and persist it for reboot. Idempotent. Returns None on success, or
    an error string when the originals could NOT be recorded — in which case NOTHING is changed. The
    invariant "TUNING_PREV exists iff tuning is applied" must hold or revert can't restore the box, so
    the save is mandatory and atomic (a failed/partial write must not leave the host tuned-but-not-
    recorded, nor let a later re-apply capture the already-tuned values as the 'original')."""
    if not tuning_active():  # first enable: record the originals DURABLY before touching anything live
        prev = {"cc": _sysctl_get("net.ipv4.tcp_congestion_control"),
                "qdisc": _sysctl_get("net.core.default_qdisc")}
        err = _atomic_write_json(TUNING_PREV, prev)
        if err:
            logline(f"kernel tuning: could not save originals, NOT applying: {err}")
            return err  # abort — never mutate live sysctls without a restore point
    knobs = list(KERNEL_TUNING)
    bbr = _bbr_available()
    if bbr:
        knobs.append(("net.ipv4.tcp_congestion_control", "bbr"))
    else:
        logline("kernel tuning: bbr unavailable — leaving the default congestion control")
    for k, v in knobs:
        run(["sysctl", "-w", f"{k}={v}"])  # spaces in v (tcp_rmem) stay in one argv element = OK
    if bbr:  # systemd-sysctl won't modprobe at boot, so preload the CC module or the drop-in's bbr line is rejected
        try:
            with open(TUNING_MODLOAD, "w", encoding="utf-8") as f:
                f.write("tcp_bbr\n")
        except Exception as e:
            logline(f"kernel tuning modules-load: {e}")
    try:  # ASCII-only header + explicit utf-8: this file is written under the service's (C) locale
        body = ["# Angize node tuning (part B) - managed by tnl-node; toggle from the panel to revert.\n"]
        body += [f"{k} = {v}\n" for k, v in knobs]
        with open(TUNING_DROPIN, "w", encoding="utf-8") as f:
            f.writelines(body)
    except Exception as e:
        logline(f"kernel tuning persist: {e}")
    return None


def revert_kernel_tuning():
    """Turn tuning off: restore the originally-recorded congestion control + qdisc live and remove
    the persisted drop-in so a reboot stays reverted. A no-op when nothing was applied (no
    TUNING_PREV) so a stray/double revert can NOT clobber a box the admin tuned by hand down to some
    invented default. Only the exact recorded values are pushed. The raised buffer CEILINGS are left
    in place — a larger ceiling is harmless (nothing forces a socket to use it) and we cannot know
    the box's original values, so restoring them would be a guess."""
    if not tuning_active():  # nothing recorded to restore — never invent defaults over a live box
        for p in (TUNING_DROPIN, TUNING_MODLOAD):
            try:
                if os.path.isfile(p):
                    os.remove(p)  # defensive: clear any orphan persist files
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
    """Shared tail of every kernel-tunnel builder: assign the tunnel IP (v6 for a SIT 6in4
    tunnel), bring the interface up, and set the MTU = base minus this carrier's header overhead."""
    addr = ["ip", "-6", "addr", "add", cfg["tunnel_ip"], "dev", name] if v6 else ["ip", "addr", "add", cfg["tunnel_ip"], "dev", name]
    must(addr)
    must(["ip", "link", "set", name, "up"])
    must(["ip", "link", "set", "dev", name, "mtu", str(base_mtu(cfg.get("iface")) - overhead)])


def build_vxlan(cfg):
    """Native kernel VXLAN (UDP 4789) — point-to-point to the peer, tunnel IP assigned directly.
    No OpenvSwitch/veth: one netdev per tunnel, same as ipip/sit. VNI == tunnel id (symmetric both ends)."""
    name = cfg["name"]
    _modprobe("vxlan")   # `ip link add type vxlan` does not auto-load the module
    run(["ip", "link", "del", name])
    dstport = int(cfg.get("port") or 4789)   # UDP port is now settable (default 4789) — e.g. to dodge a filter
    must(["ip", "link", "add", name, "type", "vxlan", "id", str(cfg["id"]),
         "local", cfg["local_ip"], "remote", cfg["remote_ip"], "dstport", str(dstport)])
    _up_netdev(name, cfg, 50)  # IP20+UDP8+VXLAN8+innerEth14


def build_gre(cfg):
    """Native kernel GRE (proto 47) — point-to-point, tunnel IP assigned directly. GRE key == tunnel id."""
    name = cfg["name"]
    _modprobe("ip_gre")   # `ip link add type gre` does not auto-load the module
    run(["ip", "link", "del", name])
    must(["ip", "link", "add", name, "type", "gre",
         "local", cfg["local_ip"], "remote", cfg["remote_ip"], "key", str(cfg["id"])])
    _up_netdev(name, cfg, 28)  # IP20+GRE4+key4


def build_sit(cfg):
    name = cfg["name"]
    run(["ip", "link", "del", name])
    must(["ip", "tunnel", "add", name, "mode", "sit", "remote", cfg["remote_ip"],
         "local", cfg["local_ip"], "ttl", "255"])
    _up_netdev(name, cfg, 20, v6=True)  # SIT = 6in4 (proto 41): outer IPv4 header only, 20 bytes


def build_ipip(cfg):
    """IPv4-in-IPv4 — the lightest L3 tunnel (20-byte overhead). Same shape as SIT but v4."""
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
    _up_netdev(name, cfg, 54)


def _fou_port(cfg):
    return int(cfg.get("port") or 20000)


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
    _up_netdev(name, cfg, 28)


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
    _up_netdev(name, cfg, 80)


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
        # Hold the lock across the whole read-modify-write so a concurrent caller (the health
        # ping loop vs. the install thread) can't observe a torn cache — sha updated without its
        # matching mtime, or two threads both hashing and interleaving their two writes.
        with _core_sha_lock:
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
    return int(cfg.get("port") or 20000)


# Carrier-header bytes each raw encapsulation profile prepends, mirroring the core's rawHeaderLens.
RAW_HEADER_LEN = {"bare": 0, "ipip": 0, "etherip": 2, "ipcomp": 4, "gre": 4, "icmp": 8, "udp": 8,
                  "esp": 8, "l2tpv3": 8, "tcp": 32, "ah": 24}  # tcp = 20 + NOP,NOP,Timestamp(10)
# The most TUN queues one tunnel may take, mirroring the core's maxWorkers. The core clamps silently, so
# refusing here is what makes an out-of-range request visible instead of quietly halved.
MAX_WORKERS = 4
# The carriers that drain every queue they are given, mirroring the core's queueingCarrier. Sending the
# key to any other carrier is a setting the wire ignores.
QUEUEING_TRANSPORTS = ("raw", "udp")

_TUNING_INT_KEYS = ("dead_retest_secs",
                    # flux_rotate_default_secs intentionally omitted: every flux tunnel carries an explicit
                    # flux_rotate_secs, so the core's tuned default is unreachable; the panel offers no knob either.
                    "ping_loss_threshold", "min_liveness_secs", "probe_timeout_secs")


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


def _ordered_pool(primary, extras):
    """Build a rotation pool: `primary` first, then `extras`, each reduced to a bare IPv4 (any
    accidental :port stripped), de-duplicated preserving first-seen order, blanks dropped. Used for
    both the destination pool (remote_ip + peer_ips) and the source pool (local_ip + src_ips)."""
    seen, ordered = set(), []
    for x in [primary] + [str(v) for v in (extras or [])]:
        ip = str(x).strip().split(":", 1)[0].strip()
        if ip and ip not in seen:
            seen.add(ip)
            ordered.append(ip)
    return ordered


def _core_config(cfg):
    """Pure: build the JSON the core binary consumes from a stored tunnel config. The tun device is
    named after the config so /proc/net/dev accounting and `ip link show <name>` health work unchanged.
    Crypto is on whenever a psk is present; the psk never leaves the node (public_configs pops it)."""
    name = cfg["name"]
    port = _core_port(cfg)
    cipher = str(cfg.get("cipher") or "auto")   # match the panel's default so the MTU/crypto sizing agrees
    crypto_on = bool(cfg.get("psk")) and cipher != "none"  # a psk with cipher=none is NOT encryption
    transport = str(cfg.get("transport") or "udp").lower()
    raw_profile = str(cfg.get("raw_profile") or "bare").lower()
    obfs = bool(cfg.get("obfs")) and crypto_on   # obfs is meaningless without the AEAD key
    # MTU budget = outer headers + core framing + obfs padding + AEAD (nonce+tag) + wire mask salt.
    flux_carrier = str(cfg.get("flux_carrier") or "udp").lower()
    if transport == "raw":
        # IP20 + the profile's carrier header. A COPY of the core's rawHeaderLens; a profile missing here
        # silently under-counts the overhead and every full-size packet fragments, so
        # TUNNEL-MANAGER/tools/tuning_consistency.py compares the two tables.
        outer = 20 + RAW_HEADER_LEN.get(raw_profile, 0)
    elif transport == "spoof":
        # Spoof forges the whole outer IPv4 header itself (IP_HDRINCL), bare-like: IP20, no L4 header.
        outer = 20
    elif transport == "flux":
        # IP20 + the carrier header. Both carriers ride UDP, so 8 is the floor. stun is NOT 8+20:
        # buildSTUN wraps the frame as a STUN attribute, so the real cost is UDP 8 + STUN header 20 +
        # attribute header 4 + the 4-byte alignment pad (0..3). Under-counting makes the crafted IPv4
        # packet exceed the egress MTU, and an oversize IP_HDRINCL send is refused with EMSGSIZE.
        outer = 20 + (8 + 20 + 4 + 3 if flux_carrier == "stun" else 8)
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
    # FEC (datagram carriers: udp/raw/flux/spoof) prepends an 11-byte block header + a 2-byte
    # shard-len to every data shard, so it costs 13 bytes of usable payload per packet.
    if transport in ("udp", "raw", "flux", "spoof") and bool(cfg.get("fec")):
        overhead += 13
    # The TUN MTU must never EXCEED the carrier budget, or datagram carriers fragment/black-hole on a
    # small underlay (PPPoE 1492 / IPv6-min 1280): floor 1280 could hand out MORE than base-overhead.
    # Sample the tunnel's own egress iface, and clamp only at a safe small minimum, never raising above budget.
    mtu = max(576, base_mtu(cfg.get("iface")) - overhead)
    if transport == "dns":
        # The dns carrier rides a reliable KCP stream that fragments internally across many tiny DNS
        # datagrams, so the per-datagram DNS/AEAD overhead is NOT a per-packet header to subtract. A
        # fixed, conservative MTU keeps each L3 packet to a few datagrams and avoids underlay issues.
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
    # Operator-tuned operational timings (self-heal / pool-health): pass the panel's `tuning` object
    # through to the core, which clamps every value. Keep it type-clean here (ints, and an int list for
    # the backoff schedule) so a malformed field can't reach the core config; the core defaults any
    # field we omit. Applies to both roles (idle/ping-loss are server-side too).
    _tn = _core_tuning(cfg.get("tuning"))
    if _tn:
        corecfg["tuning"] = _tn
    # Datagram socket-buffer size in bytes (udp/raw/flux only; the core ignores it elsewhere). Absent
    # leaves the core's own 4 MiB default; a negative value is its "leave the kernel default" sentinel,
    # so 0 is NOT a valid passthrough and is treated as "not set".
    _sb = int(cfg.get("sock_buf") or 0)
    if _sb:
        corecfg["sock_buf"] = _sb
    # TLS cover (HTTPS camouflage) — TCP only; carries an optional SNI to present.
    if bool(cfg.get("cover")) and transport == "tcp" and crypto_on:
        corecfg["cover"] = True
        sni = str(cfg.get("cover_sni") or "").strip()
        if sni:
            corecfg["cover_sni"] = sni
    # Datagram (udp/raw/flux) and direct-stream (tcp, tcp+cover) transports have no ws edge pool, but they
    # still write a self-heal event ring and startup configuration warnings to a status file we expose to
    # the panel's log. This is `status_path`, NOT `ws_status_path`, so _is_ws_pool keeps telling a pool core
    # apart from a plain one. BOTH ends get one: a server raises config warnings of its own, and only that
    # end can see them. Liveness is not in here — the tun probe decides that.
    if transport in ("udp", "tcp", "raw", "flux", "spoof", "dns"):
        corecfg["status_path"] = _cfg_path(name, ".status")
    # peer_src_ips (raw/flux SERVER): the client's source pool. These carriers receive on a socket that
    # sees every host and pre-filter by the learned peer source, so a rotated client source is otherwise
    # dropped pre-crypto and never re-learned — the tunnel dies on a source rotation until a rebuild.
    # udp/tcp bind per-source and re-learn on their own.
    if transport in ("raw", "flux") and str(cfg.get("role")) == "server":
        _psrc = [str(x).strip() for x in (cfg.get("peer_src_ips") or []) if is_ipv4(str(x).strip())]
        if _psrc:
            corecfg["peer_src_ips"] = _psrc
    if transport == "raw":
        corecfg["raw_profile"] = raw_profile
        # bare-only: override the outer IP protocol number (bare, no L4 header) to slip past a
        # protocol whitelist — e.g. 58 (ICMPv6). 0/absent keeps bare's native 253.
        try:
            _rp = int(cfg.get("raw_proto") or 0)
        except (TypeError, ValueError):
            _rp = 0
        if raw_profile == "bare" and 1 <= _rp <= 255:
            corecfg["raw_proto"] = _rp
        # udp/tcp only: the SERVER port stamped on the forged L4 header. No socket binds it; it is what
        # a middlebox reads, and the default 443 makes the udp profile look like QUIC.
        try:
            _rport = int(cfg.get("raw_port") or 0)
        except (TypeError, ValueError):
            _rport = 0
        if raw_profile in ("udp", "tcp") and 1 <= _rport <= 65535:
            corecfg["raw_port"] = _rport
        # udp/tcp only: roll the CLIENT's forged SOURCE port for the life of the tunnel instead of the
        # one constant, so a stateful box cannot burn a single 4-tuple and take the carrier with it.
        if raw_profile in ("udp", "tcp") and _as_bool(cfg.get("raw_sport_random")):
            corecfg["raw_sport_random"] = True
    if transport in QUEUEING_TRANSPORTS:
        # Extra TUN queues, so a tunnel's packets are read and written by several goroutines instead of
        # queueing behind one file's lock. NOT with FEC: its decoder rebuilds a block out of consecutive
        # frames, and the core gates its own queue count on the same pair. 0/1 = absent, which is the
        # core's single-queue default.
        try:
            _wk = int(cfg.get("workers") or 0)
        except (TypeError, ValueError):
            _wk = 0
        if 2 <= _wk <= MAX_WORKERS and not bool(cfg.get("fec")):
            corecfg["workers"] = _wk
    if transport == "spoof":
        # The spoof carrier is bare-like (no raw_profile — the core forces it); it only carries the
        # optional outer IP protocol number override, exactly like a bare raw carrier.
        try:
            _rp = int(cfg.get("raw_proto") or 0)
        except (TypeError, ValueError):
            _rp = 0
        if 1 <= _rp <= 255:
            corecfg["raw_proto"] = _rp
    if transport == "dns":
        # DNS-tunnel carrier: the delegated zone (server is its authoritative NS) and, on the
        # client, the recursive resolvers to query (typically DOMESTIC resolvers so the client
        # never sends a packet to the server IP). Crypto is mandatory (validated in the core).
        corecfg["dns_zone"] = str(cfg.get("dns_zone") or "").strip().lower()
        if cfg.get("role") == "client":
            corecfg["dns_resolvers"] = [str(x).strip() for x in (cfg.get("dns_resolvers") or []) if str(x).strip()]
    if transport == "flux":
        # flux is a distinct transport (not a raw_profile): carrier, shape profile,
        # epoch length and a manual epoch offset are all it needs — both ends derive
        # the rotating shape from the PSK + clock (+ offset), no on-wire negotiation.
        corecfg["flux_carrier"] = flux_carrier
        # Clamp to the same 10..86400 range op_tunnel validation enforces, so a value reaching the
        # core is always in-range even if op_tunnel was bypassed (the core only rejects <0). The
        # clamp also neutralizes a stored negative that `... or 600` would pass through as truthy.
        corecfg["flux_rotate_secs"] = max(10, min(86400, int(cfg.get("flux_rotate_secs") or 600)))
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
        # One field for the SHAPE this CDN-frontable carrier takes: ws | http | grpc. The http shape carries
        # the stream over a GET(down)+POST(up) request pair instead of a WebSocket upgrade, so it passes a
        # CDN or account that blocks WebSocket. Both roles need it — the server serves the endpoint, the
        # client dials it — and the same fronting fields (ws_host/ws_tls/ws_ech/ws_path) apply.
        cdn = str(cfg.get("cdn_carrier") or "ws").strip().lower()
        if cdn in ("http", "grpc"):
            corecfg["cdn_carrier"] = cdn
            # The CDN carrier shape: "http" (a POST ladder — many short POSTs, the most CDN-compatible) or
            # "grpc" (a single full-duplex request dressed as a real gRPC call, so a CDN reaches the origin
            # over h2c and streams instead of buffering; needs ws_tls). Forwarded for both roles: the core
            # server auto-detects the client's style, but the client must be told.

            # Upstream shape — the http-carrier CLIENT only. The server never POSTs, and the core
            # REJECTS these on a server or in grpc mode, so emitting them there would refuse to
            # build the tunnel rather than be ignored.
            if cfg.get("role") == "client" and cdn == "http":
                for _k in ("http_up_workers", "http_up_batch_kb", "http_up_rate"):
                    try:
                        _v = int(cfg.get(_k) or 0)
                    except (TypeError, ValueError):
                        _v = 0
                    if _v > 0:
                        corecfg[_k] = _v
        # Only the CLIENT speaks wss (TLS to the CDN edge); the server stays plain — the CDN
        # terminates TLS and forwards the WebSocket to the origin. Never emit ws_tls server-side.
        if bool(cfg.get("ws_tls")) and cfg.get("role") == "client":
            corecfg["ws_tls"] = True
            # SNI fragmentation: split the wss ClientHello so the cleartext SNI crosses a TCP segment
            # boundary — a stateless SNI-blocklist DPI can't match the full hostname. Cheap complement
            # to ECH (which hides the SNI entirely). Applies to both single-edge and pool ws/http.
            # split_pos is the byte offset into the ClientHello (0 = auto: middle of the hostname).
            if bool(cfg.get("sni_split")):
                corecfg["sni_split"] = True
                sp = int(cfg.get("split_pos") or 0)
                if sp:
                    corecfg["split_pos"] = max(0, min(1400, sp))
                # mode: "split" (in-order, the default and so never forwarded), "disorder" (low-TTL head
                # desyncs a reassembling DPI) or "fake" (a decoy ClientHello with a substituted SNI, killed
                # before the server by a bad TCP checksum). The line below accepts all three non-default
                # modes; the comment used to name only two, so "fake" read like something core-only.
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
            if ips and snis:  # rotating pool — works for both the ws and http carriers
                corecfg["ws_edge_ips"] = ips
                corecfg["ws_edge_snis"] = [{"host": str(s["host"]).strip(),
                                         "ech": str(s.get("ech") or "").strip(),
                                         "path": str(s.get("path") or "").strip()} for s in snis]
                _wrs = cfg.get("ws_rotate_secs")   # 0 = rotation OFF (failover-only); a truthiness `or 600` would wrongly force 600
                corecfg["ws_rotate_secs"] = 600 if _wrs is None else max(0, min(28800, int(_wrs)))
                corecfg["ws_status_path"] = _cfg_path(name, ".status")
    # FEC (forward error correction): reconstructs lost carrier datagrams from parity so a
    # throttled/high-loss link stays usable. Datagram carriers only (udp/raw/flux/spoof) — on
    # tcp/ws it's wasted (TCP is already reliable), so it's only forwarded for those.
    if transport in ("udp", "raw", "flux", "spoof") and bool(cfg.get("fec")):
        corecfg["fec"] = True
        corecfg["fec_data"] = int(cfg.get("fec_data") or 10)
        corecfg["fec_parity"] = int(cfg.get("fec_parity") or 3)
    if bool(cfg.get("gso")):     # TUN segmentation offload — local throughput optimization
        corecfg["gso"] = True
    # IP spoofing (the spoof transport, crypto only): forge the outer source and/or the destination
    # (a decoy). The client puts the decoy in the header dst while still routing to the real server;
    # the server then receives those frames via AF_PACKET and answers AS the decoy, so it must be told
    # the client's real IP (remote_ip) to reply to — the forged source hides it from the wire.
    if transport == "spoof" and crypto_on:
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
            # The client's real IP is never on the wire (forged source, or a decoy dst), so the server
            # is always told it — regardless of which field the client forged.
            corecfg["real_peer_ip"] = cfg["remote_ip"]
    # Fake-packet desync (client): the core emits decoy packets to mis-sync a stateful DPI without
    # touching the real session. raw/flux/spoof forge whole IPv4 packets; tcp/ws INJECT decoy TCP
    # segments on the kernel connection's 4-tuple (AF_PACKET). Plain udp has no such hook. Decoys are
    # separate packets, not extra per-frame overhead, so they cost no MTU budget.
    if transport in ("raw", "flux", "spoof", "tcp", "ws") and cfg.get("role") == "client" and bool(cfg.get("fake_desync")):
        corecfg["fake_desync"] = True
        corecfg["fake_ttl"] = max(1, min(255, int(cfg.get("fake_ttl") or 4)))
        corecfg["fake_count"] = max(1, min(64, int(cfg.get("fake_count") or 2)))
        mode = str(cfg.get("fake_mode") or "ttl").strip().lower()
        corecfg["fake_mode"] = mode if mode in ("ttl", "badsum", "both") else "ttl"
    # Destination rotation pool (client, direct transports udp/tcp/raw/flux): cycle the foreign node's IPs
    # and burn a blocked one. The primary remote_ip goes FIRST, so the pool's starting endpoint matches the
    # single `peer` the core also dials; then dedup and format per transport — udp/tcp dial "ip:port",
    # raw/flux address a bare IP. A pool of >=2 overrides the single peer.
    if transport in ("udp", "tcp", "raw", "flux") and str(cfg.get("role")) == "client":
        ordered = _ordered_pool(str(cfg.get("remote_ip") or ""), cfg.get("peer_ips"))
        if len(ordered) >= 2:
            corecfg["peer_ips"] = [f"{ip}:{port}" if transport in ("udp", "tcp") else ip for ip in ordered]
            corecfg["peer_rotate_secs"] = max(0, int(cfg.get("peer_rotate_secs") or 0))
            corecfg["peer_status_path"] = _cfg_path(name, ".peerpool")
        # Source rotation pool (client): this node's OWN IPs to send FROM, cycled alongside peer_ips. local_ip
        # goes first so the pool's start matches the client's default source; bare IPv4 for every carrier. The
        # core gate is >=1, not >=2, and deliberately so: a LONE src_ip is a fixed source that supersedes
        # bind_ip. Gate on the operator having actually chosen sources, not on the pool length.
        _src_sel = [str(x).strip() for x in (cfg.get("src_ips") or []) if str(x).strip()]
        sord = _ordered_pool(str(cfg.get("local_ip") or ""), _src_sel)
        if _src_sel and sord:
            corecfg["src_ips"] = sord
            corecfg.setdefault("peer_rotate_secs", max(0, int(cfg.get("peer_rotate_secs") or 0)))
            # The source pool writes its own live state / pin cmd file so the panel can show and pin both
            # sides (destination = .peerpool, source = .srcpool).
            corecfg["src_status_path"] = _cfg_path(name, ".srcpool")
    if cfg.get("role") == "server":
        # Bind to THIS node's physical IP for the tunnel, not 0.0.0.0. With several IPs on the host this is
        # required for the raw transport: a raw, portless socket bound to 0.0.0.0 replies from the primary IP,
        # so a second tunnel on a secondary IP would send from the wrong source and the client, which filters
        # by peer IP, drops every reply. The exact listen IP also demuxes cleanly by destination.
        lip = cfg.get("local_ip") or "0.0.0.0"
        # EXCEPTION — under a destination rotation pool the client dials THIS server across several of its
        # selected IPs, so a single concrete bind makes the server DEAF to every other pool IP. udp/tcp bind
        # EACH one explicitly (correct reply source, and accept only on pool IPs); raw must bind 0.0.0.0, since
        # its socket is demuxed by DESTINATION, and answers from the dialed IP via IP_PKTINFO. flux is exempt.
        pool_ips = [str(x).strip() for x in (cfg.get("listen_ips") or []) if str(x).strip()]
        pooled = bool(cfg.get("pool_listen"))
        if transport == "dns":
            corecfg["listen"] = f"{lip}:53"   # authoritative NS on :53 for the delegated zone
        elif pooled and transport in ("udp", "tcp") and pool_ips:
            corecfg["listen"] = f"{pool_ips[0]}:{port}"
            corecfg["listen_ips"] = [f"{ip}:{port}" for ip in pool_ips]
        elif pooled and transport == "raw":
            corecfg["listen"] = f"0.0.0.0:{port}"
        else:
            corecfg["listen"] = f"{lip}:{port}"
    elif transport == "dns":
        pass  # dns client has no peer — the core queries dns_resolvers, never the server IP
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
                # A bare edge address needs the EDGE's port, and `port` is not it: `port` is where the CDN
                # connects to US (the origin listener, typically 80), while the client talks to the edge, which
                # serves TLS on 443 and cleartext on 80. Inheriting the origin port sends a wss ClientHello to a
                # plain-HTTP :80 edge, so the tunnel works with wss OFF and breaks the moment it is turned on.
                dial, dport = edge, (443 if bool(cfg.get("ws_tls")) else 80)
        corecfg["peer"] = f"{dial}:{dport}"
        # Pin the client's outbound source to THIS node's own IP (local_ip is validated as local in
        # op_tunnel). On a host with several IPs the kernel would otherwise egress from its primary. The
        # core turns bind_ip into a ONE-ENTRY SOURCE POOL for every carrier that exposes SetSourcePool —
        # udp, raw and flux included — so on raw/flux this key is what pins the crafted header's source.
        lip = str(cfg.get("local_ip") or "").strip()
        if lip:
            corecfg["bind_ip"] = lip
    # Single-edge ws/http (not a pool): the CLIENT core writes the same self-heal event ring the
    # datagram carriers do — e.g. an in-band ECH self-heal — to a status file we expose to the panel.
    # Use status_path (NOT ws_status_path) so _is_ws_pool keeps treating it as a non-pool core (a
    # single-edge ws core installs no SIGHUP/SIGUSR handlers, so a pool-only signal would kill it).
    if (transport == "ws" and str(cfg.get("role")) == "client"
            and "ws_status_path" not in corecfg):
        corecfg["status_path"] = _cfg_path(name, ".status")
    return corecfg


def _core_unit(name):
    return "tnl-cor-" + name


def _core_last_error(name, lines=40):
    """The core's OWN reason for not coming up, read from its unit journal.

    build_core launches the core under a Restart=always unit and waits for its TUN. When the core
    REJECTS the config it exits immediately, the TUN never appears, and op_tunnel's netdev check
    fails — at which point the agent used to report «هستهٔ tnl-core روی این نود نصب/فعال نیست»,
    which is false and is most misleading in exactly the case where the true reason was one line
    away. config.go alone has ~68 distinct rejections, so mirroring them here would mean a guard per
    combination that the core can add to at any time; quoting the core instead covers all of them,
    including the ones it does not have yet.

    Returns "" when there is nothing quotable — no journalctl, unit never ran, empty output — so the
    caller keeps its old message for the case it was actually written for (the core NOT installed).

    The read is scoped to the CURRENT invocation. Without that it spanned every run the unit ever had,
    and tunnel names are recycled (core<id> over ids 1..255), so a long-dead tunnel's rejection could
    be quoted as this one's reason — with the true message ("the core is not installed") suppressed
    because something quotable was found.
    """
    unit = _core_unit(name)
    args = ["journalctl", "-u", unit, "-n", str(int(lines)), "--no-pager", "-o", "cat"]
    _, inv, _ = run(["systemctl", "show", "-p", "InvocationID", "--value", unit], timeout=10)
    inv = inv.strip()
    if inv:
        args.append("_SYSTEMD_INVOCATION_ID=" + inv)   # this boot's run of this unit, nothing older
    rc, out, _ = run(args, timeout=10)
    if rc != 0 or not out:
        return ""
    # Go's logger prefixes a date+time; every core line is tagged "tnl-core: ". Walk backwards so a
    # restart loop reports its LATEST attempt rather than the first.
    tag = "tnl-core: "
    for ln in reversed(out.splitlines()):
        i = ln.find(tag)
        if i >= 0:
            msg = ln[i + len(tag):].strip()
            if msg:
                return msg[:300]
    return ""


def _netdev_missing_reason(name, ttype):
    """Why `name`'s data path is not up, in the operator's own words — "" when the netdev is there.

    Every builder runs `ip` through run(), which never raises, so the netdev is the only proof a build
    worked. For a core tunnel its absence has THREE different causes: the core is not installed, the
    core ran and REFUSED the config (it said why — quote it), or the core is fine and its TUN has not
    appeared yet. The third is checked FIRST, because a running core's newest journal line is its
    SUCCESS line and quoting that as «پیامِ خودش» blames startup.
    """
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
    """Is the core's unit actually up right now?

    A running core did not refuse anything: op_tunnel's wait for the TUN simply ran out before the
    interface appeared, which build_core documents as a real possibility on a slow cold start. The
    journal's newest tagged line is then the core's SUCCESS line ("tnl-core 0.1.0-core: tun=… "), and
    quoting it as «پیامِ خودش» told the operator the reason the core failed was that it had started.
    Both of the other two messages are wrong here as well — it is neither missing nor refusing.
    """
    _, out, _ = run(["systemctl", "is-active", _core_unit(name)], timeout=10)
    return out.strip() in ("active", "activating")


def _cfg_path(name, suffix=""):
    """Path of a core sidecar file for tunnel `name` in CONFIG_DIR (e.g. suffix=\".status\",
    \".peerpool\", \".status.cmd\"). Centralizes the core-<name><suffix> naming used across the agent."""
    return os.path.join(CONFIG_DIR, "core-" + name + suffix)


def _atomic_write_json(path, obj):
    """Write obj as JSON to path atomically (tmp + os.replace). The core polls these command files
    once per second and deletes them, so a half-written file would be read+deleted and the command
    SILENTLY LOST. Returns None on success, or the OSError string on failure."""
    tmp = path + ".tmp"
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
    """The core's live status files for tunnel `name`: the self-heal/ws-pool status and its select-edge
    command sidecar, plus the direct-transport destination and source pool status files and their own pin
    command sidecars. Callers only iterate to clean them up, so listing all of them here means a rebuild/
    teardown never leaves stale pool state — or a leftover pin command — behind."""
    base = _cfg_path(name, ".status")
    peer = _cfg_path(name, ".peerpool")
    src = _cfg_path(name, ".srcpool")
    # base + ".echcmd" is the live-ECH push sidecar (op ech-update writes it, the core polls it). It was
    # missing here, so it alone survived rebuild/disable/delete — and a stale key file outliving the core
    # that was meant to consume it is exactly the kind of leftover this list exists to prevent.
    # base + ".verdict" is the tun probe's mailbox: it belongs to the TUNNEL, not to a pool, so a
    # pool-less core has one too and it must be swept with the rest.
    return (base, base + ".cmd", base + ".echcmd", base + ".verdict",
            peer, peer + ".cmd", src, src + ".cmd")


def _read_core_cfg(name):
    """The on-disk core config dict for `name`, or `{}` if it is missing / unreadable / not a JSON
    object. Backs the _is_* core-shape predicates below; returning `{}` (not None) on failure lets
    each caller `.get(...)` unconditionally."""
    try:
        with open(_cfg_path(name, ".json")) as f:
            cc = json.load(f)
    except (OSError, ValueError):
        return {}
    return cc if isinstance(cc, dict) else {}


def _is_ws_pool(name):
    """True if the running core for `name` is a ws edge-pool client — the ONLY core that installs
    SIGHUP/SIGUSR handlers. Signaling any other core falls through to Go's default signal
    disposition and TERMINATES the tunnel, so pool-only ops (probe-now / rotate) must guard on this."""
    cc = _read_core_cfg(name)
    return bool(cc.get("ws_status_path") or cc.get("ws_edge_ips"))


def _is_ws_single(name):
    """True if the running core for `name` is a SINGLE ws/http edge client — one fixed ws_host, no edge
    pool. Such a core reads a live ECH push into b.wsECH from its dialLoop (same <status>.echcmd sidecar
    a pool uses), so it can accept ech-update too. Needs a wired status_path for the sidecar to be read."""
    cc = _read_core_cfg(name)
    return bool(cc.get("ws_host") and cc.get("status_path")) and not (cc.get("ws_status_path") or cc.get("ws_edge_ips"))


def _is_peer_pool(name):
    """True if the running core for `name` is a direct-transport pool client (a destination and/or
    source rotation pool). Such a core installs a SIGHUP handler (probe-now) exactly like the ws pool,
    so pool-only ops must guard on this — signaling a plain core would fall through to Go's default
    disposition and TERMINATE the tunnel."""
    cc = _read_core_cfg(name)
    return bool(cc.get("peer_status_path") or cc.get("src_status_path"))


def build_core(cfg):
    """Fetch/verify the core binary, write its per-tunnel config, and (re)launch it under a transient
    systemd unit with Restart=always. Then wait for the TUN to appear so op_tunnel's verify sees it."""
    name = cfg["name"]
    _ensure_core()
    corecfg = _core_config(cfg)
    path = _cfg_path(name, ".json")
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        json.dump(corecfg, f, indent=2)
    os.chmod(tmp, 0o600)          # holds the psk -> keep it private like node.conf
    os.replace(tmp, path)
    _core_relaunch(name)


def _core_relaunch(name):
    """Launch a fresh core for `name` on the config already on disk. Returns True once its TUN is up.

    The transient unit is NOT restarted with `systemctl restart`: it is created by systemd-run with
    --collect, so a stop can take the unit definition with it. Tearing down and re-running the same
    systemd-run is the one sequence known to work, and it is the only place that sequence lives.

    The return value is the TUN, not the unit's state: `systemctl is-active` reports `activating` for
    the whole of a Restart=always crash loop, so a core that cannot start at all reads as running.
    """
    unit = _core_unit(name)
    run(["systemctl", "stop", unit])
    run(["systemctl", "reset-failed", unit])
    # Only now: a core that is still RUNNING owns its anti-leak rules, and sweeping them out from under it
    # leaves the kernel free to answer the peer with the RST / ICMP those rules exist to swallow. Once the
    # unit is stopped, an orderly core has already removed its own and whatever is left is a killed core's.
    _sweep_owned_rules(name)
    # Drop the stale status + command sidecars of the core we just stopped, so the fresh one never shows
    # its predecessor's pool state or replays a leftover "pin this edge" / "fail this destination".
    for p in _core_status_paths(name):
        try:
            os.remove(p)
        except OSError:
            pass
    run(["systemd-run", "--unit", unit, "--collect",
         "-p", "Restart=always", "-p", "RestartSec=3",
         CORE_BIN, "--config", _cfg_path(name, ".json")])
    for _ in range(80):          # up to 8s: must exceed RestartSec=3 so one restart cycle
        if os.path.exists("/sys/class/net/" + name):    # (a slow/first-launch core) isn't misread as failure
            return True
        time.sleep(0.1)
    return False


# ---------------------------------------------------------------- orphaned firewall rules
# The core removes its own anti-leak rules on Close(), which covers an orderly stop and nothing else.
# A SIGKILL, a crash or a reboot leaves them behind, and since they go in with -A and come out by
# matching their own exact spec, an orphan is invisible to the next core and a duplicate lands beside
# it. Found on the operator's boxes: a --dport 4500 rule from a tunnel that no longer existed, and the
# same ICMP rule installed twice.
#
# Every rule the core installs now carries `-m comment --comment "tnl:<tun>"`, and tun_name IS the
# tunnel name, so an orphan is attributable. Swept before a build and after a stop, which between them
# cover rebuild, edit, disable, delete and crash-then-rebuild.
RULE_OWNER_PREFIX = "tnl:"


def _sweep_owned_rules(name):
    """Delete every firewall rule tagged as owned by tunnel `name`. Returns how many went."""
    if not NAME_RE.match(name or ""):
        return 0
    tag = '--comment "%s%s"' % (RULE_OWNER_PREFIX, name)   # quoted: tnl:core4 must not match tnl:core42
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
            args[0] = "-D"                                  # -A CHAIN ... -> -D CHAIN ...
            run(["iptables", "-t", table] + args)
            removed += 1
    if removed:
        logline("%s: swept %d orphaned firewall rule(s) tagged %s%s" % (name, removed, RULE_OWNER_PREFIX, name))
    return removed


def _core_stop(name):
    """Stop the core unit for `name` and clear its live status/pool files (so a stopped tunnel's state is
    never rendered as "live", and no leftover pin command survives). The shared body of a full teardown
    and a disable; it does NOT remove the config .json — the caller decides whether to keep it."""
    unit = _core_unit(name)
    run(["systemctl", "stop", unit])       # kills the core -> its non-persistent TUN disappears
    run(["systemctl", "reset-failed", unit])
    _sweep_owned_rules(name)               # whatever it did not remove itself is now certainly nobody's
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
        os.remove(_cfg_path(name, ".json"))   # full teardown also drops the config (disable keeps it)
    except OSError:
        pass


def _set_link_state(cfg, enabled):
    """Bring a tunnel's data path up or down WITHOUT tearing the config down. For a core tunnel the
    TUN is owned by the core process (and Restart=always would fight an `ip link down`), so we stop the
    unit to disable and (re)build it to enable. Plain kernel tunnels just toggle the netdev's admin state.

    Raises when the data path did NOT actually change, so the caller reports what happened instead of
    the request it was handed."""
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
            _core_stop(name)   # stop the unit + clear stale pool status/pin files, but keep the config
            if _core_running(name):
                raise RuntimeError("واحدِ هستهٔ «" + name + "» با وجودِ stop هنوز در حال اجراست")
    else:
        must(["ip", "link", "set", name, "up" if enabled else "down"])


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


def _ipt_add_missing(table, chain, rule):
    """Append `rule` to `chain` in `table` only if an identical rule isn't already there (-C probes,
    -A adds). Idempotent, so a per-rotation rebuild never stacks duplicates."""
    rc, _, _ = run(["iptables", "-t", table, "-C", chain] + rule)
    if rc != 0:
        run(["iptables", "-t", table, "-A", chain] + rule)


def _ipt_del_all(table, chain, rule, tries=64):
    """Delete EVERY copy of `rule` from `chain` in `table`: -C probes, break when a check misses (no
    copies left), else -D removes one. iptables deletes a single matching rule per -D, so N stale
    duplicates need N deletes; `tries` bounds the loop so a pathological case can't spin forever."""
    for _ in range(tries):
        rc, _, _ = run(["iptables", "-t", table, "-C", chain] + rule)
        if rc != 0:
            break
        run(["iptables", "-t", table, "-D", chain] + rule)


def _pf_acct_build(cfg):
    """(Re)ensure this forward's accounting rules exist — idempotent, so the per-rotation build_portfw
    call never resets the counters. Rules live in a dedicated PFACCT chain hung off mangle PREROUTING."""
    run(["iptables", "-t", "mangle", "-N", "PFACCT"])  # create once; errors harmlessly if it exists
    _ipt_add_missing("mangle", "PREROUTING", ["-j", "PFACCT"])
    for r in _pf_acct_rules(cfg):
        _ipt_add_missing("mangle", "PFACCT", r)


def _pf_acct_teardown(cfg):
    for r in _pf_acct_rules(cfg):
        _ipt_del_all("mangle", "PFACCT", r)


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
            _ipt_del_all("nat", "PREROUTING", match + ["-j", "DNAT", "--to-destination", f"{ip}:{dp}"])
        run(["iptables", "-t", "nat", "-A", "PREROUTING"] + match
            + ["-j", "DNAT", "--to-destination", f"{active}:{dp}"])
    for proto in ("tcp", "udp"):   # SNAT ONLY the forwarded flow (dst+port), not all egress on the iface
        for ip in ips:             # flush every candidate first so a rotation leaves no stale masq rule
            _ipt_del_all("nat", "POSTROUTING",
                         ["-d", ip, "-p", proto, "--dport", dp, "-o", iface, "-j", "MASQUERADE"])
        run(["iptables", "-t", "nat", "-A", "POSTROUTING", "-d", active, "-p", proto,
            "--dport", dp, "-o", iface, "-j", "MASQUERADE"])
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
                    _ipt_del_all("nat", "PREROUTING",
                                 match + ["-j", "DNAT", "--to-destination", f"{ip}:{dp}"])
            for proto in ("tcp", "udp"):   # remove the per-flow MASQUERADE rules this forward installed
                for ip in cfg.get("dst_ips", []):   # (each is scoped to its own dst+port, so no cross-forward guard needed)
                    if not is_ipv4(ip):
                        continue
                    _ipt_del_all("nat", "POSTROUTING",
                                 ["-d", ip, "-p", proto, "--dport", dp, "-o", iface, "-j", "MASQUERADE"])


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
    """The OTHER end's overlay address. The two ends are hosts 1 and 2 of the same network, so this is
    "the one I am not" -- computed from the network, not by splicing the last octet, which only held
    while a tunnel owned a whole /24 and would land outside a /30."""
    addr = tunnel_ip.split("/")[0]
    prefix = tunnel_ip.split("/")[1] if "/" in tunnel_ip else ("64" if ttype == "sit" else "24")
    net = ipaddress.ip_network(f"{addr}/{prefix}", strict=False)
    mine = int(ipaddress.ip_address(addr)) - int(net.network_address)
    return str(net.network_address + (3 - mine))


# --- the liveness verdict: one TCP handshake sent THROUGH the tunnel ---------------------------------
PROBE_PORT = 9         # discard. Nothing listens, so the far KERNEL answers with RST and no agent need be up
SYN_RTO = 1.0          # s: the kernel's initial SYN retransmit timer (TCP_TIMEOUT_INIT), the value the
                       # deadline below must stay under. Not tunable from userspace, so it is a constant here.
PROBE_WAIT = 0.8       # s per attempt: ONE SYN's worth, deliberately under SYN_RTO. A deadline that spans
                       # the retransmit measures two SYNs as one sample and gets both numbers wrong -- see
                       # tun_probe. The fleet's real round trips are 78-170 ms, so this leaves 4x headroom.
PROBE_COUNT = 20       # samples per sweep, sent CONCURRENTLY. The whole set decides the verdict, so the
                       # count is the resolution of that decision: 20 gives it 5% steps, which is also
                       # the resolution of loss_pct beside it. Concurrency is what makes this free:
                       # twenty cost the same wall time as one, ~6.7 packets/s per tunnel. The SAME count
                       # everywhere: a button that samples harder than the sweep reports a different
                       # tunnel than the card it sits on.
PROBE_MIN_PCT = 15     # percent of the sample set that must answer for the tunnel to count as carrying.
                       # Operator-set from the panel (probe_min_pct); this is the fallback for a config
                       # that carries no value. A RATIO, not a count, so changing PROBE_COUNT cannot
                       # silently redefine it. 1 means "any single reply", which is what this was before
                       # the knob existed; 100 means every sample must answer.
PROBE_MIN_PCT_RANGE = (5, 100)
SWEEP_SLOW = 3.0       # s between sweeps of a tunnel whose last one crossed. Two samples this far
                       # apart are what makes RED_SWEEPS a real guard: a loss burst, a scheduling
                       # stall or an agent restart shows in one of them, not both.
SWEEP_FAST = 1.0       # s after a sweep that found nothing crossing. Keyed on the RAW crossing, not
                       # on the published colour -- settle() keeps a green tunnel green through the
                       # first bad sweep, so waiting for red would spend the very gap this saves.
                       # Every rung of the core's ladder costs one verdict, so this shortens the
                       # whole walk, not just the detection: ~17s to ~9s on a raw/tcp tunnel.
RED_SWEEPS = 2         # consecutive bad sweeps before a GREEN tunnel is repainted red. Green publishes
                       # at once -- an outage must show fast, one unlucky sweep must not.
_SO_BINDTODEVICE = getattr(socket, "SO_BINDTODEVICE", 25)   # absent off Linux, where the guards run
_ANSWERED = (0, errno.ECONNREFUSED)   # connected, or refused: either way the far side put a packet on the wire
_PENDING = (errno.EINPROGRESS, errno.EWOULDBLOCK, errno.EALREADY)


def tun_probe(iface, tunnel_ip, ttype, count=PROBE_COUNT):
    """Fire `count` TCP handshakes from the tunnel device to the peer's tunnel address and count how
    many came back. A RST proves as much as a completed handshake: both are a packet the far side put
    on the wire, so both mean the tunnel carried traffic in each direction. Answering needs no process
    at the far end, which matters because the agent restarts on every update.

    They go out TOGETHER, not one after another. Serially, `count` samples cost `count` deadlines and
    the sweep could not afford enough of them to say anything but 0/33/67/100. Concurrently the whole
    probe still costs one deadline, so the sample count is free to be the resolution of the answer.

    Every sample is sent even once one has answered. Stopping early would answer "does anything get
    through" -- which a tunnel dropping three quarters of its packets also answers yes to.

    Each sample is exactly ONE SYN: PROBE_WAIT is under the kernel's initial retransmit timer, so a
    sample either gets an answer to that SYN or ends. A longer deadline silently folds the retransmit
    into the same sample and corrupts both numbers -- the reply is counted as a hit although the first
    SYN was lost, and its "latency" is the kernel's own 1 s timer wearing the path's clothes.

    Returns (hits, sent, rtt_ms). rtt_ms is the FASTEST reply and is always a real round trip.
    sent counts the SYNs that actually went out; it is 0 only when no socket could be set up at all."""
    self_ip = tunnel_ip.split("/")[0]
    peer = peer_of(tunnel_ip, ttype)
    fam = socket.AF_INET6 if ttype == "sit" else socket.AF_INET
    hits = sent = 0
    best = None

    def faster(prev, secs):
        ms = round(secs * 1000, 1)
        return ms if prev is None else min(prev, ms)

    waiting = {}           # socket -> the moment its SYN went out, so each rtt is its own
    for _ in range(max(1, count)):
        try:
            s = socket.socket(fam, socket.SOCK_STREAM)
        except OSError:
            break
        try:
            s.setblocking(False)
            # Pin to the device AND to the tunnel address. Routing alone would usually pick this tunnel,
            # but "usually" is not a measurement: a probe free to leave by another path can report a
            # tunnel alive that is carrying nothing.
            s.setsockopt(socket.SOL_SOCKET, _SO_BINDTODEVICE, iface.encode() + b"\x00")
            s.bind((self_ip, 0))
            t0 = time.monotonic()
            err = s.connect_ex((peer, PROBE_PORT))
        except OSError:
            s.close()
            break              # device gone mid-sweep, or the address is not ours (yet)
        if err in _ANSWERED:   # answered before we even reached the wait
            sent += 1
            hits += 1
            best = faster(best, time.monotonic() - t0)
            s.close()
        elif err in _PENDING:
            sent += 1
            waiting[s] = t0
        else:
            s.close()          # the SYN never left; it is not a sample and must not count as loss

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
            break              # the deadline passed with nothing more to collect
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
        s.close()              # never answered inside the deadline: a lost SYN, already counted in sent
    return hits, sent, best


def probe_min_pct(cfg):
    """The operator's carrying threshold for this tunnel, clamped to the range the panel offers.
    Anything missing or malformed falls back to PROBE_MIN_PCT."""
    lo, hi = PROBE_MIN_PCT_RANGE
    try:
        v = int(cfg.get("probe_min_pct"))
    except (TypeError, ValueError):
        return PROBE_MIN_PCT
    return max(lo, min(hi, v))


def carrying(hits, sent, pct):
    """Did ENOUGH of the sample set answer to call this tunnel carrying?

    Integer arithmetic on both sides, so the comparison is exact and `pct` keeps meaning "percent of
    what was actually sent" when a sweep managed fewer sockets than PROBE_COUNT. At the default 15 with
    a full 20 samples that is 3 replies; at 100 it is every one of them."""
    return hits * 100 >= sent * pct


_verdict_lock = threading.Lock()
_verdict = {}          # tunnel name -> {"pub": bool|None, "bad": int}


def settle(name, ok):
    """Turn this sweep's raw yes/no into the verdict that gets published.

    A tunnel that is currently GREEN needs RED_SWEEPS consecutive bad sweeps before it is repainted;
    green publishes at once. The asymmetry is the point: a real outage must show fast, but one unlucky
    sweep must not repaint a working tunnel, and a dot that flickers is a dot the operator stops
    reading. A tunnel that is not already green goes red on its first bad sweep -- there is nothing
    to protect."""
    with _verdict_lock:
        st = _verdict.setdefault(name, {"pub": None, "bad": 0})
        if ok:
            st["pub"], st["bad"] = True, 0
        else:
            st["bad"] += 1
            if not (st["pub"] is True and st["bad"] < RED_SWEEPS):
                st["pub"] = False
        return st["pub"]


# --- node-driven destination failover ---------------------------------------------------------------


def _read_path_state(name):
    """The core's published path epoch, and whether a session is up on that path.

    (0, False) when the file is missing or says neither — a core that cannot name the path it is on is
    one no verdict may be keyed against. `ready` is what replaced the old post-jump settle timer: the
    carrier reports a session on the NEW path instead of us guessing how long a handshake takes."""
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


WS_ACTIVE_SEP = " · "   # what wsPool.writeStatus joins the active edge and SNI with


def _read_ws_pool(name):
    """Parse the ws edge pool's status file into {active_ip, active_sni, ips, snis, health}. The core
    publishes one flat health list tagged by axis; split it here so a verdict can be sized and keyed on
    the right one. Empty (well-formed) when the file is missing or the core has not written yet."""
    empty = {"ip": "", "sni": "", "ips": [], "snis": [], "health": []}
    try:
        with open(_cfg_path(name, ".status")) as f:
            st = json.load(f)
    except (OSError, ValueError):
        return empty
    if not isinstance(st, dict):
        return empty
    health = [h for h in (st.get("health") or [])[:256] if isinstance(h, dict) and h.get("key")]
    active = str(st.get("active") or "")
    ip, _, sni = active.partition(WS_ACTIVE_SEP)
    return {"ip": ip, "sni": sni,
            "ips": [str(h["key"]) for h in health if str(h.get("kind")) != "sni"],
            "snis": [str(h["key"]) for h in health if str(h.get("kind")) == "sni"],
            "health": health}


def _ws_condemned(pool, kind, key):
    """True when `key` on axis `kind` carries a not-healthy record -- suspect or dead, either way sidelined."""
    return bool(key) and any(str(h.get("key")) == key and str(h.get("state")) != "healthy"
                             and (str(h.get("kind")) == "sni") == (kind == "sni")
                             for h in (pool.get("health") or []))


def _condemned(pool, addr):
    """True when `addr` carries a not-healthy record in `pool` -- suspect or dead, either way sidelined."""
    return bool(addr) and any(h.get("key") == addr and h.get("state") != "healthy"
                              for h in (pool.get("health") or []))


def _report_carrying(name, edge, epoch):
    """Tell the core that traffic is CROSSING, naming the endpoints it crossed on.

    The core has no way to learn this for itself. Everything it can observe -- a frame coming back, a
    dial that completed, a handshake that was answered -- is something a filtered IP passes while
    carrying nothing, which is how 5.75.197.201 kept being re-admitted. So the probe that condemns an
    endpoint is the only thing allowed to clear it, and this is how it says so.

    Two occasions, not one. `edge` is the red->green recovery. The other is an endpoint that is CARRYING
    while its pool still has it condemned: a burn always rotates AWAY from what it burns, so the pair a
    recovery lands on is never the pair that was burned. The burned one only returns once its backoff
    lapses, and by then the tunnel is already green -- no edge left to report on, and it stays condemned
    for good while visibly carrying traffic. A healthy tunnel on healthy endpoints still writes nothing.

    Both keys are read from the pool files the core itself publishes, in ONE snapshot, so the endpoints
    named are the ones the burned-check was made against."""
    if _is_ws_pool(name):
        w = _read_ws_pool(name)
        ip, sni = w["ip"], w["sni"]
        if not ip and not sni:
            return
        if not edge and not (_ws_condemned(w, "ip", ip) or _ws_condemned(w, "sni", sni)):
            return
        err = _atomic_write_json(_cfg_path(name, ".status.cmd"), {"cmd": "ok", "ip": ip, "sni": sni, "epoch": epoch})
        logline(f"{name}: probe found traffic crossing — told the core {ip or '?'} / {sni or '?'} are carrying"
                + (f" [{err}]" if err else ""))
        return
    dpool, spool = _read_peer_pool(name, ".peerpool"), _read_peer_pool(name, ".srcpool")
    dst, src = dpool.get("active") or "", spool.get("active") or ""
    # Both empty on a pool-less tunnel, and it is still sent: `ok` also refills the ladder's free steps,
    # which every tunnel has whether or not it owns an endpoint to burn. Nothing to clear then, so the
    # recovery is the only occasion -- there is no condemned entry to keep announcing.
    if not edge and not (_condemned(dpool, dst) or _condemned(spool, src)):
        return
    err = _atomic_write_json(_cfg_path(name, ".status.verdict"), {"cmd": "ok", "key": dst, "src": src, "epoch": epoch})
    carrying = f"{dst or '?'} / {src or '?'} are carrying" if dst or src else "the path is carrying"
    logline(f"{name}: probe found traffic crossing — told the core {carrying}"
            + (f" [{err}]" if err else ""))


def pool_failover(name, alive, crossed, epoch, session_up):
    """Tell the core our probe found nothing crossing this tunnel, so its ladder can answer.

    EVERY client tunnel is told, pool or no pool. The verdict is about the path, and the cheap rungs
    the core answers it with -- redraw the source port, handshake again -- move the tunnel nowhere and
    need no second endpoint. Only the burn does, and this names an endpoint only when there is one.

    `epoch` is the core's path counter, unchanged across the whole probe (health_of checks) and
    stamped on every ask. The core drops one that no longer matches, so a verdict can never be charged
    to a path it did not measure. Callers only reach here for a measurement that held still.

    `session_up` says the carrier reported an established session on this path BOTH sides of the probe.
    Only the ok needs it. An ok CLEARS a burn, which is the strong claim, and it must not rest on a
    silence the handshake explains. A fail is the weak one: it blames nobody until the core has spent
    its free rungs, and the first of those rungs IS a handshake -- so requiring a session here meant
    the ladder switched off the judge the moment it took its first step, and on a path that stays
    blocked the handshake never completes, so no verdict ever arrived again and nothing was ever
    burned. The order of the rungs is what answers that worry, not muting the probe.

    `crossed` is THIS sweep's raw measurement, not the published colour: settle() keeps a green tunnel
    green through a bad sweep, and a smoothed green measured nothing, so it may never clear a burn.

    The carrier only learns a destination is dead from its own traffic, which on a crypto tunnel means
    the stale window plus a full run of failed handshakes. The probe sees the same silence far sooner,
    and sees it where the payload does.

    What the probe CANNOT do is name the guilty endpoint -- it only knows the tunnel is dead. So the
    jump is the experiment and the next endpoint is the control: burn, move, let the next sweep judge.

    There is no walk policy here. This reports; the core decides how many free rungs to spend before a
    burn, and a burned endpoint returns on the backoff the core stamped on it. Counting asks here and
    calling that "the pool has been walked" assumed one ask == one burn, which stopped being true when
    the ladder grew free rungs -- the core then never received enough verdicts to reach a burn at all.
    """
    if str(_read_core_cfg(name).get("role") or "") != "client":
        return                    # a server neither chooses a path nor climbs a ladder; it only follows
    with _verdict_lock:
        # `red` is the PREVIOUS published colour, which settle() has already overwritten in `pub` by the
        # time this runs -- so it lives here beside it rather than in a second dict with its own lock.
        # Only a MEASURED green is news; anything else says nothing about any endpoint.
        st = _verdict.setdefault(name, {"pub": None, "bad": 0})
        was_red, st["red"] = st.get("red", False), alive is False
    if alive is not False:
        if crossed and session_up:
            _report_carrying(name, was_red and alive is True, epoch)  # off the lock: it writes a file
        return
    with _verdict_lock:
        # A tunnel that was never green goes red on its FIRST bad sweep -- there was no green to protect.
        # Right for the dot, wrong for burning: the agent restarts on every update, so one momentary
        # silence in the first sweep after a restart would cost a destination. Burning waits for the
        # same confirmation the colour gets, whatever the tunnel looked like before.
        if _verdict.get(name, {}).get("bad", 0) < RED_SWEEPS:
            return
    if _is_ws_pool(name):
        _ws_failover(name, epoch)
        return
    cur = _read_peer_pool(name, ".peerpool").get("active") or ""
    # NAME the endpoint the probe measured, exactly as the ok verdict does. That poll is a one-second
    # ticker and the probe before it takes most of a second, so every proactive rotate beat is a window
    # where an unnamed verdict lands on whatever the core moved to -- condemning an endpoint nothing
    # measured and putting the tunnel back on the one that was. Empty names no endpoint, which is the
    # honest answer for a tunnel that has none: the core spends a free step and blames nobody.
    # Atomic (tmp+replace): the core polls this file once a second and deletes it, so a half-written
    # one would be read and dropped, and the failover silently lost.
    err = _atomic_write_json(_cfg_path(name, ".status.verdict"), {"cmd": "fail", "key": cur, "epoch": epoch})
    asked = f"fail destination {cur}" if cur else "spend a free step — this tunnel has no endpoint to burn"
    logline(f"{name}: probe found nothing crossing — asked the core to {asked}"
            + (f" [{err}]" if err else ""))


def _ws_failover(name, epoch):
    """pool_failover's edge-pool half: report that nothing crossed this edge/SNI combination.

    Naming the combination is not asking for a burn. The core's ladder decides what the report costs --
    a free re-dial on a new source port first, a burn only once those are spent."""
    w = _read_ws_pool(name)
    cur_ip, cur_sni = w["ip"], w["sni"]
    err = _atomic_write_json(_cfg_path(name, ".status.cmd"),
                             {"cmd": "fail", "ip": cur_ip, "sni": cur_sni, "epoch": epoch})
    logline(f"{name}: probe found nothing crossing — asked the core to fail edge "
            f"{cur_ip or '?'} / {cur_sni or '?'}" + (f" [{err}]" if err else ""))


# --- directional liveness: bytes moving on the tunnel iface, counted per direction, whatever ICMP does ---
LIVE_WINDOW = 12.0   # s: a direction counts as live only if its byte counter advanced within this window (short, so a busy tunnel that dies stops looking live quickly)
_flow_lock = threading.Lock()
_flow_state = {}     # iface name -> {"rx","tx": int, "rxp","txp": float|None} (last sample + monotonic time each direction last advanced)
def _iface_ctr(name, which):
    """Total rx_bytes/tx_bytes on <name> from the kernel, or None if the counter can't be read."""
    try:
        with open("/sys/class/net/" + name + "/statistics/" + which + "_bytes") as f:
            return int(f.read().strip())
    except Exception:
        return None


def _prune_iface_state(names):
    """Drop per-iface liveness bookkeeping for tunnels that no longer exist. Both dicts are keyed by
    config name and nothing removed their entries on delete, so a node churned by create/delete grew
    them forever — and a recreated tunnel inherited a stale rx baseline until the counter-went-backwards
    reset in _flow_sample cost it one extra sweep. The verdict's own memory is keyed the same way and
    goes with them: a recreated tunnel must not inherit the green that protected its namesake."""
    with _flow_lock:
        for nm in [n for n in _flow_state if n not in names]:
            _flow_state.pop(nm, None)
    with _verdict_lock:
        for nm in [n for n in _verdict if n not in names]:
            _verdict.pop(nm, None)



def _flow_sample(name):
    """Per-DIRECTION quiet time on <name>, as (rx_still, tx_still) in SECONDS, or None each.

    rx = bytes the tunnel DELIVERED to us, so the peer's traffic is arriving. tx = bytes we pushed INTO
    the tunnel, so we are trying. They answer different questions and are never merged: a tunnel that is
    sending into a hole has tx moving and rx still, which is exactly the state a single flag cannot say.

    A NUMBER, not a flag, because the two thresholds are different. "Moving recently" is a short window;
    "definitely not arriving" has to be a long one, or an ordinary quiet patch in bursty traffic reads as
    a broken direction. A flag collapses both into one and forces the reader to pick the wrong threshold.

    None = no baseline: first sample, nothing seen yet, unreadable counter, or the iface was recreated
    (the counter went backwards)."""
    now = time.monotonic()
    with _flow_lock:  # sample + compare + store atomically so concurrent same-name callers can't invert the order
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
                rxp = None      # counter went backwards = iface recreated; old progress is meaningless
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
    # No lock. A rebuild holds _apply_lock for seconds, and a probe that waits on it delivers no verdict
    # for that whole window — for every tunnel on the node, not just the one being rebuilt. Mid-rebuild
    # the netdev really is gone, so `up` is false and this one sweep skips the probe.
    up = os.path.exists("/sys/class/net/" + name)
    # ONE verdict for every tunnel, core and system alike: send a TCP SYN out of the tunnel device itself
    # and see whether anything comes back. That single exchange is the whole question — a packet crossed
    # in each direction, just now, through this tunnel and no other path.
    rx_still, tx_still = _flow_sample(name) if up else (None, None)   # throughput for the card; casts no vote
    alive, rtt, loss, crossed = None, None, None, None
    tip = cfg.get("tunnel_ip", "")
    if up and tip and tip != "N/A":
        # Read the core's path epoch either side of the probe. A probe that straddles a rotation, a
        # port roll or a re-dial measured two paths and can be charged to neither, so its VERDICT is
        # dropped. The COLOUR is not: "is this tunnel carrying" stays a fair question across a move,
        # and a dot that stops updating whenever the path shifts is worse than one that lags a sweep.
        epoch_before, ready_before = _read_path_state(name)
        hits, sent, rtt = tun_probe(name, tip, ttype)
        if sent:
            # The verdict rests on the WHOLE sample set, never on one packet. A single reply used to
            # decide all of it -- the colour, whether to burn the endpoint, and whether to clear a burn --
            # so a tunnel dropping 19 of 20 read green AND had its path exonerated, which is how a
            # filtered endpoint kept being re-admitted. The threshold is the operator's, set fleet-wide
            # from the panel, because only they can say how much loss is still a tunnel worth having.
            loss = round((sent - hits) * 100.0 / sent, 1)
            crossed = carrying(hits, sent, probe_min_pct(cfg))
            alive = settle(name, crossed)
            epoch, ready = _read_path_state(name)
            # The EPOCH gates both verdicts: a probe that spanned a move measured two paths and can be
            # charged to neither. `ready` gates only the ok — see pool_failover. Gating the fail on it
            # too silenced the judge for the whole outage: the core's first free rung is a handshake,
            # which turns ready false, and on a blocked path it never completes.
            if epoch == epoch_before:
                pool_failover(name, alive, crossed, epoch, ready_before and ready)
    return {"up": up, "alive": alive, "dead": alive is False, "rtt_ms": rtt, "loss_pct": loss,
            "crossed": crossed, "rx_still": rx_still, "tx_still": tx_still, "live_win": int(LIVE_WINDOW)}


def _cpu_snap():
    with open("/proc/stat") as f:
        v = [int(x) for x in f.readline().split()[1:]]
    idle = v[3] + (v[4] if len(v) > 4 else 0)  # idle + iowait
    return sum(v), idle


_cpu_prev = None            # (total, idle) of the last snapshot; the window is the gap BETWEEN calls
_cpu_last = 0.0             # the last percentage computed, returned while a fresh window is too short
_cpu_lock = threading.Lock()


def _cpu_pct():
    """CPU utilisation since the PREVIOUS call, with no sleep of its own.

    It used to sleep 100 ms between two snapshots. `op_ping` calls this through read_stats, and the panel
    times that whole RPC as the node's ping — so every ping the operator saw was ~100 ms too high, on every
    node, for ever. A remembered snapshot is also a BETTER measurement: the window is the real poll
    interval (seconds) instead of a 100 ms sliver, so a brief spike no longer reads as sustained load.

    Two callers arriving in the same jiffy would divide by a zero window, so a call that finds no tick since
    the last one reuses the last answer and leaves the older snapshot in place — the next call then measures
    across something real instead of restarting the window each time."""
    global _cpu_prev, _cpu_last
    with _cpu_lock:
        cur = _cpu_snap()
        prev = _cpu_prev
        if prev is None:
            # First call of the process: pay ONE short window so the first ping reports something real
            # rather than 0. Every later call is free.
            time.sleep(0.1)
            prev, cur = cur, _cpu_snap()
        elif cur[0] - prev[0] <= 0:
            # No jiffy has ticked since the last call. Reuse the last answer and KEEP the old snapshot, so
            # the next call measures across a window long enough to mean something. Sleeping here instead
            # would put the 100 ms straight back into every rapid caller.
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
# name -> the Future of a probe that has not been harvested yet. Touched only by the health thread.
_health_inflight = {}


_sweep_due = {}          # tunnel name -> monotonic time its next sweep is allowed to start


def _sweep_gap(res):
    """SWEEP_FAST while the last sweep found nothing crossing, SWEEP_SLOW otherwise."""
    return SWEEP_FAST if (res or {}).get("crossed") is False else SWEEP_SLOW


def _health_harvest(names):
    """Publish every FINISHED probe into the snapshot and prune tunnels that no longer exist.

    A straggler from an EARLIER round lands here too. The old code waited on one round's futures and
    then rebuilt the snapshot from that round alone, so a probe that overran HEALTH_DEADLINE had its
    answer thrown away — and since the next round immediately queued another one for the same tunnel,
    a consistently-slow probe left that tunnel's health frozen at its last value indefinitely."""
    with _health_lock:
        for nm in names:
            f = _health_inflight.get(nm)
            if f is None or not f.done():
                _health_cache.setdefault(nm, {"up": None})  # nothing yet -> unknown, never a fake down
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
    _health_harvest(names)                       # whatever finished since the last round, including stragglers
    for nm in [n for n in _health_inflight if n not in names]:
        _health_inflight.pop(nm, None)           # tunnel deleted while its probe was running
    for nm in [n for n in _sweep_due if n not in names]:
        _sweep_due.pop(nm, None)
    # ONE probe per tunnel in flight, never two. Submitting a full fresh batch every 3s regardless lets a
    # sweep that overran the deadline stack another N tasks onto the executor's unbounded queue behind its
    # own stragglers.
    now = time.monotonic()
    for c in cfgs:
        if c["name"] in _health_inflight or _sweep_due.get(c["name"], 0.0) > now:
            continue
        _health_inflight[c["name"]] = ex.submit(health_of, c)
    futures_wait(set(_health_inflight.values()), timeout=HEALTH_DEADLINE)
    _health_harvest(names)
    _prune_iface_state(names)


def health_loop():
    ex = ThreadPoolExecutor(max_workers=HEALTH_WORKERS)  # persistent; stragglers can't block the loop
    while True:
        try:
            health_refresh_once(ex)   # blocks up to HEALTH_DEADLINE, so rounds never overlap/pile up
        except Exception as e:
            logline(f"health loop: {e}")
        # The loop ticks at the FAST cadence and _sweep_due decides who is actually probed, so a
        # carrying tunnel still costs one sweep every SWEEP_SLOW and only the ones that found
        # nothing crossing are looked at more often -- where the extra samples are dropped anyway.
        time.sleep(SWEEP_FAST)

# ----------------------------------------------------------------------------- API ops

def _require(d, keys):
    for k in keys:
        if k not in d or d[k] in (None, ""):
            raise ValueError(f"missing field: {k}")


def _req_name(d):
    """Require+validate the tunnel name — the require/str/NAME_RE preamble the name-only ops all share.
    Only for ops that require nothing but "name"; ops needing extra keys keep their own _require so the
    missing-field error ordering is preserved."""
    _require(d, ["name"])
    name = str(d["name"])
    if not NAME_RE.match(name):
        raise ValueError("bad name")
    return name


def _self_sha():
    """sha256 of the on-disk agent this process is running — computed once at startup."""
    try:
        with open(INSTALLED, "rb") as f:
            return hashlib.sha256(f.read()).hexdigest()
    except OSError:
        return ""


_SELF_SHA = _self_sha()


# ----------------------------------------------------------------------------- signed control requests
# The panel proves it is the panel by SIGNING the request instead of handing over the shared secret.
# What is signed is the method, the path, a counter and the sha256 of the body:
#
#     X-Ctr:  8241
#     X-Body: <sha256 hex of the body, "" when there is none>
#     X-Sig:  base64 HMAC-SHA256(token, "METHOD\npath\nctr\nbodysha")
#
# The body's hash rides in a HEADER on purpose: the signature can then be checked before a single byte
# of the body is read, so an unauthenticated caller cannot make the node buffer 20 MB to be rejected.
# Each counter is single-use, which is what makes a captured request useless the second time.
#
# Single-use, NOT strictly increasing. The panel talks to one node from several background loops at
# once, so two requests routinely leave together and arrive in the other order; demanding an increase
# refuses the one that lost the race even though it is a first-time request. So the mark is a sliding
# window with a bitmask of what inside it was spent -- the anti-replay IPsec and WireGuard use.
REQ_CTR_STEP = 256          # how far AHEAD of the last accepted counter the file on disk is kept
REQ_CTR_WINDOW = 4096       # counters are milliseconds, so this is ~4 s of reordering tolerance
_REQ_CTR_MASK = (1 << REQ_CTR_WINDOW) - 1

_req_ctr_lock = threading.Lock()
_req_ctr = 0            # highest counter accepted in this process
_req_seen = 0           # bit i set == counter (_req_ctr - i) was already spent
_req_ctr_hwm = 0        # highest counter written to node.conf


# ----------------------------------------------------------------------------- central check-in
# The panel reaches us at host:port from its registry, so if our public IP changes we phone home. Where
# to phone is learned from the panel's own INCOMING requests, which are signed — so it moves when the
# panel does, and only the holder of our key can move it.

def _seed_req_ctr():
    """Resume the counter at the persisted mark, which is deliberately AHEAD of anything accepted, so a
    restart cannot reopen a window the panel has already spent.

    The window comes back FULL, not empty: an empty one would treat every counter below the mark as
    unspent and hand a restart back the replay window the mark exists to close."""
    global _req_ctr, _req_seen, _req_ctr_hwm
    try:
        v = int(load_conf().get("req_ctr") or 0)
    except Exception:
        v = 0
    with _req_ctr_lock:
        _req_ctr = _req_ctr_hwm = v
        _req_seen = _REQ_CTR_MASK


def _persist_req_ctr(hwm):
    """Write the mark OFF the request path. _apply_lock is held by a core build for 8-16 s at worst, and
    a health ping that waited for it would read as a dead node."""
    with _apply_lock:
        try:
            conf = load_conf()
            if int(conf.get("req_ctr") or 0) < hwm:
                conf["req_ctr"] = hwm
                save_conf(conf)
        except Exception as e:
            logline(f"req_ctr persist: {e}")


def _accept_ctr(ctr):
    """True when `ctr` has not been spent before. Advances the mark on disk in steps, not per request.

    Ahead of the window: slide up to it. Inside it: accept once, refuse the second time. Below it:
    refuse -- too old to still be tracked, and the panel resyncs off the 409 rather than being stranded."""
    global _req_ctr, _req_seen, _req_ctr_hwm
    hwm = None
    with _req_ctr_lock:
        if ctr > _req_ctr:
            step = ctr - _req_ctr
            # A jump past the whole window leaves nothing worth shifting in, and shifting by it would
            # build an integer that many bits wide.
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
    """Constant-time check of the panel's HMAC over this request's own header values."""
    try:
        want = hmac.new(secret.encode("utf-8"),
                        _sig_msg(method, path, ctr, body_sha).encode("utf-8"),
                        hashlib.sha256).digest()
        got = base64.b64decode(sig_b64, validate=True)
    except Exception:
        return False
    return hmac.compare_digest(want, got)


def note_central(ip, port, tls):
    """Learn where the panel is from the request it just made: the address it reached us from, the port
    it advertises, and whether that port speaks TLS. Nothing here is configured on the node, so the
    panel can move — address, port or scheme — and we follow on its next request."""
    global _central_cb
    try:
        p = int(port)
    except (TypeError, ValueError):
        return
    if not (1 <= p <= 65535):  # X-Central-Port is fully attacker-controlled — bound it
        return
    cb = (ip, p, bool(tls))
    with _central_cb_lock:
        if _central_cb == cb:
            return          # steady state: never touch node.conf on a request that changes nothing
        _central_cb = cb
    _save_central_cb(cb)


def _save_central_cb(cb):
    """Persist where to phone home. A node that REBOOTS with a new IP is otherwise stuck for good: the
    panel cannot reach it at the stored host, so it never sends us a request, so we never re-learn the
    callback and never check in. Only runs when it actually changed."""
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
    """Restore the callback at startup, so checking in does not depend on the panel reaching us first.

    A stored pair without the scheme is ignored rather than assumed: the panel re-teaches the whole
    origin on its very next request, which is one poll away, and guessing http for a panel that has
    moved to https would send a check-in — and the node's own address list — at a TLS port in the
    clear."""
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
    """"http://ip:port" the node currently believes the panel is at, or "" if it has never been told.
    THE one place that origin is rendered, so check-in, the plaintext-fetch gate and what ping reports
    can never describe different panels."""
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
    # The check-in used to POST the raw token, which made this the one direction where the secret still
    # crossed the wire. Whoever saw it could not command the node -- that needs a signature -- but they
    # could tell the panel "this node moved to my address", answer its signed probe with the key they
    # had just been handed, and take over the node's control traffic. So it is signed like everything
    # else, and identified by a FINGERPRINT of the token, which proves nothing on its own.
    #
    # The PORT rides along: without it the self-heal covers only half of "where this node is" -- an
    # agent that moved port is unreachable and cannot say so.
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
    return {"ok": True, "agent": "tnl-node", "version": 1, "ready": True,
            # Where this node thinks the panel is. The panel shows it so a fleet being moved to a new
            # address can be watched arriving, instead of the operator guessing when it is safe to
            # retire the old one.
            "central": central_origin(),
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
    if not 1 <= tid <= 65535:   # one /24 per tunnel out of 10/8; the panel owns the real allocation
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
    old = read_config(name)   # snapshot the prior build ONCE (serialized under _apply_lock, no write until below):
    obj["enabled"] = _as_bool(d.get("enabled", (old or {}).get("enabled", True)))   # drives the on/off carry-forward here AND the in-place teardown/rollback further down
    # probe_min_pct: EVERY type, not just core -- the tun probe judges every tunnel it can address, so a
    # core-only knob would leave two tunnels on one dashboard coloured by two different rules. This one is
    # CONSUMED here rather than forwarded: health_of reads it off the persisted config, so without this
    # whitelist entry the panel's value is dropped in silence and the threshold stays at the node default.
    if d.get("probe_min_pct") not in (None, ""):
        _lo, _hi = PROBE_MIN_PCT_RANGE
        obj["probe_min_pct"] = max(_lo, min(_hi, int(d["probe_min_pct"])))
    # tuning (core, optional): the fleet-wide operational-timing overrides the panel stamps onto EVERY core
    # body. This whitelist entry is load-bearing — _core_config reads cfg["tuning"] from the PERSISTED
    # config, so without it the key is dropped on the way in and every Settings knob is a
    # silent fleet-wide no-op. Sanitized with the same helper _core_config uses.
    if ttype == "core":
        _tn = _core_tuning(d.get("tuning"))
        if _tn:
            obj["tuning"] = _tn
    # sock_buf (core, optional): datagram socket-buffer size in BYTES, stamped fleet-wide by the panel
    # (which stores MiB and converts). Whitelist it or it is dropped like any un-whitelisted key and the
    # operator's Settings value never reaches the core. Negative = the core's "leave the kernel default"
    # sentinel, so it is passed through rather than floored; the upper bound matches the core's own clamp.
    if ttype == "core" and d.get("sock_buf") not in (None, ""):
        _sb = int(d["sock_buf"])
        obj["sock_buf"] = -1 if _sb < 0 else min(_sb, 64 << 20)
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
        if transport not in ("udp", "tcp", "raw", "flux", "spoof", "ws", "dns"):
            raise ValueError("bad core transport")
        obj["transport"] = transport

        def _clean_pool(key):
            """Strip+drop-blanks the IPv4 pool at d[key], cap it at 64, and reject any non-IPv4 entry.
            One reference for every core IP pool: peer_ips/src_ips (client), listen_ips + peer_src_ips
            (server). A config is only ever client OR server, so this being in scope for all branches
            changes no path."""
            out = [str(x).strip() for x in (d.get(key) or []) if str(x).strip()]
            if len(out) > 64:
                raise ValueError(key + " pool too large (>64)")
            for ip in out:
                if not is_ipv4(ip):
                    raise ValueError("bad " + key + " entry (must be an IPv4 address)")
            return out

        if transport == "dns":        # DNS-tunnel carrier: delegated zone + client resolver list
            zone = str(d.get("dns_zone") or "").strip().lower()
            if not zone or len(zone) > 253 or not re.match(r"^(?!-)[A-Za-z0-9-]{1,63}(?:\.(?!-)[A-Za-z0-9-]{1,63})+$", zone):
                raise ValueError("bad dns_zone")
            obj["dns_zone"] = zone
            resolvers = []
            for r in (d.get("dns_resolvers") or []):
                rs = str(r).strip()
                if not rs:
                    continue
                if rs.count(":") == 1:                       # ip:port — validate both halves
                    host, _, port = rs.partition(":")
                    if not (port.isdigit() and 1 <= int(port) <= 65535):
                        raise ValueError("bad dns_resolvers port (1..65535)")
                else:
                    host = rs
                if not is_ipv4(host):
                    raise ValueError("bad dns_resolvers entry (must be IPv4 or IPv4:port)")
                resolvers.append(rs)
            # crypto is mandatory (core rejects dns without it) and the client needs at least one
            # resolver — reject here so the failure is precise, not "interface not created".
            if not str(d.get("psk") or "").strip() or cipher == "none":
                raise ValueError("ترنسپورت dns به رمزنگاری (psk) نیاز دارد — نشست داخلِ کوئری‌های DNS با AEAD رمز و احراز می‌شود")
            if role == "client" and not resolvers:
                raise ValueError("کلاینتِ dns به حداقل یک resolverِ معتبر (IPv4) نیاز دارد")
            if resolvers:
                obj["dns_resolvers"] = resolvers
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
            # the CDN carrier shape (ws | http | grpc) — http passes a CDN
            # that blocks WebSocket. Independent of ws_tls (server side is plain HTTP either
            # way); whitelist it here so it survives persistence (dropping = silently reverts
            # to a plain WebSocket, which the WS-block rule then kills).
            _cdn = str(d.get("cdn_carrier") or "").strip().lower()
            if _cdn:
                if _cdn not in ("ws", "http", "grpc"):
                    raise ValueError("bad cdn_carrier")
                if _cdn != "ws":
                    obj["cdn_carrier"] = _cdn
                # Upstream POST-ladder shape, chosen per CDN by the panel: workers x batch is the window, and
                # the rate cap is a ceiling on POSTs/sec a worker count cannot express. A key not whitelisted
                # here is dropped in SILENCE and the tunnel rebuilds on the default shape, which a WAF-protected
                # CDN blocks. The ceilings are the CORE's own, because it REJECTS rather than clamps.
                _up_max = {"http_up_workers": 16, "http_up_batch_kb": 512, "http_up_rate": 1000}
                for _k in ("http_up_workers", "http_up_batch_kb", "http_up_rate"):
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
                    # The core dials each edge as a literal ip:port with no DNS step (config.go
                    # validatePoolEndpoint, needPort=true): the host MUST be an IPv4 and a port is REQUIRED.
                    # Reject hostnames and IPv6, and default a port-less IPv4 to :443, so the normalized ip:port
                    # we forward always loads — panel, node and core agree on IPv4:port.
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
                        _rs = d.get("ws_rotate_secs")   # 0 = rotation off (failover-only) — a truthiness `or 600` would wrongly force 600
                        obj["ws_rotate_secs"] = max(0, min(28800, int(_rs))) if _rs is not None else 600
            edge = str(d.get("edge_ip") or "").strip()   # CDN edge the client dials instead of the origin
            if edge:
                host = edge.rpartition(":")[0] or edge
                if not re.match(r"^[A-Za-z0-9.\-]{1,253}$", host):
                    raise ValueError("bad edge_ip")
                obj["edge_ip"] = edge
        if transport == "raw":        # raw-IP carrier: which protocol the sealed frame is wrapped in
            profile = str(d.get("raw_profile") or "bare").strip().lower()
            if profile not in RAW_HEADER_LEN:   # the roster the core registers, guarded across repos
                raise ValueError("bad raw_profile")
            obj["raw_profile"] = profile
            if profile == "bare":      # optional custom IP protocol number for the headerless carrier
                rproto = int(d.get("raw_proto") or 0)
                if rproto and not (1 <= rproto <= 255):
                    raise ValueError("bad raw_proto")
                if rproto:
                    obj["raw_proto"] = rproto
            if profile in ("udp", "tcp"):   # the forged server port; only these two carry ports
                rport = int(d.get("raw_port") or 0)
                if rport and not (1 <= rport <= 65535):
                    raise ValueError("bad raw_port")
                if rport:
                    obj["raw_port"] = rport
                if _as_bool(d.get("raw_sport_random")):   # ...and whether the SOURCE port rolls
                    obj["raw_sport_random"] = True
            wk = int(d.get("workers") or 0)   # extra TUN queues; 0/1 is the core's single-queue default
            if wk and not (1 <= wk <= MAX_WORKERS):
                raise ValueError("bad workers")
            if wk > 1:
                obj["workers"] = wk
        if transport == "spoof":      # standalone IP-spoofing carrier: bare-like, so only the proto override (no profile)
            rproto = int(d.get("raw_proto") or 0)
            if rproto and not (1 <= rproto <= 255):
                raise ValueError("bad raw_proto")
            if rproto:
                obj["raw_proto"] = rproto
        if transport == "flux":       # polymorphic moving-target carrier: persist carrier/shape/epoch
            carrier = str(d.get("flux_carrier") or "udp").strip().lower()
            if carrier not in ("udp", "stun"):
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
        # datagram carriers only (udp/raw/flux/spoof). Persisting these in the whitelist is mandatory:
        # an un-whitelisted key is silently dropped from the stored config and never reaches the core.
        if transport in ("udp", "raw", "flux", "spoof") and _as_bool(d.get("fec")):
            obj["fec"] = True
            fd = int(d.get("fec_data") or 10)
            fp = int(d.get("fec_parity") or 3)
            if fd < 1 or fp < 1 or fd + fp > 255:
                raise ValueError("fec_data/fec_parity out of range (>=1, sum<=255)")
            obj["fec_data"] = fd
            obj["fec_parity"] = fp
        # Destination rotation pool (client, direct transports udp/tcp/raw/flux): the panel sends the foreign
        # node's IPs to cycle through, so a single blocked server IP does not kill the tunnel. Whitelisting is
        # mandatory — an un-whitelisted key is silently dropped and never reaches the core. Each must be a
        # plain IPv4: the pool swaps the destination with no DNS step, and raw/flux are IPv4-only.
        if transport in ("udp", "tcp", "raw", "flux") and role == "client":
            pips = _clean_pool("peer_ips")   # destination pool: the SERVER's IPs the client dials
            sips = _clean_pool("src_ips")     # source pool: this client node's OWN IPs to send FROM
            if pips or sips:
                if pips:
                    obj["peer_ips"] = pips
                if sips:
                    obj["src_ips"] = sips
                _prs = d.get("peer_rotate_secs")   # 0 = failover-only; a truthiness `or N` would wrongly force N
                obj["peer_rotate_secs"] = max(0, min(86400, int(_prs))) if _prs is not None else 0
        # pool_listen (server side): the client rotates the destination across THIS server's selected IPs.
        # udp/tcp bind EACH of them explicitly rather than 0.0.0.0 — see _core_config — and listen_ips carries
        # that set as bare IPv4. raw needs the FLAG but not listen_ips, which the core ignores for raw: a
        # concrete bind makes its socket deaf to every other pool IP, so _core_config binds 0.0.0.0 instead.
        if transport in ("udp", "tcp", "raw") and role == "server" and _as_bool(d.get("pool_listen")):
            obj["pool_listen"] = True
            if transport in ("udp", "tcp"):
                lips = _clean_pool("listen_ips")
                if lips:
                    obj["listen_ips"] = lips
        # peer_src_ips (server side, raw/flux): the client's SOURCE pool. raw/flux servers see every host
        # on the wire and pre-filter by the learned source, so a rotated client source is dropped pre-
        # crypto and never re-learned without this. Whitelisting is mandatory (un-whitelisted keys are
        # dropped and never reach the core). udp/tcp bind per-source and re-learn naturally.
        if transport in ("raw", "flux") and role == "server":
            psrc = _clean_pool("peer_src_ips")
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
        # The spoof carrier is the same raw datapath with a forged IP header; crypto is likewise mandatory
        # (the AEAD is the only integrity on a forged-header frame).
        if transport == "spoof" and (not psk or cipher == "none"):
            raise ValueError("ترنسپورت spoof به رمزنگاری (psk) نیاز دارد — هر فریمِ هدرجعلی با AEAD احراز می‌شود")
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
        # raw/flux/spoof (forge IPv4) and tcp/ws (inject decoy TCP segments); not on plain udp. Whitelisting
        # is mandatory — an un-whitelisted key is silently dropped from the stored config and never
        # reaches the core (this is exactly the bug spoofing hit).
        if _as_bool(d.get("fake_desync")):
            if transport not in ("raw", "flux", "spoof", "tcp", "ws"):
                raise ValueError("fake_desync is supported on the raw, flux, spoof, tcp and ws carriers (not udp)")
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
        # IP spoofing (the spoof transport): persist the forged source and/or decoy destination so
        # _core_config can wire them per role. Without this the fields never reach the stored cfg and
        # spoofing is a no-op — the exact bug this whitelist exists to prevent.
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
    # in-place rebuild: fully tear the previous build (read once above) down first so nothing tied to a
    if old and old.get("type") != "portfw":   # now-overwritten field (e.g. FOU's old UDP-port decap listener) leaks
        teardown_config(old)
    write_config(name, obj)

    def _fail(msg):
        # The new build failed. Tear it down, then ROLL BACK to the previously-working config instead of
        # deleting the tunnel outright: a transient build or verify blip — a core cold-start slower than
        # the TUN wait, say — must not permanently destroy a tunnel that was healthy before this edit.
        # Only drop the file if there was no prior build to restore, or the restore itself also fails.
        teardown_config(obj)
        if old and old.get("type") != "portfw" and NAME_RE.match(old.get("name", "")):
            write_config(name, old)
            restored = True
            try:
                apply_config(old)
            except Exception:
                restored = False
            # A disabled tunnel legitimately has no netdev, so its restore succeeds as long as apply_config
            # did not throw; require the netdev only when it should be UP. A `core` tunnel's TUN appears
            # ASYNCHRONOUSLY, so a synchronous netdev check here would read False on a slow cold start and
            # delete the restored config. For core, a successful apply_config IS the restore signal.
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
    # Move the data path FIRST and persist only what really happened: a stored `enabled` the interface
    # does not match is the same lie in a different place, and the panel would keep showing it.
    try:
        _set_link_state(cfg, enabled)
    except Exception as e:
        return {"ok": False, "msg": str(e)}
    write_config(name, cfg)
    return {"ok": True, "enabled": enabled}


def op_core_restart(d):
    """Bounce a core tunnel's process on the config already on disk — no rebuild, no config rewrite.

    A rebuild tears the tunnel down on both nodes, re-fetches ECH, re-stamps tuning and may re-pick the
    node IP; all this does is give the core a fresh process. That is what clears state a running core
    cannot clear itself (a poisoned handshake cache, a session it can no longer complete), which is the
    class of failure where the pool failover has nothing to rotate to and stands down."""
    name = _req_name(d)
    cfg = read_config(name)
    if not cfg:
        raise ValueError("tunnel not found")
    if cfg.get("type") != "core":
        raise ValueError("only a core tunnel has a process to restart")
    if not _as_bool(cfg.get("enabled", True)):
        # Restarting one the operator switched OFF would put its data path back up behind their back.
        return {"ok": False, "msg": "تونل غیرفعال است"}
    if not os.path.exists(_cfg_path(name, ".json")):
        # No core config = nothing to launch on. systemd-run would still succeed and Restart=always
        # would spin the failure every 3s, which reads as "running" from the outside.
        return {"ok": False, "msg": "کانفیگِ هسته روی این نود نیست — تونل را بازسازی کن"}
    if not _core_relaunch(name):
        return {"ok": False, "msg": "هسته بالا نیامد (اینترفیس ظاهر نشد)"}
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
    # Undo the host kernel tuning FIRST. The drop-in and the modules-load file live in /etc, which the
    # rm -rf below never touches, while TUNING_PREV — the only record of the box's ORIGINAL cc/qdisc —
    # sits inside CONFIG_DIR and is destroyed by it. Wiping without this left the host permanently on
    # BBR+fq at every boot with the undo button deleted, which flatly contradicts "nothing remains".
    try:
        revert_kernel_tuning()
    except Exception as e:
        logline(f"wipe: kernel tuning revert failed: {e}")
    _restart_pending.set()  # reject any new mutating op during the shutdown window
    script = ("sleep 1; systemctl stop tnl-node 2>/dev/null; systemctl disable tnl-node 2>/dev/null; "
              "rm -f " + SERVICE_FILE + "; systemctl daemon-reload 2>/dev/null; rm -rf " + CONFIG_DIR)
    subprocess.Popen(["sh", "-c", script], start_new_session=True, stdin=subprocess.DEVNULL,
                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    logline("node wiped by panel request")
    return {"ok": True, "wiped": True}


def op_check(d):
    """On-demand health probe for ONE config. Deliberately the SAME measurement the sweep runs: a
    button that samples differently would disagree with the card it sits on."""
    _require(d, ["name"])
    cfg = read_config(d["name"])
    if not cfg:
        raise ValueError("not found")
    return {"ok": True, "health": health_of(cfg)}


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
    IPv4 is 8 hex chars little-endian; the all-zero form (any length) is the wildcard '0.0.0.0'.
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
    """READ_ONLY: return the ws edge pool's live status (active edge + the per-entry health FSM)
    the core writes for tunnel {name}, so the panel can surface and drive the pool. Empty status
    when the tunnel has no pool or the core hasn't written the file yet."""
    name = _req_name(d)
    path = _cfg_path(name, ".status")
    try:
        with open(path) as f:
            st = json.load(f)
    except (OSError, ValueError):
        return {"ok": True, "active": "", "health": [], "ts": 0}
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
    source) into the normalized shape the panel reads: active endpoint, the full list, the per-endpoint
    health FSM (state / fails / retest countdown), and any operator pin. Empty
    (but well-formed) when the file is missing — the pool doesn't exist or the core hasn't written yet."""
    empty = {"active": "", "addrs": [], "health": [], "pin": "", "ts": 0}
    try:
        with open(_cfg_path(name, suffix)) as f:
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
    name = _req_name(d)
    dst = _read_peer_pool(name, ".peerpool")
    src = _read_peer_pool(name, ".srcpool")
    return {"ok": True, "now": int(time.time()), "dst": dst, "src": src}


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
    path = _cfg_path(name, suffix + ".cmd")
    # Write atomically (tmp + replace): the core polls this file once per second and removes it, so a
    # half-written file would be read+deleted and the pin SILENTLY LOST. os.replace is atomic.
    err = _atomic_write_json(path, {"key": key})
    if err:
        return {"ok": False, "error": err}
    return {"ok": True}


def _pool_sighup(name, is_pool, no_pool_msg):
    """SIGHUP the running core for `name` — the shared body of the two 'probe now' ops (retest every
    suspect/dead pool entry at once). Guards that the core actually installs a SIGHUP handler first
    (is_pool): signaling a plain core would fall through to Go's default disposition and kill the tunnel."""
    if not is_pool(name):
        return {"ok": False, "error": no_pool_msg}
    rc, out, err = run(["systemctl", "kill", "-s", "SIGHUP", _core_unit(name)])
    if rc != 0:
        return {"ok": False, "error": (err or out or "").strip() or ("سیگنال به هسته نرسید (" + name + ")")}
    return {"ok": True}


def op_peer_probe_now(d):
    """Live 'probe now' for a direct-transport pool: SIGHUP tells the running core to retest EVERY
    suspect/dead endpoint immediately (re-admit it to the live rotation) instead of waiting out the
    backoff, so a lifted block heals at once. No rebuild, TUN stays up."""
    return _pool_sighup(_req_name(d), _is_peer_pool, "این تونل استخرِ آی‌پی ندارد")


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
    path = _cfg_path(name, ".status.cmd")
    # Write atomically (tmp + replace): the core polls this file once per second and removes it,
    # so a half-written file would be read+deleted and the pin SILENTLY LOST. os.replace is atomic.
    err = _atomic_write_json(path, {"kind": kind, "key": key})
    if err:
        return {"ok": False, "error": err}
    return {"ok": True}


def op_pool_probe_now(d):
    """Live 'probe now' for a ws edge pool: SIGHUP tells the running core to retest EVERY
    suspect/dead edge immediately (cheap TLS-only probes) instead of waiting out the backoff,
    so a lifted block heals at once. No rebuild, TUN stays up."""
    return _pool_sighup(_req_name(d), _is_ws_pool, "این تونل استخرِ لبه ندارد")


CORE_VER_RE = re.compile(r"^(?!.*\.\.)[A-Za-z0-9._-]{1,40}$")  # negative-lookahead rejects any '..' → no path traversal in the release URL
CORE_SHA_RE = re.compile(r"^[0-9a-f]{64}$")

# An agent source the panel accepts is capped at 256 KB; a core binary is ~3 MB. The caps are here so a
# URL that answers with something enormous cannot fill the disk before the sha256 gate ever runs.
FETCH_MAX_AGENT = 262144
FETCH_MAX_CORE = 64 << 20
# How long the whole fetch may take, and how much is read per call. The budget has to sit UNDER the
# panel's own wait for this op's answer, or the panel gives up first and reports a failure for an
# install that is still running -- see _fetch_url.
FETCH_BUDGET = 150
FETCH_CHUNK = 256 * 1024
# How many times a cut transfer may pick up where it stopped. The BUDGET is what really ends it; this
# only stops a path that resets instantly from spinning through the whole budget one byte at a time.
FETCH_TRIES = 6


def _is_central_origin(u):
    """True when u is the PANEL's own origin AND that origin is a plaintext one.

    This is the single exception to the https rule, and it exists only because the panel may still run
    plain HTTP. It is not a name a caller can claim -- it is the address the panel itself announced. Once
    the panel announces TLS, its origin is https and this returns False for any http url, so the
    exception closes itself the moment it stops being needed."""
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
    """True when this response really is the rest of the file from `offset`.

    A 206 alone is not enough: the status says "partial" while the body may be a full copy, and taking
    it on trust appends one to what is already held. Only Content-Range says where the bytes actually
    start, so a 206 without a readable one is refused too."""
    if resp.status != 206:
        return False
    m = re.match(r"\s*bytes\s+(\d+)-", resp.headers.get("Content-Range", "") or "")
    return bool(m) and int(m.group(1)) == offset


def _fetch_url(url, max_bytes, timeout=45, budget=FETCH_BUDGET):
    """Download url and return its bytes. Used ONLY in the panel's "let the node fetch it" delivery mode:
    the panel still sends the sha256 and its signature over that sha, and the caller checks both before
    anything is installed -- so this function is not trusted, it only saves the panel's uplink.

    TWO deadlines, because they answer different questions. `timeout` is the socket's, and a socket
    timeout applies PER READ -- so it only ever catches a peer that has gone silent, and a stream
    crawling at a few KB/s is never cut by it however long it takes. `budget` is the one that bounds
    the whole fetch. Without it this call had no total at all: on a path measured delivering 365 KB in
    200 s, the node kept reading long past the panel's own wait for the answer, so the operator was
    told the install had FAILED while it was still running and would go on to succeed.

    https, with ONE exception: the panel's own origin, which runs plain HTTP today. The signature is
    what makes the bytes safe either way, but for anything else a plaintext fetch would hand an on-path
    observer a free record of which version every node runs -- and that is not worth giving away to
    save the panel a certificate. When the panel gets TLS its URL is https and this exception simply
    stops being taken."""
    u = str(url or "").strip()
    low = u.lower()
    if low.startswith("http://"):
        if not _is_central_origin(u):
            raise ValueError("update url must be https (plaintext is allowed only for the panel's own origin)")
    elif not low.startswith("https://"):
        raise ValueError("update url must be https")
    deadline = time.monotonic() + budget
    chunks, got, want, err = [], 0, 0, None
    # RESUME. A path that cuts a transfer at four megabytes never finishes an eleven-megabyte one if
    # every attempt starts from zero -- MEASURED on the real path, that is exactly what happened. Ask
    # for the rest instead, so each attempt only has to carry what is left. A server with no Range
    # support answers 200 with the whole body, which is the same as never having asked.
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
                # Keep what we hold only if this really is the continuation we asked for. A 200 is the
                # whole file again; so is a 206 whose Content-Range starts anywhere but where we
                # stopped -- and THAT one is the dangerous shape, because the status says "partial"
                # while the body is a full copy. Appending either one splices, and the sha gate then
                # reports «checksum mismatch» about a file that was never wrong.
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
                    # read1, not read: read() blocks until it has the WHOLE chunk, so the budget is
                    # only checked once per chunk and overshoots it by however long that takes -- at
                    # the rate measured on the real path, minutes. read1 returns what has arrived.
                    c = r.read1(FETCH_CHUNK)
                    if not c:
                        # The body ended. That is the ONLY reliable "finished" signal: a server may
                        # send no Content-Length at all, and treating its absence as "not finished"
                        # re-fetches a complete file until the attempts run out -- MEASURED: six
                        # requests for a file served whole on the first, and a 416 on the last of them
                        # thrown in place of the bytes already in hand. Where the size IS declared, an
                        # end short of it is the close-mid-body case instead, and resuming is exactly
                        # what that wants.
                        done = not want or got >= want
                        break
                    chunks.append(c)
                    got += len(c)
            err = None
        except Exception as e:
            err = e          # a cut mid-body: whatever arrived is kept, and the next try asks for the rest
    if err is not None and not done:
        raise err
    buf = b"".join(chunks)
    if len(buf) > max_bytes:
        raise ValueError("downloaded file is larger than %d bytes" % max_bytes)
    if not buf:
        raise ValueError("downloaded file is empty")
    # A server that closes mid-body leaves read() returning SHORT and raising nothing, so without this
    # the truncation is only noticed by the sha256 gate below -- which reports «checksum mismatch», i.e.
    # it blames the file the panel staged for a transfer that was cut. MEASURED against a real panel:
    # 5613896 of 11243704 bytes arrived, silently, behind a correct Content-Length.
    if want and len(buf) != want:
        raise ValueError("download truncated: got %d of %d bytes" % (len(buf), want))
    return buf


def _verify_update_sig(msg, sig_b64):
    """Verify an RSA-SHA256 signature (base64) over `msg` (bytes) with the panel PUBLIC key stored in
    node.conf['update_pubkey'], via openssl. FAIL-CLOSED: returns True ONLY when a key is provisioned AND
    the signature verifies; False otherwise — including when NO key is provisioned yet. This is what stops
    a stolen token from pushing malicious root code: only the panel (holding the matching private key) can
    produce a valid signature, and an unprovisioned node refuses every code/binary push rather than
    accepting it unsigned. The panel provisions the key (set-update-key, first-set-only) immediately before
    every push, so a legitimate push always finds the key in place. Callers run under _apply_lock, so the
    fixed temp paths below are never used concurrently."""
    try:
        pub = str(load_conf().get("update_pubkey") or "").strip()
    except Exception:
        return False
    if not pub:
        return False  # fail-closed: no verify key -> refuse the push (the panel self-provisions the key first)
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
    _require(d, ["sha256"])
    want = str(d.get("sha256") or "").strip().lower()
    if not CORE_SHA_RE.match(want):
        raise ValueError("bad sha256")
    if d.get("data") is None and d.get("url"):
        # Delivery mode "node": fetch the release asset ourselves. `want` and the signature over it still
        # decide what may be installed, so a hostile mirror gets no further than a checksum mismatch.
        try:
            raw = _fetch_url(d["url"], FETCH_MAX_CORE)
        except Exception as e:
            return {"ok": False, "msg": "download failed: " + str(e)[:140]}
    else:
        _require(d, ["data"])
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
    src = d.get("code")
    if src is None and d.get("url"):
        # Delivery mode "node": the panel sent a URL instead of the bytes. The sha256 is REQUIRED here --
        # it is the only thing tying what we download to what the panel decided to install -- and the
        # signature below is over exactly that sha, so the trust chain is the same as a byte push.
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


# --------------------------------------------------------------------------- spoof egress probe
# --probe-spoof is a LOCAL capability check only; it cannot say whether the upstream network FORWARDS a
# forged source or a decoy destination ROUTES to the server. This probe measures that end to end: the
# RECEIVER captures off the wire (AF_PACKET) and returns a token, the SENDER forges nonce packets.

_EGRESS = {}                       # token -> {"done": bool, "saw": {...}, "observed": {...}}
_EGRESS_LOCK = threading.Lock()
_EGRESS_MAX = 32                   # cap the result map so a caller can't grow it unbounded
_PROBE_TAGS = (b"BAS", b"SRC", b"DST")   # baseline / forged-source / decoy-destination


def _egress_checksum(b):
    """16-bit one's-complement checksum (RFC 1071) over b, for the forged IPv4 header."""
    if len(b) % 2:
        b += b"\x00"
    s = 0
    for i in range(0, len(b), 2):
        s += (b[i] << 8) | b[i + 1]
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff


def _egress_build_ip4(src, dst, proto, payload, ttl=64):
    """Assemble a full IPv4 packet (for an IP_HDRINCL send) with a valid header checksum."""
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
    """A probe payload the receiver can recognise: TAG(3) + nonce bytes. Kept short and fixed."""
    return tag + nonce.encode("ascii", "ignore")[:32]


def _egress_route_local(peer):
    """The local IPv4 the kernel would send toward peer FROM (no packet sent; a connected UDP socket
    just resolves the route). Returns None on failure. Used as the default forged-header source."""
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
    """RECEIVER role: start a bounded background AF_PACKET capture for a spoof egress probe and return a
    token immediately (the capture runs in a daemon thread; read the verdict with spoof-egress-result).
    Watches for our nonce tagged BAS/SRC/DST — baseline reachability, a forged source arriving, and a
    decoy-destination frame arriving. proto is the outer IP protocol number the real tunnel would use."""
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
            fd = socket.socket(socket.AF_PACKET, socket.SOCK_DGRAM, socket.htons(0x0800))  # ETH_P_IP
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
                if len(addr) >= 3 and addr[2] == 4:   # PACKET_OUTGOING — ignore our own transmits
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
                    observed["src_seen_from"] = src   # the forged source, as it survived the path
                elif tag == b"DST" and (not decoy or dst == decoy):
                    saw["dst"] = True
                    observed["dst_seen"] = dst
                if saw["baseline"] and saw["src"] and (saw["dst"] or not decoy):
                    break   # everything expected has arrived; no need to wait out the window
        except OSError as e:
            observed["error"] = str(e)
        finally:
            if fd is not None:
                fd.close()
            with _EGRESS_LOCK:
                _EGRESS[token] = {"done": True, "saw": saw, "observed": observed}

    with _EGRESS_LOCK:
        if len(_EGRESS) >= _EGRESS_MAX:   # evict the oldest-ish finished entries
            for k in [k for k, v in list(_EGRESS.items()) if v.get("done")][: _EGRESS_MAX // 2]:
                _EGRESS.pop(k, None)
        _EGRESS[token] = {"done": False}
    threading.Thread(target=capture, daemon=True).start()
    return {"ok": True, "token": token, "window": window}


def op_spoof_egress_send(d):
    """SENDER role: forge the probe packets toward the receiver. `peer` is the receiver's REAL IP (the
    routing target for every packet). Always sends a BASELINE (real src -> real dst) so the panel can
    tell "the whole path/proto is blocked" from "the forge specifically was dropped"; sends a forged
    SOURCE when `forged_src` is set, and a decoy DESTINATION when `decoy_dst` is set. Root-only."""
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
    if not real_src:                              # default to the route-local source toward the peer
        real_src = _egress_route_local(peer) or ""
    if not real_src or real_src not in local_ips_flat():
        raise ValueError("real_src must be one of this node's own IPs (route-local lookup failed)")
    forged_src = str(d.get("forged_src") or "").strip()
    if forged_src and not is_ipv4(forged_src):
        raise ValueError("bad forged_src")
    decoy_dst = str(d.get("decoy_dst") or "").strip()
    if decoy_dst and not is_ipv4(decoy_dst):
        raise ValueError("bad decoy_dst")

    plan = [("BAS", real_src, peer)]                         # baseline: real -> real
    if forged_src:
        plan.append(("SRC", forged_src, peer))              # forged source -> real dst
    if decoy_dst:
        plan.append(("DST", real_src, decoy_dst))           # real source -> decoy dst (routed to peer)

    fd = None
    sent = []
    try:
        fd = socket.socket(socket.AF_INET, socket.SOCK_RAW, proto)
        fd.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        fd.settimeout(2.0)
        sa = (peer, 0)                                       # sendto address is ALWAYS the real peer
        for tag, s, dstip in plan:
            pkt = _egress_build_ip4(s, dstip, proto, _egress_payload(tag.encode(), nonce))
            for _ in range(3):                               # a few copies to ride out single-packet loss
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
    """Read the verdict of a background capture by its token. {done:false} while the window is still
    open; once done, {saw:{baseline,src,dst}, observed:{...}}."""
    token = str(d.get("token") or "").strip()
    with _EGRESS_LOCK:
        r = _EGRESS.get(token)
    if r is None:
        return {"ok": False, "error": "unknown or expired token"}
    return {"ok": True, **r}


def op_ech_update(d):
    """Live ECH-key push: the panel fetched a freshly-rotated ECHConfigList and pushes it here so the
    RUNNING ws core hot-swaps it (via the <status>.echcmd file the core polls) — NO rebuild, the TUN
    stays up. `snis` is {host: base64_ech}. Works for BOTH a ws edge-pool (retestLoop reads it into the
    pool) and a single ws edge (dialLoop reads it into b.wsECH); the sidecar path is the same for both.
    No-op unless this is a ws core (pool or single edge)."""
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
        if e and len(e) <= 4096 and re.match(r"^[A-Za-z0-9+/=]+$", e):   # base64, same guard as op_tunnel
            clean[str(h)[:255]] = e
    if not clean:
        return {"ok": False, "error": "no valid ech"}
    path = _cfg_path(name, ".status.echcmd")
    err = _atomic_write_json(path, {"snis": clean})
    if err:
        return {"ok": False, "error": err}
    return {"ok": True, "hosts": list(clean.keys())}


def op_kernel_tune(d):
    """Operator-triggered host network tuning (part ب). action = apply | revert | status.
    apply/revert mutate host-wide sysctls; status is a read-only snapshot for the panel button."""
    action = str(d.get("action") or "status").lower()
    if action == "apply":
        err = apply_kernel_tuning()
        if err:  # originals could not be recorded → nothing was changed; surface it, don't claim success
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
       "portcheck": op_portcheck, "edge-status": op_edge_status,
       "peer-status": op_peer_status,
       "peer-select": op_peer_select, "peer-probe-now": op_peer_probe_now,
       "pool-probe-now": op_pool_probe_now, "pool-select": op_pool_select,
       "ech-update": op_ech_update,
       "core-install": op_core_install, "spoof-probe": op_spoof_probe,
       "spoof-egress-listen": op_spoof_egress_listen, "spoof-egress-send": op_spoof_egress_send,
       "spoof-egress-result": op_spoof_egress_result,
       "set-update-key": op_set_update_key,
       "kernel-tune": op_kernel_tune,
       "link-enable": op_link_enable, "core-restart": op_core_restart}
# spoof-egress-* SEND packets / start a capture, so they are POST (not READ_ONLY) even though they
# mutate no stored config — a forged-packet send is a side effect the CSRF guard should cover.
READ_ONLY = {"ping", "list", "check", "portcheck", "spoof-probe", "edge-status", "peer-status"}

# The name on the WIRE, which is not the name in the code. This control channel is plain HTTP, so the
# request line crosses the border in the clear — and MEASURED on the Iran→Germany path, a URI containing
# the string "tunnel" is dropped (5/5 lost; `tunne1` and `xunnel` arrive 5/5). Every other op worked,
# which is why only BUILDING a tunnel on a foreign node ever timed out. So the URL carries an opaque
# token and the readable name stays in the code. Panel side: NODE_WIRE in tnl-central.py, kept in step by
# tools/wire_names_check.py.
WIRE = {
    "pg": "ping", "ls": "list", "ck": "check", "mk": "tunnel", "dl": "delete", "ap": "apply",
    "up": "update", "wz": "wipe", "pf": "portfw", "pe": "portfw-edit", "pn": "portfw-next",
    "pc": "portcheck", "es": "edge-status", "ps": "peer-status", "pl": "peer-select",
    "pp": "peer-probe-now", "qp": "pool-probe-now", "qs": "pool-select", "eu": "ech-update",
    "ci": "core-install", "sp": "spoof-probe", "sl": "spoof-egress-listen", "ss": "spoof-egress-send",
    "sr": "spoof-egress-result", "sk": "set-update-key", "kt": "kernel-tune", "le": "link-enable",
    "cr": "core-restart",
}

# ----------------------------------------------------------------------------- HTTP

class Handler(BaseHTTPRequestHandler):
    server_version = "tnl-node"
    timeout = 30   # socket timeout on slow header/body reads → a pre-auth slowloris can't pin a root thread forever

    def log_message(self, *a):
        pass

    # MAX_CONNS is enforced at the CONNECTION level, not per parsed request: ThreadingHTTPServer spawns a
    # thread per accepted TCP connection BEFORE any header is read, so a slowloris dribbling headers would
    # tie up threads bounded only by the socket timeout. We try-acquire _conn_sem the moment the connection
    # is set up and refuse instantly in handle(), so the thread exits and can never be pinned.
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

    def _authed(self, method):
        """"sig" when this request proved it came from the panel, "" otherwise.

        A SIGNATURE is now the only proof. The bearer token is gone from the wire entirely: it was a
        secret that crossed a censored path on every request and could be replayed forever, and the
        changeover window that accepted both has closed.

        The token is still the shared secret -- it is what the HMAC is keyed on -- it is simply never
        transmitted again."""
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
        n = min(max(n, 0), cap)   # default 1MB — headroom for a pushed agent source (JSON-escaped); raised for core uploads
        raw = self.rfile.read(n) if n > 0 else b""
        self._raw = raw           # kept for the signature's body check, which needs the bytes not the dict
        try:
            obj = json.loads(raw.decode()) if raw else {}
        except Exception:
            return {}
        return obj if isinstance(obj, dict) else {}   # a top-level array/string/number must not reach ops as non-dict

    def _body_matches_sig(self):
        """The body really is the one X-Body claimed — and therefore the one the signature covered."""
        raw = getattr(self, "_raw", b"")
        try:
            return hmac.compare_digest(self.headers.get("X-Body", "") or "",
                                       hashlib.sha256(raw).hexdigest() if raw else "")
        except Exception:   # a non-ASCII header makes compare_digest(str, str) raise
            return False

    def _handle(self, method):
        # The _conn_sem permit is already held for the whole connection (see setup()/handle()), so the
        # number of connections that ever reach here is bounded — no per-request acquire needed.
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
                # Told ONLY to a caller whose signature already verified. The mark is not a secret, and
                # handing it back is what lets a panel whose own counter fell behind catch up in one
                # retry instead of locking itself out of the node for good.
                with _req_ctr_lock:
                    cur = _req_ctr
                self._send(409, {"error": "stale counter", "ctr": cur})
                return
        cp = self.headers.get("X-Central-Port")
        if cp:
            # X-Central-TLS says whether that port speaks TLS; absent or "0" means plain http.
            note_central(self.client_address[0], cp,
                         str(self.headers.get("X-Central-TLS", "")).strip() not in ("", "0"))
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
        if how == "sig" and not self._body_matches_sig():
            # The signature covers X-Body, so this is what binds the bytes that arrived to the ones the
            # panel signed for. A body cut short by the cap above lands here too, which is correct.
            self._send(401, {"error": "body does not match the signature"})
            return
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
    # Native tunnels only need iproute2 (already present) + iptables for port-forwards; openssl verifies
    # signed agent updates. VXLAN/GRE/… are kernel modules loaded on demand — no OpenvSwitch.
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
    """Shared install prefix: ensure the config dir (0700), copy self to the stable INSTALLED path so the
    unit never breaks if the invoked file moves, and load any existing conf. Returns the conf dict."""
    os.makedirs(CONFIG_DIR, exist_ok=True)
    os.chmod(CONFIG_DIR, 0o700)
    if os.path.realpath(SELF_PATH) != INSTALLED:  # copy to a stable path so the unit never breaks if moved
        shutil.copy2(SELF_PATH, INSTALLED)
        os.chmod(INSTALLED, 0o755)
    return load_conf() if os.path.isfile(NODE_CONF) else {}


def _finish_install(conf):
    """Shared install suffix: mint a token if missing, persist the conf, install deps + the systemd unit,
    then enable and (re)start it."""
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
    """Non-interactive install for the central panel's SSH auto-provisioning.
    Prints machine-parseable markers the panel greps for (token/port)."""
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
    _seed_central_cb()   # know the callback BEFORE the first check-in, so a reboot with a new IP is not fatal
    _seed_req_ctr()      # resume the replay counter ahead of anything already accepted
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
