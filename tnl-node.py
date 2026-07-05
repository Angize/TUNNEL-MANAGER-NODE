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

# The custom Go data-plane engine (packet/bip): a static binary the node fetches from the engine
# repo (raw, like the agent's own git update), verifies by sha256, and supervises via systemd-run.
ENGINE_BIN = os.path.join(CONFIG_DIR, "tnl-engine")
# The engine binary is published as a GitHub Release ASSET, one release per version
# (tag v1, v2, …). A node can pin a specific version (stored as conf["engine_version"])
# or track "latest"; downgrade is just pinning an older tag. The panel drives the pin
# via the "engine-update" op.
ENGINE_RELEASES = "https://github.com/Angize/TUNNEL-MANAGER-ENGINE/releases"
_engine_lock = threading.Lock()  # serialize download/replace of the shared engine binary
_engine_sha_cache = {"mtime": None, "sha": ""}  # avoid re-hashing the 3 MB binary on every ping
OBFS_DATA_PAD_MAX = 64   # must match the engine's obfsDataPadMax so the MTU budget covers worst-case padding

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


def base_mtu():
    dev = default_iface()
    if dev:
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
    run(["ip", "link", "add", name, "type", "vxlan", "id", str(cfg["id"]),
         "local", cfg["local_ip"], "remote", cfg["remote_ip"], "dstport", str(dstport)])
    run(["ip", "addr", "add", cfg["tunnel_ip"], "dev", name])
    run(["ip", "link", "set", name, "up"])
    run(["ip", "link", "set", "dev", name, "mtu", str(base_mtu() - 50)])  # IP20+UDP8+VXLAN8+innerEth14


def build_gre(cfg):
    """Native kernel GRE (proto 47) — point-to-point, tunnel IP assigned directly. GRE key == tunnel id."""
    name = cfg["name"]
    _modprobe("ip_gre")   # `ip link add type gre` does not auto-load the module
    _purge_ovs(cfg)       # migrate: clear any OVS bridge/veth left by the old scheme so the name is free
    run(["ip", "link", "del", name])
    run(["ip", "link", "add", name, "type", "gre",
         "local", cfg["local_ip"], "remote", cfg["remote_ip"], "key", str(cfg["id"])])
    run(["ip", "addr", "add", cfg["tunnel_ip"], "dev", name])
    run(["ip", "link", "set", name, "up"])
    run(["ip", "link", "set", "dev", name, "mtu", str(base_mtu() - 28)])  # IP20+GRE4+key4


def build_sit(cfg):
    name = cfg["name"]
    run(["ip", "link", "del", name])
    run(["ip", "tunnel", "add", name, "mode", "sit", "remote", cfg["remote_ip"],
         "local", cfg["local_ip"], "ttl", "255"])
    run(["ip", "-6", "addr", "add", cfg["tunnel_ip"], "dev", name])
    run(["ip", "link", "set", name, "up"])
    run(["ip", "link", "set", "dev", name, "mtu", str(base_mtu() - 28 - 20)])


def build_ipip(cfg):
    """IPv4-in-IPv4 — the lightest L3 tunnel (20-byte overhead). Same shape as SIT but v4."""
    name = cfg["name"]
    _modprobe("ipip")
    run(["ip", "link", "del", name])
    run(["ip", "tunnel", "add", name, "mode", "ipip", "remote", cfg["remote_ip"],
         "local", cfg["local_ip"], "ttl", "255"])
    run(["ip", "addr", "add", cfg["tunnel_ip"], "dev", name])
    run(["ip", "link", "set", name, "up"])
    run(["ip", "link", "set", "dev", name, "mtu", str(base_mtu() - 20)])


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
    run(["ip", "l2tp", "add", "tunnel", "tunnel_id", str(tid), "peer_tunnel_id", str(tid),
         "encap", "udp", "local", cfg["local_ip"], "remote", cfg["remote_ip"],
         "udp_sport", str(port), "udp_dport", str(port)])
    run(["ip", "l2tp", "add", "session", "name", name, "tunnel_id", str(tid),
         "session_id", str(tid), "peer_session_id", str(tid)])
    run(["ip", "addr", "add", cfg["tunnel_ip"], "dev", name])
    run(["ip", "link", "set", name, "up"])
    run(["ip", "link", "set", "dev", name, "mtu", str(base_mtu() - 54)])


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
    run(["ip", "link", "add", "name", name, "type", "ipip", "remote", cfg["remote_ip"],
         "local", cfg["local_ip"], "ttl", "255", "encap", "fou",
         "encap-sport", "auto", "encap-dport", str(port)])
    run(["ip", "addr", "add", cfg["tunnel_ip"], "dev", name])
    run(["ip", "link", "set", name, "up"])
    run(["ip", "link", "set", "dev", name, "mtu", str(base_mtu() - 28)])


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
    run(["ip", "xfrm", "state", "add", "src", local, "dst", remote, "spi", hex(spi_out)] + common)
    run(["ip", "xfrm", "state", "add", "src", remote, "dst", local, "spi", hex(spi_in)] + common)
    for dirn, s, dst in (("out", local, remote), ("in", remote, local), ("fwd", remote, local)):
        run(["ip", "xfrm", "policy", "add", "dir", dirn, "if_id", str(tid),
             "tmpl", "src", s, "dst", dst, "proto", "esp", "reqid", str(tid), "mode", "tunnel"])
    phys = iface_for_ip(local) or default_iface()
    run(["ip", "link", "add", name, "type", "xfrm", "dev", phys, "if_id", str(tid)])
    run(["ip", "addr", "add", cfg["tunnel_ip"], "dev", name])
    run(["ip", "link", "set", name, "up"])
    run(["ip", "link", "set", "dev", name, "mtu", str(base_mtu() - 80)])


def _engine_arch():
    m = os.uname().machine
    return {"x86_64": "amd64", "amd64": "amd64", "aarch64": "arm64", "arm64": "arm64"}.get(m, "amd64")


def _http_get(url, timeout=30):
    try:
        with urllib.request.urlopen(url, timeout=timeout) as r:
            return r.read()
    except Exception:
        return None


def _engine_ref():
    """The engine version this node is pinned to: a release tag (e.g. "v2") or "latest"."""
    try:
        return str(load_conf().get("engine_version") or "latest").strip() or "latest"
    except Exception:
        return "latest"


def _engine_urls(ref, arch):
    """Download URL for the engine binary at `ref`: the GitHub Release ASSET, and only that. The panel
    publishes each version as a release asset (tnl-engine-linux-<arch> + .sha256); there is no repo-tree
    fallback, so a version exists exactly when its release asset does."""
    asset = f"tnl-engine-linux-{arch}"
    if ref in ("", "latest", None):
        return [f"{ENGINE_RELEASES}/latest/download/{asset}"]
    return [f"{ENGINE_RELEASES}/download/{ref}/{asset}"]


def _installed_engine_sha():
    """sha256 of the installed binary, cached by mtime so ping doesn't re-hash 3 MB each time."""
    try:
        st = os.stat(ENGINE_BIN)
        if _engine_sha_cache["mtime"] != st.st_mtime:
            with open(ENGINE_BIN, "rb") as f:
                _engine_sha_cache["sha"] = hashlib.sha256(f.read()).hexdigest()
            _engine_sha_cache["mtime"] = st.st_mtime
        return _engine_sha_cache["sha"]
    except Exception:
        return ""


def _ensure_engine(ref=None, force=False):
    """Make sure /opt/tunnel/tnl-engine exists. Routine callers (a tunnel build/rebuild) pass force=False:
    if a binary is ALREADY present it is left completely untouched — no network call, no version check —
    so builds, rebuilds and reconciles never change the engine. Only an explicit engine-update passes
    force=True, which downloads the release asset for `ref`, verifies its sha256, and installs it. We
    never install a binary whose checksum does not verify (it runs as root)."""
    with _engine_lock:
        have = os.path.isfile(ENGINE_BIN)
        if have and not force:
            return                       # a binary is present; only engine-update (force) ever replaces it
        if ref is None:
            ref = _engine_ref()
        arch = _engine_arch()
        cur = None
        if have:
            with open(ENGINE_BIN, "rb") as f:
                cur = hashlib.sha256(f.read()).hexdigest()
        last = "no source reachable"
        for url in _engine_urls(ref, arch):
            sha_raw = _http_get(url + ".sha256")
            want = sha_raw.decode().split()[0].strip() if sha_raw else ""
            if not want:                # can't verify this source -> try the next
                last = "checksum unavailable"
                continue
            if have and cur == want:
                return                  # already the pinned build; nothing to do
            data = _http_get(url, timeout=120)
            if not data:
                last = "download failed"
                continue
            if hashlib.sha256(data).hexdigest() != want:
                last = "checksum mismatch"    # NEVER install an unverified binary (runs as root)
                continue
            tmp = ENGINE_BIN + ".new"
            with open(tmp, "wb") as f:
                f.write(data)
            os.chmod(tmp, 0o755)
            os.replace(tmp, ENGINE_BIN)
            return
        # no source produced a verified binary
        if have:
            return                      # offline-tolerant: keep the working copy we already have
        raise RuntimeError(f"could not install engine {ref}: {last}")


def _engine_port(cfg):
    return int(cfg.get("port") or (20000 + int(cfg["id"])))


def _engine_config(cfg):
    """Pure: build the JSON the engine binary consumes from a stored tunnel config. The tun device is
    named after the config so /proc/net/dev accounting and `ip link show <name>` health work unchanged.
    Crypto is on whenever a psk is present; the psk never leaves the node (public_configs pops it)."""
    name = cfg["name"]
    port = _engine_port(cfg)
    cipher = str(cfg.get("cipher") or "auto")   # match the panel's default so the MTU/crypto sizing agrees
    crypto_on = bool(cfg.get("psk")) and cipher != "none"  # a psk with cipher=none is NOT encryption
    transport = str(cfg.get("transport") or "udp").lower()
    raw_profile = str(cfg.get("raw_profile") or "bip").lower()
    obfs = bool(cfg.get("obfs")) and crypto_on   # obfs is meaningless without the AEAD key
    # MTU budget = outer headers + bip framing + obfs padding + AEAD (nonce+tag) + wire mask salt.
    if transport == "raw":
        # IP20 + the profile's carrier header (bip/ipip add none; gre 4; icmp/udp 8; tcp 20).
        outer = 20 + {"bip": 0, "ipip": 0, "gre": 4, "icmp": 8, "udp": 8, "tcp": 20}.get(raw_profile, 0)
    else:
        outer = 40 if transport == "tcp" else 28        # IP20 + TCP20 | IP20 + UDP8
    if obfs:
        framing = (2 if transport == "tcp" else 0) + 3 + OBFS_DATA_PAD_MAX  # masked-len + [type,len] + max pad
    else:
        framing = 4 if transport == "tcp" else 2        # (len)+magic+type | magic+type
    overhead = outer + framing
    if crypto_on:
        # AEAD nonce+tag, plus the 12-byte per-frame mask salt the engine prepends (v2 wire).
        overhead += (40 if cipher == "xchacha20-poly1305" else 28) + 12
    mtu = max(1280, base_mtu() - overhead)
    ecfg = {
        "role": cfg.get("role"),
        "mode": "packet",
        "profile": "bip",
        "transport": transport,
        "obfs": obfs,
        "tun_name": name,
        "tun_addr": cfg["tunnel_ip"],
        "tun_peer": peer_of(cfg["tunnel_ip"], "engine"),
        "mtu": mtu,
        "keepalive": 15,
        "crypto": {"enabled": crypto_on, "psk": cfg.get("psk", ""), "cipher": cipher},
    }
    # TLS cover (HTTPS camouflage) — TCP only; carries an optional SNI to present.
    if bool(cfg.get("cover")) and transport == "tcp" and crypto_on:
        ecfg["cover"] = True
        sni = str(cfg.get("cover_sni") or "").strip()
        if sni:
            ecfg["cover_sni"] = sni
    if transport == "raw":
        ecfg["raw_profile"] = raw_profile
    if bool(cfg.get("gso")):     # TUN segmentation offload — local throughput optimization
        ecfg["gso"] = True
    if cfg.get("role") == "server":
        ecfg["listen"] = f"0.0.0.0:{port}"
    else:
        ecfg["peer"] = f"{cfg['remote_ip']}:{port}"
    return ecfg


def _engine_unit(name):
    return "tnl-eng-" + name


def build_engine(cfg):
    """Fetch/verify the engine binary, write its per-tunnel config, and (re)launch it under a transient
    systemd unit with Restart=always. Then wait for the TUN to appear so op_tunnel's verify sees it."""
    name = cfg["name"]
    _ensure_engine()
    ecfg = _engine_config(cfg)
    path = os.path.join(CONFIG_DIR, "engine-" + name + ".json")
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        json.dump(ecfg, f, indent=2)
    os.chmod(tmp, 0o600)          # holds the psk -> keep it private like node.conf
    os.replace(tmp, path)
    unit = _engine_unit(name)
    run(["systemctl", "stop", unit])
    run(["systemctl", "reset-failed", unit])
    run(["systemd-run", "--unit", unit, "--collect",
         "-p", "Restart=always", "-p", "RestartSec=3",
         ENGINE_BIN, "--config", path])
    for _ in range(30):          # engine opens the TUN a beat after systemd-run returns
        if run(["ip", "link", "show", name])[0] == 0:
            break
        time.sleep(0.1)


def _engine_teardown(cfg):
    name = cfg.get("name", "")
    if not NAME_RE.match(name):
        return
    unit = _engine_unit(name)
    run(["systemctl", "stop", unit])       # kills the engine -> its non-persistent TUN disappears
    run(["systemctl", "reset-failed", unit])
    try:
        os.remove(os.path.join(CONFIG_DIR, "engine-" + name + ".json"))
    except OSError:
        pass


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
    rc, _, _ = run(["iptables", "-t", "nat", "-C", "POSTROUTING", "-o", iface, "-j", "MASQUERADE"])
    if rc != 0:
        run(["iptables", "-t", "nat", "-A", "POSTROUTING", "-o", iface, "-j", "MASQUERADE"])
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
    elif t == "engine":
        build_engine(cfg)
    elif t == "portfw":
        build_portfw(cfg)


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
    elif ttype == "engine":
        _engine_teardown(cfg)
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
    rc, _, _ = run(["ip", "link", "show", name])   # every type is now a plain kernel netdev
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
        net = _read_net(cfgs)   # per-tunnel + node byte counters (skipped if unreadable — never fails ping)
        for k, v in _read_pf_net(cfgs).items():   # per-portfw counters, namespaced so they never collide
            net["pf:" + k] = v
        stats["net"] = net
    except Exception:
        pass
    return {"ok": True, "agent": "tnl-node", "version": 22, "ready": True,
            "hostname": socket.gethostname(), "ips": all_ips(), "sha256": _SELF_SHA,
            "tunnels": len([c for c in cfgs if c.get("type") != "portfw"]),
            "portfw": len([c for c in cfgs if c.get("type") == "portfw"]),
            "engine_ver": _engine_ref(), "engine_sha": _installed_engine_sha()[:12],
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
    if ttype not in ("vxlan", "gre", "sit", "ipip", "l2tpv3", "fou", "ipsec", "engine"):
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
    if ttype in ("l2tpv3", "fou", "engine", "vxlan"):   # optional UDP port; l2tp/fou/engine blank->from id, vxlan blank->4789
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
    if ttype == "engine":
        role = d.get("role")
        if role not in ("server", "client"):
            raise ValueError("engine needs role server|client")
        obj["role"] = role
        cipher = str(d.get("cipher") or "auto").strip().lower()
        if cipher not in ("auto", "aes-256-gcm", "aes-128-gcm", "chacha20-poly1305", "xchacha20-poly1305", "none"):
            raise ValueError("bad engine cipher")
        obj["cipher"] = cipher
        transport = str(d.get("transport") or "udp").strip().lower()
        if transport not in ("udp", "tcp", "raw"):
            raise ValueError("bad engine transport")
        obj["transport"] = transport
        if transport == "raw":        # raw-IP carrier: which protocol the sealed frame is wrapped in
            profile = str(d.get("raw_profile") or "bip").strip().lower()
            if profile not in ("bip", "ipip", "gre", "icmp", "udp", "tcp"):
                raise ValueError("bad raw_profile")
            obj["raw_profile"] = profile
        psk = str(d.get("psk") or "").strip()
        if psk:                       # crypto is optional but recommended; when set it must be strong enough
            if len(psk) < 16:
                raise ValueError("engine psk too short (>=16)")
            obj["psk"] = psk          # popped from public_configs, so it never leaves the node
        obfs = bool(d.get("obfs"))    # anti-DPI: needs the AEAD key, so a psk (and a real cipher) is required
        if obfs and (not psk or cipher == "none"):
            raise ValueError("obfs requires a psk and encryption")
        obj["obfs"] = obfs
        # TLS cover (HTTPS camouflage) — persist it so _engine_config can forward it to the engine.
        if bool(d.get("cover")) and transport == "tcp":
            obj["cover"] = True
            sni = str(d.get("cover_sni") or "").strip()
            if sni:
                obj["cover_sni"] = sni
        if bool(d.get("gso")):        # TUN segmentation offload (throughput); Linux only, harmless if unsupported
            obj["gso"] = True
    old = read_config(name)   # in-place rebuild: fully tear the previous build down first so nothing tied to a
    if old and old.get("type") != "portfw":   # now-overwritten field (e.g. FOU's old UDP-port decap listener) leaks
        teardown_config(old)
    write_config(name, obj)
    try:
        apply_config(obj)
    except Exception as e:
        # apply blew up (e.g. engine download/checksum failure): the old build is
        # already gone and this config was just written, so undo the partial build
        # and drop the file — otherwise it lingers, inflates op_ping/op_list counts,
        # and gets retried on every boot via apply_all. Mirrors the rc!=0 cleanup.
        teardown_config(obj)
        try:
            os.remove(os.path.join(CONFIG_DIR, name + ".json"))
        except OSError:
            pass
        return {"ok": False, "msg": str(e)}
    # builds run `ip` via run() which never raises on failure, so verify the netdev really exists
    rc, _, _ = run(["ip", "link", "show", name])   # every type is a plain kernel netdev now
    if rc != 0:
        teardown_config(obj)
        try:
            os.remove(os.path.join(CONFIG_DIR, name + ".json"))
        except OSError:
            pass
        need = {"vxlan": "vxlan", "gre": "ip_gre", "sit": "sit", "ipip": "ipip",
                "l2tpv3": "l2tp_eth", "fou": "fou و ipip", "ipsec": "xfrm_interface",
                "engine": "موتورِ tnl-engine"}[ttype]
        return {"ok": False, "msg": f"اینترفیسِ {ttype} ساخته نشد — «{need}» روی این نود نصب/فعال نیست"}
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


def _port_busy_proc(port, proto):
    """Fallback when `ss` is unavailable: scan /proc/net/{tcp,tcp6}|{udp,udp6}. No process name.
    TCP listeners have st==0A; a bound UDP socket has a non-zero local port. Returns bool."""
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
                    hexport = local.rsplit(":", 1)[-1]
                    try:
                        if int(hexport, 16) == int(port):
                            return True
                    except ValueError:
                        continue
        except (OSError, StopIteration):
            continue
    return False


def _port_busy(port, proto):
    """Is `port` already listening on this node for the given proto? Sees ALL processes
    (Xray/nginx/x-ui/…), not just our tunnels. Returns (busy, who)."""
    proto = "tcp" if str(proto).lower() == "tcp" else "udp"
    flag = "-t" if proto == "tcp" else "-u"
    rc, out, _ = run(["ss", "-H", "-l", "-n", "-p", flag])
    if rc == 0:
        for line in out.splitlines():
            f = line.split()
            if len(f) < 4:
                continue
            local = f[3]   # State Recv-Q Send-Q Local:Port Peer:Port [users:(...)]
            if ":" not in local:
                continue
            if local.rsplit(":", 1)[-1] == str(port):
                return True, _ss_proc(line)
        return False, ""
    return _port_busy_proc(port, proto), ""


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
    busy, who = _port_busy(port, proto)
    return {"ok": True, "busy": busy, "who": who, "port": port, "proto": proto}


ENGINE_VER_RE = re.compile(r"^(?!.*\.\.)[A-Za-z0-9._-]{1,40}$")  # negative-lookahead rejects any '..' → no path traversal in the release URL
ENGINE_SHA_RE = re.compile(r"^[0-9a-f]{64}$")


def op_engine_update(d):
    """Pin this node to a specific engine version (a release tag, or "latest") and install it, then
    rebuild the running engine tunnels so they restart on the new binary. Downgrade = pass an older tag.
    Pinning stops routine tunnel rebuilds from silently changing the engine."""
    version = str(d.get("version") or "latest").strip()
    if version != "latest" and (".." in version or not ENGINE_VER_RE.match(version)):
        raise ValueError("bad engine version")   # reject '..' explicitly → never let a tag traverse out of the release URL
    conf = load_conf()
    conf["engine_version"] = version
    save_conf(conf)
    _ensure_engine(version, force=True)   # explicit update: download + verify + install even if a binary exists
    restarted, errs = 0, []
    for c in raw_configs():           # relaunch every engine tunnel on the freshly-installed binary
        if c.get("type") == "engine":
            try:
                build_engine(c)
                restarted += 1
            except Exception as e:
                errs.append(f"{c.get('name')}: {e}")
    logline(f"engine pinned to {version}; rebuilt {restarted} engine tunnel(s)")
    return {"ok": True, "version": version, "engine_sha": _installed_engine_sha()[:12],
            "restarted": restarted, "errors": errs}


def op_engine_install(d):
    """Install a raw engine binary pushed from the panel (base64), not a published release. Verify its
    sha256, swap it in atomically, pin the node to a custom label, then rebuild the engine tunnels so they
    relaunch on it. NEVER install a binary whose checksum does not verify (it runs as root)."""
    _require(d, ["data", "sha256"])
    want = str(d.get("sha256") or "").strip().lower()
    if not ENGINE_SHA_RE.match(want):
        raise ValueError("bad sha256")
    try:
        raw = base64.b64decode(d["data"], validate=True)
    except Exception:
        raise ValueError("bad base64 payload")
    if len(raw) < 100000:                         # an engine binary is ~3 MB; anything tiny is a mistake, never install it
        return {"ok": False, "msg": "binary too small"}
    got = hashlib.sha256(raw).hexdigest()
    if got != want:
        return {"ok": False, "msg": "checksum mismatch"}   # transport truncation guard — never install unverified bytes
    label = str(d.get("version") or "custom").strip() or "custom"
    if not ENGINE_VER_RE.match(label):
        label = "custom"
    with _engine_lock:
        tmp = ENGINE_BIN + ".new"
        with open(tmp, "wb") as f:
            f.write(raw)
        os.chmod(tmp, 0o755)
        os.replace(tmp, ENGINE_BIN)               # atomic swap on the same fs — no half-written window
    conf = load_conf()
    conf["engine_version"] = label
    save_conf(conf)
    restarted, errs = 0, []
    for c in raw_configs():                        # relaunch every engine tunnel on the freshly-installed binary
        if c.get("type") == "engine":
            try:
                build_engine(c)
                restarted += 1
            except Exception as e:
                errs.append(f"{c.get('name')}: {e}")
    logline(f"engine installed from upload ({label}, sha {got[:12]}); rebuilt {restarted} engine tunnel(s)")
    return {"ok": True, "version": label, "engine_sha": got[:12], "restarted": restarted, "errors": errs}


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
       "delete": op_delete, "apply": op_apply, "update": op_update, "wipe": op_wipe,
       "portcheck": op_portcheck, "engine-update": op_engine_update,
       "engine-install": op_engine_install}
READ_ONLY = {"ping", "list", "check", "portcheck"}

# ----------------------------------------------------------------------------- HTTP

class Handler(BaseHTTPRequestHandler):
    server_version = "tnl-node"
    timeout = 30   # socket timeout on slow header/body reads → a pre-auth slowloris can't pin a root thread forever

    def log_message(self, *a):
        pass

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
        n = min(max(n, 0), cap)   # default 1MB — headroom for a pushed agent source (JSON-escaped); raised for engine uploads
        raw = self.rfile.read(n) if n > 0 else b""
        try:
            obj = json.loads(raw.decode()) if raw else {}
        except Exception:
            return {}
        return obj if isinstance(obj, dict) else {}   # a top-level array/string/number must not reach ops as non-dict

    def _handle(self, method):
        if not _conn_sem.acquire(blocking=False):   # too many in-flight handlers → shed load instead of spawning unbounded root threads
            try:
                self._send(503, {"error": "server busy, retry shortly"})
            except Exception:
                pass
            return
        try:
            self._handle_locked(method)
        finally:
            _conn_sem.release()

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
        # engine-install carries a base64-encoded engine binary (~3MB raw → ~4MB base64); a 1MB cap
        # would truncate it and fail the JSON parse, so raise the cap for that op only.
        cap = 20971520 if cmd == "engine-install" else 1048576
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
