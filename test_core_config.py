#!/usr/bin/env python3
# Unit tests for the pure config-mapping logic in tnl-node.py (no root / no
# network needed). Run: python3 test_core_config.py
import importlib.util
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
spec = importlib.util.spec_from_file_location("tnlnode", os.path.join(HERE, "tnl-node.py"))
tnl = importlib.util.module_from_spec(spec)
spec.loader.exec_module(tnl)
tnl.base_mtu = lambda: 1500  # deterministic, avoids shelling out to `ip`

FAILS = []


def check(name, cond):
    print(("ok  " if cond else "FAIL") + "  " + name)
    if not cond:
        FAILS.append(name)


def cfg(**kw):
    base = {"name": "cor-1", "id": 5, "role": "server", "local_ip": "198.51.100.7",
            "tunnel_ip": "10.200.0.1/24", "remote_ip": "203.0.113.9"}
    base.update(kw)
    return tnl._core_config(base)


# #20: a psk with cipher="none" must NOT be reported as encryption enabled.
e = cfg(psk="0123456789abcdef", cipher="none")
check("cipher=none + psk -> crypto disabled", e["crypto"]["enabled"] is False)
check("cipher=none -> obfs forced off", e["obfs"] is False)

# #20: a psk with a real cipher stays enabled.
e = cfg(psk="0123456789abcdef", cipher="auto")
check("cipher=auto + psk -> crypto enabled", e["crypto"]["enabled"] is True)

# obfs only survives when crypto is really on.
e = cfg(psk="0123456789abcdef", cipher="none", obfs=True)
check("obfs with cipher=none -> off", e["obfs"] is False)
e = cfg(psk="0123456789abcdef", cipher="auto", obfs=True)
check("obfs with real cipher -> on", e["obfs"] is True)

# #21: absent cipher defaults to "auto" (matching the panel), not aes-256-gcm.
e = cfg(psk="0123456789abcdef")
check("default cipher is 'auto'", e["crypto"]["cipher"] == "auto")

# no psk -> clear mode regardless of cipher text.
e = cfg(cipher="aes-256-gcm")
check("no psk -> crypto disabled", e["crypto"]["enabled"] is False)

# transport mapping + listen/peer wiring.
e = cfg(psk="0123456789abcdef", transport="tcp", role="server")
check("transport tcp passes through", e["transport"] == "tcp")
check("server role -> listen set", e.get("listen", "").endswith(":20005"))
# server must bind to THIS node's physical IP, not 0.0.0.0 — otherwise a raw (portless) tunnel on a
# secondary IP replies from the primary IP and the client drops every packet. Regression guard.
check("server listen binds the local IP (not 0.0.0.0)", e.get("listen") == "198.51.100.7:20005")
check("raw server also binds the local IP",
      cfg(psk="0123456789abcdef", transport="raw", role="server").get("listen") == "198.51.100.7:20005")
e = cfg(psk="0123456789abcdef", transport="udp", role="client")
check("client role -> peer set", e.get("peer") == "203.0.113.9:20005")

# MTU shrinks more when obfs padding + xchacha overhead are in play.
plain = cfg(psk="0123456789abcdef", cipher="auto")["mtu"]
obfsx = cfg(psk="0123456789abcdef", cipher="xchacha20-poly1305", obfs=True)["mtu"]
check("obfs+xchacha MTU < plain MTU", obfsx < plain)

# raw transport: profile forwarded, defaults to bip, and its carrier header sizes the MTU.
e = cfg(psk="0123456789abcdef", transport="raw", raw_profile="gre")
check("raw transport passes through", e["transport"] == "raw")
check("raw_profile forwarded", e["raw_profile"] == "gre")
check("raw defaults profile to bip", cfg(psk="0123456789abcdef", transport="raw")["raw_profile"] == "bip")
bip_mtu = cfg(psk="0123456789abcdef", transport="raw", raw_profile="bip")["mtu"]
tcp_mtu = cfg(psk="0123456789abcdef", transport="raw", raw_profile="tcp")["mtu"]
check("raw tcp-profile MTU < bip-profile MTU (bigger carrier header)", tcp_mtu < bip_mtu)

# GSO flag forwarded when set, omitted otherwise.
check("gso forwarded when set", cfg(psk="0123456789abcdef", gso=True).get("gso") is True)
check("gso omitted by default", "gso" not in cfg(psk="0123456789abcdef"))

# TLS cover forwarded on tcp; ignored on the raw carrier.
e = cfg(psk="0123456789abcdef", transport="tcp", cover=True, cover_sni="www.site.com")
check("cover forwarded on tcp", e.get("cover") is True and e.get("cover_sni") == "www.site.com")
check("cover ignored on raw", "cover" not in cfg(psk="0123456789abcdef", transport="raw", cover=True, cover_sni="x.com"))

# IP spoofing (raw bip + crypto): decoy destination + optional source, wired per role.
# Client end: forges the header src/dst; the real server is still the peer.
e = cfg(psk="k"*16, transport="raw", raw_profile="bip", role="client",
        spoof_src="198.51.100.9", spoof_dst="203.0.113.7")
check("client forwards spoof_src_ip", e.get("spoof_src_ip") == "198.51.100.9")
check("client forwards spoof_dst_ip", e.get("spoof_dst_ip") == "203.0.113.7")
check("client never sets spoof_peer", "spoof_peer" not in e)
# Server end: receives the decoy (AF_PACKET) and must know the client's real IP (remote_ip).
e = cfg(psk="k"*16, transport="raw", raw_profile="bip", role="server",
        spoof_dst="203.0.113.7", remote_ip="203.0.113.9")
check("server forwards spoof_dst_ip", e.get("spoof_dst_ip") == "203.0.113.7")
check("server sets spoof_peer to the client's real IP", e.get("spoof_peer") == "203.0.113.9")
check("server does not forge its own source field", "spoof_src_ip" not in e)
# Source spoofing alone (no decoy) still needs the server to know the real peer.
e = cfg(psk="k"*16, transport="raw", raw_profile="bip", role="server",
        spoof_src="198.51.100.9", remote_ip="203.0.113.9")
check("server sets spoof_peer for source-only spoofing", e.get("spoof_peer") == "203.0.113.9")
check("server without decoy sets no spoof_dst_ip", "spoof_dst_ip" not in e)
# Spoofing is bip-only and needs crypto: ignored otherwise.
check("spoof ignored on non-bip profile",
      "spoof_dst_ip" not in cfg(psk="k"*16, transport="raw", raw_profile="gre", role="client", spoof_dst="203.0.113.7"))
check("spoof ignored without crypto",
      "spoof_dst_ip" not in cfg(cipher="none", transport="raw", raw_profile="bip", role="client", spoof_dst="203.0.113.7"))

# op_tunnel must PERSIST spoof_src/spoof_dst into the stored config. Regression: the node's
# key whitelist dropped them, so _core_config never saw them and spoofing was a silent no-op
# through the real panel->node->core path (only hand-written configs worked).
_saved = {}
tnl.local_ips_flat = lambda: ["10.0.0.2"]
tnl.iface_for_ip = lambda ip: "eth0"
tnl.read_config = lambda name: None
tnl.write_config = lambda name, obj: _saved.__setitem__(name, obj)
tnl.apply_config = lambda obj: None
tnl.run = lambda args, timeout=60: (0, "", "")
tnl.op_tunnel({"type": "core", "self_ip": "10.0.0.2", "peer_ip": "203.0.113.9",
               "subnet": "192.168.9.0/24", "id": 9, "name": "core9", "role": "client",
               "cipher": "auto", "transport": "raw", "raw_profile": "bip", "psk": "0123456789abcdef",
               "spoof_src": "198.51.100.9", "spoof_dst": "203.0.113.7"})
_o = _saved.get("core9", {})
check("op_tunnel persists spoof_src", _o.get("spoof_src") == "198.51.100.9")
check("op_tunnel persists spoof_dst", _o.get("spoof_dst") == "203.0.113.7")
_ec = tnl._core_config(_o)   # end-to-end: stored cfg -> core config carries the forged addresses (client role)
check("end-to-end spoof_src_ip reaches core config", _ec.get("spoof_src_ip") == "198.51.100.9")
check("end-to-end spoof_dst_ip reaches core config", _ec.get("spoof_dst_ip") == "203.0.113.7")

# flux: _core_config forwards the carrier + epoch length; the udp carrier is the default.
e = cfg(psk="0123456789abcdef", transport="flux")
check("flux defaults carrier to udp", e.get("flux_carrier") == "udp")
check("flux defaults rotate to 600", e.get("flux_rotate_secs") == 600)
check("flux carries no raw_profile", "raw_profile" not in e)
e = cfg(psk="0123456789abcdef", transport="flux", flux_carrier="raw", flux_rotate_secs=300)
check("flux forwards carrier raw", e.get("flux_carrier") == "raw")
check("flux forwards rotate 300", e.get("flux_rotate_secs") == 300)
# stun carrier + shape + epoch offset
e = cfg(psk="k"*16, transport="flux", flux_carrier="stun", flux_shape="webrtc", flux_epoch_offset=3)
check("flux forwards carrier stun", e.get("flux_carrier") == "stun")
check("flux forwards shape webrtc", e.get("flux_shape") == "webrtc")
check("flux forwards epoch offset", e.get("flux_epoch_offset") == 3)
check("flux defaults shape random", cfg(psk="k"*16, transport="flux").get("flux_shape") == "random")
check("flux omits zero epoch offset", "flux_epoch_offset" not in cfg(psk="k"*16, transport="flux"))
# MTU: stun (IP+UDP+STUN=48) has 20 bytes less headroom than udp (IP+UDP=28).
check("flux stun MTU < udp MTU by the STUN header",
      cfg(psk="k"*16, transport="flux", flux_carrier="udp")["mtu"]
      - cfg(psk="k"*16, transport="flux", flux_carrier="stun")["mtu"] == 20)
# MTU: the udp carrier (IP+UDP) has 8 bytes less headroom than the raw carrier (IP only).
check("flux udp MTU < raw MTU by the UDP header",
      cfg(psk="k"*16, transport="flux", flux_carrier="raw")["mtu"]
      - cfg(psk="k"*16, transport="flux", flux_carrier="udp")["mtu"] == 8)

# ws (CDN-frontable WebSocket carrier): forward Host/path/TLS; server uses ports (has listen).
e = cfg(psk="k"*16, transport="ws", ws_host="cdn.example.com", ws_path="/live", ws_tls=True, role="client")
check("ws forwards ws_host", e.get("ws_host") == "cdn.example.com")
check("ws forwards ws_path", e.get("ws_path") == "/live")
check("ws forwards ws_tls", e.get("ws_tls") is True)
check("ws omits ws_tls when false", "ws_tls" not in cfg(psk="k"*16, transport="ws", role="client"))
_saved.clear()
tnl.op_tunnel({"type": "core", "self_ip": "10.0.0.2", "peer_ip": "203.0.113.9",
               "subnet": "192.168.9.0/24", "id": 7, "name": "core7", "role": "client",
               "cipher": "auto", "transport": "ws", "ws_host": "cdn.example.com", "ws_tls": True,
               "psk": "0123456789abcdef"})
_ow = _saved.get("core7", {})
check("op_tunnel persists ws_host", _ow.get("ws_host") == "cdn.example.com")
check("op_tunnel persists ws_tls", _ow.get("ws_tls") is True)
try:
    tnl.op_tunnel({"type": "core", "self_ip": "10.0.0.2", "peer_ip": "203.0.113.9", "subnet": "192.168.9.0/24",
                   "id": 6, "name": "core6", "role": "client", "transport": "ws", "ws_host": "bad host!", "psk": "0123456789abcdef"})
    check("op_tunnel rejects bad ws_host", False)
except ValueError:
    check("op_tunnel rejects bad ws_host", True)

# op_tunnel must PERSIST flux_carrier/flux_rotate_secs (same whitelist trap that dropped spoofing).
_saved.clear()
tnl.op_tunnel({"type": "core", "self_ip": "10.0.0.2", "peer_ip": "203.0.113.9",
               "subnet": "192.168.9.0/24", "id": 8, "name": "core8", "role": "client",
               "cipher": "auto", "transport": "flux", "flux_carrier": "udp",
               "flux_rotate_secs": 300, "psk": "0123456789abcdef"})
_of = _saved.get("core8", {})
check("op_tunnel persists flux_carrier", _of.get("flux_carrier") == "udp")
check("op_tunnel persists flux_rotate_secs", _of.get("flux_rotate_secs") == 300)
_ecf = tnl._core_config(_of)   # end-to-end: stored cfg -> core config carries the flux carrier
check("end-to-end flux_carrier reaches core config", _ecf.get("flux_carrier") == "udp")
check("end-to-end flux_rotate_secs reaches core config", _ecf.get("flux_rotate_secs") == 300)

# on/off: op_tunnel defaults enabled True and persists a disabled tunnel.
check("op_tunnel defaults enabled True", _o.get("enabled") is True)
_saved.clear()
tnl.op_tunnel({"type": "vxlan", "self_ip": "10.0.0.2", "peer_ip": "203.0.113.9",
               "subnet": "192.168.9.0/24", "id": 9, "name": "vxlan9", "enabled": False})
check("op_tunnel persists enabled False", _saved.get("vxlan9", {}).get("enabled") is False)

print()
if FAILS:
    print("%d FAILED: %s" % (len(FAILS), ", ".join(FAILS)))
    sys.exit(1)
print("all core-config tests passed")
