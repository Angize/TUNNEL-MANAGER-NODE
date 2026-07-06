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

print()
if FAILS:
    print("%d FAILED: %s" % (len(FAILS), ", ".join(FAILS)))
    sys.exit(1)
print("all core-config tests passed")
