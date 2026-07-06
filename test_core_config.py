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
    base = {"name": "cor-1", "id": 5, "role": "server",
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

print()
if FAILS:
    print("%d FAILED: %s" % (len(FAILS), ", ".join(FAILS)))
    sys.exit(1)
print("all core-config tests passed")
