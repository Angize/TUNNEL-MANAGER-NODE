#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Guard: the source-port band reaches the core config on EVERY carrier, and an unusable one is
refused on every carrier.

NODE #239 lifted the band out of the `raw` arm so udp, tcp and ws draw their source port from it too.
Nothing here proved it. That matters more on this side than on the panel's, because the node is the
LAST gate: the panel can be bypassed (a request straight at the agent), and a band the node drops
silently does not fail -- the core just falls back to 10000-59999 and the operator's setting is gone
with no error anywhere.

Both halves are asked per transport on purpose. A band validated in one carrier's arm is a band three
carriers do not have, and that is the exact shape of the bug #239 was fixing.

Exit 1 on any failure.
"""
import importlib.util
import json
import os
import sys
import tempfile

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

HERE = os.path.dirname(os.path.abspath(__file__))
NODE = os.path.join(os.path.dirname(HERE), "tnl-node.py")

fails = []


def fail(msg):
    fails.append(msg)
    print("FAIL: " + msg)


def ok(msg):
    print("  ok  " + msg)


def load_node():
    spec = importlib.util.spec_from_file_location("tnl_node", NODE)
    mod = importlib.util.module_from_spec(spec)
    sys.modules["tnl_node"] = mod
    spec.loader.exec_module(mod)
    return mod


CARRIERS = {
    "udp": {"transport": "udp"},
    "tcp": {"transport": "tcp"},
    "raw": {"transport": "raw", "raw_profile": "tcp", "raw_port": 443},
    "ws":  {"transport": "ws", "ws_host": "a.example.com", "ws_path": "/x"},
}


def req(carrier, **over):
    d = {"type": "core", "self_ip": "203.0.113.5", "peer_ip": "198.51.100.7",
         "subnet": "10.9.0.0/24", "host": 1, "id": 9, "name": "core9", "enabled": True,
         "cipher": "aes-256-gcm", "crypto": True, "psk": "k" * 64, "port": 20000,
         "role": "server", "mtu": 1341}
    d.update(CARRIERS[carrier])
    d.update(over)
    return d


def drive(mod, tmp, body):
    def fake_run(args, timeout=60):
        if args[:3] == ["ip", "link", "show"]:
            return 0, "2: eth0: <BROADCAST,UP> mtu 1500 qdisc fq state UP\n", ""
        return 0, "", ""

    saved = {k: getattr(mod, k) for k in ("local_ips_flat", "iface_for_ip", "run",
                                          "CONFIG_DIR", "CORE_BIN", "default_iface")}
    mod.local_ips_flat = lambda: ["203.0.113.5"]
    mod.iface_for_ip = lambda ip: "eth0"
    mod.default_iface = lambda: "eth0"
    mod.run = fake_run
    mod.CONFIG_DIR = tmp
    mod.CORE_BIN = NODE
    try:
        res = mod.op_tunnel(body)
    except Exception as e:
        res = {"ok": False, "msg": str(e)}
    finally:
        for k, v in saved.items():
            setattr(mod, k, v)
    path = os.path.join(tmp, "core-core9.json")
    cfg = None
    if os.path.isfile(path):
        with open(path, encoding="utf-8") as f:
            cfg = json.load(f)
        os.remove(path)
    return res, cfg


BAD = [
    ("narrower than the floor", {"sport_lo": 30000, "sport_hi": 30098}),
    ("into the privileged ports", {"sport_lo": 500, "sport_hi": 44999}),
    ("inverted", {"sport_lo": 50000, "sport_hi": 40000}),
    ("half a band", {"sport_lo": 10000}),
    ("past the top of the port space", {"sport_lo": 60000, "sport_hi": 70000}),
]


def main():
    mod = load_node()
    with tempfile.TemporaryDirectory() as tmp:
        print("== 1) a usable band reaches the core config on every carrier ==")
        for c in CARRIERS:
            res, cfg = drive(mod, tmp, req(c, sport_lo=12000, sport_hi=42000))
            if not res.get("ok"):
                fail("%-3s: the node refused a usable band: %s" % (c, res.get("msg")))
                continue
            got = (cfg or {}).get("sport_lo"), (cfg or {}).get("sport_hi")
            if got == (12000, 42000):
                ok("%-3s -> sport_lo=%d sport_hi=%d" % (c, got[0], got[1]))
            else:
                fail("%-3s: the core config carries %r, want (12000, 42000) -- the operator's band "
                     "is dropped and the core silently falls back to its own default" % (c, got))

        print("== 2) no band means no keys, so the core keeps its own default ==")
        for c in CARRIERS:
            res, cfg = drive(mod, tmp, req(c))
            if not res.get("ok"):
                fail("%-3s: the node refused a tunnel with no band at all: %s" % (c, res.get("msg")))
                continue
            leftover = [k for k in ("sport_lo", "sport_hi") if k in (cfg or {})]
            if leftover:
                fail("%-3s: emitted %s with no band asked for" % (c, leftover))
            else:
                ok("%-3s -> neither key is written" % c)

        print("== 3) an unusable band is refused on every carrier ==")
        for c in CARRIERS:
            for name, over in BAD:
                res, _cfg = drive(mod, tmp, req(c, **over))
                if res.get("ok"):
                    fail("%-3s: accepted a band %s -- the core will refuse it and the tunnel dies "
                         "at start with nothing between the operator and the crash" % (c, name))
                else:
                    ok("%-3s %-28s refused" % (c, name))

    print()
    if fails:
        print("FAILURES (%d):" % len(fails))
        for f in fails:
            print("  - " + f)
        return 1
    print("the band is every carrier's: it reaches the core config on all four, and an unusable one "
          "is refused on all four")
    return 0


if __name__ == "__main__":
    sys.exit(main())
