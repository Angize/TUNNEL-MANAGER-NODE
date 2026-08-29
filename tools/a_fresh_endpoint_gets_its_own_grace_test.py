#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""A destination the core has only just moved to gets its OWN grace before it is condemned.

Measured in production on a ws tunnel with three CDN edges: 185 was genuinely dead and burned, the core
arrived on 104, and 104 -- which nothing had faulted -- was condemned by the very next sweep. The
"wait RED_SWEEPS before burning" guard counted per TUNNEL, so a fresh endpoint inherited the tally its
predecessor had run up and got no grace at all.

This drives the real settle() -> pool_failover() path, the same order health_of calls them in.

    python3 tools/a_fresh_endpoint_gets_its_own_grace_test.py
"""
import importlib.util
import io
import json
import os
import shutil
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
NODE = os.path.join(os.path.dirname(HERE), "tnl-node.py")

spec = importlib.util.spec_from_file_location("tnlnode", NODE)
N = importlib.util.module_from_spec(spec)
spec.loader.exec_module(N)

D = tempfile.mkdtemp(prefix="grace")
N.CONFIG_DIR = D
N.logline = lambda *a, **k: None
NAME = "core13"
EPOCH = 7
json.dump({"role": "client", "transport": "ws"}, io.open(os.path.join(D, "core-%s.json" % NAME), "w"))
VERDICT = os.path.join(D, "core-%s.status.verdict" % NAME)


def carrier_on(low, high="cdn.spacefly.ir"):
    json.dump({"active": "%s . %s" % (low, high), "epoch": EPOCH, "ready": True,
               "pair": {"low": low, "high": high, "low_kind": "ip", "high_kind": "sni"},
               "health": [], "events": [], "ts": 0,
               "path": {"src": "", "sport": 0, "dst": "", "dport": 0}},
              io.open(os.path.join(D, "core-%s.status" % NAME), "w"))


def sweep(crossed):
    """One probe, exactly as health_of runs it. Returns the endpoint the node asked to burn, or None."""
    if os.path.exists(VERDICT):
        os.remove(VERDICT)
    alive = N.settle(NAME, crossed)
    N.pool_failover(NAME, alive, crossed, EPOCH, True, True)
    if not os.path.exists(VERDICT):
        return None
    v = json.load(io.open(VERDICT))
    return v["low"] if v.get("cmd") == "fail" else None


fails = []


def check(ok, msg):
    print(("  ok   " if ok else " FAIL ") + msg)
    if not ok:
        fails.append(msg)


print("== a fresh endpoint is not condemned on the tally of the one before it ==")
print("RED_SWEEPS = %d" % N.RED_SWEEPS)

DEAD, FRESH = "185.143.23.238:443", "104.21.42.53:443"

carrier_on(DEAD)
sweep(True)
asked = [sweep(False) for _ in range(6)]
check(asked[0] is None, "the dead endpoint gets its grace too: the first bad sweep asks for nothing")
check(all(a == DEAD for a in asked[1:]),
      "after its grace the dead endpoint is named on EVERY later sweep, with no extra delay from the "
      "colour smoothing (%r)" % (asked[1:],))

carrier_on(FRESH)
first = sweep(False)
check(first is None,
      "the FIRST bad sweep on the endpoint the core just moved to asks for nothing (got %r)" % (first,))
second = sweep(False)
check(second == FRESH,
      "the second bad sweep on it does name it, so a genuinely dead one is still condemned (got %r)"
      % (second,))

print()
print("== recovering resets the grace, so the next outage starts it over ==")
carrier_on(FRESH)
sweep(True)
check(sweep(False) is None, "after traffic crossed, the next bad sweep asks for nothing again")

print()
print("== the tunnel-wide tally the DOT uses is untouched by any of this ==")
carrier_on(DEAD)
for _ in range(4):
    sweep(False)
check(N._verdict[NAME]["bad"] >= 4,
      "the per-tunnel counter still counts every bad sweep for the colour (%d)" % N._verdict[NAME]["bad"])
check(N._verdict[NAME]["pub"] is False, "and the tunnel is published red")

shutil.rmtree(D, ignore_errors=True)
print()
if fails:
    print("%d check(s) failed." % len(fails))
    sys.exit(1)
print("a fresh endpoint is judged on its own evidence.")
