#!/usr/bin/env python3
"""Guard: the panel's «بررسی» button measures nothing and decides nothing.

`health_of` is not a reader. It advances settle()'s consecutive-bad counter and, when the epoch held,
writes the verdict file the core's ladder acts on. op_check used to call it straight from an HTTP
worker, outside the sweep's one-probe-per-tunnel guard, which meant a click could:

  * land a second sample 0.1 s after a scheduled one instead of SWEEP_SLOW apart, collapsing the two
    spaced samples RED_SWEEPS exists to require, and
  * start the ladder from that -- rung 0 closes a working carrier -- from a button the panel documents
    as reporting only, and
  * compete for the same fd budget as the sweep's own probe, which stops at its first socket() failure.

So the button returns the sweep's snapshot. Three things are pinned here, and the third is what stops
this being "fixed" back by making op_check probe again in some other way:

  1. a click leaves settle()'s state and the verdict file untouched, even mid-outage;
  2. it still answers with the measurement the sweep took;
  3. the sweep itself still judges -- the verdict path is not what was removed.

Exit 1 on any failure.
"""
import sys
sys.dont_write_bytecode = True
import importlib.util
import json
import os
import tempfile
from concurrent.futures import Future
from pathlib import Path

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

fails = []


def check(ok, msg):
    print(("  ok   " if ok else " FAIL ") + msg)
    if not ok:
        fails.append(msg)


def load():
    src = Path(__file__).resolve().parent.parent / "tnl-node.py"
    spec = importlib.util.spec_from_file_location("tnl_node_check", src)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def main():
    P = load()
    tmp = tempfile.mkdtemp()
    P.CONFIG_DIR = tmp
    P.LOG = os.path.join(tmp, "agent.log")

    cfg = {"type": "core", "name": "t1", "tunnel_ip": "10.9.0.1/30", "role": "client"}
    P.read_config = lambda n: dict(cfg) if n == "t1" else None
    P.raw_configs = lambda: [dict(cfg)]

    verdict_path = os.path.join(tmp, "core-t1.status.verdict")
    open(os.path.join(tmp, "core-t1.json"), "w").write(json.dumps({"role": "client"}))

    # health_of gates its whole probe on the netdev existing. Without this the old, probing op_check
    # would have returned early here too, and every assertion below would pass against the bug it is
    # meant to catch. Say the device is there for this one name; put os back at the end.
    real_exists = os.path.exists
    P.os.path.exists = lambda q: True if q == "/sys/class/net/t1" else real_exists(q)

    print("== 1) a click does not probe, does not settle, does not write a verdict ==")
    probed = []
    P.tun_probe = lambda *a, **k: (probed.append(1), (0, 20, None))[1]   # nothing crossed
    # Mid-outage: one bad sweep already on the books, one short of RED_SWEEPS.
    with P._verdict_lock:
        P._verdict["t1"] = {"pub": True, "bad": 1}
    with P._health_lock:
        P._health_cache["t1"] = {"up": True, "alive": True, "crossed": True, "rtt_ms": 12.5, "loss_pct": 0.0}

    out = P.op_check({"name": "t1"})

    check(not probed,
          "the button sent no probe of its own — a second sample the sweep's guard cannot see is what "
          "collapsed the gap RED_SWEEPS depends on")
    with P._verdict_lock:
        st = dict(P._verdict.get("t1") or {})
    check(st.get("bad") == 1 and st.get("pub") is True,
          "settle()'s state is untouched (bad=%s pub=%s, want 1/True) — one click must not carry a "
          "green tunnel over the line into red" % (st.get("bad"), st.get("pub")))
    check(not os.path.exists(verdict_path),
          "and no verdict reached the core: a report may not start the ladder, and rung 0 closes a "
          "carrier that is working")

    print("\n== 2) it still answers with what the sweep measured ==")
    h = out.get("health") or {}
    check(h.get("rtt_ms") == 12.5 and h.get("alive") is True,
          "the snapshot is returned as-is (rtt=%s alive=%s)" % (h.get("rtt_ms"), h.get("alive")))
    h["rtt_ms"] = 999
    with P._health_lock:
        still = P._health_cache["t1"]["rtt_ms"]
    check(still == 12.5,
          "and it is a copy — an RPC caller mutating its reply must not rewrite the node's snapshot")

    unknown = P.op_check({"name": "t1"})
    with P._health_lock:
        P._health_cache.pop("t1", None)
    unknown = P.op_check({"name": "t1"})
    check((unknown.get("health") or {}).get("up") is None,
          "a tunnel the sweep has not reached yet answers unknown, never a fake down")

    print("\n== 3) the sweep still judges ==")
    wrote = []
    P._atomic_write_json = lambda path, obj: (wrote.append((path, obj)), "")[1]
    P.tun_probe = lambda *a, **k: (0, 20, None)
    P._read_path_state = lambda n: (7, True)
    P.probe_min_pct = lambda c: 15
    with P._verdict_lock:
        P._verdict["t1"] = {"pub": True, "bad": 1}      # one more bad sweep tips the COLOUR
    P.health_of(dict(cfg))                              # the burn needs its own two: this is the first
    check(not wrote, "the first bad sweep on an endpoint asks for nothing, got %s" % (wrote,))
    P.health_of(dict(cfg))
    P.os.path.exists = real_exists
    check(any(str(p).endswith(".status.verdict") for p, _ in wrote),
          "health_of still writes the verdict — what was removed is the BUTTON's call to it, not the "
          "sweep's judgement (wrote=%r)" % ([p for p, _ in wrote],))

    print("")
    if fails:
        print("%d failure(s)" % len(fails))
        return 1
    print("the check button reports; only the sweep decides.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
