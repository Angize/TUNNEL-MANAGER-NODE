#!/usr/bin/env python3
"""Guard: a tunnel that found nothing crossing is looked at again sooner, and one that carries is not.

Every rung of the core's ladder costs one verdict, and verdicts arrive on the sweep cadence -- so the
gap between sweeps sets the whole recovery, not just the detection. A flat 3s gap spent ~17s walking a
raw/tcp ladder; looking again after 1s while a tunnel looks bad halves it.

Two things this has to hold, and both are easy to get wrong:

  * the trigger is the RAW crossing, not the published colour. settle() keeps a green tunnel green
    through its FIRST bad sweep, so a rule keyed on `alive` would still wait out the slow gap in the one
    place the saving comes from.
  * a tunnel that is CARRYING must not be accelerated, and neither must one with no tun probe at all
    (portfw) -- otherwise every healthy tunnel on the node pays for a feature it cannot use.

Driven through the real scheduler, not through _sweep_gap alone: a rule nothing consults is no rule.

Exit 1 on any failure.
"""
import sys
sys.dont_write_bytecode = True
import importlib.util
import os
import tempfile
from concurrent.futures import Future
import time
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
    spec = importlib.util.spec_from_file_location("tnl_node_sweep", src)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def main():
    P = load()

    print("== 1) the gap follows the RAW crossing, not the published colour ==")
    check(P._sweep_gap({"crossed": False, "alive": True}) == P.SWEEP_FAST,
          "a sweep that found nothing crossing shortens the gap EVEN WHILE the tunnel still publishes "
          "green -- that first bad sweep is exactly where the saving is, and settle() keeps it green")
    check(P._sweep_gap({"crossed": True, "alive": True}) == P.SWEEP_SLOW,
          "a sweep that carried keeps the long gap: two samples far apart are what makes RED_SWEEPS a guard")
    check(P._sweep_gap({"crossed": False, "alive": False}) == P.SWEEP_FAST,
          "and a tunnel already red keeps the short gap, so every rung of the ladder arrives sooner")
    check(P._sweep_gap({"up": True}) == P.SWEEP_SLOW and P._sweep_gap(None) == P.SWEEP_SLOW,
          "a result with no probe in it (portfw, a tunnel whose device is gone) is NOT accelerated -- "
          "there is no verdict to deliver faster")
    check(P.SWEEP_FAST < P.SWEEP_SLOW,
          "fast is actually faster than slow (%.1fs < %.1fs)" % (P.SWEEP_FAST, P.SWEEP_SLOW))

    print("\n== 2) the scheduler actually rations by it ==")
    tmp = tempfile.mkdtemp()
    P.CONFIG_DIR = tmp
    P.LOG = os.path.join(tmp, "agent.log")

    probed = []
    verdicts = {"green": True, "red": False}

    def fake_health(cfg):
        probed.append(cfg["name"])
        return {"up": True, "alive": verdicts[cfg["name"]], "crossed": verdicts[cfg["name"]]}

    P.health_of = fake_health
    P.raw_configs = lambda: [{"type": "core", "name": "green"}, {"type": "core", "name": "red"}]

    class Inline:
        """Runs the probe on the spot and hands back a REAL Future, so futures_wait is the real one."""
        def submit(self, fn, arg):
            f = Future()
            f.set_result(fn(arg))
            return f

    ex = Inline()
    P.health_refresh_once(ex)                      # round 1: both are due
    check(sorted(probed) == ["green", "red"], "the first round probes every tunnel (%r)" % (sorted(probed),))

    probed.clear()
    P.health_refresh_once(ex)                      # immediately again: neither gap has elapsed
    check(probed == [], "a second round in the same instant probes nothing -- the due times hold (%r)" % (probed,))

    time.sleep(P.SWEEP_FAST + 0.15)
    probed.clear()
    P.health_refresh_once(ex)
    check(probed == ["red"],
          "after SWEEP_FAST only the tunnel that found nothing crossing is swept again; the carrying one "
          "still waits out SWEEP_SLOW (got %r)" % (probed,))

    print("\n== 3) a tunnel that goes away takes its due time with it ==")
    P.raw_configs = lambda: [{"type": "core", "name": "green"}]
    P.health_refresh_once(ex)
    check("red" not in P._sweep_due,
          "the deleted tunnel's due time is dropped, so the map cannot grow forever (%r)" % (list(P._sweep_due),))

    print("")
    if fails:
        print("%d failure(s)" % len(fails))
        return 1
    print("a bad sweep is looked at again after %.0fs, a carrying one after %.0fs, and nothing else "
          "changed." % (P.SWEEP_FAST, P.SWEEP_SLOW))
    return 0


if __name__ == "__main__":
    sys.exit(main())
