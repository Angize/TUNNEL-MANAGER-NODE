"""Guard: the tunnel has two states, separated by ONE line, and crossing it is not instant.

There is no third colour. Where the line sits is the operator's, set from the panel -- that number and
its journey are probe_threshold_test.py's subject. What this file defends is the SHAPE around it:

  1. Two states and one line. Everything at or above the threshold is connected, everything below it is
     disconnected, with nothing in between and no second rule hiding anywhere.
  2. Going red takes RED_SWEEPS consecutive bad sweeps; going green takes one. A real outage must show
     fast, one unlucky sweep must not repaint a working tunnel.
  3. A sweep that could not measure at all is not a bad sweep, and the memory does not outlive the tunnel.

Both are asserted through health_of, the path that publishes, not through the helper underneath it.

Exit 1 on any failure.
"""
import sys
sys.dont_write_bytecode = True
import importlib.util
import os
from pathlib import Path

NODE = Path(__file__).resolve().parent.parent / "tnl-node.py"


def load():
    spec = importlib.util.spec_from_file_location("tnl_node_verdict", NODE)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def main():
    m = load()
    fails = []

    def want(cond, msg):
        print(("  ok  " if cond else " FAIL ") + msg)
        if not cond:
            fails.append(msg)

    want(m.PROBE_COUNT >= 16,
         f"PROBE_COUNT is {m.PROBE_COUNT}. The sample count is the RESOLUTION of the line: the operator "
         f"picks a percentage, and only a set this size can express it to better than a few points. It "
         f"is also what keeps a lossy-but-alive tunnel from flapping -- at 90% loss a whole sweep goes "
         f"quiet 35% of the time at ten samples, 12% at twenty")
    want(m.RED_SWEEPS >= 2, f"RED_SWEEPS is {m.RED_SWEEPS}: one bad sweep must not repaint a green tunnel")

    # --- drive health_of with a probe of known outcome ---------------------------------------------
    def health(name, hits, sent=None, pct=None):
        sent = m.PROBE_COUNT if sent is None else sent
        real_exists, real_flow, real_probe = os.path.exists, m._flow_sample, m.tun_probe
        os.path.exists = lambda p: True if str(p).startswith("/sys/class/net/") else real_exists(p)
        m._flow_sample = lambda n: (0.0, 0.0)
        m.tun_probe = lambda *a, **k: (hits, sent, 80.0 if hits else None)
        cfg = {"type": "core", "name": name, "tunnel_ip": "192.168.44.2/24"}
        if pct is not None:
            cfg["probe_min_pct"] = pct
        try:
            return m.health_of(cfg)
        finally:
            os.path.exists, m._flow_sample, m.tun_probe = real_exists, real_flow, real_probe

    n = m.PROBE_COUNT
    half = n // 2

    # --- 1. two states, one line ---------------------------------------------------------------------
    # Asserted against an EXPLICIT threshold rather than the default, so this file keeps saying what it
    # is about (the shape) and probe_threshold_test.py keeps owning the default and its journey.
    want(health("t-all", n)["alive"] is True, "everything answered must be connected")
    want(health("t-half-hi", half, pct=50)["alive"] is True,
         f"exactly on the line ({half} of {n} at 50%) is CONNECTED -- the line is inclusive")
    want(health("t-half-lo", half - 1, pct=50)["alive"] is False,
         f"one sample under the line ({half - 1} of {n} at 50%) is DISCONNECTED, with nothing in between")
    want(health("t-none", 0, pct=1)["alive"] is False,
         "and total silence is disconnected at every threshold, including the lowest one there is")

    # the number itself must survive, as a number: the colour says WHETHER, loss_pct says how badly
    h = health("t-loss", half)
    want(h.get("loss_pct") == 50.0, f"the loss must still be REPORTED, got {h.get('loss_pct')}")
    # A tunnel may be green while losing almost everything, if that is where the operator put the line.
    # Derived from the threshold, so retuning either the default or PROBE_COUNT cannot stale this.
    h = health("t-loss2", 1, pct=1)
    worst = round((n - 1) * 100.0 / n, 1)
    want(h.get("alive") is True and h.get("loss_pct") == worst,
         f"at the lowest threshold a single reply is green and the card must be able to SHOW {worst}% "
         f"loss beside it, got alive={h.get('alive')} loss={h.get('loss_pct')}")

    # --- 2. red needs confirming, green does not ---------------------------------------------------
    want(health("t-hys", n)["alive"] is True, "sweep 1 good -> green")
    want(health("t-hys", 0)["alive"] is True,
         f"sweep 2 bad -> still GREEN: one bad sweep is not an outage, it takes {m.RED_SWEEPS}")
    want(health("t-hys", 0)["alive"] is False, f"sweep 3 bad -> red, {m.RED_SWEEPS} in a row confirmed it")
    want(health("t-hys", n)["alive"] is True, "sweep 4 good -> green IMMEDIATELY, recovery is not delayed")
    want(health("t-hys", 0)["alive"] is True, "and the counter reset, so the next bad sweep holds again")

    # a tunnel that was never green has nothing to protect: it goes red on its first bad sweep
    want(health("t-fresh", 0)["alive"] is False,
         "a tunnel with no green to hold must go red at once, not wait for a second sweep")

    # --- 3. an unmeasurable sweep is not a bad sweep ------------------------------------------------
    want(health("t-hys2", n)["alive"] is True, "green first")
    want(health("t-hys2", 0, sent=0)["alive"] is None,
         "a sweep that could not probe at all reports 'not measured', never a verdict")
    want(health("t-hys2", 0)["alive"] is True,
         "and it must not have counted as a strike: the next bad sweep is still only the first")

    # --- 4. the memory must not outlive the tunnel -------------------------------------------------
    want(health("t-prune", m.PROBE_COUNT)["alive"] is True, "green, so there is something to prune")
    m._prune_iface_state(set())
    want(health("t-prune", 0)["alive"] is False,
         "a recreated tunnel must not inherit the green that protected its namesake")

    print()
    if fails:
        print(f"{len(fails)} failure(s)")
        return 1
    print("two states, one line, inclusive at the threshold, and steady across a single bad sweep")
    return 0


if __name__ == "__main__":
    sys.exit(main())
