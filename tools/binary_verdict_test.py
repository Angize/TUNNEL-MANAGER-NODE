"""Guard: the tunnel has two states, and the line between them is a majority.

There is no third colour any more. That puts real weight on where the line sits and on how steady it
is, because a binary dot decided by a handful of packets is a dot that flickers -- and a flickering
dot is one the operator stops reading.

Two things hold it up, and both are asserted here through health_of, the path that publishes:

  1. CONNECTED means MOST of what we sent came back, not "something came back". The old rule was
     `hits > 0`, which called a tunnel carrying one packet in four connected -- exactly how the check
     button came to disagree with the card beside it.
  2. Going red takes RED_SWEEPS consecutive bad sweeps; going green takes one. A real outage must show
     fast, one unlucky sweep must not repaint a working tunnel.

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

    want(m.PROBE_COUNT >= 8,
         f"PROBE_COUNT is {m.PROBE_COUNT}: too few samples and the majority is decided by luck. At 3 "
         f"the only readings are 0/33/67/100 and a tunnel near the line flips colour every sweep")
    want(m.RED_SWEEPS >= 2, f"RED_SWEEPS is {m.RED_SWEEPS}: one bad sweep must not repaint a green tunnel")

    # --- drive health_of with a probe of known outcome ---------------------------------------------
    def health(name, hits, sent=None):
        sent = m.PROBE_COUNT if sent is None else sent
        real_exists, real_flow, real_probe = os.path.exists, m._flow_sample, m.tun_probe
        os.path.exists = lambda p: True if str(p).startswith("/sys/class/net/") else real_exists(p)
        m._flow_sample = lambda n: (0.0, 0.0)
        m.tun_probe = lambda *a, **k: (hits, sent, 80.0 if hits else None)
        try:
            return m.health_of({"type": "core", "name": name, "tunnel_ip": "192.168.44.2/24"})
        finally:
            os.path.exists, m._flow_sample, m.tun_probe = real_exists, real_flow, real_probe

    n = m.PROBE_COUNT
    half = n // 2

    # --- 1. the line is a majority ------------------------------------------------------------------
    want(health("t-all", n)["alive"] is True, "everything answered must be connected")
    want(health("t-most", half + 1)["alive"] is True,
         f"a majority answering must be connected ({half+1} of {n})")
    want(health("t-half", half)["alive"] is False,
         f"exactly half answering is NOT connected ({half} of {n} is 50% loss, the old amber line)")
    want(health("t-one", 1)["alive"] is False,
         "one packet in ten is not a connected tunnel -- this is the whole reason the rule changed")
    want(health("t-none", 0)["alive"] is False, "nothing answering must be disconnected")

    # the number itself must survive, as a number
    h = health("t-loss", half)
    want(h.get("loss_pct") == 50.0, f"the loss must still be REPORTED, got {h.get('loss_pct')}")

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
    print("two states, decided by a majority, steady across a single unlucky sweep")
    return 0


if __name__ == "__main__":
    sys.exit(main())
