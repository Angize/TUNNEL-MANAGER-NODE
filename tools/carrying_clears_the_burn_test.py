"""Guard: an endpoint that is CARRYING must not stay condemned.

The core clears a burn on exactly one signal -- the node's `ok`. That used to be sent only on the
red->green edge, naming whichever endpoints were active at that instant. But a burn always rotates AWAY
from the endpoint it burns, so the pair a recovery lands on is never the pair that was just condemned.
The condemned one returns only when its backoff lapses, and by then the tunnel is already green: no edge,
no `ok`, and it reads «موقت» in the panel while visibly carrying traffic. Measured on core42 on
2026-08-05 -- 94.183.210.130 sat suspect with its countdown at 0:00 while it was the active source.

So the report has a second occasion: this sweep measured traffic crossing AND an endpoint the tunnel is
carrying on is still condemned. What this file defends is that second occasion, and the three ways it
must stay quiet -- a healthy pair, a sweep that measured nothing, and a tunnel with no pool.

It drives health_of -- the sweep's own path -- not _report_carrying directly, because a guard that calls
the helper says nothing about whether the sweep still calls it.

Exit 1 on any failure.
"""
import sys
sys.dont_write_bytecode = True
import importlib.util
import os
import tempfile
from pathlib import Path

NODE = Path(__file__).resolve().parent.parent / "tnl-node.py"


def load():
    spec = importlib.util.spec_from_file_location("tnl_node_heal", NODE)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def main():
    m = load()
    fails = []
    sent = []

    def want(cond, msg):
        print(("  ok  " if cond else " FAIL ") + msg)
        if not cond:
            fails.append(msg)

    m.CONFIG_DIR = tempfile.mkdtemp()
    m.logline = lambda _msg: None
    m._pool_sighup = lambda name, is_pool, msg: {"ok": True}
    m._atomic_write_json = lambda path, obj: sent.append((os.path.basename(path), obj)) and None

    # The pool as the CORE publishes it: one active endpoint per axis and a health record per entry.
    ST = {"is_pool": True, "hits": 0,
          "dst": {"active": "10.0.0.1", "state": "healthy"},
          "src": {"active": "192.168.1.1", "state": "healthy"}}

    def pool(side):
        s = ST[side]
        return {"active": s["active"], "addrs": [s["active"]], "pin": "", "ts": 0,
                "health": [{"key": s["active"], "state": s["state"], "fails": 0, "next_retest_unix": 0}]}

    m._is_peer_pool = lambda name: ST["is_pool"]
    m._read_core_cfg = lambda name: {"role": "client", "peer_status_path": "x"}
    # a core publishing a stable path with a session on it: what every verdict here is keyed to
    m._read_path_state = lambda _n: (1, True)
    m._read_peer_pool = lambda name, suffix: pool("src" if suffix == ".srcpool" else "dst")

    real_exists = os.path.exists
    os.path.exists = lambda p: True if str(p).startswith("/sys/class/net/") else real_exists(p)
    m._flow_sample = lambda n: (0.0, 0.0)
    m.tun_probe = lambda *a, **k: (ST["hits"], m.PROBE_COUNT, 80.0 if ST["hits"] else None)

    clock = {"t": 1000.0}
    m.time.monotonic = lambda: clock["t"]

    def sweep(name):
        clock["t"] += 4.0
        return m.health_of({"type": "core", "name": name, "tunnel_ip": "192.168.9.2/24"})

    def oks(n0):
        return [o for _p, o in sent[n0:] if o.get("cmd") == "ok"]

    # --- a green tunnel on healthy endpoints says nothing -------------------------------------------
    ST["hits"] = m.PROBE_COUNT
    n0 = len(sent)
    sweep("t-quiet")
    sweep("t-quiet")
    want(oks(n0) == [], f"a healthy pair must not be reported at all, got {oks(n0)}")

    # --- the whole point: carrying on a CONDEMNED source, with no red->green edge anywhere -----------
    # The tunnel is green from its very first sweep here, so `recovered` is false forever. Before the
    # fix this reported nothing and the source stayed suspect for good.
    ST["src"]["state"] = "suspect"
    n0 = len(sent)
    sweep("t-src")
    want(oks(n0) == [{"cmd": "ok", "key": "10.0.0.1", "src": "192.168.1.1", "epoch": 1}],
         f"a condemned SOURCE that is carrying must be reported, naming both actives, got {oks(n0)}")
    want(sent[n0][0].endswith(".status.verdict"),
         f"and it must go to the tunnel's verdict mailbox, which is the one the core polls, "
         f"got {sent[n0][0]}")

    # --- the same for a condemned destination -------------------------------------------------------
    ST["src"]["state"], ST["dst"]["state"] = "healthy", "dead"
    n0 = len(sent)
    sweep("t-dst")
    want(oks(n0) == [{"cmd": "ok", "key": "10.0.0.1", "src": "192.168.1.1", "epoch": 1}],
         f"a DEAD destination that is carrying must be reported too -- dead is not a life sentence, "
         f"got {oks(n0)}")

    # --- once the core has cleared it, the node goes quiet again ------------------------------------
    ST["dst"]["state"] = "healthy"
    n0 = len(sent)
    sweep("t-dst")
    sweep("t-dst")
    want(oks(n0) == [], f"after the core clears the burn the reports must stop, got {oks(n0)}")

    # --- a sweep that MEASURED NOTHING must never clear a burn ---------------------------------------
    # settle() holds a green tunnel green through one bad sweep. That published green measured nothing,
    # so it says nothing about any endpoint and must not be allowed to heal one.
    ST["dst"]["state"] = "suspect"
    ST["hits"] = m.PROBE_COUNT
    sweep("t-smooth")            # green, and the burn gets reported
    n0 = len(sent)
    ST["hits"] = 0
    sweep("t-smooth")            # bad sweep, still published green (RED_SWEEPS smoothing)
    want(oks(n0) == [],
         f"a smoothed green measured nothing crossing and must not clear a burn, got {oks(n0)}")

    # --- a tunnel with no pool: the occasion is the EDGE, and only the edge --------------------------
    # It holds no entry that could be condemned, so "carrying while condemned" cannot arise for it and a
    # green sweep must stay silent. The red->green edge below is a different question and is still sent:
    # `ok` also refills the ladder's free steps, which this tunnel has like any other.
    real_pool = m._read_peer_pool
    m._read_peer_pool = lambda name, suffix: {"active": "", "addrs": [], "health": [], "pin": "", "ts": 0}
    ST["hits"] = m.PROBE_COUNT
    n0 = len(sent)
    sweep("t-nopool")
    sweep("t-nopool")
    want(oks(n0) == [], f"a green pool-less tunnel has nothing to clear and must stay quiet, got {oks(n0)}")

    ST["hits"] = 0
    sweep("t-nopool")
    sweep("t-nopool")            # confirmed red
    ST["hits"] = m.PROBE_COUNT
    n0 = len(sent)
    sweep("t-nopool")
    want(oks(n0) == [{"cmd": "ok", "key": "", "src": "", "epoch": 1}],
         f"but its recovery must be told, naming no endpoint because it has none -- that is what "
         f"refills the free rungs it just spent. got {oks(n0)}")
    m._read_peer_pool = real_pool

    # --- the red->green edge still reports, even with nothing condemned ------------------------------
    # That is the original occasion and it must survive: after a jump the core has to hear that the pair
    # it landed on works, and the pool it publishes may not show the burn yet.
    ST["dst"]["state"], ST["src"]["state"] = "healthy", "healthy"
    ST["hits"] = 0
    sweep("t-edge")
    sweep("t-edge")              # confirmed red
    ST["hits"] = m.PROBE_COUNT
    n0 = len(sent)
    sweep("t-edge")
    want(oks(n0) == [{"cmd": "ok", "key": "10.0.0.1", "src": "192.168.1.1", "epoch": 1}],
         f"the red->green edge must still be reported on a clean pool, got {oks(n0)}")

    os.path.exists = real_exists
    print()
    if fails:
        print(f"{len(fails)} failure(s)")
        return 1
    print("a carrying endpoint cannot stay condemned, and a quiet tunnel stays quiet")
    return 0


if __name__ == "__main__":
    sys.exit(main())
