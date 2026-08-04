"""Guard: the probe may move a tunnel off a destination, but it may not eat the pool.

The probe knows one thing -- nothing is crossing this tunnel. It does NOT know that the destination IP
is why. Wire it straight to a burn and a filtered path or a peer that is simply switched off will walk
the whole pool and leave every entry burned, which is a worse outage than the one it was chasing.

So the jump is the experiment: burn, move, let the next sweep judge, and if the whole pool has been
walked and it is STILL dead, hand every entry back and stand down. What this file defends is that
chain, plus the four conditions that must hold before a single burn is asked for at all.

It drives health_of -- the sweep's own path -- not pool_failover directly, because a guard that calls
the helper says nothing about whether the sweep still calls it.

Exit 1 on any failure.
"""
import sys
sys.dont_write_bytecode = True
import importlib.util
import json
import os
import tempfile
from pathlib import Path

NODE = Path(__file__).resolve().parent.parent / "tnl-node.py"


def load():
    spec = importlib.util.spec_from_file_location("tnl_node_fo", NODE)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def main():
    m = load()
    fails = []
    sent = []          # every cmd file the node wrote, in order
    sighups = []       # every "hand it all back" call

    def want(cond, msg):
        print(("  ok  " if cond else " FAIL ") + msg)
        if not cond:
            fails.append(msg)

    tmp = tempfile.mkdtemp()
    m.CONFIG_DIR = tmp
    m.logline = lambda _msg: None
    m._pool_sighup = lambda name, is_pool, msg: sighups.append(name) or {"ok": True}
    m._atomic_write_json = lambda path, obj: sent.append((os.path.basename(path), obj)) and None

    STATE = {"role": "client", "addrs": ["10.0.0.1", "10.0.0.2", "10.0.0.3"], "active": "10.0.0.1",
             "srcs": [], "is_pool": True, "hits": 0}
    m._is_peer_pool = lambda name: STATE["is_pool"]
    m._read_core_cfg = lambda name: {"role": STATE["role"], "peer_status_path": "x"}
    m._read_peer_pool = lambda name, suffix: (
        {"active": "", "addrs": STATE["srcs"], "health": [], "pin": "", "ts": 0} if suffix == ".srcpool"
        else {"active": STATE["active"], "addrs": STATE["addrs"], "health": [], "pin": "", "ts": 0})

    real_exists, real_flow = os.path.exists, m._flow_sample
    os.path.exists = lambda p: True if str(p).startswith("/sys/class/net/") else real_exists(p)
    m._flow_sample = lambda n: (0.0, 0.0)
    m.tun_probe = lambda *a, **k: (STATE["hits"], m.PROBE_COUNT, 80.0 if STATE["hits"] else None)

    clock = {"t": 1000.0}
    m.time.monotonic = lambda: clock["t"]

    def sweep(name="t1"):
        """One real health sweep, exactly as the loop runs it."""
        return m.health_of({"type": "core", "name": name, "tunnel_ip": "192.168.9.2/24"})

    def dead_sweeps(n, name="t1", step=4.0):
        for _ in range(n):
            clock["t"] += step
            sweep(name)

    # --- a single bad sweep must not burn anything: red is confirmed over RED_SWEEPS ---------------
    STATE["hits"] = 0
    clock["t"] += 4.0
    sweep()
    want(sent == [], f"one bad sweep must ask for nothing, got {sent}")

    # --- confirmed dead -> exactly ONE burn, then silence while it settles -------------------------
    clock["t"] += 4.0
    sweep()
    want(len(sent) == 1 and sent[0][1] == {"cmd": "fail", "key": "10.0.0.1"},
         f"a confirmed-dead tunnel must ask the core to fail the destination BY NAME, got {sent}")
    want(sent[0][0].endswith(".peerpool.cmd"),
         f"and it must go to the DESTINATION pool's command file, got {sent[0][0]}")

    dead_sweeps(2, step=2.0)   # 4 s later: still inside the settle window
    want(len(sent) == 1,
         f"the settle window must swallow the sweeps right after a jump -- the fresh handshake disturbs "
         f"traffic by itself and reading that as failure walks the pool in seconds. got {len(sent)} burns")

    # --- past the settle window it asks again. The active endpoint deliberately does NOT change here:
    # the carrier fails over on its own timers too, so between our decision and the core acting it can
    # already have moved. A walk keyed on identity burns the same address forever and never finishes --
    # measured live on 2026-08-04 before this was counted instead.
    STATE["active"] = "10.0.0.1"
    clock["t"] += m.FAILOVER_SETTLE + 1
    sweep()
    want(len(sent) == 2, f"past the settle window the next endpoint may be failed too, got {len(sent)}")

    # --- the WHOLE pool walked and still dead -> hand everything back, do not burn the last one ----
    STATE["active"] = "10.0.0.1"
    clock["t"] += m.FAILOVER_SETTLE + 1
    sweep()
    want(len(sent) == 2,
         f"the third endpoint must NOT be burned: every entry has now been tried, so the destination "
         f"was never the problem. got {len(sent)} burns")
    want(sighups == ["t1"],
         f"instead every burned entry must be handed back at once, got sighups={sighups}")

    # --- and it stands down, instead of chewing through the pool again -----------------------------
    before = (len(sent), len(sighups))
    clock["t"] += m.FAILOVER_SETTLE + 1
    dead_sweeps(3)
    want((len(sent), len(sighups)) == before,
         f"after a full walk it must stand down for the cooldown, got {(len(sent), len(sighups))}")
    clock["t"] += m.FAILOVER_COOLDOWN + 1
    sweep()
    want(len(sent) == 3, f"and pick up again once the cooldown lapses, got {len(sent)}")

    # --- a tunnel that recovers clears the round --------------------------------------------------
    STATE["hits"] = m.PROBE_COUNT
    clock["t"] += 4.0
    sweep()
    with m._fo_lock:
        want(m._fo["t1"]["burns"] == 0,
             "a tunnel that starts crossing again must forget the round it was in the middle of")

    # --- the four conditions, each on its own tunnel so no state leaks between them ----------------
    def burns_for(name, **over):
        keep = {k: STATE[k] for k in over}
        STATE.update(over)
        STATE["hits"] = 0
        n0 = len(sent)
        dead_sweeps(2, name=name)
        STATE.update(keep)
        return len(sent) - n0

    want(burns_for("t-server", role="server") == 0,
         "a SERVER end must never ask: it does not choose the destination, and two ends both "
         "rotating would chase each other around the pool")
    want(burns_for("t-one", addrs=["10.0.0.9"], active="10.0.0.9") == 0,
         "a single destination with no source pool must never be burned -- there is nothing to move to "
         "on either axis, so the burn would just take the tunnel down")

    # --- the walk is the MATRIX, not the destination list -----------------------------------------
    # The pools are nested: every destination is tried against the current source, and only then is
    # THAT SOURCE burned and the next one taken. Bounding the walk by the destination count quits after
    # the first row and hands back the source burn the core had just earned -- which is the one correct
    # conclusion in the whole sequence.
    STATE["srcs"] = ["192.168.1.1", "192.168.1.2"]   # 3 destinations x 2 sources = 6 combinations
    STATE["hits"] = 0
    n0, s0 = len(sent), len(sighups)
    for _ in range(9):
        clock["t"] += m.FAILOVER_SETTLE + 1
        sweep("t-matrix")
    # N combinations take N-1 asks, not N: each ask MOVES you from one combination to the next, so by
    # the time the last one is standing there is nothing left to ask for -- that is where it gives up.
    want(len(sent) - n0 == 5,
         f"with 3 destinations and 2 sources the walk must cover 6 combinations in 5 asks, not stop "
         f"after the destination list -- got {len(sent) - n0}")
    want(len(sighups) - s0 == 1,
         f"and it must hand everything back exactly once, at the END of the matrix, got "
         f"{len(sighups) - s0}")
    STATE["srcs"] = []
    want(burns_for("t-nopool", is_pool=False) == 0, "a tunnel with no pool at all must be left alone")

    # --- EVERY ask names the endpoint the probe was measured on, never "whatever is active later" ---
    # The core reads these on a one-second ticker and its own proactive rotation runs in that gap, so an
    # unnamed ask lands on whatever the core moved to meanwhile -- condemning an endpoint nothing
    # measured and dropping the tunnel back onto the one that was. Reproduced live in netns on
    # 2026-08-05. Its own tunnel, 3 dst x 2 src, so five asks fit before the walk completes.
    STATE["srcs"] = ["10.9.0.1", "10.9.0.2"]
    STATE["is_pool"], STATE["hits"] = True, 0
    clock["t"] += m.FAILOVER_COOLDOWN + m.FAILOVER_SETTLE + 10
    STATE["active"] = "10.0.0.1"
    dead_sweeps(2, name="t-key")                      # confirm red, first ask
    for want_key in ("10.0.0.2", "10.0.0.3", "10.0.0.1"):
        STATE["active"] = want_key                    # the reading this sweep is measured on
        n = len(sent)
        clock["t"] += m.FAILOVER_SETTLE + 1
        sweep("t-key")
        got = [o for _, o in sent[n:]]
        want(len(got) == 1 and got[0].get("key") == want_key,
             f"an ask measured on {want_key} must name {want_key}, got {got}")
    STATE["srcs"] = []

    # --- the OTHER half of the verdict: recovery is reported, once, with both keys ----------------
    # The core cannot learn this for itself -- every signal it can observe is one a filtered IP passes
    # while carrying nothing. So the probe that condemns an endpoint is the only thing that clears it.
    STATE["srcs"] = ["10.9.0.1", "10.9.0.2"]
    STATE["active"], STATE["is_pool"], STATE["hits"] = "10.0.0.2", True, 0
    clock["t"] += m.FAILOVER_COOLDOWN + m.FAILOVER_SETTLE + 10
    dead_sweeps(2, name="t-ok")                      # confirm red so there is something to recover from
    n0 = len(sent)
    want(n0 > 0 and sent[-1][1]["cmd"] == "fail", f"setup: expected a burn first, got {sent[-1:]}")

    STATE["hits"] = m.PROBE_COUNT                     # traffic crosses again
    clock["t"] += 4.0
    sweep("t-ok")
    got = [o for _, o in sent[n0:]]
    want(len(got) == 1 and got[0].get("cmd") == "ok",
         f"a tunnel that came back must tell the core so, exactly once, got {got}")
    want(got and got[0].get("key") == "10.0.0.2" and got[0].get("src") == "",
         f"and it must name the endpoints it crossed on, read from the pool files, got {got}")

    n1 = len(sent)
    clock["t"] += 4.0
    sweep("t-ok")
    clock["t"] += 4.0
    sweep("t-ok")
    want(len(sent) == n1,
         f"a tunnel that is simply healthy must write nothing -- the report is edge-triggered, got "
         f"{len(sent) - n1} extra")

    # A sweep that could not RUN says nothing about any endpoint, so it must reach neither verdict.
    STATE["hits"] = 0
    clock["t"] += 4.0
    sweep("t-ok")
    clock["t"] += 4.0
    sweep("t-ok")                                     # red again, and past the settle window
    n2 = len(sent)
    real_probe = m.tun_probe
    m.tun_probe = lambda *a, **k: (0, 0, None)        # the probe socket could not be set up
    clock["t"] += m.FAILOVER_SETTLE + 4.0
    sweep("t-ok")
    m.tun_probe = real_probe
    want(len(sent) == n2,
         f"an unmeasurable sweep must produce no verdict at all, got {sent[n2:]}")
    STATE["srcs"] = []

    # --- the memory must not outlive the tunnel ---------------------------------------------------
    m._prune_iface_state(set())
    with m._fo_lock:
        want(m._fo == {}, f"pruning must drop the per-tunnel failover memory, got {list(m._fo)}")

    os.path.exists, m._flow_sample = real_exists, real_flow
    print()
    if fails:
        print(f"{len(fails)} failure(s)")
        return 1
    print("the probe may move a tunnel off a destination, and may not eat the pool")
    return 0


if __name__ == "__main__":
    sys.exit(main())
