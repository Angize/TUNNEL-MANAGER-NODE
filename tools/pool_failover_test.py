"""Guard: the probe may move a tunnel off a destination, but it may not eat the pool.

The probe knows one thing -- nothing is crossing this tunnel. It does NOT know that the destination IP
is why. Wire it straight to a burn and a filtered path or a peer that is simply switched off will walk
the whole pool and leave every entry burned, which is a worse outage than the one it was chasing.

So the jump is the experiment: burn, move, let the next sweep judge, and if the whole pool has been
walked it keeps reporting: there is no ask ceiling here and nothing is handed back on the decision
path. What this file defends is that, plus the four conditions that must hold before a single ask.

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
    m._read_core_cfg = lambda name: {"role": STATE["role"], "peer_ips": ["x"]}
    m._read_status = lambda name: {
        "active": "tcp · " + STATE["active"], "epoch": PATH["epoch"], "ready": PATH["ready"],
        "ts": 0, "events": [],
        "pair": {"low": STATE["active"], "high": (STATE["srcs"][0] if STATE["srcs"] else ""),
                 "low_kind": "dst", "high_kind": "src"},
        "health": [{"key": a, "kind": "dst", "state": "healthy"} for a in STATE["addrs"]]
        + [{"key": a, "kind": "src", "state": "healthy"} for a in STATE["srcs"]]}

    # The core's published path: the epoch a verdict is keyed on, and whether a session is up on it.
    # health_of reads this twice per sweep — once either side of the probe — so `moves_mid_probe` is
    # what a rotation landing DURING a measurement looks like from here.
    PATH = {"epoch": 1, "ready": True, "moves_mid_probe": False}

    def read_path(_name):
        e = PATH["epoch"]
        if PATH["moves_mid_probe"]:
            PATH["epoch"] += 1
        return e, PATH["ready"]

    m._read_path_state = read_path

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
    want(len(sent) == 1 and sent[0][1] == {"cmd": "fail", "low": "10.0.0.1", "high": "", "epoch": 1},
         f"a confirmed-dead tunnel must ask the core to fail the destination BY NAME, got {sent}")
    want(sent[0][0].endswith(".status.verdict"),
         f"and it must go to the TUNNEL's verdict mailbox -- not a pool's pin file, which a pool-less "
         f"tunnel does not have and which the operator's pin owns. got {sent[0][0]}")
    want(sent[0][0] in [os.path.basename(p) for p in m._core_status_paths("t1")],
         f"and that file must be one a relaunch sweeps, or the fresh core replays its predecessor's "
         f"verdict. got {sent[0][0]} vs {[os.path.basename(p) for p in m._core_status_paths('t1')]}")

    # --- a carrier with no session on the path is still reported DEAD -----------------------------
    # The core's cheapest rungs include giving the session up and handshaking again, which turns
    # ready=false for exactly as long as the path stays blocked. Gating the fail on it meant the very
    # first rung switched the judge off, so the walk that follows -- burn, move, re-judge -- was never
    # reachable. A fail blames nobody until the free rungs are spent; the ORDER of the rungs is what
    # protects the handshake, not silence from here.
    PATH["ready"] = False
    n_nosess = len(sent)
    dead_sweeps(2, step=2.0)
    want(len(sent) == n_nosess + 2,
         f"a probe measuring a path the carrier has no session on is still a measurement of that path, "
         f"got {len(sent) - n_nosess} of 2 asks")
    want(all(o["cmd"] == "fail" for _, o in sent[n_nosess:]),
         f"and every one of them must be a fail, got {sent[n_nosess:]}")

    # --- but an OK still needs one: it CLEARS a burn, and that claim may not rest on a handshake ---
    STATE["hits"] = m.PROBE_COUNT
    n_ok = len(sent)
    clock["t"] += 4.0
    sweep()
    want(len(sent) == n_ok,
         f"traffic crossed while the carrier reported no session on this path and the node cleared a "
         f"burn on it anyway, got {sent[n_ok:]}")
    PATH["ready"] = True
    STATE["hits"] = 0

    # --- a probe that STRADDLES a path change is charged to neither side of it ----------------------
    # The epoch moves between the two reads of one sweep, which is exactly a rotation landing mid-probe.
    PATH["moves_mid_probe"] = True
    n_straddle = len(sent)
    dead_sweeps(2, step=2.0)
    want(len(sent) == n_straddle,
         f"a probe that spanned a path change measured two paths and may be charged to neither, "
         f"got {len(sent) - n_straddle} asks")
    PATH["moves_mid_probe"] = False

    # --- past the settle window it asks again. The active endpoint deliberately does NOT change here:
    # the carrier fails over on its own timers too, so between our decision and the core acting it can
    # already have moved. A walk keyed on identity burns the same address forever and never finishes --
    # measured live on 2026-08-04 before this was counted instead.
    STATE["active"] = "10.0.0.1"
    n_again = len(sent)
    clock["t"] += 4.0
    sweep()
    want(len(sent) == n_again + 1,
         f"past the straddled window the next endpoint may be failed too, got {len(sent) - n_again}")

    # --- the node never rations asks, and never hands the pool back itself -------------------------
    # This is the class the old walk policy belonged to. It counted ITS OWN asks and assumed one ask
    # == one burn; when the core's ladder grew free rungs that stopped being true and the core never
    # received enough verdicts to reach a burn at all. Asserting a COUNT here would rebuild the same
    # coupling, so what is asserted is that there is no ceiling: every bad sweep is reported, whatever
    # the pool's shape and however many rungs the core spends. Releasing a burn is the core's backoff.
    n0, s0 = len(sent), len(sighups)
    for _ in range(6):
        STATE["active"] = "10.0.0.1"
        clock["t"] += 4.0
        sweep()
    want(len(sent) == n0 + 6, f"every bad sweep must reach the core, got {len(sent) - n0} of 6")
    want(len(sighups) == s0,
         f"and the node must never hand the pool back on the decision path, got sighups={sighups}")

    # --- a tunnel that recovers clears the round --------------------------------------------------
    STATE["hits"] = m.PROBE_COUNT
    clock["t"] += 4.0
    sweep()
    with m._verdict_lock:
        want(m._verdict["t1"].get("red") is False,
             "a tunnel that starts crossing again must no longer be remembered as red")

    # --- who is told, and who is not, each on its own tunnel so no state leaks between them --------
    def asks_for(name, **over):
        keep = {k: STATE[k] for k in over}
        STATE.update(over)
        STATE["hits"] = 0
        n0 = len(sent)
        dead_sweeps(2, name=name)
        STATE.update(keep)
        return [o for _, o in sent[n0:]]

    want(asks_for("t-server", role="server") == [],
         "a SERVER end must never ask: it does not choose the destination, and two ends both "
         "rotating would chase each other around the pool")

    # A tunnel with nothing to rotate to is still TOLD. The verdict is about the path, and the core
    # answers it with the free rungs -- redraw the port, handshake again -- which move the tunnel
    # nowhere and blame nobody. Only the burn needs a second endpoint, and the core is what refuses it
    # (its pool returns early below two entries). Withholding the measurement instead left every
    # single-endpoint tunnel with no ladder at all.
    one = asks_for("t-one", addrs=["10.0.0.9"], active="10.0.0.9")
    want(len(one) == 1 and one[0]["cmd"] == "fail" and one[0]["low"] == "10.0.0.9",
         f"a single-destination tunnel must still be told, naming what was measured, got {one}")
    want(sighups == [],
         f"and the node hands nothing back on the decision path, whatever the shape, got {sighups}")

    # --- a 3x2 pool is judged on every bad sweep too, with no ceiling and no hand-back ------------
    STATE["srcs"] = ["192.168.1.1", "192.168.1.2"]
    STATE["active"], STATE["hits"] = "10.0.0.1", 0
    dead_sweeps(2)                       # the first bad sweep only arms RED_SWEEPS; it asks for nothing
    n0, s0 = len(sent), len(sighups)
    for _ in range(6):
        clock["t"] += 4.0
        sweep()
    want(len(sent) - n0 == 6,
         f"3 destinations x 2 sources changes nothing: one ask per bad sweep once red is confirmed, "
         f"got {len(sent) - n0} of 6")
    want(len(sighups) - s0 == 0,
         f"and still no hand-back, got {len(sighups) - s0}")
    STATE["srcs"] = []

    # --- EVERY ask names the endpoint the probe was measured on, never "whatever is active later" ---
    # The core reads these on a one-second ticker and its own proactive rotation runs in that gap, so an
    # unnamed ask lands on whatever the core moved to meanwhile -- condemning an endpoint nothing
    # measured and dropping the tunnel back onto the one that was. Reproduced live in netns on
    # 2026-08-05. Its own tunnel, 3 dst x 2 src, so five asks fit before the walk completes.
    STATE["srcs"] = ["10.9.0.1", "10.9.0.2"]
    STATE["is_pool"], STATE["hits"] = True, 0
    clock["t"] += 4.0
    STATE["active"] = "10.0.0.1"
    dead_sweeps(2, name="t-key")                      # confirm red, first ask
    for want_key in ("10.0.0.2", "10.0.0.3", "10.0.0.1"):
        STATE["active"] = want_key                    # the reading this sweep is measured on
        n = len(sent)
        clock["t"] += 4.0
        sweep("t-key")
        want(not sent[n:], f"the first sweep on {want_key} must ask for nothing, got {sent[n:]}")
        clock["t"] += 4.0
        sweep("t-key")
        got = [o for _, o in sent[n:]]
        want(len(got) == 1 and got[0].get("low") == want_key,
             f"an ask measured on {want_key} must name {want_key}, got {got}")
    STATE["srcs"] = []

    # --- the OTHER half of the verdict: recovery is reported, once, with both keys ----------------
    # The core cannot learn this for itself -- every signal it can observe is one a filtered IP passes
    # while carrying nothing. So the probe that condemns an endpoint is the only thing that clears it.
    STATE["srcs"] = ["10.9.0.1", "10.9.0.2"]
    STATE["active"], STATE["is_pool"], STATE["hits"] = "10.0.0.2", True, 0
    clock["t"] += 4.0
    dead_sweeps(2, name="t-ok")                      # confirm red so there is something to recover from
    n0 = len(sent)
    want(n0 > 0 and sent[-1][1]["cmd"] == "fail", f"setup: expected a burn first, got {sent[-1:]}")

    STATE["hits"] = m.PROBE_COUNT                     # traffic crosses again
    clock["t"] += 4.0
    sweep("t-ok")
    got = [o for _, o in sent[n0:]]
    want(len(got) == 1 and got[0].get("cmd") == "ok",
         f"a tunnel that came back must tell the core so, exactly once, got {got}")
    want(got and got[0].get("low") == "10.0.0.2" and got[0].get("high") == "10.9.0.1",
         f"and it must name BOTH halves of the pair it crossed on, read from the one status file "
         f"the core publishes -- an ok that names only the destination leaves a burned source "
         f"condemned while it is visibly carrying, got {got}")

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
    clock["t"] += 8.0
    sweep("t-ok")
    m.tun_probe = real_probe
    want(len(sent) == n2,
         f"an unmeasurable sweep must produce no verdict at all, got {sent[n2:]}")
    STATE["srcs"] = []

    # --- the memory must not outlive the tunnel ---------------------------------------------------
    m._prune_iface_state(set())
    with m._verdict_lock:
        want(all("red" not in v for v in m._verdict.values()), f"pruning must drop the per-tunnel red memory, got {list(m._verdict)}")

    os.path.exists, m._flow_sample = real_exists, real_flow
    print()
    if fails:
        print(f"{len(fails)} failure(s)")
        return 1
    print("the probe may move a tunnel off a destination, and may not eat the pool")
    return 0


if __name__ == "__main__":
    sys.exit(main())
