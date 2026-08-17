"""Guard: the tun probe judges the CDN edge pool exactly the way it judges a direct pool.

Before this, a ws edge pool decided for itself which of its two axes was to blame: on a failed dial it
ran a differential probe -- reconnect, then try the same IP with another SNI and the same SNI on another
IP -- and burned whichever one still worked in isolation. Every one of those signals is something a
FILTERED edge passes while carrying nothing: the TCP connect completes, the TLS handshake completes, the
WebSocket upgrade completes, and the payload goes nowhere. So the pool kept re-admitting dead edges,
which is the same failure 5.75.197.201 showed on the direct side.

Now there is one judge for every carrier: the probe that sends a packet down the tunnel device and sees
whether anything comes back. The two axes are an odometer -- the SNI is the low digit, the EDGE the high
one -- so a whole ROW of SNIs failing on one edge is what convicts that edge, since the probe only ever
sees silence and silence names the COMBINATION, never one half of it.

It drives health_of -- the sweep's own path -- not _ws_failover directly, because a guard that calls the
helper says nothing about whether the sweep still calls it.

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
    spec = importlib.util.spec_from_file_location("tnl_node_wsfo", NODE)
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

    STATE = {"role": "client", "ips": ["1.1.1.1", "1.1.1.2"], "snis": ["a.example", "b.example"],
             "ip": "1.1.1.1", "sni": "a.example", "is_ws": True, "hits": 0, "burned": []}
    m._is_ws_pool = lambda name: STATE["is_ws"]
    m._is_peer_pool = lambda name: False
    m._read_core_cfg = lambda name: {"role": STATE["role"], "ws_status_path": "x"}
    # The core's published path: the epoch a verdict is keyed to, and whether a session is up on it.
    PATH = {"ready": True}
    m._read_path_state = lambda _n: (1, PATH["ready"])
    m._read_ws_pool = lambda name: {
        "ip": STATE["ip"], "sni": STATE["sni"], "ips": STATE["ips"], "snis": STATE["snis"],
        "health": ([{"key": k, "kind": d, "state": "suspect"} for k, d in STATE["burned"]]
                   + [{"key": i, "kind": "ip", "state": "healthy"} for i in STATE["ips"]]
                   + [{"key": s, "kind": "sni", "state": "healthy"} for s in STATE["snis"]])}

    real_exists = os.path.exists
    os.path.exists = lambda p: True if str(p).startswith("/sys/class/net/") else real_exists(p)
    m._flow_sample = lambda n: (0.0, 0.0)
    m.tun_probe = lambda *a, **k: (STATE["hits"], m.PROBE_COUNT, 80.0 if STATE["hits"] else None)

    clock = {"t": 1000.0}
    m.time.monotonic = lambda: clock["t"]

    def sweep(name="w1"):
        """One real health sweep, exactly as the loop runs it."""
        return m.health_of({"type": "core", "name": name, "tunnel_ip": "192.168.9.2/24"})

    # --- a single bad sweep must not burn anything: red is confirmed over RED_SWEEPS ---------------
    STATE["hits"] = 0
    clock["t"] += 4.0
    sweep()
    want(sent == [], f"one bad sweep must ask for nothing, got {sent}")

    # --- confirmed dead -> exactly ONE ask, naming BOTH axes ---------------------------------------
    clock["t"] += 4.0
    sweep()
    want(len(sent) == 1 and sent[0][1] == {"cmd": "fail", "ip": "1.1.1.1", "sni": "a.example", "epoch": 1},
         f"a confirmed-dead tunnel must name the COMBINATION it measured, not just one axis, got {sent}")
    want(sent[0][0].endswith(".status.cmd"),
         f"and it must go to the edge pool's own command file, got {sent[0][0]}")

    # --- what swallows the sweeps right after a jump is the carrier's report, not a clock -----------
    # The burn drops the connection, so the core publishes ready=false until it has re-dialled and
    # re-upgraded on the combination it moved to. A probe in that window is measuring the TLS+upgrade,
    # not the edge, and may not be charged to either axis.
    PATH["ready"] = False
    for _ in range(2):
        clock["t"] += 2.0
        sweep()
    want(len(sent) == 1,
         f"while the carrier reports no session on the combination, nothing may be asked -- the probe "
         f"is measuring the re-dial. got {len(sent)}")
    PATH["ready"] = True

    # --- the walk is the MATRIX (2 edges x 2 SNIs = 4 combinations = 3 asks) -----------------------
    for _ in range(2):
        clock["t"] += 4.0
        sweep()
    want(len(sent) == 3,
         f"2 edges x 2 SNIs is 4 combinations, covered in 3 asks -- got {len(sent)}")
    want(sighups == [],
         f"and nothing may be handed back before the matrix is done, got sighups={sighups}")

    # --- matrix exhausted -> hand everything back, do not burn the last one ------------------------
    clock["t"] += 4.0
    sweep()
    want(len(sent) == 3,
         f"the last combination must NOT be asked for: every one has been tried, so the edges were "
         f"never the problem. got {len(sent)} asks")
    want(sighups == ["w1"], f"instead every entry must be handed back at once, got sighups={sighups}")

    # --- and it stands down instead of chewing through the matrix again ----------------------------
    before = (len(sent), len(sighups))
    for _ in range(3):
        clock["t"] += 4.0
        sweep()
    want((len(sent), len(sighups)) == before,
         f"after a full walk it must stand down for the cooldown, got {(len(sent), len(sighups))}")
    clock["t"] += m.FAILOVER_COOLDOWN + 1
    sweep()
    want(len(sent) == 4, f"and pick up again once the cooldown lapses, got {len(sent)}")

    # --- the GREEN half: a carrying combination clears both burns ----------------------------------
    STATE["burned"] = [("1.1.1.1", "ip"), ("a.example", "sni")]
    STATE["hits"] = m.PROBE_COUNT
    n0 = len(sent)
    clock["t"] += 4.0
    sweep()
    want(len(sent) == n0 + 1 and sent[-1][1] == {"cmd": "ok", "ip": "1.1.1.1", "sni": "a.example", "epoch": 1},
         f"an edge that is CARRYING while its pool still has it condemned must be reported, naming both "
         f"axes -- a burn always rotates away from what it burns, so nothing else ever clears it. got "
         f"{sent[n0:]}")
    with m._fo_lock:
        want(m._fo["w1"]["burns"] == 0,
             "a tunnel that starts crossing again must forget the round it was in the middle of")

    # --- a healthy tunnel on healthy entries writes nothing ----------------------------------------
    STATE["burned"] = []
    n0 = len(sent)
    clock["t"] += 4.0
    sweep()
    want(len(sent) == n0, f"a green tunnel on green entries must stay silent, got {sent[n0:]}")

    # --- the conditions, each on its own tunnel so no state leaks between them ---------------------
    def asks_for(name, **over):
        """The EDGE-pool asks this sweep produced. A tunnel that is not an edge pool is judged on the
        direct path instead, which writes elsewhere and is that file's business, not this one's."""
        keep = {k: STATE[k] for k in over}
        STATE.update(over)
        STATE["hits"] = 0
        n0 = len(sent)
        for _ in range(2):
            clock["t"] += 4.0
            sweep(name)
        STATE.update(keep)
        return len([p for p, _o in sent[n0:] if p.endswith(".status.cmd")])

    want(asks_for("w-server", role="server") == 0,
         "a SERVER end must never ask: it does not dial, and two ends both rotating would chase each "
         "other around the matrix")
    want(asks_for("w-one", ips=["1.1.1.9"], snis=["only.example"], ip="1.1.1.9", sni="only.example") == 0,
         "a single edge and a single SNI must never be burned -- there is nothing to move to on either "
         "axis, so the ask would just take the tunnel down")
    want(asks_for("w-nopool", is_ws=False) == 0,
         "a tunnel that is not an edge pool must never be judged on the EDGE axes -- it has none, and "
         "the ip/sni keys would name nothing")

    os.path.exists = real_exists
    print()
    if fails:
        print("%d failure(s)" % len(fails))
        return 1
    print("the tun probe is the edge pool's only judge, and its verdict names the combination")
    return 0


if __name__ == "__main__":
    sys.exit(main())
