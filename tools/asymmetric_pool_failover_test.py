"""Guard: the node still judges a pool whose axes are LOPSIDED.

Every failover guard so far used a square matrix -- 2 edges x 2 SNIs, or several destinations against
several sources. The operator's live tunnels are not square. The one that misbehaved had THREE CDN edges
and ONE domain, and the other common shape is one destination with several source IPs.

Those shapes are where the "nothing to rotate to" gate and the matrix sizing are easiest to get wrong in
a way no square test can see:

  * the gate is `len(a) < 2 and len(b) < 2` -- an `or` there would silence the operator's own tunnel
    completely, and no square test would notice because both axes are >= 2;
  * the matrix is `max(1, len(a)) * max(1, len(b))` -- dropping the max() makes a one-entry axis collapse
    the whole product to zero, so the node declares "everything tried" on the FIRST bad sweep, hands the
    pool back, and stands down for five minutes without ever asking for a single failover.

It drives health_of -- the sweep's own path -- not the failover helpers directly, because a guard that
calls the helper says nothing about whether the sweep still calls it.

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
    spec = importlib.util.spec_from_file_location("tnl_node_asym", NODE)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def main():
    fails = []

    def want(cond, msg):
        print(("  ok  " if cond else " FAIL ") + msg)
        if not cond:
            fails.append(msg)

    # ---------------------------------------------------------------- one SNI, three edges
    # The operator's own tunnel. One domain means the SNI axis cannot vary, so every beat of the walk
    # changes the EDGE -- and the node must still ask, three times, before standing down.
    m = load()
    tmp = tempfile.mkdtemp()
    m.CONFIG_DIR = tmp
    m.logline = lambda _msg: None
    sent, sighups = [], []
    m._pool_sighup = lambda name, is_pool, msg: sighups.append(name) or {"ok": True}
    m._atomic_write_json = lambda path, obj: sent.append((os.path.basename(path), obj)) and None

    ST = {"hits": 0}
    m._is_ws_pool = lambda name: True
    m._is_peer_pool = lambda name: False
    m._read_core_cfg = lambda name: {"role": "client", "ws_status_path": "x"}
    m._read_ws_pool = lambda name: {
        "ip": "e1", "sni": "only.example",
        "ips": ["e1", "e2", "e3"], "snis": ["only.example"],
        "health": [{"key": k, "kind": "ip", "state": "healthy"} for k in ("e1", "e2", "e3")]
        + [{"key": "only.example", "kind": "sni", "state": "healthy"}]}
    real_exists = os.path.exists
    os.path.exists = lambda p: True if str(p).startswith("/sys/class/net/") else real_exists(p)
    m._flow_sample = lambda n: (0.0, 0.0)
    m.tun_probe = lambda *a, **k: (ST["hits"], m.PROBE_COUNT, 80.0 if ST["hits"] else None)
    clock = {"t": 1000.0}
    m.time.monotonic = lambda: clock["t"]

    def sweep(name="w1"):
        return m.health_of({"type": "core", "name": name, "tunnel_ip": "192.168.9.2/24"})

    for _ in range(2):          # RED_SWEEPS to confirm the tunnel is really dead
        clock["t"] += 4.0
        sweep()
    want(len(sent) == 1 and sent[0][1] == {"cmd": "fail", "ip": "e1", "sni": "only.example"},
         f"a 3-edge / 1-domain pool must still be judged: with one SNI the walk varies the EDGE, and "
         f"silencing it leaves the operator with a pool that rotates forever and blacklists nothing. "
         f"got {sent}")

    clock["t"] += m.FAILOVER_SETTLE + 1
    sweep()
    want(len(sent) == 2 and sighups == [],
         f"3 edges x 1 SNI is 3 combinations, so the second ask is still inside the walk. "
         f"got {len(sent)} asks, sighups={sighups}")

    clock["t"] += m.FAILOVER_SETTLE + 1
    sweep()
    want(len(sent) == 2 and sighups == ["w1"],
         f"...and the third completes it: every combination has been tried, so the edges were never the "
         f"problem and every entry is handed back. got {len(sent)} asks, sighups={sighups}")

    # ---------------------------------------------------------------- one destination, three sources
    m2 = load()
    m2.CONFIG_DIR = tempfile.mkdtemp()
    m2.logline = lambda _msg: None
    sent2, sighups2 = [], []
    m2._pool_sighup = lambda name, is_pool, msg: sighups2.append(name) or {"ok": True}
    m2._atomic_write_json = lambda path, obj: sent2.append((os.path.basename(path), obj)) and None

    ST2 = {"hits": 0}
    m2._is_ws_pool = lambda name: False
    m2._is_peer_pool = lambda name: True
    m2._read_core_cfg = lambda name: {"role": "client"}
    m2._read_peer_pool = lambda name, suf: (
        {"active": "d1", "addrs": ["d1"],
         "health": [{"key": "d1", "state": "healthy"}]} if suf == ".peerpool" else
        {"active": "s1", "addrs": ["s1", "s2", "s3"],
         "health": [{"key": k, "state": "healthy"} for k in ("s1", "s2", "s3")]})
    os.path.exists = lambda p: True if str(p).startswith("/sys/class/net/") else real_exists(p)
    m2._flow_sample = lambda n: (0.0, 0.0)
    m2.tun_probe = lambda *a, **k: (ST2["hits"], m2.PROBE_COUNT, 80.0 if ST2["hits"] else None)
    clock2 = {"t": 1000.0}
    m2.time.monotonic = lambda: clock2["t"]

    def sweep2(name="p1"):
        return m2.health_of({"type": "core", "name": name, "tunnel_ip": "192.168.9.2/24"})

    for _ in range(2):
        clock2["t"] += 4.0
        sweep2()
    want(len(sent2) == 1 and sent2[0][1] == {"cmd": "fail", "key": "d1"},
         f"one destination and three sources must still be judged -- the destination axis cannot vary, "
         f"so the core answers by walking the SOURCE, and a node that stays silent here leaves a tunnel "
         f"with three source IPs stuck on the one that does not work. got {sent2}")
    want(sent2[0][0].endswith(".peerpool.cmd"),
         f"and it must go to the destination pool's own command file, got {sent2[0][0]}")

    for _ in range(2):
        clock2["t"] += m2.FAILOVER_SETTLE + 1
        sweep2()
    want(len(sent2) == 2 and sighups2 == ["p1"],
         f"1 destination x 3 sources is 3 combinations: two asks, then the walk is complete and every "
         f"entry is handed back. got {len(sent2)} asks, sighups={sighups2}")

    # ---------------------------------------------------------------- nothing to rotate to at all
    m3 = load()
    m3.CONFIG_DIR = tempfile.mkdtemp()
    m3.logline = lambda _msg: None
    sent3 = []
    m3._pool_sighup = lambda name, is_pool, msg: {"ok": True}
    m3._atomic_write_json = lambda path, obj: sent3.append((os.path.basename(path), obj)) and None
    ST3 = {"hits": 0}
    m3._is_ws_pool = lambda name: False
    m3._is_peer_pool = lambda name: True
    m3._read_core_cfg = lambda name: {"role": "client"}
    m3._read_peer_pool = lambda name, suf: (
        {"active": "d1", "addrs": ["d1"], "health": [{"key": "d1", "state": "healthy"}]} if suf == ".peerpool"
        else {"active": "s1", "addrs": ["s1"], "health": [{"key": "s1", "state": "healthy"}]})
    os.path.exists = lambda p: True if str(p).startswith("/sys/class/net/") else real_exists(p)
    m3._flow_sample = lambda n: (0.0, 0.0)
    m3.tun_probe = lambda *a, **k: (ST3["hits"], m3.PROBE_COUNT, None)
    clock3 = {"t": 1000.0}
    m3.time.monotonic = lambda: clock3["t"]
    for _ in range(6):
        clock3["t"] += m3.FAILOVER_SETTLE + 1
        m3.health_of({"type": "core", "name": "p2", "tunnel_ip": "192.168.9.2/24"})
    want(sent3 == [],
         f"one destination and one source have nowhere to go: a verdict there can only take the tunnel "
         f"down and mark the only endpoint it has as dead. got {sent3}")

    # ---------------------------------------------------------------- a SERVER never judges
    m4 = load()
    m4.CONFIG_DIR = tempfile.mkdtemp()
    m4.logline = lambda _msg: None
    sent4 = []
    m4._pool_sighup = lambda name, is_pool, msg: {"ok": True}
    m4._atomic_write_json = lambda path, obj: sent4.append((os.path.basename(path), obj)) and None
    m4._is_ws_pool = lambda name: True
    m4._is_peer_pool = lambda name: False
    m4._read_core_cfg = lambda name: {"role": "server", "ws_status_path": "x"}
    m4._read_ws_pool = lambda name: {
        "ip": "e1", "sni": "only.example", "ips": ["e1", "e2", "e3"], "snis": ["only.example"],
        "health": [{"key": k, "kind": "ip", "state": "healthy"} for k in ("e1", "e2", "e3")]}
    os.path.exists = lambda p: True if str(p).startswith("/sys/class/net/") else real_exists(p)
    m4._flow_sample = lambda n: (0.0, 0.0)
    m4.tun_probe = lambda *a, **k: (0, m4.PROBE_COUNT, None)
    clock4 = {"t": 1000.0}
    m4.time.monotonic = lambda: clock4["t"]
    for _ in range(6):
        clock4["t"] += m4.FAILOVER_SETTLE + 1
        m4.health_of({"type": "core", "name": "w2", "tunnel_ip": "192.168.9.2/24"})
    want(sent4 == [],
         f"only the dialling end chooses endpoints; a server that judged its own pool would fight the "
         f"client's rotation. got {sent4}")

    os.path.exists = real_exists
    if fails:
        print(f"\n{len(fails)} failure(s)")
        return 1
    print("\nall good")
    return 0


if __name__ == "__main__":
    sys.exit(main())
