import sys
sys.dont_write_bytecode = True
import importlib.util
import os
import tempfile
from pathlib import Path

NODE = Path(__file__).resolve().parent.parent / "tnl-node.py"


def load():
    spec = importlib.util.spec_from_file_location("tnl_node_epoch", NODE)
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
    m._atomic_write_json = lambda path, obj: sent.append(obj) and None
    m._read_core_cfg = lambda name: {"role": "client"}
    m._flow_sample = lambda n: (0.0, 0.0)
    m._read_status = lambda name: {"active": "", "epoch": 0, "ready": True, "ts": 0, "events": [],
                                   "pair": {"low": "", "high": "94.182.131.35",
                                            "low_kind": "dst", "high_kind": "src"},
                                   "health": []}

    ST = {"hits": 0, "before": 5, "after": 5}
    reads = {"n": 0}

    def path_state(_name):
        reads["n"] += 1
        return (ST["before"] if reads["n"] % 2 else ST["after"]), True

    m._read_path_state = path_state
    m.tun_probe = lambda *a, **k: (ST["hits"], m.PROBE_COUNT, 80.0 if ST["hits"] else None)

    real_exists = os.path.exists
    os.path.exists = lambda p: True if str(p).startswith("/sys/class/net/") else real_exists(p)

    clock = {"t": 1000.0}
    m.time.monotonic = lambda: clock["t"]

    def sweep(name):
        clock["t"] += 4.0
        reads["n"] = 0
        return m.health_of({"type": "core", "name": name, "tunnel_ip": "192.168.17.2/24"})

    def since(n0, cmd):
        return [o for o in sent[n0:] if o.get("cmd") == cmd]

    ST["hits"] = 0
    ST["before"] = ST["after"] = 5
    n0 = len(sent)
    sweep("t-fail-stable")
    sweep("t-fail-stable")
    want(since(n0, "fail") == [{"cmd": "fail", "low": "", "high": "94.182.131.35", "epoch": 5}],
         f"a stable sweep that measured nothing must ask the core to fail, got {since(n0, 'fail')}")

    ST["before"], ST["after"] = 5, 6
    n0 = len(sent)
    sweep("t-fail-moved")
    sweep("t-fail-moved")
    sweep("t-fail-moved")
    want(since(n0, "fail") == [],
         f"a FAIL measured across a path move must stay unsent -- it would charge an endpoint the "
         f"carrier has already left, got {since(n0, 'fail')}")

    ST["before"] = ST["after"] = 9
    ST["hits"] = 0
    sweep("t-ok-moved")
    sweep("t-ok-moved")
    ST["hits"] = m.PROBE_COUNT
    ST["before"], ST["after"] = 9, 10
    n0 = len(sent)
    sweep("t-ok-moved")
    want(since(n0, "ok") == [{"cmd": "ok", "low": "", "high": "94.182.131.35", "epoch": 9}],
         f"an OK measured across a path move must still be sent, naming the epoch it MEASURED -- "
         f"every recovery moves the epoch while the sweep runs, so this is the only shape one has, "
         f"got {since(n0, 'ok')}")

    ST["before"] = ST["after"] = 12
    ST["hits"] = 0
    sweep("t-ok-stable")
    sweep("t-ok-stable")
    ST["hits"] = m.PROBE_COUNT
    n0 = len(sent)
    sweep("t-ok-stable")
    want(since(n0, "ok") == [{"cmd": "ok", "low": "", "high": "94.182.131.35", "epoch": 12}],
         f"and a stable recovery is still reported exactly as before, got {since(n0, 'ok')}")

    os.path.exists = real_exists
    print()
    if fails:
        print(f"{len(fails)} failure(s)")
        return 1
    print("a moved epoch swallows the fail and lets the recovery through")
    return 0


if __name__ == "__main__":
    sys.exit(main())
