"""Guard: build_core must sweep a tunnel's firewall rules only AFTER its core is stopped.

The sweep exists to clear rules a KILLED core left behind. Run it while that core is still alive and it
does the opposite of its job: the running core's anti-leak rules are gone, and until the unit is actually
stopped the kernel is free to answer the peer with the RST / ICMP-port-unreachable / echo-reply those
rules exist to swallow -- our real host replying, on the wire, which is the leak.

Not hypothetical: build_core is called on a LIVE tunnel by the core-version install, which relaunches
every core tunnel on the new binary without stopping anything first.

Ordering is the whole property, so this drives the real build_core with the system calls stubbed and
reads the order off the recorded calls. Asserting on _sweep_owned_rules alone would say nothing about
when build_core calls it -- which is the only thing that was ever wrong.

Exit 1 if the sweep does not sit between the stop and the launch.
"""
import importlib.util
import sys
from pathlib import Path

sys.dont_write_bytecode = True
NODE = Path(__file__).resolve().parent.parent / "tnl-node.py"

CFG = {
    "name": "core42", "type": "core", "id": 42, "enabled": True,
    "role": "client", "transport": "raw", "raw_profile": "tcp",
    "peer": "203.0.113.9", "listen_port": 443, "addr": "10.20.0.1/24",
    "psk": "x" * 44, "cipher": "chacha20-poly1305", "mtu": 1300,
}


def main():
    spec = importlib.util.spec_from_file_location("tnl_node_sweeporder", NODE)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)

    order = []
    m._ensure_core = lambda: order.append("ensure-core")
    m._sweep_owned_rules = lambda n: order.append("sweep:%s" % n)
    m._core_status_paths = lambda n: []
    m._core_config = lambda c: {"name": c["name"]}
    m._cfg_path = lambda n, ext: str(Path(__file__).resolve().parent / ("_sweeporder_%s%s" % (n, ext)))
    m.logline = lambda _m: None

    def fake_run(a, **k):
        a = list(a)
        if a[:2] == ["systemctl", "stop"]:
            order.append("stop")
        elif a[0] == "systemd-run":
            order.append("launch")
        elif a[:2] == ["ip", "link"]:
            return (0, "", "")      # the TUN is up on the first poll, so build_core returns at once
        return (0, "", "")
    m.run = fake_run

    try:
        m.build_core(dict(CFG))
    finally:
        for junk in Path(__file__).resolve().parent.glob("_sweeporder_*"):
            junk.unlink()

    fails = []

    def want(cond, msg):
        print(("  ok   " if cond else " FAIL ") + msg)
        if not cond:
            fails.append(msg)

    want("sweep:core42" in order, "build_core sweeps the tunnel's own rules at all: %s" % order)
    want("stop" in order and "launch" in order, "build_core stops the old unit and launches a new one")
    if "sweep:core42" in order and "stop" in order and "launch" in order:
        sw, st, la = order.index("sweep:core42"), order.index("stop"), order.index("launch")
        want(st < sw, "the unit is STOPPED before the sweep -- sweeping a live core strips the anti-leak "
                      "rules off a tunnel that is still carrying traffic (order: %s)" % order)
        want(sw < la, "the sweep runs before the new core launches -- otherwise the fresh rules it just "
                      "installed are what gets swept (order: %s)" % order)

    print()
    if fails:
        print("%d failure(s)" % len(fails))
        return 1
    print("build_core order is stop -> sweep -> launch")
    return 0


if __name__ == "__main__":
    sys.exit(main())
