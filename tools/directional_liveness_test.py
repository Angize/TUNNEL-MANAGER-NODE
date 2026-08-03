"""Guard: the tunnel verdict comes from the tun probe and from nothing else.

The old ladder mixed a core heartbeat, byte counters and an ICMP probe, and every false GREEN we ever
shipped came from one of those being true while the tunnel carried nothing. There is one signal now, so
what this guard defends is that no second one grows back: bytes moving must not rescue a tunnel whose
handshake went unanswered, and silence must not condemn one whose handshake came back.
"""
import sys
sys.dont_write_bytecode = True
import importlib.util
import socket
from pathlib import Path

NODE = Path(__file__).resolve().parent.parent / "tnl-node.py"


def load():
    spec = importlib.util.spec_from_file_location("tnl_node", NODE)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def main():
    m = load()
    fails = []

    def want(cond, msg):
        if not cond:
            fails.append(msg)

    # --- the probe reads ANY reply as proof, and only silence as a negative ------------------------
    calls = {}

    class FakeSock:
        def __init__(self, outcome):
            self.outcome = outcome
        def settimeout(self, *_): pass
        def setsockopt(self, _lvl, opt, val):
            calls.setdefault("bound", []).append((opt, val))
        def bind(self, addr):
            calls["src"] = addr[0]
        def connect(self, addr):
            calls["dst"] = addr
            if self.outcome == "refused":
                raise ConnectionRefusedError()
            if self.outcome == "timeout":
                raise socket.timeout()
        def close(self): pass

    def with_outcome(outcome, tries=2):
        calls.clear()
        real = socket.socket
        socket.socket = lambda *a, **k: FakeSock(outcome)
        try:
            return m.tun_probe("core44", "192.168.44.2/24", "core", tries=tries)
        finally:
            socket.socket = real

    alive, rtt = with_outcome("ok")
    want(alive is True, "a completed handshake must read alive")
    want(rtt is not None, "and it must carry the round trip it measured")
    want(calls.get("dst") == ("192.168.44.1", m.PROBE_PORT),
         f"the probe must target the PEER tunnel address, got {calls.get('dst')}")
    want(calls.get("src") == "192.168.44.2",
         f"and leave from our own tunnel address, got {calls.get('src')}")
    want(any(o == m._SO_BINDTODEVICE and v.startswith(b"core44") for o, v in calls.get("bound", [])),
         "and be pinned to the tunnel DEVICE: routing alone is not a measurement, a probe free to "
         "leave by another path can call a tunnel alive that carries nothing")

    alive, _ = with_outcome("refused")
    want(alive is True,
         "a RST must count as alive: the far KERNEL put a packet on the wire, which is the whole "
         "question. Requiring a listener would turn every agent restart into a red healthy tunnel")

    alive, rtt = with_outcome("timeout")
    want(alive is False, "silence, and only silence, is the negative verdict")
    want(rtt is None, "a dead probe reports no round trip")

    # one lost SYN is not a dead tunnel: the sweep retries before it condemns
    calls.clear()
    seen = []
    real = socket.socket
    socket.socket = lambda *a, **k: (seen.append(1), FakeSock("timeout"))[1]
    try:
        m.tun_probe("core44", "192.168.44.2/24", "core", tries=3)
    finally:
        socket.socket = real
    want(len(seen) == 3, f"a negative verdict must survive a retry, saw {len(seen)} attempt(s)")

    # --- no second signal may re-enter the verdict -------------------------------------------------
    src = NODE.read_text(encoding="utf-8")
    body = src[src.index("def health_of("):src.index("def _cpu_snap(")]
    for gone in ("rx_live", "beat", "nohb", "loss_pct", "round_trip", "live_src", "carrier_rtt_ms"):
        want(gone not in body,
             f"`{gone}` is back inside health_of -- the verdict is the tun probe and nothing else")
    want("tun_probe(" in body, "health_of must reach its verdict THROUGH the probe")
    for shown in ("rx_still", "tx_still"):
        want(shown in body, f"`{shown}` must still be REPORTED -- it is the card's throughput, just not a vote")

    if fails:
        for f in fails:
            print("  FAIL " + f)
        return 1
    print("  ok  the tunnel verdict comes from the tun probe and from nothing else")
    return 0


if __name__ == "__main__":
    sys.exit(main())
