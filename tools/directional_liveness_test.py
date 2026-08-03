"""Guard: the tunnel verdict comes from the tun probe and from nothing else.

The old ladder mixed a core heartbeat, byte counters and an ICMP probe, and every false GREEN we ever
shipped came from one of those being true while the tunnel carried nothing. There is one signal now, so
what this guard defends is that no second one grows back: bytes moving must not rescue a tunnel whose
handshake went unanswered, and silence must not condemn one whose handshake came back.
"""
import sys
sys.dont_write_bytecode = True
import errno
import importlib.util
import select
import socket
import time
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
        """A non-blocking connect: connect_ex reports pending and readiness is decided by the patched
        select below, which is where the kernel decides it too."""
        def __init__(self, outcome):
            self.outcome = outcome
        def setblocking(self, *_): pass
        def setsockopt(self, _lvl, opt, val):
            calls.setdefault("bound", []).append((opt, val))
        def bind(self, addr):
            calls["src"] = addr[0]
        def connect_ex(self, addr):
            calls["dst"] = addr
            return errno.EINPROGRESS
        def getsockopt(self, _lvl, _opt):
            return {"ok": 0, "refused": errno.ECONNREFUSED}.get(self.outcome, errno.ETIMEDOUT)
        def fileno(self): return -1
        def close(self): pass

    def ready_unless_timeout(_r, w, _x, _t):
        return ([], [s for s in w if getattr(s, "outcome", "") != "timeout"], [])

    def with_outcome(outcome, count=None, selector=ready_unless_timeout):
        calls.clear()
        real_sock, real_sel = socket.socket, select.select
        socket.socket = lambda *a, **k: FakeSock(outcome)
        select.select = selector
        try:
            return m.tun_probe("core44", "192.168.44.2/24", "core", count=count or m.PROBE_COUNT)
        finally:
            socket.socket, select.select = real_sock, real_sel

    hits, sent, rtt = with_outcome("ok")
    want((hits, sent) == (m.PROBE_COUNT, m.PROBE_COUNT), f"every sample answered, got {hits}/{sent}")
    want(rtt is not None, "and it must carry the round trip it measured")
    want(calls.get("dst") == ("192.168.44.1", m.PROBE_PORT),
         f"the probe must target the PEER tunnel address, got {calls.get('dst')}")
    want(calls.get("src") == "192.168.44.2",
         f"and leave from our own tunnel address, got {calls.get('src')}")
    want(any(o == m._SO_BINDTODEVICE and v.startswith(b"core44") for o, v in calls.get("bound", [])),
         "and be pinned to the tunnel DEVICE: routing alone is not a measurement, a probe free to "
         "leave by another path can call a tunnel alive that carries nothing")

    hits, sent, _ = with_outcome("refused")
    want(hits == sent == m.PROBE_COUNT,
         "a RST must count as alive: the far KERNEL put a packet on the wire, which is the whole "
         "question. Requiring a listener would turn every agent restart into a red healthy tunnel")

    hits, sent, rtt = with_outcome("timeout")
    want((hits, sent) == (0, m.PROBE_COUNT), f"silence answers nothing, got {hits}/{sent}")
    want(rtt is None, "a dead probe reports no round trip")

    # THE regression this file exists for. The manual check reported a tunnel connected while the card
    # beside it drew red, because the probe stopped at its first success -- on a tunnel dropping two
    # thirds of its packets, "did anything get through" is yes and still useless. Every sample goes out.
    seq = ["timeout", "ok", "timeout"]
    calls.clear()
    real_sock, real_sel = socket.socket, select.select
    it = iter(seq)
    socket.socket = lambda *a, **k: FakeSock(next(it))
    select.select = ready_unless_timeout
    try:
        hits, sent, _ = m.tun_probe("core44", "192.168.44.2/24", "core", count=len(seq))
    finally:
        socket.socket, select.select = real_sock, real_sel
    want((hits, sent) == (1, 3),
         f"the probe must send every sample even after one answers, got {hits}/{sent} -- stopping "
         f"early is exactly what let the button claim a 67%-loss tunnel was connected")

    # the reported latency must be the FASTEST reply, not the last one to straggle in.
    stage = {"n": 0}

    def staged(_r, w, _x, _t):
        stage["n"] += 1
        if stage["n"] == 1:
            return ([], list(w)[:1], [])     # one answers immediately
        time.sleep(0.06)                     # the rest arrive much later
        return ([], list(w), [])

    _, _, rtt = with_outcome("ok", count=3, selector=staged)
    want(rtt is not None and rtt < 30,
         f"rtt must be the fastest reply, not the slowest or the mean, got {rtt}")

    # --- one sample count, so the button and the card cannot disagree ------------------------------
    src_all = NODE.read_text(encoding="utf-8")
    want("thorough" not in src_all,
         "a second sample count is back. That is the whole bug: the check sampled three times, the "
         "sweep twice, and the operator got two answers with no way to tell which one lied")

    # --- no second signal may re-enter the verdict -------------------------------------------------
    src = NODE.read_text(encoding="utf-8")
    body = src[src.index("def health_of("):src.index("def _cpu_snap(")]
    want('"loss_pct": loss' in body, "health_of must REPORT the loss it measured, not just a boolean")
    for gone in ("rx_live", "beat", "nohb", "round_trip", "live_src", "carrier_rtt_ms"):
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
