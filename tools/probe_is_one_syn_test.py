"""Guard: one probe sample is one SYN, so the reported ping is a ping.

`connect()` does not expose retransmits. If the deadline reaches past the kernel's initial SYN
retransmit timer, one sample quietly becomes two SYNs and BOTH published numbers are wrong at once:

  * the reply to the SECOND SYN is counted as a hit, so loss under-reports -- the first SYN was lost
    and nothing records it;
  * that reply's "latency" is the kernel's own 1 s timer plus the path, so the card showed a ping of
    ~1100 ms for a tunnel whose real round trip is 80 ms.

Both disappear if the deadline stays under the retransmit timer: a sample either gets an answer to its
one SYN, or it ends. What this file defends is that the deadline never grows back.

Exit 1 on any failure.
"""
import sys
sys.dont_write_bytecode = True
import errno
import importlib.util
import os
import select
import socket
from pathlib import Path

NODE = Path(__file__).resolve().parent.parent / "tnl-node.py"


def load():
    spec = importlib.util.spec_from_file_location("tnl_node_probe", NODE)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


class Sock:
    """Non-blocking connect; whether the answer ever arrives is the patched select's decision."""
    def __init__(self, answers):
        self.answers = answers
    def setblocking(self, *_): pass
    def setsockopt(self, *_): pass
    def bind(self, _): pass
    def connect_ex(self, _): return errno.EINPROGRESS
    def getsockopt(self, *_): return 0
    def fileno(self): return -1
    def close(self): pass


def main():
    m = load()
    fails = []

    def want(cond, msg):
        print(("  ok  " if cond else " FAIL ") + msg)
        if not cond:
            fails.append(msg)

    # --- the invariant itself ----------------------------------------------------------------------
    want(m.PROBE_WAIT < m.SYN_RTO,
         f"PROBE_WAIT ({m.PROBE_WAIT}s) must stay under the kernel's initial SYN retransmit "
         f"({m.SYN_RTO}s); at or above it, one sample spans two SYNs")
    want(m.PROBE_WAIT > 0.3,
         f"PROBE_WAIT ({m.PROBE_WAIT}s) must still clear the fleet's real round trips (78-170 ms)")

    # --- an answer that never arrives inside the deadline is a LOST SYN ----------------------------
    # A reply to the retransmitted SYN lands after the deadline, which the kernel reports to us as
    # exactly this: the socket never became writable in time.
    def never(_r, _w, _x, _t):
        return ([], [], [])

    answering = {"ids": None}

    def some(_r, w, _x, _t):
        # the SAME two answer, and only those: picking two fresh ones per call would let every socket
        # answer eventually, which is the opposite of what a deadline means
        if answering["ids"] is None:
            answering["ids"] = {id(s) for s in list(w)[:2]}
        return ([], [s for s in w if id(s) in answering["ids"]], [])

    def probe(selector, count):
        real_sock, real_sel = socket.socket, select.select
        socket.socket = lambda *a, **k: Sock(True)
        select.select = selector
        try:
            return m.tun_probe("core44", "192.168.44.2/24", "core", count=count)
        finally:
            socket.socket, select.select = real_sock, real_sel

    hits, sent, rtt = probe(never, 5)
    want((hits, sent) == (0, 5), f"a reply arriving past the deadline is a lost SYN, got {hits}/{sent}")
    want(rtt is None, f"and it must contribute no latency at all, got {rtt}")

    hits, sent, rtt = probe(some, 5)
    want((hits, sent) == (2, 5), f"only the in-deadline answers count, got {hits}/{sent}")
    want(rtt is not None and rtt < m.PROBE_WAIT * 1000,
         f"the reported ping must be a real round trip, under the deadline; got {rtt} ms")

    # --- the same thing through health_of, which is the path that actually publishes ---------------
    # A test that calls the helper says nothing about the caller. health_of is what the sweep runs and
    # what the panel reads, so the assertion belongs there.
    real_exists, real_flow = os.path.exists, m._flow_sample
    real_sock, real_sel = socket.socket, select.select
    os.path.exists = lambda p: True if str(p).startswith("/sys/class/net/") else real_exists(p)
    m._flow_sample = lambda name: (0.0, 0.0)
    socket.socket = lambda *a, **k: Sock(True)
    select.select = never
    try:
        h = m.health_of({"type": "core", "name": "probe-guard", "tunnel_ip": "192.168.44.2/24"})
    finally:
        socket.socket, select.select = real_sock, real_sel
        os.path.exists, m._flow_sample = real_exists, real_flow

    want(h.get("rtt_ms") is None,
         f"health_of must publish no ping when every answer came too late to be one, got {h.get('rtt_ms')}")
    want(h.get("loss_pct") == 100.0,
         f"and it must report the loss those lost first SYNs are, got {h.get('loss_pct')}")
    want(h.get("alive") is False, f"and call the tunnel dead, got alive={h.get('alive')}")

    # --- the deadline must come from the constant, not a literal ----------------------------------
    src = NODE.read_text(encoding="utf-8")
    want("time.monotonic() + PROBE_WAIT" in src,
         "the wait must take its deadline from PROBE_WAIT, not a literal")

    print()
    if fails:
        print(f"{len(fails)} failure(s)")
        return 1
    print("the probe sends one SYN per sample; every published ping is a round trip")
    return 0


if __name__ == "__main__":
    sys.exit(main())
