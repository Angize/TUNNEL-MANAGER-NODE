"""Guard: one probe attempt is one SYN, so the reported ping is a ping.

`connect()` does not expose retransmits. If the per-attempt deadline reaches past the kernel's initial
SYN retransmit timer, one attempt quietly becomes two SYNs and BOTH published numbers are wrong at once:

  * the reply to the SECOND SYN is counted as a hit, so loss_pct under-reports -- the first SYN was lost
    and nothing records it;
  * that reply's "latency" is the kernel's own 1 s timer plus the path, so the card shows a ping of
    ~1100 ms for a tunnel whose real round trip is 80 ms.

Both disappear if the deadline stays under the retransmit timer: an attempt then either gets an answer
to its one SYN, or it ends. What this file defends is that the deadline never grows back.

Exit 1 on any failure.
"""
import sys
sys.dont_write_bytecode = True
import importlib.util
import socket
import time
from pathlib import Path

NODE = Path(__file__).resolve().parent.parent / "tnl-node.py"


def load():
    spec = importlib.util.spec_from_file_location("tnl_node_probe", NODE)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


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
         f"({m.SYN_RTO}s); at or above it, one attempt spans two SYNs")
    want(m.PROBE_WAIT > 0.3,
         f"PROBE_WAIT ({m.PROBE_WAIT}s) must still clear the fleet's real round trips (78-170 ms)")

    # --- a socket that HONOURS the deadline, which is what the real one does ------------------------
    # The far side answering later than the deadline is indistinguishable from silence, and must be
    # counted as silence rather than rescued into a hit carrying the timer as its latency.
    class DeadlineSock:
        """Answers after `delay`, but raises timeout at the deadline like a real socket."""
        def __init__(self, delay):
            self.delay = delay
            self.deadline = None
        def settimeout(self, t):
            self.deadline = t
        def setsockopt(self, *_):
            pass
        def bind(self, _):
            pass
        def connect(self, _):
            if self.deadline is not None and self.delay > self.deadline:
                time.sleep(self.deadline)
                raise socket.timeout()
            time.sleep(self.delay)
            raise ConnectionRefusedError()
        def close(self):
            pass

    def probe_with(delays):
        real = socket.socket
        it = iter(delays)
        socket.socket = lambda *a, **k: DeadlineSock(next(it))
        try:
            return m.tun_probe("core44", "192.168.44.2/24", "core", tries=len(delays))
        finally:
            socket.socket = real

    late = m.PROBE_WAIT + 0.35            # what a reply to the RETRANSMITTED SYN would look like
    hits, sent, rtt = probe_with([late, late, late])
    want((hits, sent) == (0, 3),
         f"a reply that only arrives past the deadline is a LOST first SYN, not a hit -- got {hits}/{sent}")
    want(rtt is None, f"and it must contribute no latency at all, got {rtt}")

    hits, sent, rtt = probe_with([0.05, late, 0.05])
    want((hits, sent) == (2, 3), f"the two in-deadline replies count, the late one does not -- got {hits}/{sent}")
    want(rtt is not None and rtt < m.PROBE_WAIT * 1000,
         f"the reported ping must be a real round trip, under the deadline; got {rtt} ms")

    # --- the same thing through health_of, which is the path that actually publishes ---------------
    # A test that calls the helper says nothing about the caller. health_of is what the sweep runs and
    # what the panel reads, so the assertion belongs there.
    import os
    real_exists, real_flow = os.path.exists, m._flow_sample
    os.path.exists = lambda p: True if str(p).startswith("/sys/class/net/") else real_exists(p)
    m._flow_sample = lambda name: (0.0, 0.0)
    real_sock = socket.socket
    socket.socket = lambda *a, **k: DeadlineSock(late)
    try:
        h = m.health_of({"type": "core", "name": "core44", "tunnel_ip": "192.168.44.2/24"})
    finally:
        socket.socket = real_sock
        os.path.exists, m._flow_sample = real_exists, real_flow

    want(h.get("rtt_ms") is None,
         f"health_of must publish no ping when every answer came too late to be one, got {h.get('rtt_ms')}")
    want(h.get("loss_pct") == 100.0,
         f"and it must report the loss those lost first SYNs are, got {h.get('loss_pct')}")
    want(h.get("alive") is False, f"and call the tunnel dead, got alive={h.get('alive')}")

    # --- no other deadline in the file may reach the retransmit ------------------------------------
    src = NODE.read_text(encoding="utf-8")
    want("s.settimeout(PROBE_WAIT)" in src,
         "the probe socket must take its deadline from PROBE_WAIT, not a literal")

    print()
    if fails:
        print(f"{len(fails)} failure(s)")
        return 1
    print("the probe sends one SYN per attempt; every published ping is a round trip")
    return 0


if __name__ == "__main__":
    sys.exit(main())
