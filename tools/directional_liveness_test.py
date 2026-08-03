#!/usr/bin/env python3
"""Guard: liveness is reported PER DIRECTION, and `alive` never claims more than it can see.

A tunnel can be sending into a hole -- tx advancing, rx still -- and that is precisely the state a
single flag cannot express. It is also the state that reads "connected": the peer's replies keep the
core heartbeat fresh, so the one flag says yes while nothing this side sends ever lands.

Nothing measurable on THIS host can prove what we send arrives; only the far end knows. So the node's
job is to report the two directions honestly and let the panel pair them, and `alive` here means one
thing only -- the peer's traffic reaches us. These tests hold it to that:

  * tx moving alone must NEVER make a side alive;
  * rx and the heartbeat are two views of the same fact, so either one suffices;
  * a core-reported death outranks a probe that happened to answer.

The sampler runs against a REAL netdev counter directory, so the read, the two progress clocks and the
counter-went-backwards reset are all shipping code.

Run with no arguments. Exit 0 = each direction is reported for itself.
"""

import importlib.util
import json
import os
import sys
import tempfile
import time

# Failure messages quote Persian, and this runs on a cp1252 console — without this the guard raises
# UnicodeEncodeError while PRINTING the failure it correctly found.
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

# The guard flips the source between runs, and a .pyc that survives one of those flips is loaded in
# place of the file under test — a revert then still "passes". Never write bytecode for it.
sys.dont_write_bytecode = True

HERE = os.path.dirname(os.path.abspath(__file__))
NODE = os.path.join(os.path.dirname(HERE), "tnl-node.py")

fails = []


def fail(msg):
    fails.append(msg)
    print("FAIL: " + msg)


def load():
    spec = importlib.util.spec_from_file_location("tnl_node_under_test", NODE)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def main():
    mod = load()
    tmp = tempfile.mkdtemp()
    stats = os.path.join(tmp, "ifc", "statistics")
    os.makedirs(stats)

    def setctr(rx, tx):
        for k, v in (("rx", rx), ("tx", tx)):
            with open(os.path.join(stats, k + "_bytes"), "w") as f:
                f.write(str(v))

    # Point the sampler at the fake netdev; everything inside it stays shipping code.
    real_open = mod.open if hasattr(mod, "open") else open
    mod._iface_ctr = (lambda name, which, _s=stats:
                      int(real_open(os.path.join(_s, which + "_bytes")).read().strip()))

    # ---- 1) the sampler reports the two directions separately ----
    setctr(1000, 2000)
    mod._flow_sample("ifc")                       # first sample: baseline only
    setctr(1000, 9000)                            # we sent; nothing came back
    rx, tx = mod._flow_sample("ifc")
    if tx is not True:
        fail("tx advanced and tx_live=%r — the sending direction must be reported" % tx)
    if rx is True:
        fail("rx did NOT advance and rx_live=%r — a still direction must not read live" % rx)

    setctr(7000, 9000)                            # now traffic comes back
    rx, tx = mod._flow_sample("ifc")
    if rx is not True:
        fail("rx advanced and rx_live=%r" % rx)

    setctr(5, 5)                                  # counters went backwards: iface recreated
    rx, tx = mod._flow_sample("ifc")
    if rx is not None or tx is not None:
        fail("a recreated iface must reset both directions to unknown, got rx=%r tx=%r" % (rx, tx))

    # ---- 2) alive is DOWNSTREAM only ----
    mod.os.path.exists = lambda p: True if p.startswith("/sys/class/net/") else os.path.exists(p)
    mod._cfg_path = lambda name, ext: os.path.join(tmp, name + ext)

    def health(rx_live, tx_live, hb_age=None, ping_ok=None, events=None, rt_age=None, rtms=0, role=""):
        mod._flow_sample = lambda name: (rx_live, tx_live)
        if hb_age is None:
            try:
                os.remove(os.path.join(tmp, "t0.status"))
            except OSError:
                pass
        else:
            doc = {"hb": int(time.time() - hb_age), "dw": 20, "events": events or []}
            if role:
                doc["role"] = role
            if rt_age is not None:
                doc["rt"], doc["rtt_ms"] = int(time.time() - rt_age), rtms
            with open(os.path.join(tmp, "t0.status"), "w", encoding="utf-8") as f:
                json.dump(doc, f)
        if ping_ok is None:
            mod.run = lambda *a, **k: (1, "", "")          # probe cannot run
        elif ping_ok:
            mod.run = lambda *a, **k: (0, "0% packet loss\nrtt min/avg/max/mdev = 1/2/3/4 ms", "")
        else:
            mod.run = lambda *a, **k: (1, "100% packet loss", "")
        return mod.health_of({"type": "core", "name": "t0", "tunnel_ip": "10.9.9.2/24"}, thorough=True)

    h = health(rx_live=None, tx_live=True, ping_ok=False)
    if h.get("alive") is True:
        fail("tx moving with nothing arriving reported alive=True — sending into a hole is not a "
             "connection, and nothing on THIS host can prove what we send lands")
    if h.get("tx_live") is not True:
        fail("tx_live must still be REPORTED even when it proves nothing (got %r)" % h.get("tx_live"))

    h = health(rx_live=True, tx_live=None, ping_ok=False)
    if h.get("alive") is not True:
        fail("arriving traffic must make a side alive even when the probe fails (got %r)" % h.get("alive"))
    if h.get("live_src") != "rx":
        fail("live_src=%r, want 'rx' — the panel names the reason" % h.get("live_src"))

    h = health(rx_live=None, tx_live=None, hb_age=2, ping_ok=False)
    if h.get("alive") is not True:
        fail("a fresh heartbeat is the same fact as rx and must also count (got %r)" % h.get("alive"))

    # A core-reported death: a `down` with no `up` after it. No probe may outvote it.
    dead_ev = [{"seq": 1, "ts": int(time.time()), "kind": "down", "code": "eof", "detail": ""}]
    h = health(rx_live=True, tx_live=True, hb_age=2, ping_ok=True, events=dead_ev)
    if not h.get("dead") or h.get("alive") is not False:
        fail("the core reported a real death and the side read alive=%r dead=%r — a positive death "
             "signal must outrank every other input" % (h.get("alive"), h.get("dead")))

    # ---- the answered keepalive: the one local fact covering BOTH directions ----
    h = health(rx_live=None, tx_live=True, hb_age=2, ping_ok=False, rt_age=3, rtms=42)
    if h.get("round_trip") is not True:
        fail("a keepalive answered 3s ago inside a 20s window reported round_trip=%r" % h.get("round_trip"))
    if h.get("carrier_rtt_ms") != 42:
        fail("carrier_rtt_ms=%r, want the core's own 42 — this is the RTT through obfs and crypto, not "
             "the ICMP one" % h.get("carrier_rtt_ms"))

    h = health(rx_live=None, tx_live=True, hb_age=2, ping_ok=False, rt_age=600, rtms=42)
    if h.get("round_trip") is not None:
        fail("a round trip 600s old reported %r — it must go to None and NEVER to False: the TCP family "
             "skips the ping when data just arrived, so stale means no news, not broken"
             % h.get("round_trip"))

    h = health(rx_live=None, tx_live=True, hb_age=2, ping_ok=False)
    if h.get("round_trip") is not None:
        fail("no rt published at all reported round_trip=%r, want None (dns publishes none)"
             % h.get("round_trip"))

    # ---- a SERVER waiting for its first client is not dead ----
    # It does not dial, so hb==0 means "nobody has arrived yet", not "I failed". Calling that dead would
    # paint every freshly-built server red until someone connects.
    import types
    mod._nohb_state.clear()
    h = health(rx_live=None, tx_live=None, hb_age=0, ping_ok=False, role="server")
    with open(os.path.join(tmp, "t0.status"), "w", encoding="utf-8") as f:
        json.dump({"hb": 0, "dw": 20, "events": [], "role": "server"}, f)
    mod._nohb_state.clear()
    mod._nohb_state["t0"] = 0.0        # pretend the grace period elapsed long ago
    h = mod.health_of({"type": "core", "name": "t0", "tunnel_ip": "10.9.9.2/24"}, thorough=True)
    if h.get("dead"):
        fail("a server that has never been reached was reported dead — it does not dial, so there is "
             "nothing for it to be failing at")

    with open(os.path.join(tmp, "t0.status"), "w", encoding="utf-8") as f:
        json.dump({"hb": 0, "dw": 20, "events": [], "role": "client"}, f)
    mod._nohb_state.clear(); mod._nohb_state["t0"] = 0.0
    h = mod.health_of({"type": "core", "name": "t0", "tunnel_ip": "10.9.9.2/24"}, thorough=True)
    if not h.get("dead"):
        fail("a CLIENT that published a dead-window and was never answered must still read dead")

    if fails:
        print("\n%d check(s) failed." % len(fails))
        return 1
    print("ok — directions reported separately, alive claims downstream only, "
          "and an answered keepalive passes through as positive-only")
    return 0


if __name__ == "__main__":
    sys.exit(main())
