#!/usr/bin/env python3
"""Guard: a tunnel that keeps losing its session must say so in a number, not just a dot.

`up`/`alive` answer one question — is it carrying right now — and a tunnel whose carrier is being cut
every ten seconds answers YES to that every time it is asked, because it has just reconnected. The core
already records each loss in its status file; nothing read them, so a link that dropped 24 times in five
minutes was indistinguishable from one that had never dropped at all.

`drops` is that count, over DROP_WINDOW seconds. Rotations are excluded: a source or destination rotation
is a `down` the session SURVIVES, so counting it would report churn on a healthy pool.

The tests drive the REAL health_of() against a REAL status file on disk, so the file parsing, the
window and the rotation exclusion are all shipping code.

Run with no arguments. Exit 0 = the count is real.
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


def ev(seq, kind, code, ago):
    return {"seq": seq, "ts": int(time.time() - ago), "kind": kind, "code": code, "detail": "x"}


def health_with(mod, events, tmp):
    """Drive the real health_of() for a core tunnel whose status file holds `events`."""
    name = "drp0"
    with open(os.path.join(tmp, name + ".status"), "w", encoding="utf-8") as f:
        json.dump({"hb": int(time.time()), "dw": 20, "active": "tcp", "events": events}, f)
    return mod.health_of({"type": "core", "name": name, "tunnel_ip": ""})


def main():
    mod = load()
    tmp = tempfile.mkdtemp()

    # The interface must look present, and the status file must be found where the node looks for it.
    mod.os.path.exists = lambda p: True if p.startswith("/sys/class/net/") else os.path.exists(p)
    mod._cfg_path = lambda name, ext: os.path.join(tmp, name + ext)
    mod._flow_alive = lambda name: None

    if not hasattr(mod, "DROP_WINDOW"):
        fail("DROP_WINDOW is gone — THIS GUARD is out of date")
        return 1
    win = mod.DROP_WINDOW

    h = health_with(mod, [], tmp)
    if h.get("drops") != 0:
        fail("a tunnel with no events reported drops=%r, want 0" % h.get("drops"))
    if h.get("drop_win") != int(win):
        fail("drop_win=%r, want %d — the panel labels the number with it" % (h.get("drop_win"), int(win)))

    # Six real losses inside the window, each with its reconnect. THIS is the case the dot cannot show:
    # the heartbeat is fresh, so the side reads connected, and the six drops are the whole story.
    flap = []
    for i in range(6):
        flap.append(ev(2 * i + 1, "down", "eof", win / 2 - i * 10))
        flap.append(ev(2 * i + 2, "up", "reconnect", win / 2 - i * 10 - 1))
    h = health_with(mod, flap, tmp)
    if h.get("drops") != 6:
        fail("six losses inside the window counted as %r — a link reconnecting every few seconds must "
             "not look identical to one that never dropped" % h.get("drops"))
    if h.get("alive") is not True:
        fail("the fresh heartbeat must still read alive (%r) — drops is a SEPARATE fact, not a verdict"
             % h.get("alive"))

    # Older than the window: gone.
    h = health_with(mod, [ev(1, "down", "eof", win + 60), ev(2, "up", "reconnect", win + 59)], tmp)
    if h.get("drops") != 0:
        fail("a loss %ds ago counted as %r — the window must forget it" % (win + 60, h.get("drops")))

    # A rotation is a `down` the session SURVIVES. Counting it would report churn on a healthy pool.
    rot = [ev(1, "down", "peer-rotate", 10), ev(2, "up", "reconnect", 9),
           ev(3, "down", "src-rotate", 8), ev(4, "up", "reconnect", 7)]
    h = health_with(mod, rot, tmp)
    if h.get("drops") != 0:
        fail("pool rotations counted as %r drops — they are seamless by design" % h.get("drops"))

    # Mixed: only the real loss counts.
    h = health_with(mod, rot + [ev(5, "down", "stale", 5), ev(6, "up", "reconnect", 4)], tmp)
    if h.get("drops") != 1:
        fail("one real loss beside two rotations counted as %r, want 1" % h.get("drops"))

    if fails:
        print("\n%d check(s) failed." % len(fails))
        return 1
    print("ok — session drops are counted, windowed, and rotations are not mistaken for them")
    return 0


if __name__ == "__main__":
    sys.exit(main())
