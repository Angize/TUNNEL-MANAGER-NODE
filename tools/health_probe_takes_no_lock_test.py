#!/usr/bin/env python3
"""Guard: a health probe never waits on the mutation lock.

`_apply_lock` serializes state mutations and a core build holds it for 8-16 s. The sweep is not a
mutation -- it asks the kernel whether a netdev exists and then probes -- so it must not queue behind
one. One tunnel being rebuilt must never stop the probe of every OTHER tunnel on the node: a probe that
does not run delivers no verdict, and a core with no verdict climbs no ladder.

Driven through health_refresh_once with a real thread pool, not through health_of alone: what must not
stall is the SWEEP, and a rule proven on the helper says nothing about the path that calls it.

Exit 1 on any failure.
"""
import sys
sys.dont_write_bytecode = True
import importlib.util
import os
import tempfile
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

HOLD = 6.0          # how long the fake rebuild owns the lock
BUDGET = 2.0        # the sweep must finish well inside that, and far inside HEALTH_DEADLINE

fails = []


def check(ok, msg):
    print(("  ok   " if ok else " FAIL ") + msg)
    if not ok:
        fails.append(msg)


def load():
    src = Path(__file__).resolve().parent.parent / "tnl-node.py"
    spec = importlib.util.spec_from_file_location("tnl_node_lock", src)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def main():
    P = load()
    tmp = tempfile.mkdtemp()
    P.CONFIG_DIR = tmp
    P.LOG = os.path.join(tmp, "agent.log")

    # Two tunnels whose netdev does not exist: health_of answers False without probing, so the ONLY
    # thing that can make this sweep slow is waiting on the lock.
    names = ["lockprobe-a", "lockprobe-b"]
    P.raw_configs = lambda: [{"type": "core", "name": n} for n in names]
    for n in names:
        if os.path.exists("/sys/class/net/" + n):
            print("refusing to run: a real netdev named %s exists" % n)
            return 2

    held, release = threading.Event(), threading.Event()

    def rebuild():
        with P._apply_lock:
            held.set()
            release.wait(HOLD)

    t = threading.Thread(target=rebuild, daemon=True)
    t.start()
    check(held.wait(3), "the stand-in rebuild took _apply_lock")

    ex = ThreadPoolExecutor(max_workers=4)
    t0 = time.monotonic()
    P.health_refresh_once(ex)
    dt = time.monotonic() - t0

    check(dt < BUDGET,
          "the sweep finished in %.2fs while a rebuild held _apply_lock (budget %.1fs, HEALTH_DEADLINE "
          "is %ss) -- a probe that waits on that lock cannot come in under this" % (dt, BUDGET, P.HEALTH_DEADLINE))

    for n in names:
        got = P._health_cache.get(n)
        check(got is not None and got.get("up") is False,
              "%s published a REAL answer (up=False), not the {'up': None} 'unknown' a timed-out sweep "
              "leaves behind: %r" % (n, got))

    check(P._apply_lock.locked(), "the rebuild still held the lock throughout -- the sweep did not wait it out")

    release.set()
    t.join(HOLD + 2)
    ex.shutdown(wait=True)

    print("")
    if fails:
        print("%d failure(s)" % len(fails))
        return 1
    print("a rebuild no longer silences the judge: the sweep ran in %.2fs with the lock held." % dt)
    return 0


if __name__ == "__main__":
    sys.exit(main())
