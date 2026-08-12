"""Guard: the node's ping does not SLEEP, so the number the panel shows is a latency and not our own delay.

`op_ping` reports node stats, and the panel times that whole RPC and stores it as `rtt_ms` -- its own comment
calls it "true node ping". Inside, `read_stats()` asked `_cpu_pct()` for CPU utilisation, and `_cpu_pct()
slept 100 ms between two /proc/stat snapshots to get a window. So every node ping the operator ever saw was
~100 ms too high, on every node, permanently -- and nothing about the display hinted that the panel was
timing its own sleep.

The fix REMEMBERS the previous snapshot instead, which is also a better measurement: the window becomes the
real poll interval (seconds) rather than a 100 ms sliver, so a momentary spike no longer reads as sustained
load. Only the very first call of a process pays a window, so the number is real from the first ping.

Driven through read_stats() and op_ping() -- the path the panel actually times -- not _cpu_pct() alone: a
guard that calls the helper says nothing about whether the caller still sleeps.

/proc/stat is Linux-only, so the snapshot is stubbed with a deterministic fake here; the real-kernel numbers
were measured separately on a Linux box (op_ping went from ~100 ms to ~6 ms).

Exit 1 on any failure.
"""
import importlib.util
import io
import os
import sys
import threading
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
out = io.open(1, "w", encoding="utf-8", closefd=False)
bad = []


def chk(label, got, want):
    if got != want:
        bad.append(label)
        out.write("  FAIL %-58s %r != %r\n" % (label, got, want))
    else:
        out.write("  ok   %-58s %r\n" % (label, got))


spec = importlib.util.spec_from_file_location("tnl_node", os.path.join(ROOT, "tnl-node.py"))
N = importlib.util.module_from_spec(spec)
spec.loader.exec_module(N)

# A deterministic /proc/stat: 100 jiffies of total per real second, 60% of them idle -> 40% busy.
T0 = time.perf_counter()


def fake_snap():
    el = time.perf_counter() - T0
    tot = int(el * 100)
    return tot, int(tot * 0.6)


N._cpu_snap = fake_snap

# PLATFORM stubs only -- these read Linux-only interfaces (os.uname, /sys, /proc/net) and have nothing to do
# with what is being measured. Timing is left entirely alone: if any of them slept, this guard would say so.
if not hasattr(os, "uname"):
    N._core_arch = lambda: "amd64"
    N._core_ref = lambda: "2.66.0"
    N._installed_core_sha = lambda: "0" * 64
    N.all_ips = lambda: ["203.0.113.9"]
    N.public_configs = lambda: []

# ---- the first call may pay ONE window; every later call must be free
first = time.perf_counter()
N._cpu_pct()
first_ms = (time.perf_counter() - first) * 1000
time.sleep(0.4)
worst = 0.0
for _ in range(6):
    t = time.perf_counter()
    N._cpu_pct()
    worst = max(worst, (time.perf_counter() - t) * 1000)
chk("the first call pays at most one short window", first_ms < 250, True)
chk("every later _cpu_pct is free (<5ms)", worst < 5, True)

# ---- the path the panel actually times
time.sleep(0.3)
worst_stats = 0.0
for _ in range(4):
    t = time.perf_counter()
    st = N.read_stats()
    worst_stats = max(worst_stats, (time.perf_counter() - t) * 1000)
    time.sleep(0.1)
chk("read_stats never sleeps (<10ms)", worst_stats < 10, True)
chk("and it still reports a cpu number", isinstance(st.get("cpu_pct"), (int, float)), True)

worst_ping = 0.0
for _ in range(3):
    t = time.perf_counter()
    p = N.op_ping({})
    worst_ping = max(worst_ping, (time.perf_counter() - t) * 1000)
    time.sleep(0.1)
chk("op_ping -- what the panel stores as rtt_ms -- never sleeps (<25ms)", worst_ping < 25, True)
chk("op_ping still carries the fields the panel reads",
    all(k in p for k in ("ok", "agent", "version", "sha256", "arch", "core_sha", "stats")), True)

# ---- the value must still be right, and the source must be a REMEMBERED snapshot
time.sleep(0.4)
v = N._cpu_pct()
chk("60%% idle still reports ~40%% busy", 35 <= v <= 45, True)
chk("it keeps a previous snapshot rather than sleeping for a window", N._cpu_prev is not None, True)

# ---- back-to-back callers must not divide by a zero window, and must not serialise on a sleep
res = []
lock = threading.Lock()


def hammer():
    for _ in range(60):
        x = N._cpu_pct()
        with lock:
            res.append(x)


ts = [threading.Thread(target=hammer) for _ in range(8)]
t = time.perf_counter()
for x in ts:
    x.start()
for x in ts:
    x.join()
el = (time.perf_counter() - t) * 1000
chk("480 concurrent calls all return a sane percentage",
    all(isinstance(x, (int, float)) and 0 <= x <= 100 for x in res), True)
chk("...and they do not serialise on a sleep (<500ms total)", el < 500, True)

out.write("\n%s\n" % ("FAILURES: %s" % bad if bad else
                      "the node's ping reports a latency, not the node's own sleep"))
out.flush()
sys.exit(1 if bad else 0)
