#!/usr/bin/env python3
"""Guards for the agent-side fixes of the 2026-08-21 rotation audit.

Every check drives the real function and reads what it produced. Run with no arguments; exit 1 on the
first failure, and say which fix regressed.
"""
import importlib.util
import json
import os
import socket as realsocket
import sys
import tempfile
import threading

HERE = os.path.dirname(os.path.abspath(__file__))
AGENT = os.path.join(os.path.dirname(HERE), "tnl-node.py")

spec = importlib.util.spec_from_file_location("tnlnode", AGENT)
m = importlib.util.module_from_spec(spec)
sys.modules["tnlnode"] = m
spec.loader.exec_module(m)

fails = []


def check(name, cond, detail=""):
    if cond:
        print("  ok   %s" % name)
        return
    fails.append(name)
    print("  FAIL %s%s" % (name, ("\n       " + detail) if detail else ""))


# ---------------------------------------------------------------- the operator's mailbox is a queue
def mailbox_keeps_every_command():
    m.CONFIG_DIR = tempfile.mkdtemp()
    m._is_ws_pool = lambda name: True
    m._is_peer_pool = lambda name: True
    box = m._cfg_path("t1", ".status.select")

    said = [m.op_pool_select({"name": "t1", "kind": "ip", "key": "1.1.1.1"}),
            m.op_retest_now({"name": "t1", "kind": "ip", "key": "2.2.2.2"}),
            m.op_retest_now({"name": "t1", "kind": "sni", "key": "front-c"})]
    check("every click is reported as accepted", all(r.get("ok") for r in said), repr(said))

    with open(box) as f:
        got = [json.loads(line) for line in f if line.strip()]
    keys = [c["key"] for c in got]
    check("...and every accepted click is in the mailbox",
          keys == ["1.1.1.1", "2.2.2.2", "front-c"],
          "the core will see %r" % (keys,))
    check("in the order they were clicked",
          [c.get("cmd", "") for c in got] == ["", "retest", "retest"], repr(got))


def mailbox_refuses_when_it_cannot_drain():
    m.CONFIG_DIR = tempfile.mkdtemp()
    m._is_ws_pool = lambda name: True
    box = m._cfg_path("t2", ".status.select")
    with open(box, "w") as f:
        f.write("x" * (m.CMDBOX_MAX + 1))
    r = m.op_pool_select({"name": "t2", "kind": "ip", "key": "1.1.1.1"})
    check("a core that never drains its mailbox is reported, not fed for ever",
          r.get("ok") is False, repr(r))


# ------------------------------------------------------------------- one scratch file per write
def atomic_write_survives_concurrent_writers():
    d = tempfile.mkdtemp()
    path = os.path.join(d, "core-t1.status.verdict")
    errs, corrupt = [], []
    lock = threading.Lock()

    def writer(tag):
        body = {"cmd": "fail", "low": tag, "pad": tag * 400}
        for _ in range(400):
            err = m._atomic_write_json(path, body)
            if err:
                with lock:
                    errs.append(err)
            try:
                with open(path) as f:
                    obj = json.load(f)
                if obj["low"] * 400 != obj["pad"]:
                    with lock:
                        corrupt.append(obj["low"])
            except (ValueError, OSError) as e:
                with lock:
                    corrupt.append(repr(e))

    ts = [threading.Thread(target=writer, args=(t,)) for t in ("A", "B", "C")]
    for t in ts:
        t.start()
    for t in ts:
        t.join()
    check("three writers, no failed write", not errs, "%d errors, first: %s" % (len(errs), errs[:1]))
    check("three writers, never a torn or mixed file",
          not corrupt, "%d bad reads, first: %s" % (len(corrupt), corrupt[:1]))


# ------------------------------------------------------------------------- the workers knob for udp
def workers_reaches_the_core_for_udp():
    import ast
    tree = ast.parse(open(AGENT, encoding="utf-8").read())
    fn = next(n for n in ast.walk(tree)
              if isinstance(n, ast.FunctionDef) and n.name == "op_tunnel")

    guards = []

    def walk(node, stack):
        for child in ast.iter_child_nodes(node):
            s = stack + [ast.unparse(node.test)] if isinstance(node, ast.If) and child in node.body else stack
            if isinstance(child, ast.Subscript) and isinstance(child.ctx, ast.Store) \
               and ast.unparse(child.slice).strip("'\"") == "workers":
                guards.append(" AND ".join(s))
            walk(child, s)

    walk(fn, [])
    check("op_tunnel can store workers for every queueing transport",
          len(guards) == 1 and "transport in QUEUEING_TRANSPORTS" in guards[0],
          "reachable only under: %s" % (guards,))

    for tr in m.QUEUEING_TRANSPORTS:
        cfg = {"name": "t1", "transport": tr, "mode": "packet", "role": "client",
               "remote_ip": "203.0.113.9", "port": 5555, "tunnel_ip": "10.9.0.2",
               "psk": "x" * 32, "cipher": "aes-256-gcm", "crypto": True, "workers": 4}
        if tr == "raw":
            cfg["raw_profile"] = "udp"
        out = m._core_config(cfg)
        if isinstance(out, (str, bytes)):
            out = json.loads(out)
        check("...and _core_config emits it for %s" % tr, out.get("workers") == 4, repr(out.get("workers")))


# ------------------------------------------------------------------------ the probe's sample floor
class FakeSock:
    def __init__(self, answer):
        self.answer = answer

    def setblocking(self, v):
        pass

    def setsockopt(self, *a):
        pass

    def bind(self, a):
        pass

    def connect_ex(self, a):
        return self.answer

    def close(self):
        pass

    def fileno(self):
        return -1


def a_truncated_sample_set_is_no_verdict():
    answered = sorted(m._ANSWERED)[0]

    def run(fail_after):
        made = [0]

        def fake_socket(fam, typ):
            made[0] += 1
            if made[0] > fail_after:
                raise OSError(24, "Too many open files")
            return FakeSock(answered)

        orig = m.socket.socket
        m.socket.socket = fake_socket
        try:
            return m.tun_probe("tun0", "10.9.0.2/24", "core")
        finally:
            m.socket.socket = orig

    full = run(m.PROBE_COUNT)
    check("a whole sample set still reports itself", full == (m.PROBE_COUNT, m.PROBE_COUNT, full[2]), repr(full))
    for n in (1, 2, m.PROBE_COUNT // 2 - 1):
        hits, sent, _ = run(n)
        check("%d of %d sockets is not a verdict" % (n, m.PROBE_COUNT), sent == 0,
              "returned hits=%d sent=%d, and one lost SYN out of %d condemns the path" % (hits, sent, sent))
    hits, sent, _ = run(m.PROBE_COUNT // 2)
    check("half a set still is one", sent == m.PROBE_COUNT // 2, "sent=%d" % sent)


print("the operator's mailbox")
mailbox_keeps_every_command()
mailbox_refuses_when_it_cannot_drain()
print("atomic writes")
atomic_write_survives_concurrent_writers()
print("the workers knob")
workers_reaches_the_core_for_udp()
print("the tun probe's sample set")
a_truncated_sample_set_is_no_verdict()

print()
if fails:
    print("%d check(s) failed: %s" % (len(fails), ", ".join(fails)))
    sys.exit(1)
print("all checks passed")
