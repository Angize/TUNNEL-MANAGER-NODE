#!/usr/bin/env python3
# Tests for the request-handler robustness/security hardening (no root, no live socket):
#   - IFACE_RE rejects a leading '-' (arg-injection guard)
#   - _authed() is fail-closed and constant-time on a non-ASCII token (no TypeError → no conn reset)
#   - _body() cap is endpoint-aware (1MB default, 20MB for engine-install)
#   - a bounded connection semaphore sheds load with 503 instead of spawning unbounded root threads
# Run: python3 test_hardening.py
import importlib.util
import io
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
spec = importlib.util.spec_from_file_location("tnlnode", os.path.join(HERE, "tnl-node.py"))
tnl = importlib.util.module_from_spec(spec)
spec.loader.exec_module(tnl)

FAILS = []


def check(name, cond):
    print(("ok  " if cond else "FAIL") + "  " + name)
    if not cond:
        FAILS.append(name)


class Hdr(dict):
    def get(self, k, default=None):
        return dict.get(self, k, default)


def new_handler():
    return tnl.Handler.__new__(tnl.Handler)


# ---- #3 IFACE_RE: no leading dash, but legitimate names still match ----------
check("iface: leading '-' rejected (arg-injection)", not tnl.IFACE_RE.match("-X"))
check("iface: leading '--' rejected", not tnl.IFACE_RE.match("--net"))
check("iface: tnl-* still valid", bool(tnl.IFACE_RE.match("tnl-eng-5")))
check("iface: dotted vlan still valid", bool(tnl.IFACE_RE.match("eth0.100")))
check("iface: '@' name still valid", bool(tnl.IFACE_RE.match("wg0@if1")))
check("iface: underscore-leading still valid", bool(tnl.IFACE_RE.match("_x")))
check("iface: dash in the middle still valid", bool(tnl.IFACE_RE.match("a-b-c")))

# ---- #6 _authed: non-ASCII token must not raise; fail-closed ------------------
h = new_handler()
h.server = type("S", (), {"conf": {"token": "secret"}})()
h.headers = Hdr({"X-Node-Token": "sécret"})   # non-ASCII header value
try:
    r = h._authed()
    check("_authed: non-ASCII token returns False (no TypeError)", r is False)
except Exception as e:
    check("_authed: non-ASCII token returns False (no TypeError) [raised %r]" % e, False)

# matching non-ASCII token compares equal on bytes (constant-time, no crash)
h.server = type("S", (), {"conf": {"token": "sécret"}})()
h.headers = Hdr({"X-Node-Token": "sécret"})
check("_authed: matching non-ASCII token authenticates", h._authed() is True)

# empty token / empty want are fail-closed
h.server = type("S", (), {"conf": {"token": ""}})()
h.headers = Hdr({"X-Node-Token": "anything"})
check("_authed: empty configured token -> False", h._authed() is False)
h.server = type("S", (), {"conf": {"token": "secret"}})()
h.headers = Hdr({})
check("_authed: missing token header -> False", h._authed() is False)

# happy path still works
h.headers = Hdr({"X-Node-Token": "secret"})
check("_authed: correct ASCII token authenticates", h._authed() is True)

# ---- #8 _body cap is a parameter and truncates past it ------------------------
payload = b'{"data":"' + b'x' * 4000 + b'"}'
h = new_handler()
h.headers = Hdr({"Content-Length": str(len(payload))})
h.rfile = io.BytesIO(payload)
big = h._body(cap=20971520)
check("_body: large cap reads the full JSON", isinstance(big, dict) and len(big.get("data", "")) == 4000)

h.rfile = io.BytesIO(payload)
small = h._body(cap=100)   # truncates -> JSON parse fails -> {}
check("_body: tiny cap truncates -> empty dict", small == {})

h.rfile = io.BytesIO(payload)
default = h._body()
check("_body: default cap is 1MB and still parses this body", isinstance(default, dict) and default.get("data"))

# ---- #8 endpoint-aware cap selection in _handle_locked ------------------------
def drive(path, cmd_stub_name):
    captured = []
    hh = new_handler()
    hh.path = path
    hh.server = type("S", (), {"conf": {"token": "t"}})()
    hh.headers = Hdr({"X-Node-Token": "t"})
    hh.client_address = ("127.0.0.1", 1)
    hh._body = lambda cap=1048576: (captured.append(cap), {})[1]
    hh._send = lambda code, body: None
    orig = tnl.OPS[cmd_stub_name]
    tnl.OPS[cmd_stub_name] = lambda d: {"ok": True}
    try:
        hh._handle_locked("POST")
    finally:
        tnl.OPS[cmd_stub_name] = orig
    return captured


cap = drive("/api/engine-install", "engine-install")
check("engine-install gets the 20MB body cap", cap == [20971520])
cap = drive("/api/ping", "ping")   # read-only op, ordinary cap
check("ordinary op gets the 1MB body cap", cap == [1048576])

# ---- N1 bounded connection semaphore sheds load with 503 ----------------------
check("Handler.timeout is set (slow-read guard)", getattr(tnl.Handler, "timeout", None) == 30)

held = []
for _ in range(tnl.MAX_CONNS):
    held.append(tnl._conn_sem.acquire(blocking=False))
check("all %d permits acquirable" % tnl.MAX_CONNS, all(held))

sent = []
h = new_handler()
h._send = lambda code, body: sent.append((code, body))
h._handle("POST")   # no free permit -> must shed load, never touch _handle_locked
check("over-cap request returns 503", sent and sent[0][0] == 503)

for _ in held:
    tnl._conn_sem.release()
# semaphore fully released again -> permits available for real traffic
after = tnl._conn_sem.acquire(blocking=False)
check("permit freed after handler releases", after is True)
if after:
    tnl._conn_sem.release()

print()
if FAILS:
    print("%d FAILED: %s" % (len(FAILS), ", ".join(FAILS)))
    sys.exit(1)
print("all hardening tests passed")
