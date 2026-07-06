#!/usr/bin/env python3
# Tests for op_portcheck / _port_busy against real bound sockets. Run:
#   python3 test_portcheck.py
import importlib.util
import os
import socket
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


def free_port(kind):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM if kind == "tcp" else socket.SOCK_DGRAM)
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


# --- TCP listener is detected as busy -----------------------------------------
ts = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
ts.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
ts.bind(("127.0.0.1", 0))
ts.listen()
tport = ts.getsockname()[1]

busy, who = tnl._port_busy(tport, "tcp")
check("bound TCP port reported busy", busy is True)
# The same number on UDP must be free (separate socket space).
budp, _ = tnl._port_busy(tport, "udp")
check("same number on UDP is free (proto isolation)", budp is False)

# --- UDP socket is detected as busy -------------------------------------------
us = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
us.bind(("127.0.0.1", 0))
uport = us.getsockname()[1]
busy, who = tnl._port_busy(uport, "udp")
check("bound UDP port reported busy", busy is True)

# --- a definitely-free port ----------------------------------------------------
fp = free_port("tcp")
b, _ = tnl._port_busy(fp, "tcp")
check("unbound port reported free", b is False)

# --- op_portcheck wrapper + validation ----------------------------------------
r = tnl.op_portcheck({"port": tport, "proto": "tcp"})
check("op_portcheck returns busy=True for a used TCP port", r["busy"] is True and r["proto"] == "tcp")
r = tnl.op_portcheck({"port": fp, "proto": "udp"})
check("op_portcheck returns busy=False for a free UDP port", r["busy"] is False)
try:
    tnl.op_portcheck({"port": 70000})
    check("out-of-range port rejected", False)
except ValueError:
    check("out-of-range port rejected", True)
try:
    tnl.op_portcheck({})
    check("missing port rejected", False)
except ValueError:
    check("missing port rejected", True)

# --- /proc/net fallback (force ss to 'fail') ----------------------------------
orig_run = tnl.run
tnl.run = lambda *a, **k: (127, "", "no ss")
try:
    b, who = tnl._port_busy(tport, "tcp")
    check("fallback: TCP listener detected via /proc/net", b is True)
    b2, _ = tnl._port_busy(fp, "tcp")
    check("fallback: free port still free", b2 is False)
    b3, _ = tnl._port_busy(uport, "udp")
    check("fallback: UDP socket detected via /proc/net", b3 is True)
finally:
    tnl.run = orig_run

ts.close()
us.close()

# --- ss parsing path (canned `ss` output, since the sandbox lacks ss) ---------
SS_TCP = (
    "LISTEN 0      511          0.0.0.0:443        0.0.0.0:*     users:((\"nginx\",pid=1201,fd=6))\n"
    "LISTEN 0      4096       127.0.0.1:10085      0.0.0.0:*     users:((\"xray\",pid=990,fd=12))\n"
    "LISTEN 0      128             [::]:22            [::]:*     users:((\"sshd\",pid=700,fd=3))\n"
)
SS_UDP = (
    "UNCONN 0      0            0.0.0.0:4789       0.0.0.0:*     users:((\"tnl-core\",pid=2222,fd=4))\n"
)


def fake_run(args, **k):
    # args like ["ss","-H","-l","-n","-p","-t"] or "-u"
    if "-t" in args:
        return 0, SS_TCP, ""
    if "-u" in args:
        return 0, SS_UDP, ""
    return 127, "", ""


orig_run = tnl.run
tnl.run = fake_run
try:
    b, who = tnl._port_busy(443, "tcp")
    check("ss parse: 443/tcp busy with process name", b is True and who == "nginx")
    b, who = tnl._port_busy(10085, "tcp")
    check("ss parse: loopback-only 10085/tcp seen as busy", b is True and who == "xray")
    b, who = tnl._port_busy(22, "tcp")
    check("ss parse: IPv6 [::]:22 matched", b is True and who == "sshd")
    b, _ = tnl._port_busy(8443, "tcp")
    check("ss parse: unlisted port free", b is False)
    b, who = tnl._port_busy(4789, "udp")
    check("ss parse: 4789/udp busy (tnl-core)", b is True and who == "tnl-core")
    b, _ = tnl._port_busy(4789, "tcp")
    check("ss parse: 4789 free on TCP (proto isolation)", b is False)
finally:
    tnl.run = orig_run

print()
if FAILS:
    print("%d FAILED: %s" % (len(FAILS), ", ".join(FAILS)))
    sys.exit(1)
print("all portcheck tests passed")
