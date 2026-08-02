#!/usr/bin/env python3
"""Guard: a POOLED raw server must be handed 0.0.0.0, and the core must still take only one.

A raw carrier has no ports, so the only thing the kernel can use to tell two raw sockets apart is the
DESTINATION IP: `listenRawBase` binding a concrete address receives packets addressed to that address
and to nothing else. Under a destination-rotation pool the client dials several of this server's IPs in
turn, so a concrete bind makes the server deaf on every pool IP but the one it bound — only the anchor
ever completes a handshake, and the pool burns the rest with nothing logged anywhere.

The core cannot easily guard it: from inside `ListenRaw` a concrete bind is indistinguishable from a
deliberate single-IP server. So the invariant is held on this side, where the value is chosen.

Two halves:

  1. Drive the REAL `_core_config` for a pooled raw server and assert it emits `0.0.0.0:<port>` — and
     that a NON-pooled raw server still binds its own address, so the guard cannot be satisfied by
     making everything a wildcard.
  2. Read the core's `main.go` and assert `ListenRaw` still takes ONE listen address. The reason the
     node sends a wildcard is that the core cannot bind a list for raw the way it does for udp/tcp; if
     that changes, this fails, which is the moment to revisit both sides.

Run with no arguments. Exit 0 = the two sides agree.
"""

import importlib.util
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
NODE = os.path.join(os.path.dirname(HERE), "tnl-node.py")
# Same sibling-checkout layout tools/http_up_bounds_test.py and the panel's tuning_consistency.py use.
CORE = os.environ.get("CORE_REPO") or os.path.join(
    os.path.dirname(os.path.dirname(HERE)), "TUNNEL-MANAGER-CORE")

fails = []


def fail(msg):
    fails.append(msg)
    print("FAIL: " + msg)


def ok(msg):
    print("  ok  " + msg)


def load_node():
    spec = importlib.util.spec_from_file_location("tnl_node", NODE)
    mod = importlib.util.module_from_spec(spec)
    sys.modules["tnl_node"] = mod
    spec.loader.exec_module(mod)
    # _core_config samples the uplink MTU. Answer it here rather than letting the guard shell out to
    # the host it happens to run on — an unreadable uplink is a build error, not this guard's subject.
    mod.run = lambda args, timeout=60: (
        (0, "2: eth0: <BROADCAST,UP> mtu 1500 qdisc fq state UP\n", "")
        if args[:3] == ["ip", "link", "show"] else (0, "", ""))
    return mod


def cfg_for(pooled):
    """A stored raw SERVER config, as op_tunnel would have persisted it."""
    c = {"type": "core", "name": "cor7", "id": 7, "role": "server", "transport": "raw",
         "raw_profile": "bip", "iface": "eth0", "local_ip": "10.0.0.1",
         "self_ip": "10.0.0.1", "peer_ip": "10.0.0.2", "subnet": "10.200.0.0/24",
         "tunnel_ip": "10.200.0.1/30", "mtu": 1400,
         "psk": "a-sufficiently-long-preshared-key", "port": 20077, "enabled": True}
    if pooled:
        c["pool_listen"] = True
        c["listen_ips"] = ["10.0.0.1", "10.0.0.2", "10.0.0.3"]
    return c


def check_node(mod):
    pooled = mod._core_config(cfg_for(True))
    listen = str(pooled.get("listen") or "")
    if not listen.startswith("0.0.0.0:"):
        fail("a POOLED raw server was given listen=%r; it must be 0.0.0.0:<port>, or the core "
             "binds one address and goes silently deaf on every other IP the client rotates to" % listen)
    else:
        ok("pooled raw server -> listen=%s" % listen)

    # The core ignores listen_ips for raw (main.go hands it cfg.Listen), so sending it would be a key
    # that reads like it does something. The FLAG is what the pooled server needs; the list is not.
    if "listen_ips" in pooled:
        fail("a pooled raw server was sent listen_ips=%r, which the core ignores for raw — it reads "
             "as configuration that has an effect and has none" % (pooled["listen_ips"],))
    else:
        ok("pooled raw server -> no listen_ips (the core ignores it for raw)")

    # The other half of the invariant: a plain raw server must still bind its OWN address, so two
    # unpooled raw tunnels on one host are demuxed by destination IP instead of both seeing everything.
    single = mod._core_config(cfg_for(False))
    slisten = str(single.get("listen") or "")
    if not slisten.startswith("10.0.0.1:"):
        fail("a NON-pooled raw server was given listen=%r; it must bind its own address, or two raw "
             "tunnels on one host both receive every packet" % slisten)
    else:
        ok("non-pooled raw server -> listen=%s" % slisten)


def check_core():
    path = os.path.join(CORE, "main.go")
    if not os.path.exists(path):
        print("SKIP cross-repo check: no core checkout at %s" % CORE)
        return
    with open(path, encoding="utf-8") as f:
        src = f.read()
    m = re.search(r"packet\.ListenRaw\(\s*([A-Za-z0-9_.\[\]]+)\s*,", src)
    if not m:
        fail("could not find the packet.ListenRaw call in the core's main.go")
        return
    arg = m.group(1)
    if arg != "cfg.Listen":
        fail("the core now calls ListenRaw(%s): it no longer takes a single listen address. The "
             "wildcard this guard enforces exists ONLY because raw could not bind a list the way "
             "udp/tcp do — revisit both sides instead of keeping the wildcard by inertia." % arg)
    else:
        ok("core still binds ONE address for raw (ListenRaw(cfg.Listen)), so the wildcard is required")


def main():
    print("== a pooled raw server binds the wildcard ==")
    check_node(load_node())
    print("== the core still takes one listen address for raw ==")
    check_core()
    if fails:
        print("\n%d problem(s)." % len(fails))
        return 1
    print("\npooled raw binding is consistent across node and core.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
