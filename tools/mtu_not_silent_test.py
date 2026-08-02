#!/usr/bin/env python3
"""Guard: an unreadable underlay MTU must fail the build, not quietly become 1500.

`base_mtu(dev)` bound `ip link show`'s exit code and never looked at it, so an iface that is gone or
renamed produced no match and the function returned its 1500 fallback. Downstream cannot tell that
apart from a genuine 1500 link: a tunnel on a PPPoE 1492 or IPv6-min 1280 uplink then gets an MTU its
underlay cannot carry and black-holes or fragments, with nothing said anywhere. `_up_netdev` then set
that MTU through run(), so even the set failing was silent.

The tests drive the REAL op_tunnel -> apply_config -> build_vxlan -> _up_netdev with `run` stubbed at
the process boundary, so base_mtu, the subtraction, the `ip link set mtu` and op_tunnel's error tail
are all shipping code.

Run with no arguments. Exit 0 = the MTU is either read or reported.
"""

import importlib.util
import os
import re
import sys
import tempfile

# Failure messages quote Persian, and this runs on a cp1252 console — without this the guard raises
# UnicodeEncodeError while PRINTING the failure it correctly found.
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

HERE = os.path.dirname(os.path.abspath(__file__))
NODE = os.path.join(os.path.dirname(HERE), "tnl-node.py")

VXLAN_OVERHEAD = 50   # IP20+UDP8+VXLAN8+innerEth14, from build_vxlan

fails = []


def fail(msg):
    fails.append(msg)
    print("FAIL: " + msg)


def load_node():
    spec = importlib.util.spec_from_file_location("tnl_node", NODE)
    mod = importlib.util.module_from_spec(spec)
    sys.modules["tnl_node"] = mod
    spec.loader.exec_module(mod)
    return mod


def req(**over):
    d = {"type": "vxlan", "self_ip": "10.0.0.1", "peer_ip": "10.0.0.2", "subnet": "10.200.0.0/24",
         "id": 7, "name": "vx7", "iface": "eth0", "enabled": True}
    d.update(over)
    return d


def drive(mod, tmp, uplink_mtu=1492, show_rc=0, mtu_set_rc=0, request=None):
    """Run the REAL op_tunnel for a vxlan and return (result, the mtu it set or None)."""
    seen = {"mtu": None}

    def fake_run(args, timeout=60):
        if args[:3] == ["ip", "link", "show"]:
            dev = args[3] if len(args) > 3 else ""
            if dev == "vx7":
                return 0, "9: vx7: <UP> mtu 1442 qdisc noqueue state UNKNOWN\n", ""   # the netdev verify
            if show_rc != 0:
                return show_rc, "", "Device \"%s\" does not exist." % dev
            return 0, "2: %s: <BROADCAST,UP> mtu %d qdisc fq state UP\n" % (dev, uplink_mtu), ""
        if args[:4] == ["ip", "link", "set", "dev"] and "mtu" in args:
            seen["mtu"] = int(args[args.index("mtu") + 1])
            return mtu_set_rc, "", "mtu greater than device maximum" if mtu_set_rc else ""
        return 0, "", ""

    saved = {k: getattr(mod, k) for k in ("local_ips_flat", "iface_for_ip", "run", "CONFIG_DIR")}
    mod.local_ips_flat = lambda: ["10.0.0.1"]
    mod.iface_for_ip = lambda ip: "eth0"
    mod.run = fake_run
    mod.CONFIG_DIR = tmp
    try:
        return mod.op_tunnel(request or req()), seen["mtu"]
    finally:
        for k, v in saved.items():
            setattr(mod, k, v)


def main():
    mod = load_node()
    with tempfile.TemporaryDirectory() as tmp:
        # 1. A readable uplink: the tunnel MTU is that link's MTU minus this carrier's overhead.
        res, mtu = drive(mod, tmp, uplink_mtu=1492)
        if not res.get("ok"):
            fail("a normal build failed: %r" % res)
        if mtu != 1492 - VXLAN_OVERHEAD:
            fail("tunnel MTU is %r, want %d (uplink 1492 - %d)" % (mtu, 1492 - VXLAN_OVERHEAD, VXLAN_OVERHEAD))

        # 2. The named iface cannot be read -> the build FAILS and names it. It must NOT silently
        #    build at 1500, which is the whole finding.
        res, mtu = drive(mod, tmp, show_rc=1)
        if res.get("ok"):
            fail("an unreadable uplink MTU was reported as a successful build")
        if "eth0" not in (res.get("msg") or ""):
            fail("the failure does not name the interface it could not read: %r" % res.get("msg"))
        if mtu == 1500 - VXLAN_OVERHEAD:
            fail("still fell back to 1500 for a named iface (mtu set to %r)" % mtu)

        # 3. With NO iface asked for there is nothing better than 1500, so that fallback must survive.
        saved = mod.default_iface
        mod.default_iface = lambda: None
        try:
            if mod.base_mtu() != 1500:
                fail("the no-dev fallback is no longer 1500: %r" % mod.base_mtu())
        finally:
            mod.default_iface = saved

        # 4. The `ip link set mtu` itself failing is a build failure, not a shrug.
        res, mtu = drive(mod, tmp, mtu_set_rc=2)
        if res.get("ok"):
            fail("a failed `ip link set mtu` was reported as a successful build")
        if "mtu" not in (res.get("msg") or "").lower():
            fail("the failed MTU set is not in the message: %r" % res.get("msg"))

        # 5. A small underlay must reach the tunnel: this is the case the silent 1500 broke.
        res, mtu = drive(mod, tmp, uplink_mtu=1280)
        if not res.get("ok") or mtu != 1280 - VXLAN_OVERHEAD:
            fail("a 1280 uplink did not reach the tunnel MTU: ok=%r mtu=%r" % (res.get("ok"), mtu))

    if fails:
        print("\n%d failure(s)." % len(fails))
        return 1
    print("\nthe underlay MTU is either read or reported, never guessed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
