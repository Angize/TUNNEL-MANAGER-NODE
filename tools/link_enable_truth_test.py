#!/usr/bin/env python3
"""Guard: the on/off toggle must report what happened to the data path, not what was asked for.

`op_link_enable` persisted the new `enabled` and returned `{"ok": True}` unconditionally, while the
only thing that actually moves the data path — `ip link set` for a kernel tunnel, the core unit for a
core tunnel — ran through run(), which never raises. So a toggle that changed nothing was reported as
success, and the stored config then disagreed with the interface for as long as nobody rebuilt it.

The tests drive the REAL op_link_enable with `run` stubbed at the process boundary, so the state
change, the verify, the branch and the returned message are all shipping code. They also assert the
config is NOT persisted on failure: recording an `enabled` the interface does not match is the same
lie one layer down.

Run with no arguments. Exit 0 = the toggle tells the truth.
"""

import importlib.util
import json
import os
import sys
import tempfile

# Failure messages quote Persian, and this runs on a cp1252 console — without this the guard raises
# UnicodeEncodeError while PRINTING the failure it correctly found.
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

HERE = os.path.dirname(os.path.abspath(__file__))
NODE = os.path.join(os.path.dirname(HERE), "tnl-node.py")

LINK_ERR = "Cannot find device \"vx1\""
CORE_REJECTION = "obfs is not supported on the dns transport (the DNS carrier has no obfs framing)"
JOURNAL = "2026/08/02 10:00:05 tnl-core: config: " + CORE_REJECTION + "\n"

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


def drive(mod, tmp, cfg, enabled, link_rc=0, netdev_rc=0, is_active="inactive", journal=""):
    """Run the REAL op_link_enable over a config on disk; return (result, stored config)."""
    def fake_run(args, timeout=60):
        if args[:3] == ["ip", "link", "set"]:
            return link_rc, "", LINK_ERR if link_rc else ""
        if args[:3] == ["ip", "link", "show"]:
            return netdev_rc, "", ""
        if args[:2] == ["systemctl", "is-active"]:
            return 0, is_active + "\n", ""
        if args[:2] == ["systemctl", "show"]:
            return 0, "\n", ""
        if args and args[0] == "journalctl":
            return 0, journal, ""
        return 0, "", ""

    saved = {k: getattr(mod, k) for k in ("run", "CONFIG_DIR", "build_core")}
    mod.CONFIG_DIR = tmp
    mod.write_config(cfg["name"], cfg)
    mod.run = fake_run
    mod.build_core = lambda c: None   # the unit launch itself is build_core's subject, not this one
    try:
        res = mod.op_link_enable({"name": cfg["name"], "enabled": enabled})
        return res, mod.read_config(cfg["name"])
    finally:
        for k, v in saved.items():
            setattr(mod, k, v)


def main():
    mod = load_node()
    with tempfile.TemporaryDirectory() as tmp:
        vx = {"type": "vxlan", "name": "vx1", "id": 1, "enabled": False}
        core = {"type": "core", "name": "cor1", "id": 2, "enabled": False}

        # 1. `ip link set` failed -> say so, and do NOT record an enabled the interface does not match.
        res, stored = drive(mod, tmp, dict(vx), True, link_rc=2)
        if res.get("ok"):
            fail("a failed `ip link set up` was reported as success")
        if LINK_ERR not in (res.get("msg") or ""):
            fail("the reason the link did not come up is missing: %r" % res.get("msg"))
        if stored.get("enabled") is not False:
            fail("a FAILED enable was persisted anyway: stored enabled=%r" % stored.get("enabled"))

        # 2. It worked -> ok, and the state is recorded.
        res, stored = drive(mod, tmp, dict(vx), True)
        if not res.get("ok") or res.get("enabled") is not True:
            fail("a successful enable was not reported as one: %r" % res)
        if stored.get("enabled") is not True:
            fail("a successful enable was not persisted: %r" % stored)

        # 3. Disable has to be verified too, not assumed.
        res, stored = drive(mod, tmp, dict(vx, enabled=True), False, link_rc=2)
        if res.get("ok"):
            fail("a failed `ip link set down` was reported as success")
        if stored.get("enabled") is not True:
            fail("a FAILED disable was persisted anyway: %r" % stored)

        # 4. A core tunnel whose TUN never appears: the core's OWN reason must reach the operator,
        #    the same message op_tunnel gives for the same situation.
        res, stored = drive(mod, tmp, dict(core), True, netdev_rc=1, journal=JOURNAL)
        if res.get("ok"):
            fail("a core enable whose TUN never appeared was reported as success")
        if CORE_REJECTION not in (res.get("msg") or ""):
            fail("the core's own reason did not reach the operator: %r" % res.get("msg"))
        if stored.get("enabled") is not False:
            fail("a core enable that failed was persisted anyway: %r" % stored)

        # 5. ...and a core enable that DID come up is still a success.
        res, stored = drive(mod, tmp, dict(core), True, netdev_rc=0)
        if not res.get("ok"):
            fail("a core enable whose TUN appeared was reported as failure: %r" % res)
        if stored.get("enabled") is not True:
            fail("a successful core enable was not persisted: %r" % stored)

        # 6. Disabling a core tunnel whose unit refuses to stop is not a success either.
        res, stored = drive(mod, tmp, dict(core, enabled=True), False, is_active="active")
        if res.get("ok"):
            fail("a core unit that kept running was reported as disabled")
        if stored.get("enabled") is not True:
            fail("a failed core disable was persisted anyway: %r" % stored)

        # 7. The idempotent branch must survive: a portfw / unknown config still answers ok.
        pf = {"type": "portfw", "name": "pf1", "id": 3}
        res, _ = drive(mod, tmp, dict(pf), True)
        if not res.get("ok") or not res.get("already"):
            fail("the portfw no-op branch changed: %r" % res)

    if fails:
        print("\n%d failure(s)." % len(fails))
        return 1
    print("\nthe on/off toggle reports the data path, not the request")
    return 0


if __name__ == "__main__":
    sys.exit(main())
