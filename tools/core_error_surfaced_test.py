#!/usr/bin/env python3
"""Guard: when the CORE refuses a config, the operator is told what the core said.

build_core launches the core under a Restart=always unit and waits for its TUN to appear. A config
the core REJECTS makes it exit at once, so the TUN never appears and op_tunnel's netdev check fails —
and the agent reported «هستهٔ tnl-core روی این نود نصب/فعال نیست», which is false, and most
misleading in the one case where the real reason was one line away in the unit's journal.

config.go has ~68 distinct rejections. Findings #41 and #42 each asked for a node-side twin of one of
them (obfs+dns, fake_desync+http-carrier). Two guards would have covered two rejections and left 66,
and the core can add more at any time. Quoting the core covers all of them, including future ones.

The tests drive the REAL op_tunnel through the REAL failure tail, with `run` stubbed at the process
boundary — the only thing that cannot exist on a dev box — so the netdev check, the branch, the
journal read, the parse and the returned message are all the shipping code.

Run with no arguments. Exit 0 = the core's reason reaches the operator.
"""

import importlib.util
import os
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
NODE = os.path.join(os.path.dirname(HERE), "tnl-node.py")

# A real rejection, verbatim from a core that was handed obfs on a dns tunnel (config.go:771).
CORE_REJECTION = "obfs is not supported on the dns transport (the DNS carrier has no obfs framing)"
JOURNAL = (
    "2026/07/29 00:11:02 tnl-core: writing status/events to /etc/tnl/core-cor1.status\n"
    "2026/07/29 00:11:05 tnl-core: config: " + CORE_REJECTION + "\n"
)

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


def base_req():
    return {"type": "core", "self_ip": "10.0.0.1", "peer_ip": "10.0.0.2",
            "subnet": "10.200.0.0/24", "id": 1, "name": "cor1", "iface": "eth0",
            "role": "client", "transport": "ws", "psk": "a-sufficiently-long-preshared-key",
            "enabled": True}


def drive(mod, tmpdir, journal, journal_rc=0, netdev_rc=1):
    """Run the REAL op_tunnel to the netdev-verify tail and return its result dict.

    `run` is stubbed at the process boundary: `ip link show` reports the TUN missing (what a rejected
    config looks like) and `journalctl` returns whatever the case under test wants. Everything else
    the build would shell out to succeeds silently.
    """
    calls = []

    def fake_run(args, timeout=60):
        calls.append(list(args))
        if args[:3] == ["ip", "link", "show"]:
            return netdev_rc, "", ""
        if args and args[0] == "journalctl":
            return journal_rc, journal, ""
        return 0, "", ""

    saved = {k: getattr(mod, k) for k in
             ("local_ips_flat", "iface_for_ip", "read_config", "apply_config", "run", "CONFIG_DIR")}
    mod.local_ips_flat = lambda: ["10.0.0.1"]
    mod.iface_for_ip = lambda ip: "eth0"
    mod.read_config = lambda n: None
    mod.apply_config = lambda obj: None      # the build "succeeds"; the core then refuses the config
    mod.run = fake_run
    mod.CONFIG_DIR = tmpdir
    try:
        return mod.op_tunnel(base_req()), calls
    finally:
        for k, v in saved.items():
            setattr(mod, k, v)


def main():
    mod = load_node()
    with tempfile.TemporaryDirectory() as tmp:
        # 1. The core ran and said why. Its reason must reach the operator, and the old guess must not.
        res, calls = drive(mod, tmp, JOURNAL)
        if res.get("ok"):
            fail("a missing netdev was reported as success")
        msg = res.get("msg") or ""
        if CORE_REJECTION not in msg:
            fail("the core's own reason is not in the message: %r" % msg)
        if "نصب/فعال نیست" in msg:
            fail("still claims the core is not installed, though it ran and rejected the config: %r" % msg)
        if not any(c and c[0] == "journalctl" for c in calls):
            fail("the unit journal was never read")

        # 2. Nothing quotable -> the ORIGINAL message survives. That message was written for the case
        #    where the core really is absent, and this change must not cost us it.
        for label, kwargs in (("journalctl missing", {"journal": "", "journal_rc": 127}),
                              ("empty journal", {"journal": "", "journal_rc": 0}),
                              ("journal without a core line", {"journal": "-- No entries --\n"})):
            res, _ = drive(mod, tmp, **kwargs)
            if res.get("ok"):
                fail("%s: a missing netdev was reported as success" % label)
            if "نصب/فعال نیست" not in (res.get("msg") or ""):
                fail("%s: lost the not-installed fallback: %r" % (label, res.get("msg")))

        # 3. A restart loop must report its LATEST attempt, not the first one it ever logged.
        two = ("2026/07/29 00:10:00 tnl-core: config: an older reason\n"
               "2026/07/29 00:11:05 tnl-core: config: " + CORE_REJECTION + "\n")
        res, _ = drive(mod, tmp, two)
        if CORE_REJECTION not in (res.get("msg") or ""):
            fail("reported an older attempt instead of the latest: %r" % res.get("msg"))

        # 4. A netdev that DOES appear is still a success — the new branch must not fire on the
        #    healthy path, where journalctl would also have plenty to say.
        res, calls = drive(mod, tmp, JOURNAL, netdev_rc=0)
        if not res.get("ok"):
            fail("a present netdev was reported as failure: %r" % res)
        if any(c and c[0] == "journalctl" for c in calls):
            fail("read the journal on the success path")

    if fails:
        print("\n%d failure(s)" % len(fails))
        return 1
    print("OK: a core that refuses its config says so, and the not-installed message still covers its own case")
    return 0


if __name__ == "__main__":
    sys.exit(main())
