"""Guard: a node that reboots with a NEW IP can still phone home.

The check-in exists so a node whose public IP changed can tell the panel where it moved. But the
callback (the panel's ip AND port) was learned only from an INCOMING panel request and kept in memory,
so the one case it was built for could not work:

    the IP changes -> the panel cannot reach the stored host -> it never sends us a request ->
    we never learn the callback -> do_checkin() has nowhere to call -> the node is stuck for good.

Two properties close that, and both must keep holding:

  * note_central PERSISTS the pair, so a restart starts out knowing where to call;
  * it writes only when the pair CHANGED -- node.conf must not be rewritten on every ping.

Driven against the real note_central / _seed_central_cb / do_checkin with node.conf pointed at a temp
file. Exit 1 on any failure.
"""
import sys

sys.dont_write_bytecode = True
import importlib.util
import json
import os
import tempfile
from pathlib import Path

NODE = Path(__file__).resolve().parent.parent / "tnl-node.py"
PANEL_IP, PANEL_PORT = "185.252.86.72", 2053


def load(conf_path):
    spec = importlib.util.spec_from_file_location("tnl_node_cb", NODE)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    m.CONFIG_DIR = os.path.dirname(conf_path)
    m.NODE_CONF = conf_path
    return m


def main():
    bad = []

    def chk(label, got, want):
        if got != want:
            bad.append("%s: got %r, expected %r" % (label, got, want))
            print("  FAIL %-58s %r != %r" % (label, got, want))
        else:
            print("  ok   %-58s %r" % (label, got))

    tmp = tempfile.mkdtemp(prefix="tnlcb")
    conf_path = os.path.join(tmp, "node.conf")
    with open(conf_path, "w") as f:
        json.dump({"token": "tok", "port": 8099}, f)

    m = load(conf_path)
    writes = {"n": 0}
    real_save = m.save_conf
    m.save_conf = lambda c: (writes.__setitem__("n", writes["n"] + 1), real_save(c))[1]

    # first contact: the panel's IP is pinned (TOFU) and the callback is learned AND written down
    m.note_central(PANEL_IP, PANEL_PORT, False)
    chk("the callback is learned", m.get_central(), (PANEL_IP, PANEL_PORT, False))
    with open(conf_path) as f:
        conf = json.load(f)
    chk("and written to node.conf", conf.get("central_cb"), [PANEL_IP, PANEL_PORT, False])

    # The steady state is EVERY request, including read-only pings. Nothing may be written there -- and
    # nothing may take _apply_lock either, or a ping would block behind a core build that holds it for
    # ~8-16s and the panel would read a building node as down.
    class CountingLock:
        def __init__(self, inner):
            self.inner, self.n = inner, 0

        def __enter__(self):
            self.n += 1
            return self.inner.__enter__()

        def __exit__(self, *a):
            return self.inner.__exit__(*a)

    m._apply_lock = CountingLock(m._apply_lock)
    before = writes["n"]
    for _ in range(50):
        m.note_central(PANEL_IP, PANEL_PORT, False)
    chk("an unchanged callback writes nothing", writes["n"] - before, 0)
    chk("and never takes the lock a core build holds", m._apply_lock.n, 0)

    # the panel moved to another port -> one write, not fifty, and that write IS serialized with every
    # other node.conf writer (the TOFU pin, the ops) so it cannot clobber one of them
    locks_before = m._apply_lock.n
    m.note_central(PANEL_IP, 8443, False)
    with open(conf_path) as f:
        chk("a changed callback is persisted", json.load(f).get("central_cb"), [PANEL_IP, 8443, False])
    chk("exactly one write for one change", writes["n"] - before, 1)
    chk("the write is serialized with the other conf writers", m._apply_lock.n - locks_before, 1)

    # ---- THE case: the agent restarts, and the panel cannot reach us at the stored host
    m2 = load(conf_path)
    chk("a fresh process starts out blind", m2.get_central(), None)
    m2._seed_central_cb()
    chk("seeding restores the callback from node.conf", m2.get_central(), (PANEL_IP, 8443, False))

    called = {}
    m2.urllib.request.urlopen = lambda req, timeout=8: (_ for _ in ()).throw(
        AssertionError("unreachable"))  # replaced below; keeps a bare call from hitting the network

    class Resp:
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def read(self):
            return b'{"ok":true,"updated":true}'

    def fake_open(req, timeout=8):
        called["url"] = req.full_url
        called["body"] = json.loads(req.data.decode())
        return Resp()

    m2.urllib.request.urlopen = fake_open
    m2.all_ips = lambda: {"eth0": ["5.6.7.8"]}
    chk("the check-in succeeds after a reboot", m2.do_checkin(), True)
    chk("and it goes to the persisted address", called.get("url"),
        "http://%s:%d/api/checkin" % (PANEL_IP, 8443))

    # ---- the scheme is part of the origin, and it decides where the check-in is sent
    m2.note_central(PANEL_IP, 9443, True)
    chk("a TLS panel is learned as one", m2.get_central(), (PANEL_IP, 9443, True))
    chk("...and the rendered origin is https", m2.central_origin(), "https://%s:9443" % PANEL_IP)
    m2.do_checkin()
    chk("...so the check-in goes to https, not to a TLS port in the clear", called.get("url"),
        "https://%s:9443/api/checkin" % PANEL_IP)
    # ...and the one plaintext exception closes itself the moment the panel is TLS
    chk("a plaintext fetch from the panel's own address is now refused",
        m2._is_central_origin("http://%s:9443/api/dl" % PANEL_IP), False)
    m2.note_central(PANEL_IP, 2053, False)
    chk("...and allowed again when the panel really is plain http",
        m2._is_central_origin("http://%s:2053/api/dl" % PANEL_IP), True)
    # The check-in used to POST the raw token. It carries a FINGERPRINT of it now, plus an HMAC over
    # the rest of the claim -- so the secret does not cross the wire in this direction either, and a
    # listener who copies the fingerprint still cannot produce the signature.
    import base64 as _b64, hashlib as _h, hmac as _hm, json as _j
    body = called["body"]
    chk("the check-in carries no token", "token" in body, False)
    chk("...it identifies us by a fingerprint of it", body.get("fp"), _h.sha256(b"tok").hexdigest())
    signed = {k: v for k, v in body.items() if k != "sig"}
    want = _b64.b64encode(_hm.new(b"tok", _j.dumps(signed, sort_keys=True, separators=(",", ":")).encode(),
                                  _h.sha256).digest()).decode()
    chk("...and is signed with it", body.get("sig"), want)
    chk("...and carries a counter, so a captured check-in cannot be replayed",
        isinstance(body.get("ctr"), int) and body["ctr"] > 0, True)

    # a junk value in node.conf must not crash the agent or invent a callback
    # A pair with no scheme is junk too: it is what an older agent wrote, and guessing http for a
    # panel that has since moved to https would send the check-in at a TLS port in the clear. The
    # panel re-teaches the whole origin on its next request, one poll away.
    for junk in ("nonsense", [PANEL_IP], [PANEL_IP, "x", False], ["not-an-ip", 2053, False],
                 [PANEL_IP, 99999, False], [PANEL_IP, 2053]):
        with open(conf_path) as f:
            c = json.load(f)
        c["central_cb"] = junk
        with open(conf_path, "w") as f:
            json.dump(c, f)
        m3 = load(conf_path)
        m3._seed_central_cb()
        chk("junk callback %r is ignored" % (junk,), m3.get_central(), None)

    if bad:
        print("\nFAILURES (%d):" % len(bad))
        for b in bad:
            print("  - %s" % b)
        return 1
    print("\na reboot with a new IP can still reach the panel")
    return 0


if __name__ == "__main__":
    sys.exit(main())
