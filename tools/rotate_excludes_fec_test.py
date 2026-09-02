#!/usr/bin/env python3
"""Guard: every combination the core REJECTS for raw_sport_rotate must be refused here first.

The core does not clamp raw_sport_rotate — config.go's validate() rejects a bad combination outright,
and a rejected config means tnl-core exits at startup, the TUN never appears, and the operator is left
with a tunnel that is simply down. fec + raw_sport_rotate was exactly that hole: the panel accepted it,
the node persisted both keys and wrote them into the core config, and the core then refused to run.

Two halves, and the second closes the class:

  1. Drive the REAL op_tunnel and assert each rejected combination is refused before anything is built,
     and that a legal rotation still survives all the way into the emitted core config.
  2. Read the rejected combinations straight out of the core's config.go, so a rule added on either
     side fails here instead of drifting apart in silence.

Run with no arguments. Exit 0 = the node refuses everything the core refuses.
"""

import importlib.util
import os
import re
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
NODE = os.path.join(os.path.dirname(HERE), "tnl-node.py")
CORE = os.environ.get("CORE_REPO") or os.path.join(
    os.path.dirname(os.path.dirname(HERE)), "TUNNEL-MANAGER-CORE")

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


def core_rules():
    """Which conflicts the core's validate() names for raw_sport_rotate, and its range."""
    path = os.path.join(CORE, "config.go")
    if not os.path.exists(path):
        return None
    with open(path, encoding="utf-8") as f:
        src = f.read()
    i = src.find("if c.RawSportRotate != 0 {")
    if i < 0:
        fail("could not find the RawSportRotate block in the core's config.go")
        return None
    block = src[i:i + 2200]
    rng = re.search(r"c\.RawSportRotate\s*<\s*(\d+)\s*\|\|\s*c\.RawSportRotate\s*>\s*(\d+)", block)
    return {
        "lo": int(rng.group(1)) if rng else 1,
        "hi": int(rng.group(2)) if rng else 64,
        "udp_only": 'c.RawProfile != "udp"' in block,
        "excludes_sport": "c.RawSport != 0" in block,
        "excludes_random": "c.RawSportRandom" in block,
        "excludes_fec": "c.Fec" in block,
    }


def base_req(**kw):
    req = {"type": "core", "self_ip": "10.0.0.1", "peer_ip": "10.0.0.2",
           "subnet": "10.200.0.0/24", "id": 1, "name": "cor1", "iface": "eth0", "host": 1,
           "role": "client", "transport": "raw", "raw_profile": "udp", "raw_port": 20401,
           "psk": "a-sufficiently-long-preshared-key", "enabled": True}
    req.update(kw)
    return req


def drive(mod, req, tmpdir):
    """Run the REAL op_tunnel far enough to validate and build the persisted object."""
    captured = {}

    class Stop(Exception):
        pass

    def fake_apply(obj):
        captured.update(obj)
        raise Stop("stop before building")

    saved = {k: getattr(mod, k) for k in
             ("local_ips_flat", "iface_for_ip", "read_config", "apply_config", "CONFIG_DIR")}
    mod.local_ips_flat = lambda: ["10.0.0.1"]
    mod.iface_for_ip = lambda ip: "eth0"
    mod.read_config = lambda n: None
    mod.apply_config = fake_apply
    mod.CONFIG_DIR = tmpdir
    try:
        mod.op_tunnel(dict(req))
    except Stop:
        pass
    except ValueError as e:
        return None, str(e)
    finally:
        for k, v in saved.items():
            setattr(mod, k, v)
    return captured, None


def main():
    mod = load_node()
    # _core_config reads the real link MTU; there is no eth0 on a checkout machine.
    mod.base_mtu = lambda iface: 1500
    rules = core_rules()
    if rules is None:
        print("SKIP cross-repo check: no core checkout at %s" % CORE)
        rules = {"lo": 1, "hi": 64, "udp_only": True, "excludes_sport": True,
                 "excludes_random": True, "excludes_fec": True}
    else:
        named = [k for k in ("udp_only", "excludes_sport", "excludes_random", "excludes_fec") if rules[k]]
        print("core rejects: %s; range %d..%d" % (", ".join(named), rules["lo"], rules["hi"]))
    if not rules["excludes_fec"]:
        fail("the core no longer rejects fec + raw_sport_rotate — this guard is now watching a rule "
             "that moved, so either the core learned to rotate under FEC or the check needs updating")

    with tempfile.TemporaryDirectory() as tmp:
        obj, err = drive(mod, base_req(), tmp)
        if err is not None or not obj:
            fail("the base raw:udp request did not reach apply_config (err=%r) — nothing below proves anything" % err)
            return 1

        # A legal rotation survives persistence AND the config the core is handed.
        for n in (rules["lo"], 5, rules["hi"]):
            obj, err = drive(mod, base_req(raw_sport_rotate=n), tmp)
            if err is not None:
                fail("raw_sport_rotate=%d was rejected: %s" % (n, err))
                continue
            if obj.get("raw_sport_rotate") != n:
                fail("raw_sport_rotate=%d did not survive into the persisted config (got %r)"
                     % (n, obj.get("raw_sport_rotate")))
                continue
            core = mod._core_config(obj)
            if core.get("raw_sport_rotate") != n:
                fail("raw_sport_rotate=%d never reached the core config (got %r)"
                     % (n, core.get("raw_sport_rotate")))

        # 0 is off: accepted, and deliberately not stored.
        obj, err = drive(mod, base_req(raw_sport_rotate=0), tmp)
        if err is not None:
            fail("raw_sport_rotate=0 (off) was rejected: %s" % err)
        elif "raw_sport_rotate" in obj:
            fail("raw_sport_rotate=0 was stored as %r instead of being left out" % obj["raw_sport_rotate"])

        # Every combination the core refuses must be refused here, before a config is written.
        cases = [
            ("fec", rules["excludes_fec"], base_req(raw_sport_rotate=5, fec=True)),
            ("raw_sport", rules["excludes_sport"], base_req(raw_sport_rotate=5, raw_sport=4500)),
            ("raw_sport_random", rules["excludes_random"], base_req(raw_sport_rotate=5, raw_sport_random=True)),
            ("a non-udp profile", rules["udp_only"], base_req(raw_sport_rotate=5, raw_profile="tcp")),
            ("above the range", True, base_req(raw_sport_rotate=rules["hi"] + 1)),
            ("below the range", True, base_req(raw_sport_rotate=-1)),
        ]
        for label, enforced, req in cases:
            if not enforced:
                continue
            obj, err = drive(mod, req, tmp)
            if err is None:
                got = mod._core_config(obj) if obj else {}
                fail("raw_sport_rotate with %s was ACCEPTED; the core config would carry "
                     "raw_sport_rotate=%r fec=%r and tnl-core would refuse to start"
                     % (label, got.get("raw_sport_rotate"), got.get("fec")))
            else:
                print("  ok  refused: raw_sport_rotate with %s" % label)

        # FEC on its own must keep working — the guard must not have swallowed it.
        obj, err = drive(mod, base_req(fec=True), tmp)
        if err is not None or not obj.get("fec"):
            fail("fec on its own stopped working (err=%r, fec=%r)" % (err, obj and obj.get("fec")))

    if fails:
        print("\n%d failure(s)." % len(fails))
        return 1
    print("\nthe node refuses every raw_sport_rotate combination the core refuses")
    return 0


if __name__ == "__main__":
    sys.exit(main())
