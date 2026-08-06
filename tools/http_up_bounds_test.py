#!/usr/bin/env python3
"""Guard: the node's bounds for the http_up_* upstream knobs must be the CORE's bounds.

The core does not clamp these three — config.go's validate() REJECTS an out-of-range value, and a
rejected config means the core exits, its TUN never appears, and the operator is told the interface was
not created. So a bound here that is wider than the core's does not "allow more", it converts a value
the panel could send into a tunnel that never comes up. The node pre-checks every other combination the
core rejects for precisely this reason.

Two halves, and the second is the one that closes the class:

  1. Drive the REAL op_tunnel — not the whitelist loop beside it — and assert an over-range value is
     refused before anything is built, and an at-limit value survives into the persisted config.
  2. Read the ceilings straight out of the core's config.go and assert the node agrees, so a bound
     changed on either side fails here instead of drifting silently.

Run with no arguments. Exit 0 = the two sides agree.
"""

import importlib.util
import os
import re
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
NODE = os.path.join(os.path.dirname(HERE), "tnl-node.py")
# Same sibling-checkout layout the panel's tuning_consistency.py assumes.
CORE = os.environ.get("CORE_REPO") or os.path.join(
    os.path.dirname(os.path.dirname(HERE)), "TUNNEL-MANAGER-CORE")

KEYS = ("http_up_workers", "http_up_batch_kb", "http_up_rate")
GO_FIELD = {"http_up_workers": "HTTPUpWorkers",
            "http_up_batch_kb": "HTTPUpBatchKB",
            "http_up_rate": "HTTPUpRate"}

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


def core_bounds():
    """The upper bound each knob has in the core, parsed from its validate()."""
    path = os.path.join(CORE, "config.go")
    if not os.path.exists(path):
        return None
    with open(path, encoding="utf-8") as f:
        src = f.read()
    out = {}
    for key, field in GO_FIELD.items():
        m = re.search(r"c\.%s\s*<\s*0\s*\|\|\s*c\.%s\s*>\s*(\d+)" % (field, field), src)
        if not m:
            fail("could not find the %s bound in the core's config.go" % field)
            return None
        out[key] = int(m.group(1))
    return out


def base_req(name="cor1"):
    return {"type": "core", "self_ip": "10.0.0.1", "peer_ip": "10.0.0.2",
            "subnet": "10.200.0.0/24", "id": 1, "name": name, "iface": "eth0", "host": 1,
            "role": "client", "transport": "ws", "cdn_carrier": "http",
            "psk": "a-sufficiently-long-preshared-key", "enabled": True}


def drive(mod, req, tmpdir):
    """Run the REAL op_tunnel far enough to validate and build the persisted object.

    Only the host-dependent lookups op_tunnel makes before the whitelist are stubbed, plus
    apply_config, where the real build would begin. Returns (obj_or_None, error_or_None).
    """
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
    bounds = core_bounds()
    if bounds is None:
        print("SKIP cross-repo check: no core checkout at %s" % CORE)
    else:
        print("core bounds: " + ", ".join("%s<=%d" % (k, bounds[k]) for k in KEYS))

    with tempfile.TemporaryDirectory() as tmp:
        # Sanity: the base request must build, or every case below proves nothing.
        obj, err = drive(mod, base_req(), tmp)
        if err is not None or not obj:
            fail("base core request did not reach apply_config (err=%r) — the cases below prove nothing" % err)
            return 1

        limits = bounds or {"http_up_workers": 16, "http_up_batch_kb": 512, "http_up_rate": 1000}
        for k in KEYS:
            lim = limits[k]
            # At the limit and just under: accepted, and the value must SURVIVE into the object the
            # node persists (an un-whitelisted key is dropped in silence — the bug class this guards).
            for v in (1, lim):
                req = base_req()
                req[k] = v
                obj, err = drive(mod, req, tmp)
                if err is not None:
                    fail("%s=%d (core allows up to %d) was rejected: %s" % (k, v, lim, err))
                elif obj.get(k) != v:
                    fail("%s=%d did not survive into the persisted config (got %r)" % (k, v, obj.get(k)))
            # 0 means "core default": accepted, and deliberately NOT stored.
            req = base_req()
            req[k] = 0
            obj, err = drive(mod, req, tmp)
            if err is not None:
                fail("%s=0 (the default) was rejected: %s" % (k, err))
            elif k in obj:
                fail("%s=0 was stored as %r; 0 means 'let the core default apply'" % (k, obj.get(k)))
            # Over the limit: refused HERE, with a message naming the knob, instead of reaching a
            # core that will not start.
            for v in (lim + 1, 100000):
                req = base_req()
                req[k] = v
                obj, err = drive(mod, req, tmp)
                if err is None:
                    fail("%s=%d accepted, but the core rejects anything over %d and would refuse to start" % (k, v, lim))
                elif k not in err:
                    fail("%s=%d rejected without naming the knob: %s" % (k, v, err))
            # Negative stays refused too.
            req = base_req()
            req[k] = -1
            obj, err = drive(mod, req, tmp)
            if err is None:
                fail("%s=-1 accepted" % k)

    if fails:
        print("\n%d failure(s)" % len(fails))
        return 1
    print("OK: node bounds match the core's, and op_tunnel enforces them on the real path")
    return 0


if __name__ == "__main__":
    sys.exit(main())
