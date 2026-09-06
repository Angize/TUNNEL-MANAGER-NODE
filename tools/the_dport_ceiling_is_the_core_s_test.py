#!/usr/bin/env python3
"""Guard: the node accepts exactly the destination-port count the core does, and writes it through.

The ceiling lives in four places -- the core's MaxDports, this node's MAX_DPORTS, and the panel's two
copies -- and the node's is the one that fails SILENTLY. `_core_config` only copies raw_dports into
the core config when it passes the node's own range test:

    if 1 <= _rdp <= MAX_DPORTS:
        corecfg["raw_dports"] = _rdp

so a node whose ceiling is lower than the panel's does not refuse the tunnel. It builds it, drops the
key on the floor, and the core comes up with ONE destination port while the panel card, the stored
link and the operator's form all still read twelve. Nothing on any screen is wrong; the wire is.

That is why the node's number is asserted against the CORE's here rather than against a literal, and
why the path is driven rather than the helper: op_tunnel is what a panel request actually reaches.

The ceiling runs in BOTH directions, and the second one is where it actually broke. _read_status
sanitises the core's status file before the ping carries it to the panel, and it clamped the reported
count with a literal 8 that nobody moved when the ceiling went to sixteen. A core running fifteen
destination ports -- correctly, with fifteen anti-leak rules on the wire to prove it -- was reported
as running eight, so the card contradicted the form the operator had just filled in. Accepting a
value and reporting it are two ceilings, and a guard that only drives the first says nothing at all
about the second.

    python3 tools/the_dport_ceiling_is_the_core_s_test.py

Exit 0 = the node's ceiling is the core's, a request at the ceiling reaches the core config, one
above it is refused rather than quietly trimmed, and a core reporting the ceiling is relayed whole.
"""
import importlib.util
import json
import os
import re
import sys
import tempfile

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

HERE = os.path.dirname(os.path.abspath(__file__))
NODE = os.path.join(os.path.dirname(HERE), "tnl-node.py")
CORE_RAWPROFILE = os.path.join(os.path.dirname(os.path.dirname(HERE)),
                               "TUNNEL-MANAGER-CORE", "internal", "packet", "rawprofile.go")
CORE_RAWPROFILE = os.environ.get("CORE_RAWPROFILE") or CORE_RAWPROFILE

fails = []


def check(ok, msg, got=None):
    print(("  ok   " if ok else " FAIL  ") + msg + ("" if ok or got is None else "\n         %s" % (got,)))
    if not ok:
        fails.append(msg)


def load_node():
    spec = importlib.util.spec_from_file_location("tnl_node", NODE)
    mod = importlib.util.module_from_spec(spec)
    sys.modules["tnl_node"] = mod
    spec.loader.exec_module(mod)
    return mod


def read_rot(mod, tmp, dports=4, every=6):
    """Write a status file the way the core writes one, then run the REAL sanitiser over it."""
    st = {"active": "raw:tcp", "epoch": 3, "ready": True, "ts": 1,
          "pair": {"low": "", "high": "", "low_kind": "", "high_kind": ""},
          "path": {"src": "", "sport": 0, "dst": "", "dport": 0},
          "health": [], "events": [],
          "rot": {"sport": 40001, "dport": 443, "dports": dports, "every": every,
                  "lo": 1024, "hi": 65000, "drawn": 90000}}
    with open(os.path.join(tmp, "core-core9.status"), "w", encoding="utf-8") as f:
        json.dump(st, f)
    return mod._read_status("core9")["rot"]


def req(n, **over):
    d = {"type": "core", "self_ip": "203.0.113.5", "peer_ip": "198.51.100.7",
         "subnet": "10.9.0.0/24", "host": 1, "id": 9, "name": "core9", "enabled": True,
         "transport": "raw", "raw_profile": "tcp", "raw_port": 443, "raw_sport_rotate": 6,
         "cipher": "aes-256-gcm", "crypto": True, "psk": "k" * 64, "port": 20000,
         "role": "server", "mtu": 1341}
    if n is not None:
        d["raw_dports"] = n
    d.update(over)
    return d


def drive(mod, tmp, n):
    """Run the REAL op_tunnel and hand back (result, the core config it wrote)."""
    def fake_run(args, timeout=60):
        if args[:3] == ["ip", "link", "show"]:
            return 0, "2: eth0: <BROADCAST,UP> mtu 1500 qdisc fq state UP\n", ""
        return 0, "", ""

    saved = {k: getattr(mod, k) for k in ("local_ips_flat", "iface_for_ip", "run",
                                          "CONFIG_DIR", "CORE_BIN", "default_iface")}
    mod.local_ips_flat = lambda: ["203.0.113.5"]
    mod.iface_for_ip = lambda ip: "eth0"
    mod.default_iface = lambda: "eth0"
    mod.run = fake_run
    mod.CONFIG_DIR = tmp
    mod.CORE_BIN = NODE                      # any real file: _ensure_core only stats it
    try:
        res = mod.op_tunnel(req(n))
    except Exception as e:
        return {"ok": False, "msg": str(e)}, None
    finally:
        for k, v in saved.items():
            setattr(mod, k, v)
    path = os.path.join(tmp, "core-core9.json")
    cfg = None
    if os.path.isfile(path):
        with open(path, encoding="utf-8") as f:
            cfg = json.load(f)
    return res, cfg


def main():
    mod = load_node()
    ceiling = mod.MAX_DPORTS

    print("\n-- the node's ceiling IS the core's --")
    if not os.path.isfile(CORE_RAWPROFILE):
        check(False, "the core checkout is not beside this repo, so the ceilings cannot be compared",
              CORE_RAWPROFILE)
    else:
        src = open(CORE_RAWPROFILE, encoding="utf-8").read()
        m = re.search(r"MaxDports\s*=\s*(\d+)", src)
        check(m is not None, "core MaxDports is parseable")
        if m:
            check(int(m.group(1)) == ceiling,
                  "node MAX_DPORTS=%d == core MaxDports=%s" % (ceiling, m.group(1)))
        pool = re.search(r"var dportPool = \[\.\.\.\]uint16\{(.*?)\}", src, re.S)
        check(pool is not None, "the core's destination pool is parseable")
        if pool:
            ports = re.findall(r"\d+", pool.group(1))
            check(len(ports) >= ceiling,
                  "the core's pool can deliver the ceiling: %d ports for a ceiling of %d"
                  % (len(ports), ceiling))

    print("\n-- and a request AT the ceiling reaches the core config --")
    with tempfile.TemporaryDirectory() as tmp:
        for n in (1, 2, ceiling - 1, ceiling):
            res, cfg = drive(mod, tmp, n)
            check(bool(res.get("ok")), "raw_dports=%d builds" % n, res.get("msg"))
            got = (cfg or {}).get("raw_dports")
            want = None if n < 1 else n
            check(got == want, "raw_dports=%d reaches the core config as %r" % (n, want), got)

    print("\n-- one ABOVE the ceiling is refused, not silently trimmed --")
    with tempfile.TemporaryDirectory() as tmp:
        for n in (ceiling + 1, ceiling + 9, 999):
            res, cfg = drive(mod, tmp, n)
            check(not res.get("ok"), "raw_dports=%d is refused" % n, res)
            check(cfg is None or "raw_dports" not in cfg,
                  "raw_dports=%d wrote no core config carrying a trimmed value" % n,
                  (cfg or {}).get("raw_dports"))

    print("\n-- the ceiling also bounds what the node REPORTS, and it is the same ceiling --")
    # This is the half the first version of this guard missed, and it cost a real bug: the config
    # direction was raised to sixteen while _read_status kept a literal 8, so a core running fifteen
    # destination ports reported eight, and the operator's card contradicted the operator's own form.
    # Reading is a ceiling too. Drive the real sanitiser, from a real status file.
    with tempfile.TemporaryDirectory() as tmp:
        saved_dir = mod.CONFIG_DIR
        mod.CONFIG_DIR = tmp
        try:
            for n in (1, 2, ceiling - 1, ceiling):
                got = read_rot(mod, tmp, dports=n)
                check(got.get("dports") == n,
                      "a core reporting %d destination ports is relayed as %d" % (n, n), got)
            for n in (1, 7, mod.MAX_SPROT_EVERY):
                got = read_rot(mod, tmp, every=n)
                check(got.get("every") == n,
                      "a core reporting every=%d is relayed as %d" % (n, n), got)
            # and nonsense from a corrupt file is still bounded -- the clamp is not being deleted here,
            # only made to agree with the number the core enforces.
            got = read_rot(mod, tmp, dports=10 ** 6, every=10 ** 6)
            check(got.get("dports") == ceiling and got.get("every") == mod.MAX_SPROT_EVERY,
                  "an impossible status is clamped to the real ceilings, not passed through", got)
        finally:
            mod.CONFIG_DIR = saved_dir

    print("\n-- and no literal ceiling is left in the sanitiser to drift again --")
    # There are two `"rot": {` literals in the node -- the all-zero default _read_status falls back to,
    # and the one that sanitises a real file. Only the second has clamps in it, so pick by content:
    # the first version of this check anchored on position, matched the default, and passed happily
    # while both literals were still there.
    src = open(NODE, encoding="utf-8").read()
    blocks = [m.group(0) for m in re.finditer(r'"rot": \{[^{}]*\}', src, re.S) if "rt.get(" in m.group(0)]
    check(len(blocks) == 1, "the status sanitiser's rot block is the one that reads rt, and there is one",
          "%d blocks matched" % len(blocks))
    if len(blocks) == 1:
        lits = re.findall(r"min\((\d+)", blocks[0])
        check(not lits,
              "the rot block clamps with named constants, not literals",
              "literal ceilings still there: %s" % (lits,))

    print("\n-- and the axis still needs the rotation it spreads --")
    with tempfile.TemporaryDirectory() as tmp:
        saved = {k: getattr(mod, k) for k in ("local_ips_flat", "iface_for_ip", "run",
                                              "CONFIG_DIR", "CORE_BIN", "default_iface")}
        mod.local_ips_flat = lambda: ["203.0.113.5"]
        mod.iface_for_ip = lambda ip: "eth0"
        mod.default_iface = lambda: "eth0"
        mod.run = lambda args, timeout=60: (0, "2: eth0: <UP> mtu 1500 qdisc fq state UP\n", "")
        mod.CONFIG_DIR, mod.CORE_BIN = tmp, NODE
        try:
            res = mod.op_tunnel(req(4, raw_sport_rotate=0))
            ok = False
        except Exception as e:
            res, ok = {"msg": str(e)}, True
        finally:
            for k, v in saved.items():
                setattr(mod, k, v)
        check(ok or not res.get("ok"),
              "raw_dports without raw_sport_rotate is refused (it spreads a source port that never moves)",
              res)

    print()
    if fails:
        print("FAILED (%d)" % len(fails))
        for f in fails:
            print("  - " + f)
        return 1
    print("the node's destination-port ceiling is the core's, and it reaches the wire")
    return 0


if __name__ == "__main__":
    sys.exit(main())
