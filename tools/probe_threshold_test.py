#!/usr/bin/env python3
"""Guard: the tun probe's verdict rests on the WHOLE sample set, and the operator sets where the line is.

One reply out of twenty used to decide everything -- the dot, whether to burn the endpoint, and whether
to CLEAR a burn. A tunnel dropping 19 of 20 read green and had its path exonerated, which is how a
filtered endpoint kept being re-admitted. Now a configurable percentage of the samples must answer.

Two halves, and both are driven through the REAL path rather than the helper:

  * the VERDICT -- health_of, the sweep's own entry point, with only tun_probe stubbed. A guard that
    called carrying() directly would stay green if health_of stopped consulting it.
  * the JOURNEY -- op_tunnel, so the panel's value is actually PERSISTED. health_of reads the threshold
    off the stored config, so an un-whitelisted key is dropped in silence and the knob does nothing at
    all. That is exactly how cdn_profile was lost, and no amount of verdict testing would show it.

Exit 1 on any failure.
"""
import sys
sys.dont_write_bytecode = True
import importlib.util
import json
import os
import tempfile
from pathlib import Path

if hasattr(sys.stdout, "reconfigure"):   # Persian in a failure message on a cp1252 console
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

NODE = Path(__file__).resolve().parent.parent / "tnl-node.py"

fails = []


def want(cond, msg):
    print(("  ok  " if cond else " FAIL ") + msg)
    if not cond:
        fails.append(msg)


def load():
    spec = importlib.util.spec_from_file_location("tnl_node_probe", NODE)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


# ---------------------------------------------------------------- half 1: the verdict, via health_of
def verdict_half(m):
    print("== the verdict follows the threshold, driven through health_of ==")
    m.CONFIG_DIR = tempfile.mkdtemp()
    m.logline = lambda _msg: None
    m._pool_sighup = lambda name, is_pool, msg: {"ok": True}
    sent = []
    m._atomic_write_json = lambda path, obj: sent.append(obj) and None

    state = {"hits": 0, "dst_state": "healthy"}

    def pool(suffix):
        if suffix == ".srcpool":
            return {"active": "", "addrs": [], "pin": "", "ts": 0, "health": []}
        return {"active": "10.0.0.1", "addrs": ["10.0.0.1", "10.0.0.2"], "pin": "", "ts": 0,
                "health": [{"key": "10.0.0.1", "state": state["dst_state"], "fails": 0,
                            "next_retest_unix": 0}]}

    m._is_peer_pool = lambda name: True
    m._is_ws_pool = lambda name: False
    m._read_core_cfg = lambda name: {"role": "client"}
    m._read_peer_pool = lambda name, suffix: pool(suffix)
    m._flow_sample = lambda n: (0.0, 0.0)
    real_exists = os.path.exists
    os.path.exists = lambda p: True if str(p).startswith("/sys/class/net/") else real_exists(p)
    clock = {"t": 1000.0}
    m.time.monotonic = lambda: clock["t"]

    def sweep(name, hits, cfg_extra):
        """One real sweep: health_of -> tun_probe -> settle -> pool_failover."""
        state["hits"] = hits
        m.tun_probe = lambda *a, **k: (hits, m.PROBE_COUNT, 80.0 if hits else None)
        clock["t"] += 400.0     # past FAILOVER_SETTLE and any cooldown from a previous case
        n0 = len(sent)
        cfg = {"type": "core", "name": name, "tunnel_ip": "192.168.9.2/24"}
        cfg.update(cfg_extra)
        res = m.health_of(cfg)
        return res, [o for o in sent[n0:]]

    def cmds(msgs, kind):
        return [o for o in msgs if o.get("cmd") == kind]

    # --- the default threshold: 15% of 20 samples is 3 replies -------------------------------------
    for hits, alive_want, label in ((20, True, "a clean sweep"), (3, True, "exactly on the line"),
                                    (2, False, "one reply under the line"), (0, False, "silence")):
        res, _ = sweep(f"t-def-{hits}", hits, {})
        want(res["alive"] is alive_want,
             f"default 15%: {hits}/20 ({label}) -> alive={res['alive']}, want {alive_want}")

    # --- the same sample set, judged differently because the OPERATOR moved the line ----------------
    res, _ = sweep("t-lo", 2, {"probe_min_pct": 1})
    want(res["alive"] is True,
         f"2/20 at the operator's 1% must be ALIVE (that is the pre-knob behaviour), got {res['alive']}")
    res, _ = sweep("t-hi", 19, {"probe_min_pct": 100})
    want(res["alive"] is False,
         f"19/20 at the operator's 100% must be DEAD -- 100 means every sample, got {res['alive']}")
    res, _ = sweep("t-hi-ok", 20, {"probe_min_pct": 100})
    want(res["alive"] is True, f"20/20 at 100% must be alive, got {res['alive']}")

    # --- a lossy-but-crossing tunnel must NOT clear a burn ------------------------------------------
    # This is the one that let a filtered endpoint back in: 2 replies is not evidence the path carries.
    state["dst_state"] = "suspect"
    _res, msgs = sweep("t-clear-no", 2, {})
    want(cmds(msgs, "ok") == [],
         f"2/20 must NOT clear the burn on a condemned endpoint, got {cmds(msgs, 'ok')}")
    _res, msgs = sweep("t-clear-yes", 3, {})
    want(len(cmds(msgs, "ok")) == 1,
         f"3/20 is over the line, so a condemned endpoint that is carrying IS reported, got {msgs}")
    # ...and the same 2/20 clears it once the operator says 1% is enough.
    _res, msgs = sweep("t-clear-lo", 2, {"probe_min_pct": 1})
    want(len(cmds(msgs, "ok")) == 1,
         f"at 1% the same 2/20 must clear the burn -- the knob is what moved, got {msgs}")
    state["dst_state"] = "healthy"

    # --- and it BURNS, after the same RED_SWEEPS confirmation the colour gets -----------------------
    _res, msgs = sweep("t-burn", 2, {})
    want(cmds(msgs, "fail") == [], "one bad sweep must not burn anything (RED_SWEEPS still applies)")
    _res, msgs = sweep("t-burn", 2, {})
    want([o.get("key") for o in cmds(msgs, "fail")] == ["10.0.0.1"],
         f"a second sweep under the line must burn the measured endpoint, got {msgs}")
    # The identical sample set burns NOTHING when the operator's line is below it.
    for _ in range(3):
        _res, msgs = sweep("t-noburn", 2, {"probe_min_pct": 1})
    want(cmds(msgs, "fail") == [],
         f"2/20 at 1% must never burn -- it is over the operator's line, got {msgs}")

    # --- a malformed or out-of-range value falls back / clamps rather than crashing the sweep -------
    for bad, label in (({"probe_min_pct": "abc"}, "garbage"), ({"probe_min_pct": None}, "null"),
                       ({"probe_min_pct": 0}, "below the range"), ({"probe_min_pct": 9999}, "above it")):
        try:
            res, _ = sweep(f"t-bad-{label}", 20, bad)
        except Exception as e:
            want(False, f"a {label} threshold crashed the sweep: {type(e).__name__}: {e}")
            continue
        want(res["alive"] is True, f"a {label} threshold must still judge a clean 20/20 as alive")
    # 9999 clamps to 100, so it must be STRICTER than the default, not silently ignored.
    res, _ = sweep("t-clamp-hi", 19, {"probe_min_pct": 9999})
    want(res["alive"] is False,
         f"an out-of-range 9999 must CLAMP to 100 (19/20 dead), not fall back to the default, "
         f"got alive={res['alive']}")

    os.path.exists = real_exists


# ------------------------------------------------------- half 2: the journey, via the real op_tunnel
def journey_half(m):
    print()
    print("== the panel's value survives op_tunnel, for EVERY tunnel type ==")
    tmp = tempfile.mkdtemp()
    m.CONFIG_DIR = tmp
    m.logline = lambda _msg: None
    m.local_ips_flat = lambda: ["203.0.113.5"]
    m.iface_for_ip = lambda ip: "eth0"
    m.apply_config = lambda obj: None
    m.teardown_config = lambda obj: None
    m._netdev_missing_reason = lambda name, ttype: ""
    m.unique_name = lambda ttype, tid: f"{ttype}{tid}"

    def build(ttype, extra):
        d = {"type": ttype, "self_ip": "203.0.113.5", "peer_ip": "198.51.100.7",
             "subnet": "10.42.0.0/24", "host": 1, "id": 42, "name": f"{ttype}42"}
        if ttype == "core":
            d.update({"role": "server", "psk": "x" * 32, "cipher": "aes-256-gcm", "transport": "udp"})
        d.update(extra)
        res = m.op_tunnel(d)
        if not res.get("ok"):
            return res, None
        with open(os.path.join(tmp, f"{ttype}42.json")) as f:
            return res, json.load(f)

    # EVERY type the node builds, because the probe judges every one of them. A core-only knob would
    # colour a vxlan and a core tunnel on the same dashboard by two different rules.
    for ttype in ("vxlan", "gre", "ipip", "l2tpv3", "fou", "core"):
        res, stored = build(ttype, {"probe_min_pct": 42})
        if stored is None:
            want(False, f"{ttype}: op_tunnel refused the build: {res}")
            continue
        want(stored.get("probe_min_pct") == 42,
             f"{ttype}: stored probe_min_pct={stored.get('probe_min_pct')}, want 42 "
             f"(an un-whitelisted key is dropped in SILENCE and the knob does nothing)")

    # Out of range is clamped on the way IN as well, so a bad body cannot park a nonsense value on disk.
    _res, stored = build("vxlan", {"probe_min_pct": 500})
    want(stored is not None and stored.get("probe_min_pct") == 100,
         f"an out-of-range body value must be clamped on store, got {stored and stored.get('probe_min_pct')}")

    # Absent means absent: the node must not invent a value, or every tunnel would carry the node's
    # default frozen at build time and a later Settings change would never reach the ones not rebuilt.
    _res, stored = build("gre", {})
    want(stored is not None and "probe_min_pct" not in stored,
         f"a body with no threshold must store none, got {stored and stored.get('probe_min_pct')}")

    # ...and health_of then falls back to the node default for exactly that config.
    want(m.probe_min_pct(stored or {}) == m.PROBE_MIN_PCT,
         f"a stored config with no threshold must read back as PROBE_MIN_PCT={m.PROBE_MIN_PCT}")


def main():
    m = load()
    verdict_half(m)
    journey_half(m)
    print()
    if fails:
        print(f"FAILED - {len(fails)} problem(s).")
        return 1
    print("the probe verdict follows the operator's threshold, and the value reaches it.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
