#!/usr/bin/env python3
# Tests for the engine version pin / update logic (no root, no live install).
# Run: python3 test_engine_update.py
import importlib.util
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
spec = importlib.util.spec_from_file_location("tnl", os.path.join(HERE, "tnl-node.py"))
tnl = importlib.util.module_from_spec(spec)
spec.loader.exec_module(tnl)

FAILS = []


def check(name, cond):
    print(("ok  " if cond else "FAIL") + "  " + name)
    if not cond:
        FAILS.append(name)


# ---- download URL priority: Release asset first, raw-from-tag fallback ----
u = tnl._engine_urls("v2", "amd64")
check("pinned: release asset URL first",
      u[0] == "https://github.com/Angize/TUNNEL-MANAGER-ENGINE/releases/download/v2/tnl-engine-linux-amd64")
check("pinned: raw-from-tag fallback second",
      u[1] == "https://raw.githubusercontent.com/Angize/TUNNEL-MANAGER-ENGINE/v2/dist/tnl-engine-linux-amd64")
u = tnl._engine_urls("latest", "amd64")
check("latest: releases/latest asset first", "/releases/latest/download/" in u[0])
check("latest: raw main/dist fallback second", u[1].endswith("/main/dist/tnl-engine-linux-amd64"))
check("arch flows into the asset name", "arm64" in tnl._engine_urls("v1", "arm64")[0])

# ---- version-string validation (op_engine_update) ----
check("accepts a tag", bool(tnl.ENGINE_VER_RE.match("v2")))
check("accepts v10", bool(tnl.ENGINE_VER_RE.match("v10")))
check("accepts a dotted version", bool(tnl.ENGINE_VER_RE.match("1.2.3")))
check("rejects spaces", not tnl.ENGINE_VER_RE.match("v2 rm -rf"))
check("rejects path traversal", not tnl.ENGINE_VER_RE.match("../etc"))
check("rejects slashes", not tnl.ENGINE_VER_RE.match("a/b"))

# ---- op_engine_update validation path (bad version rejected before any I/O) ----
try:
    tnl.op_engine_update({"version": "bad; version"})
    check("op_engine_update rejects a bad version", False)
except ValueError:
    check("op_engine_update rejects a bad version", True)

# ---- pin default is "latest" when conf has no pin ----
tnl.load_conf = lambda: {}
check("_engine_ref defaults to latest", tnl._engine_ref() == "latest")
tnl.load_conf = lambda: {"engine_version": "v1"}
check("_engine_ref reads the pin", tnl._engine_ref() == "v1")

print()
if FAILS:
    print("%d FAILED: %s" % (len(FAILS), ", ".join(FAILS)))
    sys.exit(1)
print("all engine-update tests passed")
