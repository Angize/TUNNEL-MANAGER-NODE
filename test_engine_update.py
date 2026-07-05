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


# ---- download source: the GitHub Release ASSET only (no repo-tree fallback) ----
u = tnl._engine_urls("v2", "amd64")
check("pinned: single release-asset URL",
      u == ["https://github.com/Angize/TUNNEL-MANAGER-ENGINE/releases/download/v2/tnl-engine-linux-amd64"])
u = tnl._engine_urls("latest", "amd64")
check("latest: single releases/latest asset URL",
      len(u) == 1 and "/releases/latest/download/" in u[0])
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

# ---- no auto-update: with a binary present, force=False touches nothing ----
import tempfile
d = tempfile.mkdtemp()
tnl.ENGINE_BIN = os.path.join(d, "tnl-engine")
open(tnl.ENGINE_BIN, "wb").write(b"EXISTING-BINARY")
net = {"n": 0}
tnl._http_get = lambda *a, **k: (net.__setitem__("n", net["n"] + 1) or None)
tnl._ensure_engine(force=False)   # routine rebuild path
check("rebuild (force=False) makes no network call when a binary exists", net["n"] == 0)
check("rebuild (force=False) leaves the binary unchanged", open(tnl.ENGINE_BIN, "rb").read() == b"EXISTING-BINARY")

print()
if FAILS:
    print("%d FAILED: %s" % (len(FAILS), ", ".join(FAILS)))
    sys.exit(1)
print("all engine-update tests passed")
