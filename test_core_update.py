#!/usr/bin/env python3
# Tests for the core version pin / update logic (no root, no live install).
# Run: python3 test_core_update.py
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
u = tnl._core_urls("v2", "amd64")
check("pinned: single release-asset URL",
      u == ["https://github.com/Angize/TUNNEL-MANAGER-ENGINE/releases/download/v2/tnl-core-linux-amd64"])
u = tnl._core_urls("latest", "amd64")
check("latest: single releases/latest asset URL",
      len(u) == 1 and "/releases/latest/download/" in u[0])
check("arch flows into the asset name", "arm64" in tnl._core_urls("v1", "arm64")[0])

# ---- version-string validation (op_core_update) ----
check("accepts a tag", bool(tnl.CORE_VER_RE.match("v2")))
check("accepts v10", bool(tnl.CORE_VER_RE.match("v10")))
check("accepts a dotted version", bool(tnl.CORE_VER_RE.match("1.2.3")))
check("rejects spaces", not tnl.CORE_VER_RE.match("v2 rm -rf"))
check("rejects path traversal", not tnl.CORE_VER_RE.match("../etc"))
check("rejects slashes", not tnl.CORE_VER_RE.match("a/b"))
check("rejects bare '..'", not tnl.CORE_VER_RE.match(".."))
check("rejects embedded '..'", not tnl.CORE_VER_RE.match("v1..v2"))
check("still accepts single-dot dotted tag", bool(tnl.CORE_VER_RE.match("v1.2")))

# ---- op_core_update rejects a traversal tag before any I/O (#L2) ----
try:
    tnl.op_core_update({"version": ".."})
    check("op_core_update rejects '..'", False)
except ValueError:
    check("op_core_update rejects '..'", True)

# ---- op_core_update validation path (bad version rejected before any I/O) ----
try:
    tnl.op_core_update({"version": "bad; version"})
    check("op_core_update rejects a bad version", False)
except ValueError:
    check("op_core_update rejects a bad version", True)

# ---- pin default is "latest" when conf has no pin ----
tnl.load_conf = lambda: {}
check("_core_ref defaults to latest", tnl._core_ref() == "latest")
tnl.load_conf = lambda: {"core_version": "v1"}
check("_core_ref reads the pin", tnl._core_ref() == "v1")

# ---- no auto-update: with a binary present, force=False touches nothing ----
import tempfile
d = tempfile.mkdtemp()
tnl.CORE_BIN = os.path.join(d, "tnl-core")
open(tnl.CORE_BIN, "wb").write(b"EXISTING-BINARY")
net = {"n": 0}
tnl._http_get = lambda *a, **k: (net.__setitem__("n", net["n"] + 1) or None)
tnl._ensure_core(force=False)   # routine rebuild path
check("rebuild (force=False) makes no network call when a binary exists", net["n"] == 0)
check("rebuild (force=False) leaves the binary unchanged", open(tnl.CORE_BIN, "rb").read() == b"EXISTING-BINARY")

# ---- core-install: custom binary pushed from the panel (base64 + sha verify) ----
import base64
import hashlib
tnl.raw_configs = lambda: []           # no core tunnels to rebuild in the test
tnl.logline = lambda *a, **k: None
_conf = {}
tnl.load_conf = lambda: dict(_conf)
tnl.save_conf = lambda c: _conf.update(c)
blob = b"\x7fELF" + b"x" * 100000       # >100KB so it clears the size gate
b64 = base64.b64encode(blob).decode()
good = hashlib.sha256(blob).hexdigest()

r = tnl.op_core_install({"data": b64, "sha256": "0" * 64})
check("core-install rejects a checksum mismatch", r.get("ok") is False)

small = b"tiny"
r = tnl.op_core_install({"data": base64.b64encode(small).decode(), "sha256": hashlib.sha256(small).hexdigest()})
check("core-install rejects a too-small binary", r.get("ok") is False)

try:
    tnl.op_core_install({"data": b64, "sha256": "nothex"})
    check("core-install rejects a malformed sha", False)
except ValueError:
    check("core-install rejects a malformed sha", True)

r = tnl.op_core_install({"data": b64, "sha256": good, "version": "custom"})
check("core-install ok on a verified binary", r.get("ok") is True and r.get("core_sha") == good[:12])
check("core-install wrote the exact bytes", open(tnl.CORE_BIN, "rb").read() == blob)
check("core-install pins the node to the label", _conf.get("core_version") == "custom")
check("core-install is a mutation (not read-only)", "core-install" in tnl.OPS and "core-install" not in tnl.READ_ONLY)

print()
if FAILS:
    print("%d FAILED: %s" % (len(FAILS), ", ".join(FAILS)))
    sys.exit(1)
print("all core-update tests passed")
