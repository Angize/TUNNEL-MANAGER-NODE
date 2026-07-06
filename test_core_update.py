#!/usr/bin/env python3
# Tests for the core binary delivery. The node NEVER downloads the core itself — the panel pushes
# verified bytes via op core-install. Run: python3 test_core_update.py
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


# ---- the node no longer has any self-download machinery ----
check("no _core_urls (self-download removed)", not hasattr(tnl, "_core_urls"))
check("no _http_get (self-download removed)", not hasattr(tnl, "_http_get"))
check("no op_core_update (node never downloads)", not hasattr(tnl, "op_core_update"))
check("no core-update op route", "core-update" not in tnl.OPS)

# ---- pin label reflects what was installed; empty when nothing installed ----
tnl.load_conf = lambda: {}
check("_core_ref empty when nothing installed", tnl._core_ref() == "")
tnl.load_conf = lambda: {"core_version": "v2.2.2"}
check("_core_ref reads the installed label", tnl._core_ref() == "v2.2.2")

# ---- _ensure_core: present -> ok; absent -> a clear, panel-detectable error (no network) ----
import tempfile
d = tempfile.mkdtemp()
tnl.CORE_BIN = os.path.join(d, "tnl-core")
try:
    tnl._ensure_core()
    check("_ensure_core raises when the binary is missing", False)
except RuntimeError as e:
    check("_ensure_core raises when the binary is missing", "not installed" in str(e))
open(tnl.CORE_BIN, "wb").write(b"EXISTING-BINARY")
try:
    tnl._ensure_core()
    check("_ensure_core is a no-op when a binary exists", True)
except Exception:
    check("_ensure_core is a no-op when a binary exists", False)
check("_ensure_core leaves the binary untouched", open(tnl.CORE_BIN, "rb").read() == b"EXISTING-BINARY")

# ---- core-install: verified bytes pushed from the panel (base64 + sha verify) ----
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

r = tnl.op_core_install({"data": b64, "sha256": good, "version": "v2.2.2"})
check("core-install ok on a verified binary", r.get("ok") is True and r.get("core_sha") == good[:12])
check("core-install wrote the exact bytes", open(tnl.CORE_BIN, "rb").read() == blob)
check("core-install pins the node to the pushed label", _conf.get("core_version") == "v2.2.2")
check("core-install is a mutation (not read-only)", "core-install" in tnl.OPS and "core-install" not in tnl.READ_ONLY)

# re-pushing the SAME binary is a no-op: no swap, no tunnel restart (unchanged=True)
_rebuilt = {"n": 0}
tnl.raw_configs = lambda: [{"type": "core", "name": "c1"}]
tnl.build_core = lambda c: _rebuilt.__setitem__("n", _rebuilt["n"] + 1)
r = tnl.op_core_install({"data": b64, "sha256": good, "version": "v2.2.2"})
check("re-push same binary => unchanged", r.get("unchanged") is True)
check("re-push same binary => no tunnel restart", _rebuilt["n"] == 0 and r.get("restarted") == 0)

# ---- ping advertises arch + installed sha so the panel can relay/label ----
check("ping reports arch", tnl._core_arch() in ("amd64", "arm64"))

print()
if FAILS:
    print("%d FAILED: %s" % (len(FAILS), ", ".join(FAILS)))
    sys.exit(1)
print("all core-update tests passed")
