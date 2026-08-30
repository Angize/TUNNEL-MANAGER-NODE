#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Guard: when the panel sends only a signed URL, the node proves the bytes against the release itself.

In github delivery the panel spends nothing: it never opens a connection to GitHub, so it has no
checksum to sign. It signs the download URL instead, and the node fetches the binary AND the release's
own .sha256 sidecar and checks one against the other.

That moves the checksum out of the panel's hands, so the security property has to be re-proved on this
side. Whoever can serve that URL still must not be able to install code the panel did not authorize,
and the worst they can do is fail. Every case drives the REAL op_core_put and op_core_apply with only
the download boundary stubbed, and looks at what is on disk afterwards -- not at the return value.

The older shape, where the panel DID download and signs the sha256, is re-asserted in the same run:
both live at once, one per delivery mode, and neither may weaken the other.

Run with no arguments. Exit 0 = a signed URL is as safe as a signed checksum.
"""
import base64
import hashlib
import importlib.util
import os
import subprocess
import sys
import tempfile

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

HERE = os.path.dirname(os.path.abspath(__file__))
NODE = os.path.join(os.path.dirname(HERE), "tnl-node.py")

CORE = b"\x7fELF" + b"x" * 300000
CSHA = hashlib.sha256(CORE).hexdigest()
URL = "https://github.com/Angize/TUNNEL-MANAGER-CORE/releases/download/v9.9.9/tnl-core-linux-amd64"
VER = "v9.9.9"

FAILED = []


def check(name, cond, detail=""):
    print(("  ok   " if cond else " FAIL  ") + name + (("  -- " + detail) if detail and not cond else ""))
    if not cond:
        FAILED.append(name)


def load_node():
    spec = importlib.util.spec_from_file_location("tnl_node_urlgrant", NODE)
    mod = importlib.util.module_from_spec(spec)
    sys.modules["tnl_node_urlgrant"] = mod
    spec.loader.exec_module(mod)
    return mod


def keypair(d):
    os.makedirs(d, exist_ok=True)
    priv, pub = os.path.join(d, "k.pem"), os.path.join(d, "k.pub")
    subprocess.run(["openssl", "genrsa", "-out", priv, "2048"], capture_output=True, check=True)
    subprocess.run(["openssl", "rsa", "-in", priv, "-pubout", "-out", pub], capture_output=True, check=True)
    with open(pub) as f:
        return priv, f.read()


def sign(priv, msg):
    p = subprocess.run(["openssl", "dgst", "-sha256", "-sign", priv], input=msg,
                       capture_output=True, check=True)
    return base64.b64encode(p.stdout).decode()


def serve(mod, tmp, table):
    got = []

    def fetch(url, max_bytes, timeout=180, budget=None):
        got.append(url)
        if url not in table:
            raise OSError("HTTP 404")
        b = table[url]
        if len(b) > max_bytes:
            raise ValueError("downloaded file is larger than %d bytes" % max_bytes)
        return b

    mod._fetch_url = fetch
    mod.CORE_BIN = os.path.join(tmp, "tnl-core")
    mod.CORE_STAGED = mod.CORE_BIN + ".new"
    mod.build_core = lambda c: None
    mod.raw_configs = lambda: []
    mod.svc = lambda *a, **k: None
    mod.logline = lambda *a, **k: None
    for p in (mod.CORE_BIN, mod.CORE_STAGED):
        if os.path.isfile(p):
            os.remove(p)
    return got


def on_disk(mod):
    if not os.path.isfile(mod.CORE_BIN):
        return None
    with open(mod.CORE_BIN, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()


def main():
    mod = load_node()
    tmp = tempfile.mkdtemp()
    priv, pub = keypair(os.path.join(tmp, "panel"))
    other, _ = keypair(os.path.join(tmp, "impostor"))
    mod.CONFIG_DIR = tmp
    mod.NODE_CONF = os.path.join(tmp, "node.conf")
    mod.save_conf({"port": 8099, "token": "t", "update_pubkey": pub})

    good = {URL: CORE, URL + ".sha256": (CSHA + "  tnl-core-linux-amd64\n").encode()}
    grant = {"url": URL, "version": VER, "sig": sign(priv, URL.encode())}

    got = serve(mod, tmp, good)
    r1 = mod.op_core_put(dict(grant))
    r2 = mod.op_core_apply(dict(grant))
    check("a signed url installs, and the node fetched both halves itself",
          r1.get("ok") and r2.get("ok") and on_disk(mod) == CSHA, "%r %r" % (r1, r2))
    check("  the sidecar really came from the release", (URL + ".sha256") in got, repr(got))
    check("  and the version label survived", r2.get("version") == VER, repr(r2))

    got = serve(mod, tmp, {URL: CORE[:-1] + b"Z", URL + ".sha256": good[URL + ".sha256"]})
    r = mod.op_core_put(dict(grant))
    check("a binary that misses the release checksum installs nothing",
          r.get("code") == "sha_mismatch" and on_disk(mod) is None, repr(r))

    got = serve(mod, tmp, good)
    bad = dict(grant, url=URL.replace("amd64", "evil"))
    r = mod.op_core_put(bad)
    check("a url the panel never signed installs nothing", r.get("code") == "bad_signature", repr(r))
    check("  and is refused before the node touches that url", not got, repr(got))

    got = serve(mod, tmp, good)
    r = mod.op_core_put(dict(grant, sig=sign(other, URL.encode())))
    check("a url signed by someone else installs nothing",
          r.get("code") == "bad_signature" and not got and on_disk(mod) is None, repr(r))

    got = serve(mod, tmp, good)
    nosig = {k: v for k, v in grant.items() if k != "sig"}
    r = mod.op_core_put(nosig)
    check("a url with no signature at all installs nothing",
          r.get("code") == "bad_signature" and not got and on_disk(mod) is None, repr(r))

    got = serve(mod, tmp, {URL: CORE})
    r = mod.op_core_put(dict(grant))
    check("a release that publishes no checksum installs nothing",
          r.get("code") == "checksum_unavailable" and on_disk(mod) is None, repr(r))

    got = serve(mod, tmp, {URL: CORE, URL + ".sha256": b"not-a-checksum\n"})
    r = mod.op_core_put(dict(grant))
    check("a sidecar that is not a checksum installs nothing",
          r.get("code") == "checksum_unavailable" and on_disk(mod) is None, repr(r))

    got = serve(mod, tmp, good)
    mod.op_core_put(dict(grant))
    r = mod.op_core_apply(dict(grant, url=URL.replace("amd64", "evil")))
    check("the apply step checks the signature too, not just the put step",
          r.get("code") == "bad_signature" and on_disk(mod) is None, repr(r))

    got = serve(mod, tmp, good)
    signed_sha = {"url": URL, "sha256": CSHA, "version": VER, "sig": sign(priv, CSHA.encode())}
    r1 = mod.op_core_put(dict(signed_sha))
    r2 = mod.op_core_apply(dict(signed_sha))
    check("the older shape -- a signed sha256 -- still installs, for the modes that use it",
          r1.get("ok") and r2.get("ok") and on_disk(mod) == CSHA, "%r %r" % (r1, r2))
    check("  and with a sha256 present the node does NOT go asking for a sidecar",
          (URL + ".sha256") not in got, repr(got))

    got = serve(mod, tmp, good)
    r = mod.op_core_put(dict(signed_sha, sha256=hashlib.sha256(b"other").hexdigest()))
    check("  a sha256 the panel did not sign still installs nothing",
          r.get("code") == "bad_signature" and on_disk(mod) is None, repr(r))

    got = serve(mod, tmp, good)
    try:
        r = mod.op_core_put({"version": VER, "sig": sign(priv, URL.encode())})
        why, refused = repr(r), False
    except ValueError as e:
        why, refused = str(e), True
    check("a grant with neither a checksum nor a url is refused outright",
          refused and on_disk(mod) is None and not got, why)

    print()
    if FAILED:
        print("%d failure(s)" % len(FAILED))
        return 1
    print("a signed url is proved against the release, and only the panel can name one")
    return 0


if __name__ == "__main__":
    sys.exit(main())
