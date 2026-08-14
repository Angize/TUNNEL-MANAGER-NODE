#!/usr/bin/env python3
"""Guard: a node that fetches its own update verifies it exactly as hard as one that is handed the bytes.

The panel can deliver an agent or a core two ways: it uploads the bytes, or it sends a URL and the node
downloads them itself. The second mode saves the panel's uplink -- and it is the mode that can quietly
lose the whole security property, because the bytes now come from somewhere the panel does not control.

They must not. The panel still sends the sha256 and its RSA signature OVER that sha, and the node
checks both before anything is written. So the trust chain is identical in both modes: whoever serves
the URL cannot install code the panel did not authorize; the worst they can do is fail the checksum.

Every test drives the REAL op_update / op_core_install with only the network boundary stubbed.

Run with no arguments. Exit 0 = a fetched update is as safe as a pushed one.
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

AGENT_SRC = '# {"agent": "tnl-node", "version": 999}\nprint("hello")\n'
CORE_BYTES = b"\x7fELF" + b"x" * 200000          # over the node's 100 KB floor

fails = []


def fail(msg):
    fails.append(msg)
    print("FAIL: " + msg)


def ok(msg):
    print("  ok  " + msg)


def load_node():
    spec = importlib.util.spec_from_file_location("tnl_node", NODE)
    mod = importlib.util.module_from_spec(spec)
    sys.modules["tnl_node"] = mod
    spec.loader.exec_module(mod)
    return mod


def keypair(tmp):
    """A real RSA keypair, so the signature path under test is the real openssl one."""
    priv = os.path.join(tmp, "k.pem")
    pub = os.path.join(tmp, "k.pub")
    subprocess.run(["openssl", "genrsa", "-out", priv, "2048"],
                   capture_output=True, check=True)
    subprocess.run(["openssl", "rsa", "-in", priv, "-pubout", "-out", pub],
                   capture_output=True, check=True)
    with open(pub) as f:
        return priv, f.read()


def sign(priv, msg):
    p = subprocess.run(["openssl", "dgst", "-sha256", "-sign", priv],
                       input=msg, capture_output=True, check=True)
    return base64.b64encode(p.stdout).decode()


def drive(mod, tmp, op, payload, served=None, serve_err=None):
    """Run the real op with the download boundary stubbed. Returns its result dict."""
    calls = []

    def fake_fetch(url, max_bytes, timeout=180):
        calls.append((url, max_bytes))
        if serve_err:
            raise serve_err
        if len(served) > max_bytes:
            raise ValueError("downloaded file is larger than %d bytes" % max_bytes)
        return served

    saved = {k: getattr(mod, k) for k in ("_fetch_url", "CONFIG_DIR", "NODE_CONF", "INSTALLED",
                                          "CORE_BIN", "build_core", "svc")}
    mod._fetch_url = fake_fetch
    mod.CONFIG_DIR = tmp
    mod.NODE_CONF = os.path.join(tmp, "node.conf")
    mod.INSTALLED = os.path.join(tmp, "tnl-node.py")
    mod.CORE_BIN = os.path.join(tmp, "tnl-core")
    mod.build_core = lambda c: None     # relaunching real tunnels is build_core's subject, not this one
    mod.svc = lambda *a, **k: None
    try:
        return op(payload), calls
    finally:
        for k, v in saved.items():
            setattr(mod, k, v)


def main():
    mod = load_node()
    with tempfile.TemporaryDirectory() as tmp:
        os.makedirs(os.path.join(tmp, "panel"), exist_ok=True)
        os.makedirs(os.path.join(tmp, "impostor"), exist_ok=True)
        priv, pub = keypair(os.path.join(tmp, "panel"))
        # A SEPARATE directory: generating the impostor's key over the panel's would replace the very
        # key the node was provisioned with, and every later case would fail for the wrong reason.
        other_priv, _ = keypair(os.path.join(tmp, "impostor"))
        mod.CONFIG_DIR = tmp
        mod.NODE_CONF = os.path.join(tmp, "node.conf")
        mod.save_conf({"port": 8099, "token": "t", "update_pubkey": pub})

        asha = hashlib.sha256(AGENT_SRC.encode()).hexdigest()
        csha = hashlib.sha256(CORE_BYTES).hexdigest()

        # --- the mode has to WORK, or the rest of this proves nothing about a real path -------------
        r, calls = drive(mod, tmp, mod.op_update,
                         {"url": "https://example/agent.py", "sha256": asha, "sig": sign(priv, asha.encode())},
                         served=AGENT_SRC.encode())
        if not r.get("ok"):
            fail("a correctly signed URL update was refused: %s" % r.get("msg"))
        elif not calls:
            fail("op_update reported ok without downloading anything")
        else:
            ok("a signed URL update installs, and the node really fetched it")

        # --- and it must be refused on every gate a byte push has ------------------------------------
        cases = [
            ("no sha256 at all", {"url": "https://example/a.py", "sig": sign(priv, asha.encode())},
             AGENT_SRC.encode(), "sha256"),
            ("the sha does not match what was served",
             {"url": "https://example/a.py", "sha256": asha, "sig": sign(priv, asha.encode())},
             AGENT_SRC.encode() + b"# tampered\n", "checksum"),
            ("no signature", {"url": "https://example/a.py", "sha256": asha}, AGENT_SRC.encode(), "signature"),
            ("a signature by SOMEONE ELSE's key",
             {"url": "https://example/a.py", "sha256": asha,
              "sig": sign(other_priv, asha.encode())},
             AGENT_SRC.encode(), "signature"),
        ]
        for name, payload, served, want in cases:
            r, _ = drive(mod, tmp, mod.op_update, payload, served=served)
            if r.get("ok"):
                fail("op_update ACCEPTED an update with %s — a hostile mirror owns every node" % name)
            elif want not in str(r.get("msg", "")).lower():
                fail("op_update refused %s but said %r, which does not name the reason" % (name, r.get("msg")))
            else:
                ok("op_update refuses: %s" % name)

        # a download that fails must be an error, never a silent success
        r, _ = drive(mod, tmp, mod.op_update,
                     {"url": "https://example/a.py", "sha256": asha, "sig": sign(priv, asha.encode())},
                     serve_err=OSError("connection refused"))
        if r.get("ok") or "download" not in str(r.get("msg", "")).lower():
            fail("a failed download did not surface as a download error: %r" % r)
        else:
            ok("op_update surfaces a failed download")

        # --- the core half ---------------------------------------------------------------------------
        r, calls = drive(mod, tmp, mod.op_core_install,
                         {"url": "https://example/tnl-core", "sha256": csha,
                          "sig": sign(priv, csha.encode()), "version": "v2.68.0"},
                         served=CORE_BYTES)
        if not r.get("ok"):
            fail("a correctly signed URL core install was refused: %s" % r.get("msg"))
        elif not calls:
            fail("op_core_install reported ok without downloading anything")
        else:
            ok("a signed URL core install works, and the node really fetched it")

        for name, payload, served, want in [
            ("the sha does not match what was served",
             {"url": "https://example/c", "sha256": csha, "sig": sign(priv, csha.encode())},
             CORE_BYTES + b"tamper", "checksum"),
            ("no signature", {"url": "https://example/c", "sha256": csha}, CORE_BYTES, "signature"),
        ]:
            r, _ = drive(mod, tmp, mod.op_core_install, payload, served=served)
            if r.get("ok"):
                fail("op_core_install ACCEPTED a core with %s — that binary runs as root" % name)
            elif want not in str(r.get("msg", "")).lower():
                fail("op_core_install refused %s but said %r" % (name, r.get("msg")))
            else:
                ok("op_core_install refuses: %s" % name)

        # a tiny download is still refused by the size floor, exactly as a tiny push is
        small = b"nope"
        r, _ = drive(mod, tmp, mod.op_core_install,
                     {"url": "https://example/c", "sha256": hashlib.sha256(small).hexdigest(),
                      "sig": sign(priv, hashlib.sha256(small).hexdigest().encode())},
                     served=small)
        if r.get("ok"):
            fail("op_core_install installed a 4-byte 'core'")
        else:
            ok("op_core_install still refuses a too-small binary in URL mode")

        # --- the REAL _fetch_url, with only urlopen stubbed ------------------------------------------
        opened = []

        class FakeResp:
            def __init__(self, body, declared=None):
                self.body = body
                # A real server announces the full size and can still close mid-body; read() then
                # returns SHORT and raises nothing. `declared` is how that is reproduced here.
                self.headers = {"Content-Length": str(len(body) if declared is None else declared)}

            def read(self, n=-1):
                return self.body[:n] if n and n > 0 else self.body

            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

        def fake_urlopen(req, timeout=None):
            opened.append(getattr(req, "full_url", req))
            return FakeResp(body[0], declared[0])

        body, declared = [b"x" * 10], [None]
        saved_open = mod.urllib.request.urlopen
        mod.urllib.request.urlopen = fake_urlopen
        try:
            for name, url, payload, cap, want in [
                ("a plaintext http:// URL to somewhere else", "http://evil.example/a.py", b"x" * 10, 1024, "https"),
                ("a plaintext URL at the panel's IP but the wrong port",
                 "http://10.9.9.9:9999/a.py", b"x" * 10, 1024, "https"),
                ("a URL that is neither http nor https", "file:///etc/passwd", b"x" * 10, 1024, "https"),
                ("a body over the cap", "https://example/a.py", b"x" * 2048, 1024, "larger"),
                ("an empty body", "https://example/a.py", b"", 1024, "empty"),
            ]:
                opened.clear()
                body[0] = payload
                try:
                    mod._fetch_url(url, cap)
                    fail("_fetch_url accepted %s" % name)
                except ValueError as e:
                    if want not in str(e).lower():
                        fail("_fetch_url refused %s but said %r" % (name, str(e)))
                    else:
                        ok("_fetch_url refuses %s" % name)
                except Exception as e:
                    fail("_fetch_url refused %s with the wrong kind of error: %r" % (name, e))
                # A bad SCHEME must be refused before anything is dialled; the size/empty cases can only
                # be judged after reading, so only the first case is checked for this.
                if name.startswith("a plaintext") and opened:
                    fail("_fetch_url dialled %s before refusing its scheme" % opened[-1])
            opened.clear()
            body[0] = b"fine"
            if mod._fetch_url("https://example/a.py", 1024) != b"fine" or not opened:
                fail("_fetch_url did not return the body it downloaded")
            else:
                ok("_fetch_url returns the body of an acceptable download")

            # A CUT TRANSFER MUST SAY SO. Without this the short body reaches the sha256 gate and comes
            # back as «checksum mismatch», which blames the file the panel staged for a transfer that
            # was cut -- measured against a real panel at 5613896 of 11243704 bytes.
            body[0], declared[0] = b"x" * 400, 1000
            try:
                mod._fetch_url("https://example/core", 65536)
                fail("_fetch_url accepted a body shorter than its own Content-Length")
            except ValueError as e:
                msg = str(e).lower()
                if "truncated" in msg and "400" in msg and "1000" in msg:
                    ok("_fetch_url refuses a truncated download and names both sizes")
                else:
                    fail("_fetch_url refused the truncation but said %r" % str(e))
            # ...and it must not turn a server that declares nothing into a failure.
            body[0], declared[0] = b"fine", 0
            if mod._fetch_url("https://example/a.py", 1024) != b"fine":
                fail("_fetch_url refused a download whose server declared no Content-Length")
            else:
                ok("_fetch_url still accepts a body with no Content-Length declared")
            declared[0] = None

            # The ONE plaintext exception: the panel's own origin, and only while the node really has
            # one pinned. The panel runs plain HTTP today; nothing else may be fetched that way.
            saved_cb = mod._central_cb
            try:
                mod._central_cb = None
                try:
                    mod._fetch_url("http://10.9.9.9:2053/api/artifact", 1024)
                    fail("_fetch_url accepted plaintext with NO panel origin pinned — anyone could claim it")
                except ValueError:
                    ok("_fetch_url refuses plaintext when no panel origin is pinned")

                mod._central_cb = ("10.9.9.9", 2053, False)
                opened.clear()
                if mod._fetch_url("http://10.9.9.9:2053/api/artifact", 1024) != b"fine" or not opened:
                    fail("_fetch_url refused plaintext from the panel's OWN origin, so a plain-HTTP "
                         "panel could never serve the artifacts")
                else:
                    ok("_fetch_url allows plaintext from the panel's own origin")
                for bad, why in [("http://10.9.9.9:9999/a", "a different port"),
                                 ("http://10.9.9.8:2053/a", "a different host")]:
                    try:
                        mod._fetch_url(bad, 1024)
                        fail("_fetch_url accepted plaintext from %s" % why)
                    except ValueError:
                        ok("_fetch_url still refuses plaintext from %s" % why)
                # ...and once the panel announces TLS, its own origin is https, so the plaintext
                # exception has nothing left to apply to and closes itself.
                mod._central_cb = ("10.9.9.9", 2053, True)
                try:
                    mod._fetch_url("http://10.9.9.9:2053/api/artifact", 1024)
                    fail("_fetch_url accepted plaintext from a panel that announced TLS")
                except ValueError:
                    ok("_fetch_url refuses plaintext once the panel announces TLS")
            finally:
                mod._central_cb = saved_cb
        finally:
            mod.urllib.request.urlopen = saved_open

    print()
    if fails:
        print("%d FAILURE(S)" % len(fails))
        return 1
    print("a fetched update is verified exactly as a pushed one is")
    return 0


if __name__ == "__main__":
    sys.exit(main())
