#!/usr/bin/env python3
"""The panel can prove it is the panel without handing over the secret — and a capture cannot be replayed.

Today every panel->node request carries the shared token in cleartext, on a path that crosses a censor.
Anyone who watches one request owns the node's control plane. A signed request fixes that at the root:
what crosses is an HMAC over this request's own method, path, counter and body hash, so an observer
learns nothing reusable.

Four properties, all of which a plausible-looking implementation can lose:

  1. a correctly signed request is ACCEPTED, and the token never has to appear;
  2. a captured request REPLAYED verbatim is refused -- this is the counter's whole job;
  3. a signature that does not cover THIS request is refused: wrong method, wrong path, wrong body,
     wrong counter, or a signature made with someone else's secret;
  4. the bare token proves NOTHING any more -- the changeover window is closed, and a token is exactly
     what an observer of this wire would have -- and the node must not read the body of a request that
     proved nothing.

Driven against the REAL handler over a REAL socket. Nothing is stubbed but the config directory.

    python3 tools/signed_request_test.py
"""
import base64
import hashlib
import hmac
import http.client
import importlib.util
import json
import os
import socket
import sys
import tempfile
import threading
import time

HERE = os.path.dirname(os.path.abspath(__file__))
NODE = os.path.join(os.path.dirname(HERE), "tnl-node.py")
TOKEN = "s3cr3t-token"

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

fails = []


def ok(m):
    print("  ok   " + m)


def fail(m):
    fails.append(m)
    print(" FAIL  " + m)


def check(name, cond, detail=""):
    (ok if cond else fail)(name + (("  -- " + detail) if detail and not cond else ""))


def load_node(tmp):
    spec = importlib.util.spec_from_file_location("tnl_node_sig", NODE)
    mod = importlib.util.module_from_spec(spec)
    sys.modules["tnl_node_sig"] = mod
    spec.loader.exec_module(mod)
    mod.CONFIG_DIR = tmp
    mod.NODE_CONF = os.path.join(tmp, "node.conf")
    mod.LOG_FILE = os.path.join(tmp, "agent.log")
    mod.save_conf({"port": 8099, "token": TOKEN})
    mod._seed_req_ctr()
    return mod


def sign(secret, method, path, ctr, body=b""):
    body_sha = hashlib.sha256(body).hexdigest() if body else ""
    msg = "%s\n%s\n%s\n%s" % (method, path, ctr, body_sha)
    mac = hmac.new(secret.encode(), msg.encode(), hashlib.sha256).digest()
    return {"X-Ctr": str(ctr), "X-Body": body_sha, "X-Sig": base64.b64encode(mac).decode()}


def call(port, method, path, headers, body=b"", timeout=10):
    """(status, json). status 0 = the node closed on us without answering."""
    c = http.client.HTTPConnection("127.0.0.1", port, timeout=timeout)
    h = dict(headers)
    if body:
        h["Content-Type"] = "application/json"
    try:
        c.request(method, path, body=body or None, headers=h)
        r = c.getresponse()
        raw = r.read()
        try:
            d = json.loads(raw.decode() or "{}")
        except Exception:
            d = {}
        return r.status, d
    except (ConnectionResetError, http.client.RemoteDisconnected, OSError):
        return 0, {}
    finally:
        c.close()


# The subject here is AUTHENTICATION, not what an op does. Several ops shell out to `ip` and friends
# and cannot run against a bare temp directory, so a 500 means "the node accepted me and then the op
# failed" -- which for this guard is a pass. Only 401 and 409 are refusals.
def served(st):
    return st not in (0, 401, 409)


class Slow:
    """A client that announces a body and then never sends it. If the node reads before it has decided
    the caller is genuine, this pins a worker; if it decides first, the socket is dropped at once."""

    def __init__(self, port, headers, announce=20 * 1024 * 1024):
        self.port, self.headers, self.announce = port, headers, announce

    def run(self, timeout=6):
        s = socket.create_connection(("127.0.0.1", self.port), timeout=timeout)
        try:
            head = "POST /api/mk HTTP/1.1\r\nHost: x\r\nContent-Length: %d\r\n" % self.announce
            for k, v in self.headers.items():
                head += "%s: %s\r\n" % (k, v)
            s.sendall((head + "\r\n").encode())
            s.sendall(b"{")                     # one byte, then nothing, ever
            s.settimeout(timeout)
            t0 = time.time()
            buf = b""
            try:
                while b"\r\n\r\n" not in buf:
                    c = s.recv(4096)
                    if not c:
                        break
                    buf += c
            except OSError:
                # Refusing before reading leaves our announced body unsent, and the close comes back to
                # this side as a reset. That IS the refusal, so it counts as one.
                pass
            return (buf.split(b" ")[1].decode() if b" " in buf else "reset"), time.time() - t0
        finally:
            s.close()


def main():
    tmp = tempfile.mkdtemp(prefix="tnl-sig-")
    mod = load_node(tmp)
    srv = mod.ThreadingHTTPServer(("127.0.0.1", 0), mod.Handler)
    srv.conf = {"port": 8099, "token": TOKEN}
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    port = srv.server_address[1]
    ctr = int(time.time() * 1000)

    try:
        print("== 1) a signed request is accepted, with no token anywhere ==")
        st, d = call(port, "GET", "/api/pg", sign(TOKEN, "GET", "/api/pg", ctr))
        check("a correctly signed GET is accepted", served(st), "%s %s" % (st, d))
        check("...and it carried no X-Node-Token at all", True)

        body = json.dumps({"name": "x"}).encode()
        st, d = call(port, "POST", "/api/ls", sign(TOKEN, "POST", "/api/ls", ctr + 1, body), body)
        check("a correctly signed POST with a body is accepted", served(st), "%s %s" % (st, d))

        print("== 2) a replay is refused ==")
        hdr = sign(TOKEN, "GET", "/api/pg", ctr + 2)
        st1, _ = call(port, "GET", "/api/pg", hdr)
        st2, d2 = call(port, "GET", "/api/pg", hdr)          # byte-for-byte the same request
        check("the first one is accepted", served(st1), str(st1))
        check("the SAME request replayed is refused", st2 == 409, str(st2))
        check("...and the refusal hands back the mark, so a lagging panel can resync",
              isinstance(d2.get("ctr"), int) and d2["ctr"] >= ctr + 2, json.dumps(d2))
        st3, _ = call(port, "GET", "/api/pg", sign(TOKEN, "GET", "/api/pg", d2.get("ctr", 0) + 1))
        check("...and after resyncing above it, the panel is accepted again", served(st3), str(st3))

        print("== 3) a signature that does not cover THIS request is refused ==")
        base = ctr + 100
        cases = [
            ("a signature made for a different PATH",
             dict(sign(TOKEN, "GET", "/api/ls", base + 1)), "GET", "/api/pg", b""),
            ("a signature made for a different METHOD",
             dict(sign(TOKEN, "GET", "/api/mk", base + 2)), "POST", "/api/mk", b""),
            ("a signature made with someone else's secret",
             dict(sign("not-the-token", "GET", "/api/pg", base + 3)), "GET", "/api/pg", b""),
            ("a counter changed after signing",
             dict(sign(TOKEN, "GET", "/api/pg", base + 4), **{"X-Ctr": str(base + 5)}), "GET", "/api/pg", b""),
            ("no signature and no token at all", {}, "GET", "/api/pg", b""),
            ("an empty signature", {"X-Ctr": str(base + 6), "X-Body": "", "X-Sig": ""}, "GET", "/api/pg", b""),
            ("a signature that is not base64",
             {"X-Ctr": str(base + 7), "X-Body": "", "X-Sig": "!!!!"}, "GET", "/api/pg", b""),
        ]
        for name, headers, method, path, b in cases:
            st, dd = call(port, method, path, headers, b)
            check("refuses " + name, st == 401, "got %s %s" % (st, dd))

        # THE DOWNGRADE. Every case above sends a signature ALONE, so none of them can catch a node
        # that falls back to the token when the signature does not verify. That fallback is exactly the
        # attack the signature exists to stop: whoever watched this wire before the changeover holds a
        # valid token, and could pair it with any garbage signature.
        st, dd = call(port, "GET", "/api/pg",
                      dict(sign("not-the-token", "GET", "/api/pg", base + 30), **{"X-Node-Token": TOKEN}))
        check("a bad signature does NOT fall back to a valid token", st == 401, "got %s %s" % (st, dd))
        st, dd = call(port, "GET", "/api/pg",
                      {"X-Ctr": str(base + 31), "X-Body": "", "X-Sig": "", "X-Node-Token": TOKEN})
        check("...nor does an empty one", st == 401, "got %s %s" % (st, dd))

        # The body is the one place where the signature and the bytes can drift apart.
        real = json.dumps({"name": "real"}).encode()
        swapped = json.dumps({"name": "swap"}).encode()
        st, dd = call(port, "POST", "/api/ls", sign(TOKEN, "POST", "/api/ls", base + 20, real), swapped)
        check("refuses a body swapped for the one that was signed", st == 401, "got %s %s" % (st, dd))

        print("== 4) the token proves nothing any more, and an unproven request never reaches the body ==")
        # The changeover window is closed. A bearer token is exactly what an observer of this wire
        # WOULD have, so accepting one would hand the control plane to anyone who watched a request
        # before the switch -- and the tokens themselves have not been rotated.
        st, d = call(port, "GET", "/api/pg", {"X-Node-Token": TOKEN})
        check("the CORRECT bare token is refused: only a signature proves the panel now",
              st == 401, "%s %s" % (st, d))
        st, _ = call(port, "GET", "/api/pg", {"X-Node-Token": "wrong"})
        check("...and a wrong one, obviously", st == 401, str(st))

        # An unauthenticated caller announcing 20 MB must be answered from the headers alone. If the
        # node reads the body first, this blocks until the socket times out instead.
        code, el = Slow(port, {"X-Node-Token": "wrong"}).run()
        check("an unproven caller is refused WITHOUT its body being read",
              code in ("401", "reset") and el < 3, "code=%s after %.1fs" % (code, el))
        code, el = Slow(port, sign(TOKEN, "POST", "/api/mk", base + 40, b"whatever")).run()
        check("...and a signed caller whose body never arrives is not served either",
              code != "200", "code=%s after %.1fs" % (code, el))

        print("== 5) the counter survives a restart without reopening a window ==")
        with mod._req_ctr_lock:
            highest = mod._req_ctr
        for _ in range(40):                      # the mark is written off the request path
            if int(json.load(open(mod.NODE_CONF)).get("req_ctr") or 0) > highest:
                break
            time.sleep(0.05)
        on_disk = int(json.load(open(mod.NODE_CONF)).get("req_ctr") or 0)
        check("the mark on disk is AHEAD of every counter accepted", on_disk > highest,
              "disk=%d highest=%d" % (on_disk, highest))
        mod._seed_req_ctr()                      # what a restart does
        st, _ = call(port, "GET", "/api/pg", sign(TOKEN, "GET", "/api/pg", highest))
        check("after a restart, a counter already spent is still refused", st == 409, str(st))
        with mod._req_ctr_lock:
            mark = mod._req_ctr
        # The window comes back from a restart FULL. An empty one would call everything below the mark
        # unspent and hand back exactly the replay window the mark exists to close.
        st, _ = call(port, "GET", "/api/pg", sign(TOKEN, "GET", "/api/pg", mark - 1))
        check("...and so is one just under the mark, not only the mark itself", st == 409, str(st))

        print("== 6) requests that arrive out of ORDER are all served, each still only once ==")
        # The panel talks to one node from five background loops plus the operator's own click, so two
        # requests routinely leave together and arrive in the other order. Demanding a strict increase
        # refused whichever one lost the race -- a first-time request, not a replay. Measured live before
        # this was fixed: 7 of 8 concurrent signed requests came back 409.
        base = mark + 10000
        rev = list(range(9, -1, -1))             # highest FIRST: every later one lands inside the window
        codes = [call(port, "GET", "/api/pg", sign(TOKEN, "GET", "/api/pg", base + i))[0] for i in rev]
        check("ten counters delivered newest-first are ALL served",
              all(served(s) for s in codes), " ".join(str(s) for s in codes))

        st, _ = call(port, "GET", "/api/pg", sign(TOKEN, "GET", "/api/pg", base + 5))
        check("...and replaying one of them is still refused", st == 409, str(st))

        with mod._req_ctr_lock:
            top = mod._req_ctr
        st, _ = call(port, "GET", "/api/pg", sign(TOKEN, "GET", "/api/pg", top - mod.REQ_CTR_WINDOW))
        check("a counter older than the whole window is refused", st == 409, str(st))
        st, _ = call(port, "GET", "/api/pg", sign(TOKEN, "GET", "/api/pg", top - mod.REQ_CTR_WINDOW + 1))
        check("...and the one just inside it is served, so the edge is where it is claimed",
              served(st), str(st))

        # The same thing the panel actually does: distinct increasing counters, spent from threads that
        # then race each other to the node. Arrival order is the OS's to decide; every one of them is a
        # first-time request and every one must be served.
        alloc = [base + 1000 + i for i in range(24)]
        got = {}
        lk = threading.Lock()

        def fire(c):
            s, _d = call(port, "GET", "/api/pg", sign(TOKEN, "GET", "/api/pg", c))
            with lk:
                got[c] = s

        ts = [threading.Thread(target=fire, args=(c,)) for c in alloc]
        for t in ts:
            t.start()
        for t in ts:
            t.join()
        refused = sorted(c for c, s in got.items() if s == 409)
        check("24 concurrent signed requests: none refused as stale",
              not refused, "%d refused: %s" % (len(refused), refused[:6]))
    finally:
        srv.shutdown()
        srv.server_close()

    print()
    if fails:
        print("%d FAILURE(S)" % len(fails))
        return 1
    print("the panel proves itself without sending the secret, and a capture is worthless.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
