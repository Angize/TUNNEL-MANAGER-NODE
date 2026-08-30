import sys
sys.dont_write_bytecode = True
import base64
import hashlib
import hmac
import http.client
import importlib.util
import json
import os
import tempfile
import threading
import time
from pathlib import Path

NODE = Path(__file__).resolve().parent.parent / "tnl-node.py"
TOKEN = "t0k3n-for-the-central-host-test"
FAILED = []


def check(name, cond, detail=""):
    print(("  ok  " if cond else " FAIL ") + name + (("  -- " + detail) if detail and not cond else ""))
    if not cond:
        FAILED.append(name)


def load_node(tmp):
    spec = importlib.util.spec_from_file_location("tnl_node_ch", NODE)
    mod = importlib.util.module_from_spec(spec)
    sys.modules["tnl_node_ch"] = mod
    spec.loader.exec_module(mod)
    mod.CONFIG_DIR = tmp
    mod.NODE_CONF = os.path.join(tmp, "node.conf")
    mod.LOG_FILE = os.path.join(tmp, "agent.log")
    mod.save_conf({"port": 8099, "token": TOKEN})
    mod._seed_req_ctr()
    return mod


def sign(method, path, ctr, body=b""):
    body_sha = hashlib.sha256(body).hexdigest() if body else ""
    msg = "%s\n%s\n%s\n%s" % (method, path, ctr, body_sha)
    mac = hmac.new(TOKEN.encode(), msg.encode(), hashlib.sha256).digest()
    return {"X-Ctr": str(ctr), "X-Body": body_sha, "X-Sig": base64.b64encode(mac).decode()}


def call(port, extra, ctr):
    path = "/api/pg"
    h = sign("GET", path, ctr)
    h.update(extra)
    c = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    try:
        c.request("GET", path, headers=h)
        r = c.getresponse()
        r.read()
        return r.status
    except OSError:
        return 0
    finally:
        c.close()


def main():
    tmp = tempfile.mkdtemp(prefix="tnl-ch-")
    m = load_node(tmp)
    srv = m.ThreadingHTTPServer(("127.0.0.1", 0), m.Handler)
    srv.conf = {"port": 8099, "token": TOKEN}
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    port = srv.server_address[1]
    ctr = [int(time.time() * 1000)]

    def go(extra):
        ctr[0] += 1
        with m._central_cb_lock:
            m._central_cb = None
        st = call(port, extra, ctr[0])
        return st, m.get_central()

    try:
        st, cb = go({"X-Central-Port": "2053", "X-Central-TLS": "0"})
        check("with no host header the node still falls back to the peer address",
              st not in (0, 401, 409) and cb == ("127.0.0.1", 2053, False), "%s %s" % (st, cb))

        st, cb = go({"X-Central-Port": "2053", "X-Central-TLS": "0",
                     "X-Central-Host": "185.252.86.72"})
        check("the panel's own host wins over the address the request arrived from",
              cb == ("185.252.86.72", 2053, False), repr(cb))

        st, cb = go({"X-Central-Port": "2053", "X-Central-TLS": "1",
                     "X-Central-Host": "185.252.86.72"})
        check("and it carries the tls flag with it", cb == ("185.252.86.72", 2053, True), repr(cb))

        for bad in ("", "not-an-ip", "999.1.1.1", "185.252.86.72:2053", "::1"):
            st, cb = go({"X-Central-Port": "2053", "X-Central-TLS": "0", "X-Central-Host": bad})
            check("a host header of %r is refused and the peer address is used" % bad,
                  cb == ("127.0.0.1", 2053, False), repr(cb))

        ctr[0] += 1
        with m._central_cb_lock:
            m._central_cb = None
        call(port, {"X-Central-Host": "185.252.86.72"}, ctr[0])
        check("a host with no port header records nothing, as before",
              m.get_central() is None, repr(m.get_central()))

        ctr[0] += 1
        call(port, {"X-Central-Port": "2053", "X-Central-TLS": "0",
                    "X-Central-Host": "185.252.86.72"}, ctr[0])
        saved = json.load(open(m.NODE_CONF)).get("central_cb")
        check("and what it learned is written to node.conf so a restart keeps it",
              saved == ["185.252.86.72", 2053, False], repr(saved))
    finally:
        srv.shutdown()

    print()
    if FAILED:
        print("%d failure(s)" % len(FAILED))
        return 1
    print("the node believes the panel about where the panel is")
    return 0


if __name__ == "__main__":
    sys.exit(main())
