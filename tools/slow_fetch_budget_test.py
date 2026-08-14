#!/usr/bin/env python3
"""A fetch the node cannot finish must end BEFORE the panel stops waiting for it.

`_fetch_url` had one deadline, the socket's — and a socket timeout is applied PER READ, so it only ever
catches a peer that has gone silent. A stream crawling at a few KB/s is never cut by it however long it
takes. MEASURED on the real path: 365 KB in 200 s. The panel gives up on the op at 200 s, so the node
kept downloading past that point and the operator was told the install had FAILED while it was still
running and would go on to succeed.

So there are two deadlines now, and they answer different questions. This pins both, and pins that they
are ordered against the panel's own wait — the ordering is the whole point, and it lives in two repos.

    python3 tools/slow_fetch_budget_test.py
"""
import http.server
import importlib.util
import os
import re
import socketserver
import sys
import threading
import time

HERE = os.path.dirname(os.path.abspath(__file__))
NODE = os.path.join(os.path.dirname(HERE), "tnl-node.py")
PANEL = os.path.join(os.path.dirname(os.path.dirname(HERE)), "TUNNEL-MANAGER", "tnl-central.py")

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

FAILED = []


def check(name, cond, detail=""):
    print(("  ok   " if cond else " FAIL  ") + name + (("  -- " + detail) if detail and not cond else ""))
    if not cond:
        FAILED.append(name)


def bounded(fn, cap):
    """Run fn on a thread and give up on WAITING for it after cap seconds.

    Without this the no-budget case runs until the crawling server finishes -- minutes -- and a mutation
    harness that removes the budget hangs instead of reporting a failure. The bound belongs to the test,
    not to the subject: "still going at cap" IS the observation being made.
    """
    out = {}
    t = threading.Thread(target=lambda: out.update(_call(fn)), daemon=True)
    t0 = time.monotonic()
    t.start()
    t.join(cap)
    return out if not t.is_alive() else {"stuck": True}, time.monotonic() - t0


def _call(fn):
    try:
        fn()
        return {"ret": True}
    except Exception as e:
        return {"err": e}


def load():
    spec = importlib.util.spec_from_file_location("sfb_node", NODE)
    m = importlib.util.module_from_spec(spec)
    sys.modules["sfb_node"] = m
    spec.loader.exec_module(m)
    return m


TOTAL = 4 << 20     # what the server claims
RATE = 8 * 1024     # ...and how slowly it delivers it: 4 MB would need ~8 minutes


class Crawl(http.server.BaseHTTPRequestHandler):
    """Answers with a correct Content-Length and then trickles, forever. Exactly the shape measured on
    the real path: never silent, never finished."""

    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Content-Length", str(TOTAL))
        self.end_headers()
        sent = 0
        try:
            while sent < TOTAL:
                self.wfile.write(b"\0" * RATE)
                self.wfile.flush()
                sent += RATE
                time.sleep(1.0)
        except OSError:
            pass

    def log_message(self, *a):
        pass


def main():
    N = load()
    N.FETCH_BUDGET = 6          # the real one is 150 s; the shape is what matters, not the wall clock
    N._is_central_origin = lambda u: True

    srv = socketserver.ThreadingTCPServer(("127.0.0.1", 0), Crawl)
    srv.daemon_threads = True
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    url = "http://127.0.0.1:%d/blob" % srv.server_address[1]

    try:
        print("== a stream that never stops and never finishes ends at the BUDGET ==")
        res, el = bounded(lambda: N._fetch_url(url, N.FETCH_MAX_CORE, budget=6), 25)
        check("a crawling fetch is given up on", isinstance(res.get("err"), ValueError),
              "still running after %.0fs" % el if res.get("stuck") else repr(res))
        e = res.get("err")
        # The message has to name what happened, or the operator reads «download failed» for a transfer
        # that was moving the whole time and blames the file.
        check("...saying it gave up, and how far it got",
              bool(e) and "gave up" in str(e) and "of" in str(e), str(e))
        check("...at the budget, not at the socket timeout", 5.0 <= el <= 11.0, "%.1fs" % el)

        print("== and it stays under the panel's own wait for the answer ==")
        # Two repos, one ordering. If the node's budget ever passes the panel's wait, the panel reports a
        # failure for an install that is still running -- which is what sent the operator looking at the
        # network instead of the clock.
        src = open(PANEL, encoding="utf-8").read()
        m = re.search(r"^NODE_UPLOAD_TIMEOUT\s*=\s*(\d+)", src, re.M)
        check("the panel's wait is readable from its source", bool(m))
        if m:
            wait, budget = int(m.group(1)), load().FETCH_BUDGET
            check("the node gives up first", budget < wait, "node %ds vs panel %ds" % (budget, wait))
            check("...with room for the verify and swap that follow", wait - budget >= 30,
                  "only %ds of slack" % (wait - budget))

        print("== a socket that goes SILENT is still caught by the socket timeout ==")
        # The budget must not have replaced the stall detector: a peer that stops mid-body has to fail
        # fast, not sit out the whole budget.
        class Mute(Crawl):
            def do_GET(self):
                self.send_response(200)
                self.send_header("Content-Type", "application/octet-stream")
                self.send_header("Content-Length", str(TOTAL))
                self.end_headers()
                self.wfile.write(b"\0" * 4096)
                self.wfile.flush()
                time.sleep(30)

        s2 = socketserver.ThreadingTCPServer(("127.0.0.1", 0), Mute)
        s2.daemon_threads = True
        threading.Thread(target=s2.serve_forever, daemon=True).start()
        res, el = bounded(lambda: N._fetch_url("http://127.0.0.1:%d/blob" % s2.server_address[1],
                                               N.FETCH_MAX_CORE, timeout=2, budget=60), 25)
        # Each ATTEMPT is cut by the socket timeout; the fetch then resumes, so the wall clock is the
        # timeout times the attempt cap, not one timeout. Bounding this at a single timeout asserted
        # that retrying does not happen -- which is the opposite of what was built.
        cap = 2 * N.FETCH_TRIES + 4
        check("a silent peer is cut by the socket timeout, every attempt",
              bool(res.get("err")) and el < cap, "%.1fs of a %ds bound %r" % (el, cap, res))
        s2.shutdown()
    finally:
        srv.shutdown()

    print()
    if FAILED:
        print("%d FAILED:" % len(FAILED))
        for f in FAILED:
            print("  - " + f)
        return 1
    print("the node gives up on its own, and does it before the panel does.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
