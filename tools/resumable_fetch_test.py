#!/usr/bin/env python3
"""A transfer that keeps getting cut still finishes, because each attempt asks for the REST.

MEASURED on the real path: a server cut the body at 3,997,696 of 11,243,704 bytes. Every attempt started
from zero, so a path that cuts at four megabytes could never deliver eleven — the node reported
«download truncated» forever while the file was perfectly fine.

The pieces that make resuming work are each easy to get wrong in a way that still LOOKS right:

  1. what already arrived is kept, and the next attempt asks for the rest;
  2. a server with no Range support answers 200 with the whole file — and the bytes already held must
     be DROPPED, or they are spliced in front of a full copy and the sha can never match;
  3. the budget still ends it, so a path that cuts instantly cannot spin forever;
  4. and the attempt cap is a floor under that, not a replacement for it.

    python3 tools/resumable_fetch_test.py
"""
import hashlib
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

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

FAILED = []
BLOB = bytes(range(256)) * 4096          # 1 MiB, and every offset is checkable
SHA = hashlib.sha256(BLOB).hexdigest()


def check(name, cond, detail=""):
    print(("  ok   " if cond else " FAIL  ") + name + (("  -- " + detail) if detail and not cond else ""))
    if not cond:
        FAILED.append(name)


def load():
    spec = importlib.util.spec_from_file_location("rf_node", NODE)
    m = importlib.util.module_from_spec(spec)
    sys.modules["rf_node"] = m
    spec.loader.exec_module(m)
    m._is_central_origin = lambda u: True
    return m


class Server(socketserver.ThreadingTCPServer):
    daemon_threads = True
    allow_reuse_address = True


def serve(handler):
    s = Server(("127.0.0.1", 0), handler)
    threading.Thread(target=s.serve_forever, daemon=True).start()
    return s, "http://127.0.0.1:%d/blob" % s.server_address[1]


class Base(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def start(self):
        m = re.fullmatch(r"bytes=(\d+)-", self.headers.get("Range", "") or "")
        return int(m.group(1)) if m else 0


class Cuts(Base):
    """Serves at most CUT_AT bytes per connection, then drops it. Honours Range."""
    CUT_AT = 200 * 1024
    seen = []

    def do_GET(self):
        s = self.start()
        Cuts.seen.append(s)
        body = BLOB[s:]
        self.send_response(206 if s else 200)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Accept-Ranges", "bytes")
        if s:
            self.send_header("Content-Range", "bytes %d-%d/%d" % (s, len(BLOB) - 1, len(BLOB)))
        self.end_headers()
        try:
            self.wfile.write(body[:self.CUT_AT])
            self.wfile.flush()
        except OSError:
            pass
        self.close_connection = True
        try:
            self.connection.close()   # cut it, mid-body
        except OSError:
            pass


class NoRange(Base):
    """Ignores Range and always answers 200 with the WHOLE file — cutting the first attempt."""
    first = [True]
    seen = []

    def do_GET(self):
        NoRange.seen.append(self.start())
        self.send_response(200)
        self.send_header("Content-Length", str(len(BLOB)))
        self.end_headers()
        if NoRange.first[0]:
            NoRange.first[0] = False
            try:
                self.wfile.write(BLOB[:300 * 1024])
                self.wfile.flush()
                self.connection.close()
            except OSError:
                pass
            return
        self.wfile.write(BLOB)


class Instant(Base):
    """Accepts the connection and drops it with nothing at all. The pathological case."""
    hits = [0]

    def do_GET(self):
        Instant.hits[0] += 1
        try:
            self.connection.close()
        except OSError:
            pass


def main():
    N = load()

    print("== a body cut every attempt still arrives, whole ==")
    srv, url = serve(Cuts)
    try:
        buf = None
        try:
            buf = N._fetch_url(url, 8 << 20, timeout=5, budget=30)
        except Exception as e:
            check("the file is complete", False, "%s: %s" % (type(e).__name__, e))
        if buf is not None:
            check("the file is complete", len(buf) == len(BLOB), "%d of %d" % (len(buf), len(BLOB)))
            # Length alone would pass on a file spliced from overlapping attempts. The hash is what says
            # the bytes are in the right ORDER, the whole risk in stitching a download together.
            check("...and byte-for-byte correct", hashlib.sha256(buf).hexdigest() == SHA)
        # OUTSIDE the success path on purpose. What the node ASKED FOR is recorded by the server whether
        # the fetch finished or not, and a node that never asks for a range fails the completeness check
        # first -- which would leave this one unreached, and unproven.
        check("...having asked for the REST each time, not the start",
              len(Cuts.seen) > 1 and Cuts.seen[0] == 0 and all(x > 0 for x in Cuts.seen[1:]),
              repr(Cuts.seen))
    finally:
        srv.shutdown()

    print("== a server that ignores Range must not be spliced ==")
    # It answers 200 with the WHOLE body. Appending that to what was already held makes a file that is
    # too long and hashes to nothing -- and the sha gate would blame the panel's staged artifact.
    srv, url = serve(NoRange)
    try:
        buf = N._fetch_url(url, 8 << 20, timeout=5, budget=30)
        check("the file is exactly one copy", len(buf) == len(BLOB), "%d of %d" % (len(buf), len(BLOB)))
        check("...and still hashes correctly", hashlib.sha256(buf).hexdigest() == SHA)
        check("...and the node did ask for a range (the server just ignored it)",
              len(NoRange.seen) > 1 and NoRange.seen[1] > 0, repr(NoRange.seen))
    except Exception as e:
        check("the file is exactly one copy", False, "%s: %s" % (type(e).__name__, e))
    finally:
        srv.shutdown()

    print("== a path that gives nothing at all is bounded, and says so ==")
    srv, url = serve(Instant)
    t0 = time.monotonic()
    try:
        N._fetch_url(url, 8 << 20, timeout=3, budget=20)
        check("a hopeless path fails rather than returning", False, "it returned")
    except Exception as e:
        el = time.monotonic() - t0
        check("a hopeless path fails rather than returning", True)
        check("...bounded by the attempt cap, not by the budget", el < 15, "%.1fs" % el)
        check("...and the cap is what stopped it", Instant.hits[0] <= N.FETCH_TRIES,
              "%d attempts for a cap of %d" % (Instant.hits[0], N.FETCH_TRIES))
        _ = e
    finally:
        srv.shutdown()

    print()
    if FAILED:
        print("%d FAILED:" % len(FAILED))
        for f in FAILED:
            print("  - " + f)
        return 1
    print("a cut transfer resumes, and a hopeless one stops.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
