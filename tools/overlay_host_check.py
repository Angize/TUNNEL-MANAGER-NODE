# -*- coding: utf-8 -*-
"""Guard: the node takes its overlay address from the panel, and never invents one.

`host` is 1 or 2 and the panel sets it from the ROLE -- server .1, client .2. The node used to work it
out itself by comparing the two public IPs, so which end became .1 depended on which provider handed out
the larger address; a tunnel between the same two machines could flip ends when one of them changed IP.

The danger of taking it from the wire is the mirror of that: a missing or nonsense `host` must be a loud
refusal, not a quiet guess, because a guessed address that disagrees with the far end gives a tunnel that
comes UP and carries nothing -- both ends pinging an address neither of them holds.

This drives the real op_tunnel and reads the address it persisted, so a path that stops honouring `host`
fails here even if derive_tunnel_ip alone still looks right.

Exit 1 on any mismatch.
"""
import importlib.util
import os
import sys
import tempfile

sys.dont_write_bytecode = True
NODE = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "tnl-node.py")

fails = []


def check(ok, msg):
    print(("  ok   " if ok else " FAIL ") + msg)
    if not ok:
        fails.append(msg)


def load(tmp):
    spec = importlib.util.spec_from_file_location("tnl_node_overlay", NODE)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    m.CONFIG_DIR = tmp
    # rc=0 on `ip link show` = the netdev is there, which is what op_tunnel's own verify needs to pass.
    # unique_name asks the same question expecting the opposite answer, so it gets its own fixture below.
    m.run = lambda a, **k: (0, "", "")
    m.logline = lambda _m: None
    m.local_ips_flat = lambda: ["10.0.0.1", "10.0.0.2"]
    m.iface_for_ip = lambda ip: "eth0"
    m.apply_config = lambda cfg: None
    m.teardown_config = lambda cfg: None
    m.tun_probe = lambda *a, **k: (0, 0.0)
    return m


def req(**kw):
    d = {"type": "gre", "self_ip": "10.0.0.1", "peer_ip": "10.0.0.2",
         "subnet": "192.168.42.0/24", "id": 42, "name": "native42", "iface": "eth0", "host": 1}
    d.update(kw)
    return d


def main():
    tmp = tempfile.mkdtemp()

    print("== 1) the address is the host the panel asked for ==")
    for host, want in ((1, "192.168.42.1/24"), (2, "192.168.42.2/24")):
        m = load(tmp)
        m.op_tunnel(req(host=host))
        got = (m.read_config("native42") or {}).get("tunnel_ip")
        check(got == want, "host=%s -> %s" % (host, got))

    print("\n== 2) it does NOT depend on which public IP is larger ==")
    seen = set()
    for self_ip, peer_ip in (("10.0.0.1", "10.0.0.2"), ("10.0.0.2", "10.0.0.1")):
        m = load(tmp)
        m.op_tunnel(req(self_ip=self_ip, peer_ip=peer_ip, host=1))
        seen.add((m.read_config("native42") or {}).get("tunnel_ip"))
    check(seen == {"192.168.42.1/24"},
          "host=1 gives .1 whichever public IP is the larger, got %s" % sorted(seen))

    print("\n== 3) a missing or nonsense host is refused, never guessed ==")
    for bad, why in ((None, "absent"), (0, "zero"), (3, "out of range"), (-1, "negative")):
        m = load(tmp)
        d = req()
        if bad is None:
            d.pop("host")
        else:
            d["host"] = bad
        try:
            m.op_tunnel(d)
            check(False, "host %s (%s) was ACCEPTED -- a guessed address the far end does not share "
                         "gives a tunnel that comes up and carries nothing" % (bad, why))
        except ValueError:
            check(True, "host %s (%s) refused" % (bad, why))

    print("\n== 4) the two ends land on addresses that are each other's peer ==")
    m = load(tmp)
    for host, nm in ((1, "endA"), (2, "endB")):
        m.op_tunnel(req(host=host, name=nm))
    a = (m.read_config("endA") or {}).get("tunnel_ip")
    b = (m.read_config("endB") or {}).get("tunnel_ip")
    check(m.peer_of(a, "gre") == b.split("/")[0] and m.peer_of(b, "gre") == a.split("/")[0],
          "%s <-> %s are each other's peer (peer_of is what the tun probe aims at)" % (a, b))

    print("\n== 5) the id range and the name follow the panel's 1..255 ==")
    for tid, ok_want in ((1, True), (255, True), (0, False), (256, False)):
        m = load(tmp)
        try:
            m.op_tunnel(req(id=tid, name="native%d" % tid))
            got = True
        except ValueError:
            got = False
        check(got == ok_want, "id=%s %s" % (tid, "accepted" if got else "refused"))
    m = load(tempfile.mkdtemp())          # a clean dir, and a netdev that is ABSENT: what unique_name asks
    m.run = lambda a, **k: ((1, "", "") if list(a)[:3] == ["ip", "link", "show"] else (0, "", ""))
    check(m.unique_name("gre", 7) == "native7" and m.unique_name("core", 7) == "core7",
          "unique_name spells them core<id> / native<id> like the panel: %s / %s"
          % (m.unique_name("gre", 7), m.unique_name("core", 7)))

    print()
    if fails:
        print("%d failure(s)" % len(fails))
        return 1
    print("the overlay address is the panel's decision, and a missing one is refused")
    return 0


if __name__ == "__main__":
    sys.exit(main())
