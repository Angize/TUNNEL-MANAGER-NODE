"""Guard: a firewall rule the core installs must be attributable, and sweepable by its owner alone.

The core removes its own rules on Close(). That covers an orderly stop and nothing else -- a SIGKILL,
a crash or a reboot leaves them behind, and because they go in with -A and come out by matching their
own exact spec, an orphan is invisible to the next core and a duplicate lands beside it. Both were
found on production boxes: a --dport 4500 rule from a tunnel that no longer existed, and one ICMP rule
installed twice.

The sweep is the safety net, and its danger is the mirror of the leak: deleting a rule that belongs to
somebody else. This drives _sweep_owned_rules against a realistic iptables-save and pins both halves --
what it must remove, and what it must not touch.

Exit 1 on any mismatch.
"""
import importlib.util
import sys
from pathlib import Path

sys.dont_write_bytecode = True
NODE = Path(__file__).resolve().parent.parent / "tnl-node.py"

SAVE = {
    "filter": """# Generated
*filter
:INPUT ACCEPT [0:0]
-A OUTPUT -d 1.2.3.4/32 -p tcp -m tcp --sport 51820 --dport 443 -m comment --comment "tnl:core42" -j DROP
-A OUTPUT -d 1.2.3.4/32 -p icmp -m icmp --icmp-type 0 -m comment --comment "tnl:core42" -j DROP
-A OUTPUT -d 5.6.7.8/32 -p tcp -m comment --comment "tnl:core4" -j DROP
-A OUTPUT -d 5.6.7.8/32 -p tcp -m comment --comment "tnl:core420" -j DROP
-A OUTPUT -d 9.9.9.9/32 -p esp -m comment --comment "tnl:othertun" -j DROP
-A OUTPUT -d 9.9.9.9/32 -p tcp -j DROP
COMMIT
""",
    "raw": """*raw
-A PREROUTING -d 2.3.4.5/32 -p 253 -m comment --comment "tnl:core42" -j DROP
COMMIT
""",
    "mangle": "*mangle\nCOMMIT\n",
    "nat": "*nat\nCOMMIT\n",
}


def main():
    spec = importlib.util.spec_from_file_location("tnl_node_orphan", NODE)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)

    calls = []
    m.run = lambda a, **k: calls.append(list(a))
    m.logline = lambda _m: None

    class R:
        def __init__(self, out): self.returncode, self.stdout = 0, out
    m.subprocess.run = lambda a, **k: R(SAVE.get(a[2], ""))

    n = m._sweep_owned_rules("core42")
    fails = []

    def want(cond, msg):
        print(("  ok   " if cond else " FAIL ") + msg)
        if not cond:
            fails.append(msg)

    want(n == 3, "removed 3 rules owned by core42 (2 filter + 1 raw), got %d" % n)

    # Compare the comment as a TOKEN, never as a substring -- "tnl:core4" is a substring of
    # "tnl:core42", which is the very confusion this guard exists to catch, and the first draft of the
    # check fell for it.
    def owner_of(c):
        return c[c.index("--comment") + 1] if "--comment" in c else None
    owners = [owner_of(c) for c in calls]
    want(all(o == "tnl:core42" for o in owners),
         "every delete names core42 and nothing else, got %s" % sorted(set(map(str, owners))))
    for foreign in ("tnl:core4", "tnl:core420", "tnl:othertun"):
        want(foreign not in owners,
             'left %s alone -- a prefix or a neighbour must never be swept by "core42"' % foreign)
    want(None not in owners, "never deleted an untagged rule -- an unowned rule is not ours to remove")

    for c in calls:
        want(c[0] == "iptables" and c[1] == "-t" and c[3] == "-D",
             "delete is `iptables -t <table> -D <chain> ...`: %s" % " ".join(c[:5]))
        want("--comment" in c, "the delete carries the comment too, or -D matches nothing: %s" % " ".join(c[-4:]))
    want(any(c[2] == "raw" for c in calls), "swept the raw table as well as filter")

    # A name that could not be a tunnel must sweep nothing rather than build a loose match.
    calls.clear()
    for bad in ("", "*", "../etc", "a b"):
        m._sweep_owned_rules(bad)
    want(not calls, "a malformed tunnel name sweeps nothing, got %d deletes" % len(calls))

    print()
    if fails:
        print("%d failure(s)" % len(fails))
        return 1
    print("orphaned rules are swept by owner, and only by owner")
    return 0


if __name__ == "__main__":
    sys.exit(main())
