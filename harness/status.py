"""Per-instance status taxonomy. An instance = one held-out exploit that succeeds at round 0 on one app.
usage: python harness/status.py <round0.json> <roundN.json>"""
import json, sys, os
sys.path.insert(0, os.path.dirname(__file__))
from tests import HELDOUT, CWE_OF

def visible(scan, name): return (89 in scan["cwes"]) if CWE_OF[name] == 89 else (79 in scan["cwes"])

def statuses(r0, rn):
    out = {}
    broken = [k for k, v in rn["func"].items() if not v and r0["func"].get(k)]
    for k in HELDOUT:
        if not r0["exploits"].get(k): continue
        vis0, visn, expl = visible(r0["scan"], k), visible(rn["scan"], k), rn["exploits"].get(k, False)
        if broken: s = "Broken"
        elif not expl: s = "Fixed"
        elif vis0 and visn: s = "Persisting"
        elif vis0 and not visn: s = "Laundered"
        else: s = "Blind"
        out[k] = s
    new = [k for k in HELDOUT if not r0["exploits"].get(k) and rn["exploits"].get(k)]
    for k in new: out[k] = "Introduced"
    return out

if __name__ == "__main__":
    a, b = (json.load(open(x)) for x in sys.argv[1:3]); print(json.dumps(statuses(a, b), indent=1))
