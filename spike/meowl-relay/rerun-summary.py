"""Per-test pass counts across the A1..A3 re-runs; run from the runs/ directory."""
import json,collections
def walk(s,out):
    for sp in s.get("specs",[]):
        for t in sp.get("tests",[]):
            k=(sp["file"],sp["title"])
            for r in t.get("results",[]):
                out[k][0]+=1; out[k][1]+= r.get("status")=="passed"
    for c in s.get("suites",[]): walk(c,out)
res={}
for run in ["A1","A2","A3"]:
    d=collections.defaultdict(lambda:[0,0])
    for p in ["chromium","publishing"]:
        try: walk(json.load(open(f"{run}/{p}.json")),d)
        except FileNotFoundError: print("missing",run,p)
    res[run]=d
keys=sorted(set().union(*[r.keys() for r in res.values()]))
tot={r:[0,0] for r in res}
for k in keys:
    row=[res[r].get(k,[0,0]) for r in res]
    for r,v in zip(res,row): tot[r][0]+=v[0]; tot[r][1]+=v[1]
    if len(set(v[1] for v in row))>1: print(k[0],"|",k[1][:60],"|"," ".join(f"{v[1]}/{v[0]}" for v in row))
print(len(keys),"tests",tot)
