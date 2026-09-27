#!/usr/bin/env python3
# Start bench/adjudication.json from the template: adds one entry per harness (existing entries are never overwritten) and
# lists every non-model endpoint the analysed units contacted, so each can be classified by hand. Each entry records the batch
# it was made for; score_bench.py refuses an entry whose batch differs from the digest's, so a re-run is re-adjudicated.
# Usage: adjudication_init.py HARNESS...
import copy, json, os, sys
S = os.path.dirname(os.path.abspath(__file__)); OUT = f"{S}/adjudication.json"
if len(sys.argv) < 2: sys.exit("usage: adjudication_init.py HARNESS...")
tpl = json.load(open(f"{S}/adjudication.example.json"))
adj = json.load(open(OUT)) if os.path.exists(OUT) else {"_about": tpl["_about"]}
for h in sys.argv[1:]:
    d = f"{S}/digest/{h}.json"; batch = json.load(open(d)).get("batch", "") if os.path.exists(d) else ""
    if h in adj:
        print(f"{h}: already in {OUT}, left unchanged")
        if adj[h].get("batch") != batch: print(f"  WARNING: that entry is for batch {adj[h].get('batch')!r}, the digest is batch {batch!r}: re-check it, then update its batch field")
    else:
        e = copy.deepcopy(tpl["example-harness"]); e["name"] = h
        for k in ("vendor_hosts", "classes", "c4_documented"): e[k] = []
        e["telemetry_optout_doc"] = None; e["r5_allowed"] = None       # null = not adjudicated yet: the tests that need them stay nt
        e["batch"] = batch
        adj[h] = e; print(f"{h}: added to {OUT} with every documentation-dependent cell marked not adjudicated")
    if os.path.exists(d):
        eps = sorted({(f["host"], f["path"].split("?")[0][:80]) for u in json.load(open(d))["units"] for f in u["nonmodel"]})
        print(f"  {len(eps)} non-model endpoints to classify:" if eps else "  no non-model endpoint seen")
        for host, path in eps: print(f"    {host}{path}")
    else: print(f"  no digest yet for {h}: run analyse_all.sh, then run this again to list endpoints")
json.dump(adj, open(OUT, "w"), indent=1, ensure_ascii=False)
