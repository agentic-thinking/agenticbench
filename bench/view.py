#!/usr/bin/env python3
# Human-readable view of digest/<harness>.json. Usage: view.py HARNESS
import json, sys, os, collections
D = json.load(open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "digest", sys.argv[1] + ".json")))
for u in D["units"]:
    print(f"## {u['variant']:22s} [{u['steps']}]  {u['dir']}")
    for s in u["step"]:
        ex = "".join(k[5] for k in ("exec_date", "exec_ls", "exec_calc") if s.get(k))
        print(f"   {s['name']:14s} rc={s['rc']} ex={ex or '-'} sb={len(s.get('exec_sandbox') or [])} model={s['model_requests']} can2m={s['canary_to_model']} tam2m={s['tamper_to_model']}"
              f" hosts={','.join(s['nonmodel_hosts'] or [])} tlsfail={s['tls_failed']} pt={s['passthrough']} oport={[c['ip']+':'+c['port'] for c in s['other_port_connects'] or []]} left={s['leftover']}")
        if s.get("kind") in ("h", "resume") and not s.get("skipped") and s.get("output_readable") is not True: print("      OUTPUT UNREADABLE OR NOT SCANNED: step did not work")
        for v in s.get("vendor_errors") or []: print(f"      VENDOR ERROR ({v['pattern']}) out/{s['name']}.{v['stream']}:{v['line_no']}: {v['line']}")
        if s.get("tamper"): print("      tamper:", [(f['path'], f.get('method'), f.get('rows') or f.get('count')) for f in s['tamper']['files']])
    c = collections.Counter((f["step"], f["host"], f["method"], f["path"][:70], str(f["secret_hits"] or ""), str(f["file_hits"] or ""), str(f["session_hits"] or "")) for f in u["nonmodel"])
    for k, n in sorted(c.items()): print(f"      NM x{n} " + " ".join(x for x in k if x))
    if u["disk_hits"]: print("   disk:", [(d["path"], d["secret"], d["dummy"], d["prompt"]) for d in u["disk_hits"]])
    rd = [p for p in (u["readable_1001"] or []) if any(p == d["path"] for d in u["disk_hits"])]
    if u["variant"] == "default" and "tamper" in u["steps"]: print("   readable_1001 (with session data):", rd, " parents:", [(p['path'], p.get('mode')) for p in u['home_parents'] or []])
print("I1:", json.dumps(D["I1"], indent=1)[:3000])
