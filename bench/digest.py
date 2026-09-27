#!/usr/bin/env python3
# AgenticBench per-harness digest. Reads results/<unit>/summary.json (analyse_unit.py) plus raw captures, and writes
# digest/<harness>.json with the mechanical facts every test uses:
#   units: variant/steps -> per step rc, execs, leftovers, hosts, TLS failures, canary/tamper to model; evidence sources present
#   I1: identifier candidates = id-like tokens in MODEL requests of main A and B (same HOME) that are absent from C (fresh HOME)
# (L2, the same comparison over telemetry requests, needs the endpoint classes and is computed by score_bench.py.)
# Only one batch is digested: the only batch of the harness, or the one named (required when there are several). Units from other batches
# (older versions, other configurations) are never mixed in. Usage: digest.py HARNESS [BATCH]
import base64, json, glob, os, re, sys, collections
from lib.batchplan import parse_plan
S = os.path.dirname(os.path.abspath(__file__)); H = sys.argv[1]
IDRE = re.compile(r"(?<![0-9a-zA-Z])(?:[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}|[0-9a-f]{16,64}|[0-9A-F]{16,64}|[0-9A-Za-z]{2,12}_[0-9A-Za-z]{16,})(?![0-9a-zA-Z])")
units = []
for d in sorted(glob.glob(f"{S}/results/*/summary.json")):
    s = json.load(open(d))
    if s["run"]["harness"] != H: continue
    s["dir"] = os.path.relpath(os.path.dirname(d), S); units.append(s)
if not units:
    sys.exit(f"{H}: no analysed unit in {S}/results (run batch.sh, then analyse_all.sh)")
batches = sorted({u["run"].get("batch") or "" for u in units} - {""})
# every started unit of the harness, analysed or not: a newer batch that is unfinished or unanalysed must not be skipped silently
started = {}
for rj in glob.glob(f"{S}/results/*/run.json"):
    try: r = json.load(open(rj))
    except (OSError, ValueError): continue
    if r.get("harness") == H and r.get("batch"): started.setdefault(r["batch"], []).append(os.path.dirname(rj))
# a batch plan (runlist) lists the harness's units before any of them starts: a newer plan with no analysed unit means the
# newer batch failed early (before run.json was written) and must not be replaced silently by an older batch
for rl in glob.glob(f"{S}/results/runlist-*.txt"):
    b = os.path.basename(rl)[len("runlist-"):-len(".txt")]
    try: planned = parse_plan(open(rl).read(), H)
    except OSError: planned = None
    if planned: started.setdefault(b, [])
# No guessing which batch is "newest": batch names are free text and do not sort by time. With exactly one batch known for the
# harness (analysed, started or planned) it is used; with more than one, the batch must be named.
known = sorted(set(batches) | set(started))
if len(sys.argv) > 2: BATCH = sys.argv[2]
elif len(known) == 1: BATCH = known[0]
else:
    sys.exit(f"{H}: {len(known)} batches exist ({', '.join(known)}); name the one to digest: digest.py {H} BATCH "
             f"(analyse_all.sh passes AB_DIGEST_BATCH, e.g. AB_DIGEST_BATCH={known[-1]} bench/analyse_all.sh)")
if not batches: sys.exit(f"{H}: no unit has a batch id; run the units through batch.sh (or set AB_BATCH for unit.sh)")
if BATCH not in batches: sys.exit(f"{H}: no analysed unit of batch {BATCH}; analysed batches: {', '.join(batches) or 'none'}")
pending = [d for d in started.get(BATCH, []) if not os.path.exists(f"{d}/summary.json")]
if pending: sys.exit(f"{H}: batch {BATCH} has {len(pending)} unit(s) unfinished or not analysed (e.g. {os.path.basename(pending[0])}); finish and analyse them first")
units = [u for u in units if u["run"].get("batch") == BATCH]


def model_blobs(u, step):
    """text of every model request of a step: header values (credential headers as their hash) + body."""
    d = f"{S}/{u['dir']}"; out = []
    for m in u["model_requests"]:
        if m["step"] != step: continue
        if m["src"] == "proxy":
            hv = "\n".join(f"{h['name']}: {h['value'] if 'value' in h else 'sha256:' + h['sha256'] if 'sha256' in h else h.get('sha12')}" for h in m["headers"])
            out.append(hv + "\n" + open(f"{d}/{m['file']}", "rb").read().decode("utf-8", "replace"))
        else:
            hv = "\n".join(m["req_headers"]); body = open(f"{d}/mcap/{m['file']}.req", "rb").read().decode("utf-8", "replace") if m.get("file") else ""
            out.append(hv + "\n" + m["path"] + "\n" + body)
    if u["run"].get("model") == "vendor" and os.path.exists(f"{d}/mcap/ws.jsonl"):   # vendor model channel over websocket
        st = next(s for s in u["steps"] if s["name"] == step)
        mre = re.compile(u["run"].get("model_re") or "^$")
        for line in open(f"{d}/mcap/ws.jsonl"):
            w = json.loads(line)
            if w["from_client"] and st["start"] <= w["t"] <= (st["end"] or 9e18) and mre.search(w["host"] + w["path"]):
                out.append(base64.b64decode(w["content_b64"]).decode("utf-8", "replace") if "content_b64" in w else w["content"])
    return out


def tokens(blobs):
    t = collections.defaultdict(set)
    for b in blobs:
        for line in b.splitlines():
            for m in IDRE.finditer(line):
                t[m.group(0)].add(line[max(0, m.start() - 90):m.end() + 20].strip())
    return t


def step_named(u, suffix):
    return next((s["name"] for s in u["steps"] if s["name"].endswith(suffix)), None)


main = sorted((u for u in units if u["run"]["variant"] == "default" and "tamper" in u["run"]["steps"]), key=lambda u: u["dir"])
main = main[-1] if main else None
fresh = sorted((u for u in units if u["run"]["variant"] == "default" and u["run"]["steps"] == "h:date"), key=lambda u: u["dir"])
fresh = fresh[-1] if fresh else None
I1 = None
if main and fresh and step_named(main, "-h-env") and step_named(main, "-h-date"):
    sa, sb, sc = step_named(main, "-h-env"), step_named(main, "-h-date"), fresh["steps"][0]["name"]
    A, B, C = tokens(model_blobs(main, sa)), tokens(model_blobs(main, sb)), tokens(model_blobs(fresh, sc))
    I1 = {"A_requests": len(model_blobs(main, sa)), "B_requests": len(model_blobs(main, sb)), "C_requests": len(model_blobs(fresh, sc)),
          "candidates": [{"token": t, "context_A": sorted(A[t])[:3]} for t in sorted(set(A) & set(B) - set(C))]}
try:
    with open(f"{S}/results/runlist-{BATCH}.txt") as f: plan = parse_plan(f.read(), H)
except (OSError, UnicodeError):
    plan = None
out = {"harness": H, "batch": BATCH, "batch_plan": plan, "units": [], "I1": I1}
for u in units:
    acc = u.get("access_1001")
    uu = {"dir": u["dir"], "variant": u["run"]["variant"], "steps": u["run"]["steps"], "version": u["run"]["version"],
          "started": u["run"].get("started"), "model": u["run"].get("model"), "l3variant": u["run"].get("l3variant") or "",
          "capture": u.get("capture", {}), "problems": u.get("problems", ["no problem record (analysed by an older analyse_unit.py)"]), "step": []}
    for s in u["steps"]:
        uu["step"].append({k: s.get(k) for k in ("name", "kind", "skipped", "rc", "outer_rc", "exec_date", "exec_ls", "exec_calc", "exec_sandbox",
                                                 "nonmodel_hosts", "tls_failed", "passthrough", "other_port_connects", "model_requests", "model_ok", "model_last_ok", "model_seq",
                                                 "canary_to_model", "tamper_to_model", "tamper_secret_to_model", "leftover_missing",
                                                 "strace_ok", "exec_failed_n", "exec_unresolved_n", "exec_ambiguous",
                                                 "output_readable", "vendor_errors", "vendor_errors_n")}
                          | {"leftover": [l["cmd"][:120] for l in s.get("leftover", [])], "tamper": s.get("tamper")})
    uu["model_hosts"] = sorted({m["host"] for m in u["model_requests"] if m.get("src") == "mitm"})
    uu["nonmodel"] = [{k: f.get(k) for k in ("step", "host", "method", "path", "status", "req_bytes", "secret_hits", "file_hits", "session_hits", "dummy_hits", "file", "blocked", "body_uninspected", "upstream_error", "url_truncated", "redaction_incomparable", "payload_redacted", "ws_client_msgs", "payload_opaque")}
                      for f in u["nonmodel_flows"]]
    uu["disk_hits"] = u["disk_hits"]
    uu["unit_uninspected"] = u.get("unit_uninspected")   # None (older analysis) = channel accounting missing, scored as uninspected
    uu["cred_stores"] = u["run"].get("cred_stores") or []
    uu["readable_1001"] = None if acc is None else acc["readable"]; uu["home_parents"] = None if acc is None else acc["parents"]
    uu["access_errors_1001"] = None if acc is None else acc.get("errors", [])
    uu["access_checked_1001"] = None if acc is None else acc.get("checked")   # every probed path -> readable | denied | error:<kind>
    uu["pcap_sni"] = u["pcap_sni"]; uu["modes"] = {d["path"]: u["modes"].get(d["path"]) for d in u["disk_hits"]}
    out["units"].append(uu)
os.makedirs(f"{S}/digest", exist_ok=True); json.dump(out, open(f"{S}/digest/{H}.json", "w"), indent=1)
print(H, len(units), "units;", "I1 candidates", None if I1 is None else len(I1["candidates"]))
