#!/usr/bin/env python3
# Runs INSIDE a logged-in harness container. Copies files from the in-memory HOME (or /tmp) to DEST_ROOT, replacing every
# credential string found in the given credential files (and any JWT) with <redacted:sha12>.
# Before scrubbing, it counts per file how many credential strings and JWTs (bearer tokens issued to the account, which the
# credential file may not contain) each file held, and writes that list (paths and counts only, never the strings) to
# DEST_ROOT.hits.json, so R5 can check where account credentials were left on disk.
# Credential stores are only the absolute paths given as STORES (from the harness definition's CRED_STORES, never guessed from
# a file name). They are never copied, but before they are skipped they are scanned for the unit's needles (fake secrets, dummy
# key, prompts; NEEDLES.json as for bigscan.py) and the names of the needles found are recorded ("needle_hits"), so a session
# record or leaked secret inside a store still reaches R3 and R5.
# Usage: scrub_copy.py SRC_ROOT DEST_ROOT CRED_FILE[,CRED_FILE...] STORE[,STORE...] NEEDLES.json [glob ...]
# Env OWNED_ONLY=1: only files owned by this user (the harness user); used for /tmp, which also holds files from the image build.
import sys, os, re, json, glob, hashlib
src, dst, creds = sys.argv[1], sys.argv[2], sys.argv[3].split(",")
stores = {os.path.abspath(x) for x in sys.argv[4].split(",") if x}
sys.path.insert(0, os.environ.get("AB_BENCH_LIB", "/opt/bench")); from bigscan import needles   # noqa: E402
NEEDLES = {k: v.encode() for k, v in needles(json.load(open(sys.argv[5]))).items() if v}
pats = sys.argv[6:] or ["**/*"]
secrets = set()
def walk(o):
    if isinstance(o, dict): [walk(v) for v in o.values()]
    elif isinstance(o, list): [walk(v) for v in o]
    elif isinstance(o, str) and len(o) >= 16: secrets.add(o)
for c in creds:
    try: walk(json.load(open(c)))
    except Exception: pass
JWT = re.compile(rb"eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{4,}")
h = lambda b: hashlib.sha256(b).hexdigest()[:12]
left = 0; n = 0; hits = []; errors = []
for p in pats:
    for f in glob.glob(os.path.join(src, p), recursive=True, include_hidden=True):
        if not os.path.isfile(f): continue
        if os.environ.get("OWNED_ONLY") == "1" and os.lstat(f).st_uid != os.getuid(): continue
        rel = os.path.relpath(f, src)
        try: b = open(f, "rb").read()
        except Exception as e: errors.append({"path": rel, "error": type(e).__name__}); continue
        found = {h(s.encode()): b.count(s.encode()) for s in secrets if s.encode() in b}
        jwts = {h(m.group(0)) for m in JWT.finditer(b)} - set(found)
        store = os.path.abspath(f) in stores
        if found or jwts or store:
            e = {"path": rel, "credential_strings": len(found) + len(jwts), "occurrences": sum(found.values()), "jwts": len(jwts), "credential_store": store}
            if store: e["needle_hits"] = sorted(k for k, v in NEEDLES.items() if v in b)   # the store is not copied: scanned here
            hits.append(e)
        if store: continue
        for s in secrets: b = b.replace(s.encode(), b"<redacted:" + h(s.encode()).encode() + b">")
        b = JWT.sub(lambda m: b"<jwt:" + h(m.group(0)).encode() + b">", b)
        left += sum(b.count(s.encode()) for s in secrets)
        o = os.path.join(dst, rel); os.makedirs(os.path.dirname(o), exist_ok=True)
        open(o, "wb").write(b); os.chmod(o, 0o644); n += 1
os.makedirs(dst, exist_ok=True)
json.dump({"credential_strings_known": len(secrets), "copied": n, "remaining_after_scrub": left, "unreadable": errors, "files": hits},
          open(dst.rstrip("/") + ".hits.json", "w"), indent=1)
print(f"copied {n} files, credential strings known {len(secrets)}, remaining after scrub {left}, unreadable {len(errors)}")
sys.exit(1 if errors or left else 0)
