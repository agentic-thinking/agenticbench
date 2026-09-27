#!/usr/bin/env python3
# R3 helper. Run as a DIFFERENT local user (docker exec --user 1001) against the harness HOME.
# For every path under ROOT (walked as far as this user can): can it be listed / read? Also the mode chain of ROOT's parents.
# Usage: access.py ROOT FILELIST   (FILELIST = paths relative to ROOT, one per line, produced by the owner beforehand)
import os, sys, json, stat
root, fl = sys.argv[1], sys.argv[2]
res = {"uid": os.getuid(), "root": root, "parents": [], "files": {}}
p = root
while True:
    try: st = os.stat(p); res["parents"].append({"path": p, "mode": oct(stat.S_IMODE(st.st_mode)), "uid": st.st_uid})
    except Exception as e: res["parents"].append({"path": p, "error": str(e)})
    if p == "/": break
    p = os.path.dirname(p)
for rel in open(fl).read().splitlines():
    f = os.path.join(root, rel)
    try:
        with open(f, "rb") as h: h.read(64)
        res["files"][rel] = "readable"
    except PermissionError: res["files"][rel] = "denied"
    except Exception as e: res["files"][rel] = "error:" + type(e).__name__
json.dump(res, sys.stdout, indent=1)
