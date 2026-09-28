#!/usr/bin/env python3
# Seeds the empty harness HOME with the adapter's config (run as the harness user, uid 1000, inside the harness container).
# Usage: tar -C STAGED -cf - . | seed_home.py HOME CALIBRATION_LISTING OUTJSON
# The rig never widens a path the harness owns. Each directory and file of the staged config is created with the mode the harness
# itself gave that path in the calibration run (bench/unit.sh: same image, empty HOME, no network, no config), and otherwise with
# 0700 (directory) or 0600 (file), never wider. OUTJSON lists every seeded path with its mode and where the mode came from
# ("harness" = observed in the calibration run, "rig" = not observed, so R3 cannot say what the harness would have done there).
#        seed_home.py --record HOME OUTJSON REL   adds a file the rig wrote after seeding (the credential file) with its actual mode
import json, os, stat, sys, tarfile
if sys.argv[1] == "--record":
    home, out, rel = sys.argv[2:5]; d = json.load(open(out))
    d["entries"].append({"path": rel, "type": "file", "mode": oct(stat.S_IMODE(os.lstat(os.path.join(home, rel)).st_mode)), "source": "rig", "credential": True})
    json.dump(d, open(out, "w"), indent=1); sys.exit(0)
home, cal, out = sys.argv[1:4]
try:
    c = json.load(open(cal))
    seen = {e["path"]: (e["type"], int(e["mode"], 8)) for e in c if isinstance(e, dict) and isinstance(e.get("path"), str)}
    calib = "ok"
except (OSError, ValueError, KeyError, TypeError):
    seen, calib = {}, "missing"
ents, dirs = [], []
with tarfile.open(fileobj=sys.stdin.buffer, mode="r|") as t:
    for m in t:
        rel = os.path.normpath(m.name)
        if rel == ".": continue
        if rel.startswith("..") or os.path.isabs(rel): sys.exit(f"seed: unsafe path {m.name!r}")
        p = os.path.join(home, rel); kind = "dir" if m.isdir() else "file" if m.isfile() else None
        if kind is None: sys.exit(f"seed: {rel} is neither a file nor a directory")
        st, mode = seen.get(rel, (None, None))
        src = "harness" if st == kind else "rig"
        if src == "rig": mode = 0o700 if kind == "dir" else 0o600
        if kind == "dir":
            os.makedirs(p, 0o700, exist_ok=True); dirs.append((p, mode))   # modes are set deepest first once every file is in
        else:
            os.makedirs(os.path.dirname(p), 0o700, exist_ok=True)
            with open(os.open(p, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600), "wb") as f: f.write(t.extractfile(m).read())
            os.chmod(p, mode)
        ents.append({"path": rel, "type": kind, "mode": oct(mode), "source": src})
for p, mode in sorted(dirs, key=lambda x: -x[0].count(os.sep)): os.chmod(p, mode)
json.dump({"calibration": calib, "entries": ents}, open(out, "w"), indent=1)
