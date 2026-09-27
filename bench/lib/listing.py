#!/usr/bin/env python3
# Owner-side listing of the harness HOME: mode, uid, size, sha256 for every file and dir. Usage: listing.py ROOT OUTJSON FILELIST [--own]
#   --own: only entries owned by this user (the harness user); used for /tmp, which also holds root-owned files from the image build.
# A file whose content cannot be hashed is listed with hash_error (never skipped silently).
import os, sys, json, stat, hashlib
root, out, fl = sys.argv[1:4]; own = "--own" in sys.argv[4:]; ent = []; files = []
for d, ds, fs in os.walk(root):
    for n in ds + fs:
        p = os.path.join(d, n); rel = os.path.relpath(p, root)
        try: st = os.lstat(p)
        except Exception: continue
        if own and st.st_uid != os.getuid(): continue
        e = {"path": rel, "mode": oct(stat.S_IMODE(st.st_mode)), "uid": st.st_uid, "size": st.st_size,
             "type": "dir" if stat.S_ISDIR(st.st_mode) else "link" if stat.S_ISLNK(st.st_mode) else "file"}
        if stat.S_ISSOCK(st.st_mode) or stat.S_ISFIFO(st.st_mode): e["type"] = "socket/fifo"
        if e["type"] == "file":
            files.append(rel)
            if st.st_size < 200_000_000:
                try:
                    h = hashlib.sha256()
                    with open(p, "rb") as f:
                        for c in iter(lambda: f.read(1 << 20), b""): h.update(c)
                    e["sha256"] = h.hexdigest()
                except Exception as x: e["hash_error"] = type(x).__name__
        ent.append(e)
json.dump(ent, open(out, "w"), indent=0); open(fl, "w").write("\n".join(files) + "\n")
