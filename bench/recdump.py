#!/usr/bin/env python3
# Evidence helper for R1/R2 adjudication: prints, per file in a unit's copied HOME (+/tmp), short excerpts around the
# requested command and around approval/permission words. SQLite files are dumped row by row first.
# Usage: recdump.py UNITDIR [REGEX]
import os, re, sys, sqlite3
U = sys.argv[1]; RX = re.compile(sys.argv[2] if len(sys.argv) > 2 else
    r"print\(6\*7\)|approv|permission|denied|reject|auto[-_ ]?approve|yolo|decision|allow|toolDenial|ask")
for base in ("homeout", "tmpout"):
    for d, ds, fs in os.walk(f"{U}/{base}"):
        if "/plugins/" in d or "/node_modules" in d or "/.bun/" in d: continue
        for fn in fs:
            p = os.path.join(d, fn)
            try: b = open(p, "rb").read(30_000_000)
            except Exception: continue
            if b.startswith(b"SQLite format 3"):
                try:
                    c = sqlite3.connect(f"file:{p}?mode=ro&immutable=1", uri=True)
                    t = "\n".join(f"[{tb}] " + repr(r) for (tb,) in c.execute("select name from sqlite_master where type='table'") for r in c.execute(f'select * from "{tb}"'))
                except Exception as e: t = f"<sqlite error {e}>"
            else: t = b.decode("utf-8", "replace")
            hits = [m for m in RX.finditer(t)]
            if not hits or (len(sys.argv) <= 2 and "print(6*7)" not in t and "python3" not in t): continue
            print(f"=== {os.path.relpath(p, U)} ({len(hits)} hits)")
            seen = 0
            for m in hits:
                if m.start() < seen: continue
                print("   ..." + t[max(0, m.start() - 160):m.end() + 200].replace("\n", " ") + "...")
                seen = m.end() + 200
