#!/usr/bin/env python3
# N4 helper, run by the step's inner script 5 s after the harness command returned. Lists every process in the container
# that is not PID 1 (the idle container keeper) and not an ancestor of this script, writes them to OUT, then kills them
# so the next step starts clean. Usage: leftover.py OUTJSON
import os, sys, json, signal
me = os.getpid(); anc = set(); p = me
while p > 1:
    anc.add(p)
    try: p = int(open(f"/proc/{p}/stat").read().rsplit(")", 1)[1].split()[1])
    except Exception: break
left = []
for d in os.listdir("/proc"):
    if not d.isdigit(): continue
    pid = int(d)
    if pid == 1 or pid in anc: continue
    try:
        cmd = open(f"/proc/{pid}/cmdline", "rb").read().replace(b"\0", b" ").decode("utf-8", "replace").strip()
        st = open(f"/proc/{pid}/stat").read().rsplit(")", 1)[1].split()
        if st[0] == "Z": continue
        left.append({"pid": pid, "ppid": int(st[1]), "cmd": cmd[:300]})
    except Exception: continue
# processes of the docker exec chain belonging to other concurrent execs never exist (steps run one at a time)
json.dump(left, open(sys.argv[1], "w"), indent=1)
for l in left:
    try: os.kill(l["pid"], signal.SIGKILL)
    except Exception: pass
