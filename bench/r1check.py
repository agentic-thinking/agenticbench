#!/usr/bin/env python3
# R1 helper: for the main unit, list the session-record files (hold the env prompt or a secret) and whether the record
# set contains: the prompt, a tool call on .env (path/command in a tool-call structure), the tool output (secret or TAMPER
# marker), the model id, timestamps. Prints excerpts so the call can be checked by eye. Usage: r1check.py UNITDIR MODELID
import os, re, sys, sqlite3, json
U, MID = sys.argv[1], sys.argv[2]; run = json.load(open(f"{U}/run.json")); tag = run["canary"][6:]
prompt = open(next(f"{U}/out/steps/{f}" for f in os.listdir(f"{U}/out/steps") if f.endswith("h-env.prompt"))).read()
texts = {}
for d, ds, fs in os.walk(f"{U}/homeout"):
    for fn in fs:
        p = os.path.join(d, fn); b = open(p, "rb").read(50_000_000)
        if b.startswith(b"SQLite format 3"):
            try:
                c = sqlite3.connect(f"file:{p}?mode=ro&immutable=1", uri=True)
                t = "\n".join(repr(r) for (tb,) in c.execute("select name from sqlite_master where type='table'") for r in c.execute(f'select * from "{tb}"'))
            except Exception: t = ""
        else: t = b.decode("utf-8", "replace")
        if prompt[:40] in t or prompt[:40].replace('"', '\\"') in t or ("TAMPER" + tag) in t or ("CANARY" + tag) in t or "exactly as TAMPERD" in t:
            texts[os.path.relpath(p, U)] = t
allt = "\n".join(texts.values())
def ex(rx):
    m = re.search(rx, allt); return (allt[max(0, m.start() - 100):m.end() + 100].replace("\n", " ") if m else None)
chk = {"prompt": ex(re.escape(prompt[:40]).replace('\\"', '\\\\?"') + "|exactly as TAMPERD"),
       "tool_call": ex(r'(?:tool_use|function_call|functionCall|toolCall|tool_calls|"tool"\s*:|"callID"|"toolName"|"type"\s*:\s*"tool)[^\n]{0,600}?(?:\.env|\bdate\b)'),
       "tool_output": ex("(?:TAMPER|CANARY)(?:pw)?" + re.escape(tag)),
       "model": ex(re.escape(MID)),
       "time": ex(r"20\d\d-\d\d-\d\dT\d\d:\d\d:\d\d|\b1[6-9]\d{8}(?:\d{3})?\b")}
print("record files:", list(texts))
for k, v in chk.items(): print(f"{k:18s} {'YES' if v else 'NO '} {(v or '')[:260]}")
