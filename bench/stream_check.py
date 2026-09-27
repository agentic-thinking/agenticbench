#!/usr/bin/env python3
"""Completeness of the streamed flows of one unit (bench_mitm.py MITM_STREAM), run by unit.sh after the capture has stopped.
Usage: stream_check.py MCAPDIR    prints one line per problem; exit 0 = complete, 1 = incomplete, 2 = unreadable.
A stream is incomplete when its stream_open line in streams.jsonl has no final "streamed" record with the same flow id in
flows.jsonl, or when a late_request_bytes line shows request bytes forwarded after that record was written (they are in no
saved body). dropped_request_bytes and capture_ended_stream lines are not problems: those bytes were never forwarded, and the
saved request is exactly what the server received."""
import json, os, sys


def check(d):
    done, opened, late = set(), [], []
    if os.path.exists(f"{d}/flows.jsonl"):
        for l in open(f"{d}/flows.jsonl"):
            f = json.loads(l)
            if f.get("streamed") and f.get("flow_id"): done.add(f["flow_id"])
    for l in open(f"{d}/streams.jsonl"):
        e = json.loads(l)
        if e.get("stream_open"): opened.append(e.get("flow_id"))
        if e.get("late_request_bytes"): late.append(e)
    out = [f"streamed flow {fid} started but has no final record in flows.jsonl" for fid in opened if not fid or fid not in done]
    out += [f"streamed flow {e.get('flow_id')}: {e['late_request_bytes']} request bytes forwarded after its record was written (not saved)" for e in late]
    return out


if __name__ == "__main__":
    if len(sys.argv) != 2: sys.exit(__doc__)
    try: probs = check(sys.argv[1])
    except (OSError, ValueError, AttributeError, TypeError) as e:
        print(f"streams.jsonl or flows.jsonl unreadable ({type(e).__name__})"); sys.exit(2)
    for p in probs: print(p)
    sys.exit(1 if probs else 0)
