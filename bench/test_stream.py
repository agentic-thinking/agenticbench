#!/usr/bin/env python3
# Tests for the opt-in MITM_STREAM tee of bench_mitm.py. Run in the mitm image: python3 bench/test_stream.py
import gzip, json, os, struct, sys, tempfile, zlib
os.environ["MITM_CAP"] = tempfile.mkdtemp(); os.environ["MITM_STREAM"] = r"^model\.test/stream"
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import bench_mitm as M
from mitmproxy.test import tflow
def env(msg, fl=0): return bytes([fl]) + struct.pack(">I", len(msg)) + msg
ok = 0
def check(c, what):
    global ok
    if not c: sys.exit("FAIL: " + what)
    ok += 1
# 1 plain and gzip-compressed Connect frames decode to the concatenated messages; frame list recorded
raw = env(b"hello ") + env(gzip.compress(b"CANARY42"), 1) + env(b'{"end":1}', 2)
d, fr = M.connect_payloads(raw, True); check(d == b'hello CANARY42{"end":1}' and [f[0] for f in fr] == [0, 1, 2], "decode")
# 2 compressed frame without connect-content-encoding gzip, unknown flag, short frame: not decoded (raw kept)
check(M.connect_payloads(env(gzip.compress(b"x"), 1), False)[0] is None, "compressed without encoding")
check(M.connect_payloads(env(b"x", 8), True)[0] is None, "unknown flag")
check(M.connect_payloads(env(b"xyz")[:-1], True)[0] is None, "short frame")
# 3 inflate limit: a frame inflating beyond INFLATE_MAX is not decoded
check(M.connect_payloads(env(gzip.compress(b"a") + b"junk", 1), True)[0] is None, "trailing bytes after gzip member")
check(M.connect_payloads(env(gzip.compress(b"a") + gzip.compress(b"b"), 1), True)[0] is None, "second gzip member")
M.INFLATE_MAX = 1000; check(M.connect_payloads(env(gzip.compress(b"a" * 5000), 1), True)[0] is None, "inflate limit"); M.INFLATE_MAX = 64 << 20
# 4 end to end through the hooks: request streamed, chunks forwarded unchanged, raw and decoded files written, record flagged
f = tflow.tflow(resp=True); f.request.host = "model.test"; f.request.path = "/stream"
f.request.headers["content-type"] = "application/connect+proto"; f.request.headers["connect-content-encoding"] = "gzip"
f.response.headers["content-type"] = "application/connect+proto"
M.requestheaders(f); check(f.metadata.get("streamed") and callable(f.request.stream), "stream set")
chunks = [raw[:7], raw[7:]]; check([f.request.stream(c) for c in chunks] == chunks, "chunks unchanged")
big = b"z" * 6_000_000
M.responseheaders(f); f.response.stream(env(b"answer")); f.response.stream(env(big))
M.response(f)
recs = [json.loads(l) for l in open(os.environ["MITM_CAP"] + "/flows.jsonl") if '"i"' in l]
r = recs[-1]; base = os.environ["MITM_CAP"] + "/" + r["file"]
check(r["streamed"] and r["req_connect"]["connect_decoded"] and r["req_connect"]["frames_n"] == 3, "record flags")
check(open(base + ".req", "rb").read() == b'hello CANARY42{"end":1}' and open(base + ".req.raw", "rb").read() == raw, "files")
check(open(base + ".resp", "rb").read() == b"answer" + big, "resp decoded in full (over 5 MB)")
check(any(json.loads(l).get("stream_open") for l in open(os.environ["MITM_CAP"] + "/streams.jsonl")), "stream_open event")
# 5 a streamed flow that never ends is recorded at shutdown with an error; non-Connect streamed body saved raw
g = tflow.tflow(); g.request.host = "model.test"; g.request.path = "/stream"; g.request.headers["content-type"] = "application/octet-stream"
M.requestheaders(g); g.request.stream(b"partial"); M.done()
r = [json.loads(l) for l in open(os.environ["MITM_CAP"] + "/flows.jsonl") if '"i"' in l][-1]
check(r["upstream_error"] == "capture ended before the stream finished" and open(os.environ["MITM_CAP"] + "/" + r["file"] + ".req", "rb").read() == b"partial", "unfinished stream")
# 6 response ends while the request stream is still open. HTTP/2: recorded at once (the addon then ends the stream; the
#   stream state machine itself is exercised end to end by the mock-server harness, see the fix report). Other protocols:
#   the record waits for the end of the request, so request bytes forwarded after the response are saved too.
recs = lambda: [json.loads(l) for l in open(os.environ["MITM_CAP"] + "/flows.jsonl") if '"i"' in l]
k = tflow.tflow(resp=True); k.request.host = "model.test"; k.request.path = "/stream"; k.client_conn.alpn = b"h2"
k.request.headers["content-type"] = "application/octet-stream"; M.requestheaders(k); k.request.stream(b"req"); k.request.timestamp_end = None
M.responseheaders(k); k.response.stream(b"answer"); check(M.ends_early(k), "ends early over h2")
n0 = len(recs()); M.response(k); r = recs()[-1]
check(len(recs()) == n0 + 1 and r["flow_id"] == k.id and r["req_open_at_response_end"] is True and "proxy_ended_stream" not in r, "h2: recorded at response, open request flagged")
k.request.stream(b"late")   # defensive: a byte forwarded after the record is on record as late
late = [json.loads(l) for l in open(os.environ["MITM_CAP"] + "/streams.jsonl") if "late_request_bytes" in l]
check(late and late[-1]["late_request_bytes"] == 4 and late[-1]["flow_id"] == k.id, "late request bytes logged")
j = tflow.tflow(resp=True); j.request.host = "model.test"; j.request.path = "/stream"; j.client_conn.alpn = b"http/1.1"
j.request.headers["content-type"] = "application/octet-stream"
M.requestheaders(j); j.request.stream(b"one"); j.request.timestamp_end = None; M.responseheaders(j); j.response.stream(b"answer")
check(not M.ends_early(j), "http/1.1 keeps mitmproxy behaviour")
n0 = len(recs()); M.response(j); check(len(recs()) == n0 and j.metadata.get("record_deferred"), "http/1.1: record deferred while the request is open")
j.request.stream(b"two"); M.request(j); r = recs()[-1]
check(r["flow_id"] == j.id and r["req_open_at_response_end"] is True and open(os.environ["MITM_CAP"] + "/" + r["file"] + ".req.raw", "rb").read() == b"onetwo", "http/1.1: recorded at request end with every forwarded byte")
check(not any(json.loads(l).get("flow_id") == j.id for l in open(os.environ["MITM_CAP"] + "/streams.jsonl") if "late_request_bytes" in l), "http/1.1: no late bytes")
check("req_open_at_response_end" not in recs()[0], "ended request not flagged")
e = tflow.tflow(resp=True); e.request.host = "model.test"; e.request.path = "/stream"; e.client_conn.alpn = b"h2"
M.requestheaders(e); e.request.stream(b"req"); e.request.timestamp_end = None; M.responseheaders(e); e.response.stream(b"part")
M.error(e); r = recs()[-1]   # the response never completed (stream reset or connection lost after its headers)
check(r["flow_id"] == e.id and r["upstream_error"] and "req_open_at_response_end" not in r, "partial response error: not flagged")
from mitmproxy.proxy.layers import http as L
check(L.HttpStream.send_response is M._send_response_end, "send_response patched")
# 7 non-matching flows are untouched
h = tflow.tflow(); h.request.host = "other.test"; M.requestheaders(h); check(not h.metadata.get("streamed") and not h.request.stream, "non-matching untouched")
print(f"ok: {ok} checks")
