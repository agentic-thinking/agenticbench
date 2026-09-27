# AgenticBench mitmproxy addon (transparent mode, lab CA). Writes CAPDIR/flows.jsonl plus decoded bodies.
# - A start record is written when the addon loads, so an empty capture can be told apart from a capture that never ran.
# - Every request is logged with its TLS SNI, host, path, headers, timestamps, including requests that fail upstream
#   (recorded from the error hook with their body and the error text). Logged-in runs store credential headers only as their
#   full sha256 (64 hex, unsalted, so the same value compares equal across units for the identifier tests), unless the value
#   holds one of the unit's fake secrets. Paths (with query) and header values are recorded in full, never cut. Websocket
#   frames are saved losslessly (base64 of the exact bytes, with the frame's text/binary type); frames over 5 MB are truncated
#   and marked "truncated", which analysis counts as uninspected.
# - Bodies are saved content-decoded (gzip/br/zstd/deflate) as .req/.resp. MITM_NOBODY (set by unit.sh for logged-in
#   accounts only; regex on host+path of authentication endpoints): those bodies are never written, and the record says
#   so (bodies_saved false), so analysis counts the request as uninspected instead of empty.
# - Logged-in runs only (MITM_SCRUB=1): JWTs become <jwt:SHA256> and *_token fields <redacted:SHA256> (full 64-hex digest,
#   comparable across units, so a stable token still shows up as a persistent identifier). Detection runs before redaction: a
#   value that holds, raw or base64-encoded (2 levels), any needle the analysis searches for (MITM_KEEP: the unit's fake secrets,
#   dummy key, tamper markers, file names, paths and contents, step prompts; each also as base64 and sha256/sha1/md5 hex) is never
#   redacted. Each record counts its replaced values (redacted_n); analysis treats a request with any replaced value as
#   uninspected for payload and identifier tests (a hash can prove a repeat, never an absence). Runs without an account save bodies as sent.
# - A client that rejects the lab CA shows up as a tls_failed event; later connections to that SNI are passed through
#   untouched (recorded as passthrough), so the harness keeps working and the uninspected channel is on record.
# - MITM_STREAM (opt-in, empty by default; regex on host+path): matching requests and responses are streamed through chunk by
#   chunk instead of buffered (needed for bidirectional streams, e.g. Connect/gRPC over HTTP/2, which never finish while the
#   proxy waits for the whole request). Chunks are forwarded unchanged; every byte is also kept (no cap). A "stream_open" line is
#   written to streams.jsonl when such a request starts, so a stream that never ends is still on record (unit.sh records a unit
#   problem for any open without a final record in flows.jsonl). When the flow ends (response, error, or
#   capture shutdown) the kept bytes are saved as .req.raw/.resp.raw as sent (after the same credential scrubbing as every saved
#   body), and in full (no 5 MB cut) as .req/.resp decoded for analysis: a
#   Connect envelope stream (flag byte, 4-byte length, message) becomes its concatenated message payloads (compressed messages
#   inflated, at most 64 MB each); anything that is not a clean envelope stream (unknown flag, bad length, inflate error, limit,
#   trailing bytes or a second gzip member)
#   is saved raw in .req/.resp too. The record carries "streamed": true, "connect_decoded" and the frame list [flags, length].
#   A streamed response that ends while the client's request stream is still open: mitmproxy 11.0.2 holds the response
#   end-of-stream back until the client ends its request (HttpStream.send_response), so a client that keeps its side open until
#   the server finishes (Cursor's agent stream sends heartbeat frames) never sees the answer end. For such flows over HTTP/2 the
#   addon ends the stream itself right after the response hook has recorded the flow: END_STREAM to the server (its response is
#   complete), then mitmproxy's own flow_done (drops the stream, then END_STREAM to the client), and a "capture_ended_stream"
#   line in streams.jsonl once that is done. As the stream is dropped, request bytes the client still sends are neither forwarded nor saved (bytes already queued in mitmproxy
#   are counted in a "dropped_request_bytes" line; bytes arriving after the drop are ignored by mitmproxy uncounted), and the
#   saved request is exactly what was forwarded to the server. Other protocols keep mitmproxy's behaviour, and the record of
#   such a flow waits until the request ends (if the flow is aborted instead, until the capture stops: mitmproxy calls no error
#   hook once the response is complete), so every forwarded request byte is saved. The record carries req_open_at_response_end when the response completed while the request was still open.
#   A "late_request_bytes" line would mean request bytes were forwarded after the record was written (not expected).
# - MITM_BLOCK (opt-in, empty by default; regex on host+path): answered 503 locally, never forwarded; the attempt and body are
#   captured and the flow is marked blocked.
import os, re, json, time, hashlib, base64
from mitmproxy import http, tls
CAP = os.environ["MITM_CAP"]; os.makedirs(CAP, exist_ok=True); n = [0]
BOOT = time.strftime("%H%M%S")
BLOCK = re.compile(os.environ["MITM_BLOCK"]) if os.environ.get("MITM_BLOCK") else None
STREAM = re.compile(os.environ["MITM_STREAM"]) if os.environ.get("MITM_STREAM") else None
OPEN = {}                      # streamed flows not yet recorded (flow id -> flow)
NOBODY = re.compile(os.environ["MITM_NOBODY"]) if os.environ.get("MITM_NOBODY") else None
SENS = re.compile(r"authorization|cookie|api[-_]?key|token|secret|session-key", re.I)
JWT = re.compile(rb"eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{4,}")
TOKF = re.compile(rb'("(?:access_token|refresh_token|id_token|token|api_key|apiKey|key|accessToken|refreshToken)"\s*:\s*")[^"]{8,}(")')
PASS = set()
SCRUB = os.environ.get("MITM_SCRUB") == "1"
KEEP = []
for v in json.loads(os.environ.get("MITM_KEEP") or "[]"):
    b = v.encode(); KEEP += [b, base64.b64encode(b).rstrip(b"=")] + [h(b).hexdigest().encode() for h in (hashlib.sha256, hashlib.sha1, hashlib.md5)]
def h12(v): return hashlib.sha256(v.encode() if isinstance(v, str) else v).hexdigest()[:12]
def h64(v): return hashlib.sha256(v.encode() if isinstance(v, str) else v).hexdigest()
B64 = re.compile(rb"[A-Za-z0-9+/_-]{16,}={0,2}")
def decoded(v, depth=0):
    """v plus its base64 / base64url-decoded runs (2 levels), as the analysis decodes bodies."""
    out = [v]
    if depth < 2:
        for m in B64.finditer(v):
            s = m.group(0)
            for dec in (base64.b64decode, base64.urlsafe_b64decode):
                try: d = dec(s + b"=" * (-len(s) % 4)); out += decoded(d, depth + 1); break
                except Exception: pass
    return out
def keep(v):
    """detection before redaction: a value holding (raw or base64-encoded) any needle the analysis searches for is never redacted."""
    return any(k in x for x in decoded(v) for k in KEEP if k)
def scrub(b):
    """returns (scrubbed bytes, number of values replaced)."""
    if not SCRUB: return b, 0
    n = [0]
    def jw(m):
        if keep(m.group(0)): return m.group(0)
        n[0] += 1; return b"<jwt:" + h64(m.group(0)).encode() + b">"
    b = JWT.sub(jw, b)
    def tok(m):
        v = m.group(0)[len(m.group(1)):-1]
        if keep(v) or v.startswith(b"<jwt:"): return m.group(0)
        n[0] += 1; return m.group(1) + b"<redacted:" + h64(v).encode() + b">" + m.group(2)
    return TOKF.sub(tok, b), n[0]
def hdr(k, v):
    if SCRUB and SENS.search(k) and not keep(v.encode()):
        return {"name": k, "sha256": h64(v), "redacted": True}
    return {"name": k, "value": v}
def hdrs(h): return [hdr(k, v) for k, v in h.items(multi=True)]
def ev(rec):
    with open(f"{CAP}/flows.jsonl", "a") as f: f.write(json.dumps(rec) + "\n")
INFLATE_MAX = 64 * 1024 * 1024
def connect_payloads(raw, gz):
    """Connect streaming envelopes: 1 flag byte (bit 0 compressed, bit 1 end-of-stream), 4-byte big-endian length, message.
    Returns (decoded concatenated messages, [[flags, length], ...]) or (None, frames so far) if raw is not a clean envelope stream."""
    import struct, zlib
    out, frames, i = [], [], 0
    while i < len(raw):
        if len(raw) - i < 5: return None, frames
        fl, ln = raw[i], struct.unpack(">I", raw[i + 1:i + 5])[0]; m = raw[i + 5:i + 5 + ln]
        frames.append([fl, ln])
        if fl & ~3 or len(m) != ln: return None, frames
        if fl & 1:
            if not gz: return None, frames
            d = zlib.decompressobj(16 + zlib.MAX_WBITS)
            try: m2 = d.decompress(m, INFLATE_MAX)
            except Exception: return None, frames
            if d.unconsumed_tail or not d.eof or d.unused_data: return None, frames   # over the limit, cut short, or trailing bytes / a second member
            m = m2
        out.append(m); i += 5 + ln
    return b"".join(out), frames
def body(m):
    try: return m.get_content(strict=False) or b""
    except Exception: return m.raw_content or b""
def sbody(flow, m, side):
    """body of a streamed side: (bytes for analysis, raw bytes, connect info)"""
    raw = bytes(flow.metadata.get("stream_" + side) or b"")
    if "connect" in m.headers.get("content-type", ""):
        d, frames = connect_payloads(raw, "gzip" in m.headers.get("connect-content-encoding", ""))
        return (d if d is not None else raw), raw, {"connect_decoded": d is not None, "frames": frames[:5000], "frames_n": len(frames)}
    return raw, raw, {"connect_decoded": False}
def tee(flow, side):
    buf = flow.metadata["stream_" + side] = bytearray()
    def f(chunk):
        buf.extend(chunk)
        if chunk and flow.metadata.get("recorded"):   # forwarded after the record was written: not in the saved files
            with open(f"{CAP}/streams.jsonl", "a") as g:
                g.write(json.dumps({"late_request_bytes": len(chunk), "side": side, "flow_id": flow.id, "t": time.time()}) + "\n")
        return chunk
    return f
def ends_early(flow):
    """streamed flow whose request is still open when the response ends, over HTTP/2: the addon ends the stream itself"""
    return bool(flow.metadata.get("streamed")) and flow.request.timestamp_end is None and flow.client_conn.alpn == b"h2"
try:
    from mitmproxy.proxy.layers import http as _L
    from mitmproxy.version import VERSION as _MV
except ImportError: _L = _MV = None                 # test_capture.py imports this file with a stub mitmproxy module
if _MV != "11.0.2":                                 # the patch below relies on this version's HttpStream internals
    if STREAM: raise RuntimeError(f"MITM_STREAM needs the end-of-stream patch, written for mitmproxy 11.0.2 (found {_MV})")
    _L = None
_send_response = _L and _L.HttpStream.send_response
def _send_response_end(self, already_streamed: bool = False):
    yield from _send_response(self, already_streamed)   # response hook (the flow is recorded there), headers/trailers to the client
    if (self.server_state == self.state_done and self.client_state == self.state_stream_request_body and ends_early(self.flow)):
        yield _L.SendHttp(_L.RequestEndOfMessage(self.stream_id), self.context.server)
        self.client_state = self.state_ended_by_addon
        yield from self.flow_done()                     # END_STREAM to the client, stream dropped
        with open(f"{CAP}/streams.jsonl", "a") as g:
            g.write(json.dumps({"capture_ended_stream": True, "flow_id": self.flow.id, "t": time.time()}) + "\n")
def _state_ended_by_addon(self, event):
    # request events that were queued while the response hook ran: neither forwarded nor saved (on record in streams.jsonl)
    if isinstance(event, _L.RequestData) and event.data:
        with open(f"{CAP}/streams.jsonl", "a") as g:
            g.write(json.dumps({"dropped_request_bytes": len(event.data), "flow_id": self.flow.id, "t": time.time()}) + "\n")
    yield from ()
if _L:
    _L.HttpStream.state_ended_by_addon = _state_ended_by_addon
    _L.HttpStream.send_response = _send_response_end
def requestheaders(flow: http.HTTPFlow):
    if STREAM and STREAM.search(flow.request.pretty_host + flow.request.path):
        flow.metadata["streamed"] = True; flow.request.stream = tee(flow, "req"); OPEN[flow.id] = flow
        with open(f"{CAP}/streams.jsonl", "a") as f:   # not flows.jsonl: the analyser reads every record there as a request
            f.write(json.dumps({"stream_open": True, "flow_id": flow.id, "t": time.time(), "host": flow.request.pretty_host, "path": flow.request.path}) + "\n")
def responseheaders(flow: http.HTTPFlow):
    if flow.metadata.get("streamed"): flow.response.stream = tee(flow, "resp")
def done():
    for f in list(OPEN.values()): record(f, "capture ended before the stream finished")
def nobody(hp): return bool(NOBODY and NOBODY.search(hp))

def running():
    ev({"mitm_started": True, "t": time.time(), "block": os.environ.get("MITM_BLOCK", ""), "stream": os.environ.get("MITM_STREAM", ""), "stream_end_patch": bool(_L), "nobody": os.environ.get("MITM_NOBODY", "")})

def tls_clienthello(data: tls.ClientHelloData):
    sni = data.client_hello.sni or ""
    if sni in PASS:
        data.ignore_connection = True
        ev({"passthrough": True, "sni": sni, "t": time.time()})
def tls_failed_client(data: tls.TlsData):
    sni = data.conn.sni or ""
    PASS.add(sni)
    ev({"tls_failed": True, "sni": sni, "t": time.time(), "error": str(data.conn.error)[:300]})
def request(flow: http.HTTPFlow):
    if flow.metadata.get("record_deferred"): record(flow); return   # streamed request ended after its response (see response)
    hp = flow.request.pretty_host + flow.request.path
    if BLOCK and BLOCK.search(hp):
        flow.metadata["blocked"] = True
        flow.response = http.Response.make(503, b'{"error":"blocked by the test rig"}', {"content-type": "application/json"})
def record(flow: http.HTTPFlow, err=None):
    if flow.metadata.get("recorded"): return          # a flow can reach the error hook after its response was recorded
    flow.metadata["recorded"] = True
    n[0] += 1; i = n[0]; r = flow.request; hp = r.pretty_host + r.path
    st = {}
    if flow.metadata.get("streamed"):
        OPEN.pop(flow.id, None)
        b, braw, ci = sbody(flow, r, "req"); st = {"streamed": True, "req_connect": ci}
        if flow.metadata.get("req_open_at_response_end"): st["req_open_at_response_end"] = True   # set only when the response completed
        if flow.response: rb, rbraw, rci = sbody(flow, flow.response, "resp"); st["resp_connect"] = rci
        else: rb = rbraw = b""
    else: b = body(r); rb = body(flow.response) if flow.response else b""
    nob = nobody(hp); sb, rn = scrub(b)
    if not nob:
        with open(f"{CAP}/f{BOOT}-{i:04d}.req", "wb") as f: f.write(sb)
        with open(f"{CAP}/f{BOOT}-{i:04d}.resp", "wb") as f: f.write(scrub(rb if st else rb[:5_000_000])[0])   # streamed: never cut
        if st:
            with open(f"{CAP}/f{BOOT}-{i:04d}.req.raw", "wb") as f: f.write(scrub(braw)[0])
            with open(f"{CAP}/f{BOOT}-{i:04d}.resp.raw", "wb") as f: f.write(scrub(rbraw)[0])
    rh = hdrs(r.headers)
    ev({"i": i, "flow_id": getattr(flow, "id", None), "t": r.timestamp_start, "sni": flow.client_conn.sni, "blocked": bool(flow.metadata.get("blocked")),
        "method": r.method, "scheme": r.scheme, "host": r.pretty_host, "port": r.port,
        "path": (r.path.split("?")[0] + ("?<query>" if "?" in r.path else "")) if nob else r.path, "url_truncated": False,
        "status": flow.response.status_code if flow.response else None, "req_bytes": len(b), "resp_bytes": len(rb),
        "req_sha12": h12(b) if b else None, "bodies_saved": not nob, "query_dropped": nob and "?" in r.path,
        "file": None if nob else f"f{BOOT}-{i:04d}",
        "upstream_error": err, **st, "req_headers": rh, "redacted_n": rn + sum(1 for x in rh if x.get("redacted")), "resp_headers": hdrs(flow.response.headers) if flow.response else []})
def response(flow: http.HTTPFlow):
    if flow.metadata.get("streamed") and flow.request.timestamp_end is None:   # the response completed, the request is still open
        flow.metadata["req_open_at_response_end"] = True
        if not ends_early(flow):   # not HTTP/2: mitmproxy keeps forwarding request bytes, so record when the request ends
            flow.metadata["record_deferred"] = True; return
    record(flow)
def error(flow: http.HTTPFlow):
    record(flow, str(flow.error)[:300])
def websocket_message(flow: http.HTTPFlow):
    m = flow.websocket.messages[-1]; c = m.content if isinstance(m.content, bytes) else m.content.encode()
    hp = flow.request.pretty_host + flow.request.path; nob = nobody(hp)
    rec = {"ws": True, "flow_id": getattr(flow, "id", None), "t": time.time(), "host": flow.request.pretty_host, "path": flow.request.path.split("?")[0],
           "from_client": m.from_client, "is_text": bool(getattr(m, "is_text", False)), "bytes": len(c), "sha12": h12(c), "bodies_saved": not nob,
           "truncated": len(c) > 5_000_000}
    if not nob:
        sc, rec["redacted_n"] = scrub(c)
        with open(f"{CAP}/ws.jsonl", "ab") as w: w.write(json.dumps({**rec, "content_b64": base64.b64encode(sc[:5_000_000]).decode()}).encode() + b"\n")
    ev(rec)
