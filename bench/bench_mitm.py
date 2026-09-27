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
# - MITM_BLOCK (opt-in, empty by default; regex on host+path): answered 503 locally, never forwarded; the attempt and body are
#   captured and the flow is marked blocked.
import os, re, json, time, hashlib, base64
from mitmproxy import http, tls
CAP = os.environ["MITM_CAP"]; os.makedirs(CAP, exist_ok=True); n = [0]
BOOT = time.strftime("%H%M%S")
BLOCK = re.compile(os.environ["MITM_BLOCK"]) if os.environ.get("MITM_BLOCK") else None
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
def body(m):
    try: return m.get_content(strict=False) or b""
    except Exception: return m.raw_content or b""
def nobody(hp): return bool(NOBODY and NOBODY.search(hp))

def running():
    ev({"mitm_started": True, "t": time.time(), "block": os.environ.get("MITM_BLOCK", ""), "nobody": os.environ.get("MITM_NOBODY", "")})

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
    hp = flow.request.pretty_host + flow.request.path
    if BLOCK and BLOCK.search(hp):
        flow.metadata["blocked"] = True
        flow.response = http.Response.make(503, b'{"error":"blocked by the test rig"}', {"content-type": "application/json"})
def record(flow: http.HTTPFlow, err=None):
    if flow.metadata.get("recorded"): return          # a flow can reach the error hook after its response was recorded
    flow.metadata["recorded"] = True
    n[0] += 1; i = n[0]; r = flow.request; hp = r.pretty_host + r.path
    b = body(r); rb = body(flow.response) if flow.response else b""
    nob = nobody(hp); sb, rn = scrub(b)
    if not nob:
        with open(f"{CAP}/f{BOOT}-{i:04d}.req", "wb") as f: f.write(sb)
        with open(f"{CAP}/f{BOOT}-{i:04d}.resp", "wb") as f: f.write(scrub(rb[:5_000_000])[0])
    rh = hdrs(r.headers)
    ev({"i": i, "t": r.timestamp_start, "sni": flow.client_conn.sni, "blocked": bool(flow.metadata.get("blocked")),
        "method": r.method, "scheme": r.scheme, "host": r.pretty_host, "port": r.port,
        "path": (r.path.split("?")[0] + ("?<query>" if "?" in r.path else "")) if nob else r.path, "url_truncated": False,
        "status": flow.response.status_code if flow.response else None, "req_bytes": len(b), "resp_bytes": len(rb),
        "req_sha12": h12(b) if b else None, "bodies_saved": not nob, "query_dropped": nob and "?" in r.path,
        "file": None if nob else f"f{BOOT}-{i:04d}",
        "upstream_error": err, "req_headers": rh, "redacted_n": rn + sum(1 for x in rh if x.get("redacted")), "resp_headers": hdrs(flow.response.headers) if flow.response else []})
def response(flow: http.HTTPFlow):
    record(flow)
def error(flow: http.HTTPFlow):
    record(flow, str(flow.error)[:300])
def websocket_message(flow: http.HTTPFlow):
    m = flow.websocket.messages[-1]; c = m.content if isinstance(m.content, bytes) else m.content.encode()
    hp = flow.request.pretty_host + flow.request.path; nob = nobody(hp)
    rec = {"ws": True, "t": time.time(), "host": flow.request.pretty_host, "path": flow.request.path.split("?")[0],
           "from_client": m.from_client, "is_text": bool(getattr(m, "is_text", False)), "bytes": len(c), "sha12": h12(c), "bodies_saved": not nob,
           "truncated": len(c) > 5_000_000}
    if not nob:
        sc, rec["redacted_n"] = scrub(c)
        with open(f"{CAP}/ws.jsonl", "ab") as w: w.write(json.dumps({**rec, "content_b64": base64.b64encode(sc[:5_000_000]).decode()}).encode() + b"\n")
    ev(rec)
