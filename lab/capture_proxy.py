# AgenticBench capture proxy (runs in its own container on the rig network).
# Logs each request to CAPDIR: body (reqNNN.json), method, path, header values (credential headers only as their full sha256; values never cut),
# status and errors (reqNNN.meta); swaps the per-run dummy key the harness holds for the real model key, forwards over HTTPS
# to UPSTREAM, streams the reply to the harness and saves it (reqNNN.resp, first 20 MB).
# The harness container never sees the real key. Usage: capture_proxy.py PORT CAPDIR UPSTREAM_HOST
# Env: REAL_KEY_FILE (read-only mounted file holding the model key), DUMMY_KEY (per-run fake key given to the harness).
import http.server, http.client, json, sys, os, hashlib, threading, time
PORT = int(sys.argv[1]); CAP = sys.argv[2]; UP = sys.argv[3]
REAL = open(os.environ["REAL_KEY_FILE"]).read().strip() if os.environ.get("REAL_KEY_FILE") else ""; DUMMY = os.environ.get("DUMMY_KEY", "")
SECRET = {"authorization", "x-api-key", "api-key", "cookie", "proxy-authorization", "x-goog-api-key"}
HOP = {"host", "content-length", "connection", "accept-encoding", "transfer-encoding", "keep-alive"}
lock = threading.Lock(); n = [0]

def sha256(v): return hashlib.sha256(v.encode()).hexdigest()

class H(http.server.BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.0'

    def read_body(self):
        if 'chunked' in self.headers.get('Transfer-Encoding', '').lower():
            out = b''
            while True:
                size = int(self.rfile.readline().split(b';')[0].strip() or b'0', 16)
                if size == 0:
                    while self.rfile.readline() not in (b'\r\n', b'\n', b''): pass
                    return out
                out += self.rfile.read(size); self.rfile.readline()
        ln = int(self.headers.get('Content-Length', 0) or 0)
        return self.rfile.read(ln) if ln else b''

    def handle_any(self):
        body = self.read_body()
        with lock:
            n[0] += 1; i = n[0]
        hdrs, fwd = [], {}
        for k, v in self.headers.items():
            if k.lower() in SECRET:
                hdrs.append({"name": k, "sha256": sha256(v), "redacted": True, "has_dummy": bool(DUMMY and DUMMY in v)})
                if DUMMY and DUMMY in v and REAL: v = v.replace(DUMMY, REAL)
            else:
                hdrs.append({"name": k, "value": v})
            if k.lower() not in HOP: fwd[k] = v
        fwd["Accept-Encoding"] = "identity"
        meta = {"n": i, "t": time.time(), "method": self.command, "path": self.path, "headers": hdrs,
                "body_bytes": len(body), "dummy_in_body": bool(DUMMY and DUMMY.encode() in body),
                "realkey_in_body": bool(REAL and REAL.encode() in body)}
        open(f"{CAP}/req{i:03d}.json", "wb").write(body)
        try:
            c = http.client.HTTPSConnection(UP, timeout=300)
            c.request(self.command, self.path, body=body if body else None, headers=fwd); r = c.getresponse()
            meta["status"] = r.status
            self.send_response(r.status)
            for k, v in r.getheaders():
                if k.lower() not in ("transfer-encoding", "content-length", "connection", "content-encoding"): self.send_header(k, v)
            self.send_header("Connection", "close"); self.end_headers()
            saved = 0
            with open(f"{CAP}/req{i:03d}.resp", "wb") as rf:
                while True:
                    ch = r.read1(65536)
                    if not ch: break
                    if saved < 20_000_000: rf.write(ch[:20_000_000 - saved]); saved += len(ch)
                    self.wfile.write(ch); self.wfile.flush()
            meta["resp_bytes"] = saved
        except Exception as e:
            meta["error"] = repr(e)[:300]
        open(f"{CAP}/req{i:03d}.meta", "w").write(json.dumps(meta, indent=1))

    do_GET = do_POST = do_PUT = do_DELETE = do_PATCH = do_HEAD = do_OPTIONS = handle_any
    def log_message(self, *a): pass

srv = http.server.ThreadingHTTPServer(("0.0.0.0", PORT), H)
open(f"{CAP}/proxy-started", "w").write(json.dumps({"t": time.time(), "upstream": UP}))   # marks a capture that ran, even with no request
srv.serve_forever()
