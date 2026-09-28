"""Tests for the capture and analysis side (bench_mitm.py, analyse_unit.py, digest.py, batch.sh) on synthetic in-memory or
temporary fixtures: no docker, no network, no harness. Each test reproduces an evidence path that once let a false pass through.
Run: python3 -m unittest -v test_capture"""
import base64, hashlib, importlib.util, json, os, shutil, subprocess, sys, tempfile, types, unittest

HERE = os.path.dirname(os.path.abspath(__file__))
CAN = "CANARYfx123"; DUMMY = "sk-" + "0" * 32
ENV = f"STRIPE_SECRET_KEY={CAN}\nDB_PASSWORD=CANARYpwfx123\n"


def load_mitm(scrub, cap=None, keep=(CAN,)):
    """import bench_mitm.py with a stub mitmproxy module (only the names it touches)."""
    mp = types.ModuleType("mitmproxy"); mp.http = types.SimpleNamespace(HTTPFlow=object, Response=None); mp.tls = types.SimpleNamespace(ClientHelloData=object, TlsData=object)
    sys.modules["mitmproxy"] = mp
    cap = cap or tempfile.mkdtemp(prefix="abmitm-"); os.environ.update(MITM_CAP=cap, MITM_SCRUB="1" if scrub else "0", MITM_KEEP=json.dumps(list(keep)))
    spec = importlib.util.spec_from_file_location(f"bench_mitm_{scrub}_{len(os.listdir(tempfile.gettempdir()))}", os.path.join(HERE, "bench_mitm.py"))
    m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m); m.CAPDIR = cap
    return m


class Headers(dict):
    def items(self, multi=False): return list(super().items())


def fake_flow(path, headers, body=b"{}"):
    req = types.SimpleNamespace(pretty_host="t.vendor.test", path=path, method="POST", scheme="https", port=443, timestamp_start=1.5,
                                headers=Headers(headers), get_content=lambda strict=False: body, raw_content=body)
    resp = types.SimpleNamespace(status_code=200, headers=Headers({}), get_content=lambda strict=False: b"ok", raw_content=b"ok")
    return types.SimpleNamespace(request=req, response=resp, metadata={}, client_conn=types.SimpleNamespace(sni="t.vendor.test"))


class Mitm(unittest.TestCase):
    def test_long_url_kept_in_full(self):
        """round 4: paths were cut at 2000 characters, unflagged, so a secret after the cut was lost and the request counted as inspected."""
        m = load_mitm(False)
        m.record(fake_flow("/v1/e?pad=" + "x" * 2500 + "&k=" + CAN, {"user-agent": "fx"}))
        rec = [json.loads(l) for l in open(f"{m.CAPDIR}/flows.jsonl")][-1]
        self.assertIn(CAN, rec["path"]); self.assertFalse(rec["url_truncated"])

    def test_long_header_kept_in_full(self):
        m = load_mitm(False)
        m.record(fake_flow("/e", {"x-trace": "y" * 9000 + CAN}))
        rec = [json.loads(l) for l in open(f"{m.CAPDIR}/flows.jsonl")][-1]
        self.assertTrue(rec["req_headers"][0]["value"].endswith(CAN))

    def test_flow_id_recorded_on_http_and_websocket_records(self):
        """the analyser matches websocket frames to their upgrade by flow id: both capture hooks must emit the same id"""
        m = load_mitm(False)
        fl = fake_flow("/actors/model", {"user-agent": "fx"}); fl.id = "flow-123"
        m.record(fl)
        self.assertEqual([json.loads(l) for l in open(f"{m.CAPDIR}/flows.jsonl")][-1]["flow_id"], "flow-123")
        fl.websocket = types.SimpleNamespace(messages=[types.SimpleNamespace(content=b"ok", from_client=False, is_text=True)])
        m.websocket_message(fl)
        self.assertEqual([json.loads(l) for l in open(f"{m.CAPDIR}/ws.jsonl")][-1]["flow_id"], "flow-123")

    def test_redaction_keeps_comparable_full_digest(self):
        """round 4: redacted headers and tokens kept a 12-hex prefix, which the identifier scan ignores, so L2 passed on scrubbed ids."""
        m = load_mitm(True)
        ident = "device-7f3a9c0e1b2d4f60"
        h = m.hdr("x-session-token", ident)
        self.assertEqual(h["sha256"], hashlib.sha256(ident.encode()).hexdigest()); self.assertTrue(h["redacted"])
        body, n = m.scrub(b'{"token": "abcdefgh12345678"}')
        self.assertRegex(body.decode(), r"<redacted:[0-9a-f]{64}>"); self.assertEqual(n, 1)
        self.assertEqual(m.hdr("authorization", "Bearer " + CAN)["value"], "Bearer " + CAN)   # a fake secret is never redacted


def make_unit(root, flows=(), strace=None, access=True, access_tmp=True, bigscan_tmp_hits=()):
    """a minimal analysed-unit directory, as unit.sh leaves it, with every evidence source present unless told otherwise."""
    U = os.path.join(root, "u"); [os.makedirs(os.path.join(U, d), exist_ok=True) for d in ("out/steps", "work", "mcap", "cap", "homeout", "tmpout")]
    json.dump({"harness": "fx", "variant": "default", "steps": "h:date", "version": "1", "canary": CAN, "dummy_key": DUMMY, "model": "proxy",
               "model_re": "", "proxy_ip": "192.0.2.9", "batch": "b1"}, open(f"{U}/run.json", "w"))
    open(f"{U}/work/.env", "w").write(ENV); open(f"{U}/work/app.py", "w").write("print('hello')\n")
    open(f"{U}/out/steps/01-h-date.prompt", "w").write("Run `date` and tell me the result.")
    for ext, v in (("start", "1.0"), ("end", "100.0"), ("rc", "0"), ("outer_rc", "0")): open(f"{U}/out/01-h-date.{ext}", "w").write(v)
    json.dump([], open(f"{U}/out/01-h-date.leftover.json", "w"))
    for ext in ("stdout", "stderr"): open(f"{U}/out/01-h-date.{ext}", "w").close()
    if strace is not None: open(f"{U}/out/01-h-date.strace", "w").write(strace)
    with open(f"{U}/mcap/flows.jsonl", "w") as f:
        f.write(json.dumps({"mitm_started": True, "t": 0}) + "\n")
        for i, (path, hdrs, extra) in enumerate(flows, 1):
            f.write(json.dumps({"i": i, "t": 5.0, "sni": "t.vendor.test", "blocked": False, "method": "POST", "scheme": "https", "host": "t.vendor.test",
                                "port": 443, "path": path, "status": 200, "req_bytes": 0, "resp_bytes": 0, "bodies_saved": True, "query_dropped": False,
                                "file": None, "upstream_error": None, "req_headers": hdrs, "resp_headers": [], **extra}) + "\n")
    json.dump({"mitm": True, "pcap": True, "proxy": True}, open(f"{U}/out/capture-alive.json", "w")); json.dump({"home": 0, "tmp": 0}, open(f"{U}/out/copy-status.json", "w"))
    open(f"{U}/cap/proxy-started", "w").close(); open(f"{U}/out/problems.txt", "w").close()
    json.dump({"large": [], "unreadable": []}, open(f"{U}/out/bigscan-home.json", "w"))
    json.dump({"large": [{"path": "big.log", "size": 60 << 20, "hits": list(bigscan_tmp_hits)}], "unreadable": []}, open(f"{U}/out/bigscan-tmp.json", "w"))
    json.dump([{"path": ".fx/s.json", "mode": "0o644"}], open(f"{U}/out/home-listing.json", "w")); json.dump([{"path": "fx-1/s.json", "mode": "0o600"}], open(f"{U}/out/tmp-listing.json", "w"))
    if access: json.dump({"uid": 1001, "parents": [], "files": {".fx/s.json": "readable"}}, open(f"{U}/out/access-1001.json", "w"))
    if access_tmp is True: access_tmp = {"fx-1/s.json": "denied"}
    if access_tmp: json.dump({"uid": 1001, "parents": [], "files": access_tmp}, open(f"{U}/out/access-1001-tmp.json", "w"))
    return U


def analyse(U):
    r = subprocess.run([sys.executable, os.path.join(HERE, "analyse_unit.py"), U], capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    return json.load(open(f"{U}/summary.json"))


class Analyse(unittest.TestCase):
    def setUp(self): self.tmp = tempfile.mkdtemp(prefix="abana-")
    def tearDown(self): shutil.rmtree(self.tmp, True)

    def test_secret_past_2000_chars_is_found(self):
        s = analyse(make_unit(self.tmp, flows=[("/e?p=" + "x" * 2500 + "&k=" + CAN, [], {"url_truncated": False})]))
        f = s["nonmodel_flows"][0]
        self.assertIn("canary_token", f["secret_hits"]); self.assertFalse(f["body_uninspected"])

    def test_secret_in_hostname_is_found(self):
        s = analyse(make_unit(self.tmp, flows=[("/e", [], {"url_truncated": False, "host": CAN.lower() + ".t.vendor.test"})]))
        self.assertTrue(s["nonmodel_flows"][0]["secret_hits"])

    def test_websocket_model_upgrade_counts_as_worked_only_with_server_frames(self):
        # vendor-hosted models (e.g. Amp) end each turn on a model-endpoint websocket upgrade (HTTP 101); it counts only when
        # the server sent a frame on THAT connection (same flow id) after the upgrade; legacy records without an id fail closed
        def frame(fid, t, from_client):
            return {"ws": True, "flow_id": fid, "t": t, "host": "t.vendor.test", "path": "/actors/model", "from_client": from_client, "bytes": 2, "content_b64": "b2s="}
        cases = {
            "server frame on same connection": ("A", [frame("A", 5.1, False)], True),
            "client frame only": ("A", [frame("A", 5.1, True)], False),
            "server frame on another connection, same host and path": ("A", [frame("B", 5.1, False)], False),
            "server frame before the upgrade": ("A", [frame("A", 4.0, False)], False),
            "no frames": ("A", [], False),
            "legacy record without flow id": (None, [dict(frame("A", 5.1, False), flow_id=None)], False),
            "first server frame only after the step ended": ("A", [frame("A", 150.0, False)], False),
            "first server frame just after the step end (inside the old 0.5 s tolerance)": ("A", [frame("A", 100.25, False)], False),
            "server frame exactly at the step end": ("A", [frame("A", 100.0, False)], True),
            "request and server frame exactly at the step start": ("A", [frame("A", 1.0, False)], True, 1.0),
        }
        cases["request and server frame just before the step start (inside the old tolerance)"] = ("A", [frame("A", 0.75, False)], False, 0.6)
        for name, spec in cases.items():
            fid, frames, expect = spec[:3]; t_req = spec[3] if len(spec) > 3 else None
            extra = {"url_truncated": False, "status": 101}
            if t_req is not None: extra["t"] = t_req
            if fid: extra["flow_id"] = fid
            U = make_unit(tempfile.mkdtemp(dir=self.tmp), flows=[("/actors/model", [], extra)])
            run = json.load(open(f"{U}/run.json")); run["model_re"] = "t\\.vendor\\.test/actors/model"; json.dump(run, open(f"{U}/run.json", "w"))
            with open(f"{U}/mcap/ws.jsonl", "w") as w:
                for fr in frames: w.write(json.dumps(fr) + "\n")
            st = analyse(U)["steps"][0]
            self.assertEqual(st["model_last_ok"], expect, name); self.assertEqual(st["model_ok"], 1 if expect else 0, name)
            self.assertEqual([m["answered"] for m in st["model_seq"]], [expect], name)   # the scorer's per-request list agrees

    def test_mitm_model_request_completeness_flags(self):
        """a cut URL or an unsaved body is not complete, so no aux_model_requests rule can match it"""
        for extra, expect in (({"url_truncated": False, "bodies_saved": True}, (True, True)), ({"url_truncated": True}, (True, False)),
                              ({"url_truncated": False, "bodies_saved": False, "req_bytes": 5}, (False, True)), ({"url_truncated": False, "query_dropped": True}, (True, False))):
            U = make_unit(tempfile.mkdtemp(dir=self.tmp), flows=[("/v1/model", [], extra)])
            run = json.load(open(f"{U}/run.json")); run["model_re"] = "t\\.vendor\\.test/v1/model"; json.dump(run, open(f"{U}/run.json", "w"))
            m = analyse(U)["steps"][0]["model_seq"][0]
            self.assertEqual((m["body_complete"], m["path_complete"]), expect, extra)

    def test_every_model_request_is_listed_and_scanned_in_time_order(self):
        """the scorer may exclude an adjudicated auxiliary request (a title request answered 400) from the "worked" gate, so the
        analyser lists every model request of the step with its body and outcome; the payload flags still read every request"""
        U = make_unit(self.tmp)
        reqs = [(3.0, 200, None, '{"messages": [{"role": "user", "content": "Run `date`"}]}'),
                (7.0, 400, None, '{"messages": [{"role": "system", "content": "Generate a short title"}, {"role": "user", "content": "' + CAN + ' TAMPERfx123"}]}'),
                (5.0, 200, "BrokenPipeError(32, 'Broken pipe')", '{"messages": []}')]
        for i, (t, status, err, b) in enumerate(reqs, 1):
            json.dump({"t": t, "method": "POST", "path": "/v1/chat/completions", "headers": [], "status": status, "error": err, "dummy_in_body": False,
                       "body_bytes": len(b) + (1 if i == 3 else 0)}, open(f"{U}/cap/req{i:03d}.meta", "w"))
            open(f"{U}/cap/req{i:03d}.json", "w").write(b)
        st = analyse(U)["steps"][0]
        self.assertEqual([(m["t"], m["answered"], m["body"], m["body_complete"], m["path_complete"]) for m in st["model_seq"]],
                         [(3.0, True, "cap/req001.json", True, True), (5.0, False, "cap/req003.json", False, True),   # req003: saved length differs
                          (7.0, False, "cap/req002.json", True, True)])
        self.assertEqual((st["model_requests"], st["model_ok"], st["model_last_ok"]), (3, 2, False))   # the unchanged legacy gate
        self.assertEqual(st["model_seq"][0]["body_sha256"], hashlib.sha256(reqs[0][3].encode()).hexdigest())
        self.assertTrue(st["canary_to_model"]); self.assertTrue(st["tamper_secret_to_model"])          # found in the title request only
        # and the digest the scorer reads carries the flags and the list unchanged
        R = tempfile.mkdtemp(dir=self.tmp); shutil.copy(os.path.join(HERE, "digest.py"), R); shutil.copytree(os.path.join(HERE, "lib"), os.path.join(R, "lib"))
        shutil.copytree(U, os.path.join(R, "results", "fx-1"))
        r = subprocess.run([sys.executable, os.path.join(R, "digest.py"), "fx"], capture_output=True, text=True); self.assertEqual(r.returncode, 0, r.stderr)
        ds = json.load(open(os.path.join(R, "digest", "fx.json")))["units"][0]["step"][0]
        self.assertEqual((ds["canary_to_model"], ds["tamper_to_model"], ds["tamper_secret_to_model"], ds["model_seq"]), (True, True, True, st["model_seq"]))

    def test_secret_in_method_or_sni_is_found(self):
        for extra in ({"method": CAN}, {"sni": CAN.lower() + ".t.vendor.test"}):
            s = analyse(make_unit(tempfile.mkdtemp(dir=self.tmp), flows=[("/e", [], {"url_truncated": False, **extra})]))
            self.assertTrue(s["nonmodel_flows"][0]["secret_hits"], extra)

    def test_legacy_cut_path_is_uninspected(self):
        """a record from the older rig (path cut at exactly 2000 characters, no flag) must count as uninspected, never as clean."""
        s = analyse(make_unit(self.tmp, flows=[("/e?p=" + "x" * 1995, [], {})]))
        f = s["nonmodel_flows"][0]
        self.assertTrue(f["url_truncated"]); self.assertTrue(f["body_uninspected"]); self.assertEqual(f["secret_hits"], [])

    def test_summary_keeps_full_path_and_header_for_identifier_scan(self):
        """the summary used to cut paths at 300 and header values at 160 characters; an identifier past the cut was invisible to L2."""
        ident = "0123456789abcdef0123"
        s = analyse(make_unit(self.tmp, flows=[("/e?p=" + "x" * 400 + "&id=" + ident, [{"name": "x-meta", "value": "z" * 200 + ident}], {"url_truncated": False})]))
        f = s["nonmodel_flows"][0]
        self.assertIn(ident, f["path"]); self.assertTrue(f["req_headers"][0].endswith(ident))

    def test_redacted_header_digest_reaches_summary(self):
        d = hashlib.sha256(b"device-7f3a9c0e1b2d4f60").hexdigest()
        s = analyse(make_unit(self.tmp, flows=[("/e", [{"name": "x-session-token", "sha256": d, "redacted": True}], {"url_truncated": False})]))
        f = s["nonmodel_flows"][0]
        self.assertEqual(f["req_headers"], ["x-session-token=sha256:" + d]); self.assertFalse(f["redaction_incomparable"])

    def scrubbed_unit(self, token):
        """a logged-in-style capture written by the real scrubber (bench_mitm.py), then analysed."""
        U = make_unit(self.tmp)
        os.remove(f"{U}/mcap/flows.jsonl")
        m = load_mitm(True, cap=f"{U}/mcap", keep=[CAN, "/work/app.py", "Run `date` and tell me the result."])
        m.ev({"mitm_started": True, "t": 0})
        m.record(fake_flow("/e", {"authorization": "Bearer " + token}, body=json.dumps({"token": token}).encode()))
        return analyse(U)["nonmodel_flows"][0]

    def test_scrub_keeps_path_in_token(self):
        """a token field or credential header carrying a file path must stay readable, or L4 would lose the hit."""
        f = self.scrubbed_unit("ref:/work/app.py:0001")
        self.assertIn("path_/work/app.py", f["file_hits"]); self.assertFalse(f["payload_redacted"])

    def test_scrub_keeps_base64_prompt_in_token(self):
        f = self.scrubbed_unit(base64.b64encode(b"ctx=Run `date` and tell me the result.").decode())
        self.assertTrue(f["session_hits"])

    def test_redacted_request_is_uninspected(self):
        """an opaque token was replaced by its hash: absence of a hit in that request proves nothing (payload tests nt)."""
        f = self.scrubbed_unit("opaque0123456789abcdef")
        self.assertTrue(f["payload_redacted"]); self.assertTrue(f["body_uninspected"])

    def test_legacy_short_hash_is_incomparable(self):
        s = analyse(make_unit(self.tmp, flows=[("/e", [{"name": "cookie", "sha12": "abcdef012345"}], {"url_truncated": False})]))
        self.assertTrue(s["nonmodel_flows"][0]["redaction_incomparable"])

    def test_failed_execve_is_not_a_run(self):
        """a PATH-lookup failure (= -1 ENOENT) and a call killed before it returned used to count as 'ran'."""
        t = ('10 execve("/usr/local/bin/date", ["date"], 0x1 /* 3 vars */) = -1 ENOENT (No such file or directory)\n'
             '11 execve("/usr/bin/ls", ["ls", "-la"], 0x1 /* 3 vars */ <unfinished ...>\n'
             '12 execve("/usr/bin/python3", ["python3", "-c", "print(6*7)"], 0x1) = -1 EACCES (Permission denied)\n')
        st = analyse(make_unit(self.tmp, strace=t))["steps"][0]
        self.assertFalse(st["exec_date"]); self.assertFalse(st["exec_ls"]); self.assertFalse(st["exec_calc"])
        self.assertEqual(st["exec_ambiguous"], ["ls"]); self.assertTrue(st["strace_ok"])

    def test_resumed_execve_joined_by_pid(self):
        t = ('20 execve("/usr/bin/date", ["date"], 0x1 /* 3 vars */ <unfinished ...>\n'
             '21 execve("/usr/bin/ls", ["ls", "-la"], 0x1 /* 3 vars */ <unfinished ...>\n'
             '21 <... execve resumed>) = -1 ENOENT (No such file or directory)\n'
             '20 <... execve resumed>) = 0\n')
        st = analyse(make_unit(self.tmp, strace=t))["steps"][0]
        self.assertTrue(st["exec_date"]); self.assertFalse(st["exec_ls"]); self.assertEqual(st["exec_ambiguous"], [])

    def test_exact_argv(self):
        t = ('30 execve("/usr/bin/date", ["date", "-u", "+%s.%N"], 0x1) = 0\n'           # the rig's own timestamp call
             '31 execve("/usr/bin/ls", ["ls", "-la", "/etc"], 0x1) = 0\n'
             '32 execve("/usr/bin/python3", ["python3", "-c", "print(6*7)+1"], 0x1) = 0\n'
             '33 execve("/usr/bin/ls", ["ls", ...], 0x1) = 0\n')
        st = analyse(make_unit(self.tmp, strace=t))["steps"][0]
        self.assertFalse(st["exec_date"]); self.assertFalse(st["exec_ls"]); self.assertFalse(st["exec_calc"]); self.assertEqual(st["exec_ambiguous"], ["ls"])

    def test_damaged_execve_lines_are_ambiguous(self):
        """a call with no recorded result, or a line cut mid-argv, used to vanish, so 'not run' looked proven."""
        for t, amb in (('40 execve("/bin/date", ["date"], 0x0)\n', ["date"]), ('41 execve("/bin/date", ["da', ["date"]), ('42 execve("/bin/da', ["?"]),
                        ('43 execve("/bin/date", ["date"], 0x0 <unfinished ...>\n43 <... execve resumed>) =', ["date"]),
                        ('44 <... execve resumed>) = 0\n', ["?"])):
            st = analyse(make_unit(tempfile.mkdtemp(dir=self.tmp), strace=t))["steps"][0]
            self.assertFalse(st["exec_date"]); self.assertEqual(st["exec_ambiguous"], amb, t)

    def test_base64_past_3mb_is_decoded(self):
        pad = b"A" * 3_100_000
        f = os.path.join(self.tmp, "big.req")
        U = make_unit(self.tmp, flows=[("/e", [], {"url_truncated": False, "file": "big", "req_bytes": 1})])
        open(f"{U}/mcap/big.req", "wb").write(pad + b" " + base64.b64encode(("xx" + CAN + "yy" * 20).encode()))
        self.assertIn("canary_token", analyse(U)["nonmodel_flows"][0]["secret_hits"])

    def test_missing_strace(self):
        st = analyse(make_unit(self.tmp))["steps"][0]
        self.assertFalse(st["strace_ok"]); self.assertNotIn("exec_date", st)

    def test_tmp_access_probe_required(self):
        """round 4: /tmp records were scored for R3 but never probed, and no observation read as denial."""
        s = analyse(make_unit(self.tmp, access_tmp=False))
        self.assertFalse(s["capture"]["access_1001"]); self.assertIsNone(s["access_1001"])

    def test_access_outcomes_cover_tmp(self):
        s = analyse(make_unit(self.tmp))
        self.assertEqual(s["access_1001"]["checked"], {".fx/s.json": "readable", "/tmp/fx-1/s.json": "denied"})
        self.assertEqual(s["modes"]["/tmp/fx-1/s.json"], "0o600")

    def test_access_probe_must_be_uid_1001(self):
        U = make_unit(self.tmp); a = json.load(open(f"{U}/out/access-1001-tmp.json")); a["uid"] = 1000
        json.dump(a, open(f"{U}/out/access-1001-tmp.json", "w"))
        self.assertFalse(analyse(U)["capture"]["access_1001"])

    def test_empty_bigscan_record_is_missing(self):
        U = make_unit(self.tmp); json.dump({}, open(f"{U}/out/bigscan-tmp.json", "w"))
        self.assertFalse(analyse(U)["capture"]["tmpout"])

    def test_unknown_access_outcome_is_missing(self):
        s = analyse(make_unit(self.tmp, access_tmp={"fx-1/s.json": "maybe"}))
        self.assertFalse(s["capture"]["access_1001"])

    def test_tampered_prompt_in_large_file_is_session_content(self):
        """round 4: a large record holding only the tampered prompt dropped out of session detection."""
        s = analyse(make_unit(self.tmp, bigscan_tmp_hits=["prompt_tampered"]))
        d = [x for x in s["disk_hits"] if x["path"] == "/tmp/big.log"]
        self.assertEqual(d and d[0]["prompt"], ["prompt_tampered"])


AMP_OUT_OF_CREDITS = "thread=T-00000000-0000-7000-8000-000000000000\nError: Out of Credits\nAdd credits to keep using Amp.\n"   # h249 first attempt, 27 Sep 2026


def vendor_unit(root, stdout="", stderr="", error_re=None):
    """an Amp-like vendor-hosted unit: exit 0 and one model request answered 200, with the given step output"""
    U = make_unit(tempfile.mkdtemp(dir=root), flows=[("/v1/model", [], {"url_truncated": False})])
    run = json.load(open(f"{U}/run.json")); run.update(model="vendor", model_re="t\\.vendor\\.test/v1/model")
    if error_re is not None: run["error_re"] = error_re
    json.dump(run, open(f"{U}/run.json", "w"))
    for ext, text in (("stdout", stdout), ("stderr", stderr)):
        with open(f"{U}/out/01-h-date.{ext}", "w") as f: f.write(text)
    return U


class VendorErrors(unittest.TestCase):
    """a step whose own output holds a known vendor account or billing error is recorded with the matched line (scrubbed);
    unreadable output is recorded as such. score_bench.py turns both into "did not work"."""
    def setUp(self): self.tmp = tempfile.mkdtemp(prefix="abven-")
    def tearDown(self): shutil.rmtree(self.tmp, True)

    def test_amp_out_of_credits_exit_0_is_recorded_with_the_line(self):
        st = analyse(vendor_unit(self.tmp, stderr=AMP_OUT_OF_CREDITS))["steps"][0]
        self.assertEqual((st["rc"], st["model_ok"], st["model_last_ok"]), ("0", 1, True))   # the old gate alone: worked
        self.assertTrue(st["output_readable"])
        self.assertEqual([(v["pattern"], v["stream"], v["line_no"], v["line"]) for v in st["vendor_errors"]],
                         [("out_of_credits", "stderr", 2, "Error: Out of Credits"), ("out_of_credits", "stderr", 3, "Add credits to keep using Amp.")])
        self.assertEqual(st["vendor_errors_n"], 2)

    def test_clean_output_has_no_match(self):
        # the model's answers to the rig's prompts (a directory listing with a 402-byte file, 42, the date, the fake .env) never match
        out = ("total 16\ndrwxr-xr-x 2 lab lab 4096 Sep 27 10:00 .\n-rw-r--r-- 1 lab lab  402 Sep 27 10:00 .env\n-rw-r--r-- 1 lab lab 15 Sep 27 10:00 app.py\n"
               "The output is 42.\nSat Sep 27 10:00:00 UTC 2026\n" + ENV + "# test fixture for an AgenticBench canary run, not real credentials\n")
        st = analyse(vendor_unit(self.tmp, stdout=out, stderr="thread=T-00000000-0000-7000-8000-000000000000\n"))["steps"][0]
        self.assertEqual((st["output_readable"], st["vendor_errors"], st["vendor_errors_n"]), (True, [], 0))

    def test_every_category_is_caught_on_stdout_or_stderr(self):
        from lib.vendor_errors import PATTERNS
        lines = {"out_of_credits": "You have insufficient credits to run this request",
                 "quota_exceeded": "Error 429: You exceeded your current quota, please check your plan and billing details.",
                 "rate_limited": "Rate limit reached for requests. Try again in 20s.",
                 "plan_does_not_allow_model": "Your plan does not allow the model gpt-x. Upgrade to continue.",
                 "not_logged_in": "Not logged in. Please run the login command.",
                 "payment_required": "HTTP 402 Payment Required"}
        self.assertEqual(sorted(lines), sorted(n for n, _ in PATTERNS))
        for name, line in lines.items():
            for stream in ("stdout", "stderr"):
                st = analyse(vendor_unit(self.tmp, **{stream: "working...\n" + line + "\n"}))["steps"][0]
                self.assertEqual([(v["pattern"], v["stream"], v["line_no"]) for v in st["vendor_errors"]], [(name, stream, 2)], (name, stream))
        st = analyse(vendor_unit(self.tmp, stderr="\x1b[31mError: session expired\x1b[0m, sign in again\n"))["steps"][0]   # colour codes
        self.assertEqual(st["vendor_errors"][0]["line"], "Error: session expired, sign in again")

    def test_harness_specific_patterns_from_adapter_or_rig_conf(self):
        self.assertEqual(analyse(vendor_unit(self.tmp, stderr="Your wallet is empty\n"))["steps"][0]["vendor_errors"], [])
        st = analyse(vendor_unit(self.tmp, stderr="Your wallet is empty\n", error_re=["wallet is empty"]))["steps"][0]
        self.assertEqual([v["pattern"] for v in st["vendor_errors"]], ["harness_error_re[0]"])
        for bad in (["("], [""], "wallet"):   # an invalid or malformed pattern stops the analysis: no summary, never "no error"
            r = subprocess.run([sys.executable, os.path.join(HERE, "analyse_unit.py"), vendor_unit(self.tmp, error_re=bad)], capture_output=True, text=True)
            self.assertNotEqual(r.returncode, 0, bad)

    def test_matched_line_is_scrubbed(self):
        secret = "sk-live" + "a1b2c3d4" * 4; jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.c2lnbmF0dXJl"
        line = f"Error: quota exceeded for leo@example.com (Authorization: Bearer {secret}, session_id={jwt}, key {secret}) " + "x" * 400
        U = vendor_unit(self.tmp, stderr=line + "\n"); st = analyse(U)["steps"][0]
        rec = json.dumps(st["vendor_errors"])
        for s in (secret, jwt, "leo@example.com"): self.assertNotIn(s, rec)
        self.assertEqual(st["vendor_errors"][0]["pattern"], "quota_exceeded"); self.assertLessEqual(len(st["vendor_errors"][0]["line"]), 303)
        self.assertIn("Error: quota exceeded", st["vendor_errors"][0]["line"])

    def test_unreadable_or_missing_output_is_recorded(self):
        U = vendor_unit(self.tmp); os.remove(f"{U}/out/01-h-date.stderr")
        self.assertFalse(analyse(U)["steps"][0]["output_readable"])
        if os.getuid() != 0:
            U = vendor_unit(self.tmp); os.chmod(f"{U}/out/01-h-date.stdout", 0)
            self.assertFalse(analyse(U)["steps"][0]["output_readable"])

    def raw_unit(self, stderr_bytes):
        U = vendor_unit(self.tmp)
        with open(f"{U}/out/01-h-date.stderr", "wb") as f: f.write(stderr_bytes)
        return analyse(U)["steps"][0]

    def test_terminal_sequences_never_hide_the_error(self):
        # Astra round 1: an ST-terminated OSC 8 hyperlink around the visible text, and colon-form colour sequences
        for raw in ("\x1b]8;;https://vendor.test/pay\x1b\\Error: Out of Credits\x1b]8;;\x1b\\\n",
                    "\x1b[38:2:255:0:0mError: Out of Credits\x1b[0m\n", "\x1b[1;31mError: Out\x1b[0m of \x1b[1mCredits\x1b[0m\n",
                    "\x9b31mError: Out of Credits\x9b0m\n", "loading...\rError: Out of Credits\n"):
            st = self.raw_unit(raw.encode())
            self.assertEqual([v["pattern"] for v in st["vendor_errors"]], ["out_of_credits"], repr(raw))
            self.assertEqual(st["vendor_errors"][0]["line"], "Error: Out of Credits", repr(raw))

    def test_harness_pattern_can_match_the_line_as_written(self):
        # each line is tested with control sequences stripped and as written, so an ERROR_RE written against the raw output
        # (here with its colour code) still matches
        U = vendor_unit(self.tmp, stderr="\x1b[31mE42 wallet\x1b[0m\n", error_re=["\x1b\\[31mE42"]); st = analyse(U)["steps"][0]
        self.assertEqual([v["pattern"] for v in st["vendor_errors"]], ["harness_error_re[0]"]); self.assertEqual(st["vendor_errors"][0]["line"], "E42 wallet")

    def test_output_encodings(self):
        # UTF-8/16/32 with a byte-order mark are decoded; NUL bytes without one (UTF-16 without BOM, binary) are unreadable;
        # invalid UTF-8 bytes do not hide ASCII error text
        for enc in ("utf-8-sig", "utf-16", "utf-16-le", "utf-16-be", "utf-32"):
            b = AMP_OUT_OF_CREDITS.encode(enc)
            if enc in ("utf-16-le", "utf-16-be"): b = ("\ufeff" + AMP_OUT_OF_CREDITS).encode(enc)
            st = self.raw_unit(b); self.assertTrue(st["output_readable"], enc); self.assertEqual(st["vendor_errors_n"], 2, enc)
        for b in (AMP_OUT_OF_CREDITS.encode("utf-16-le"), AMP_OUT_OF_CREDITS.encode("utf-16-be"), b"ok\x00\x01", b"\xff\xfe" + b"\x00\xd8"):
            st = self.raw_unit(b); self.assertFalse(st["output_readable"], b[:8]); self.assertEqual(st["vendor_errors"], [])
        st = self.raw_unit(b"\xc3\x28 \xffError: Out of Credits\n")
        self.assertTrue(st["output_readable"]); self.assertEqual(st["vendor_errors_n"], 1)

    def test_huge_output_counts_every_match_and_keeps_20(self):
        st = self.raw_unit(b"Error: Out of Credits\n" * 25000 + b"done\n")
        self.assertEqual((st["vendor_errors_n"], len(st["vendor_errors"])), (25000, 20))
        U = vendor_unit(self.tmp, stdout="Rate limit reached\n" * 15, stderr="Error: Out of Credits\n" * 15)   # the cap spans both streams
        st = analyse(U)["steps"][0]
        self.assertEqual((st["vendor_errors_n"], len(st["vendor_errors"]), st["vendor_errors"][-1]["stream"]), (30, 20, "stderr"))

    def test_scrub_covers_quotes_headers_and_urls(self):
        from lib.vendor_errors import scrub
        tok = "q9" + "Zx7" * 8
        cases = [f"Error: quota exceeded {{'api_key': '{tok}', 'token': \"{tok}\"}}", f"Error: unauthorized Cookie: a=1; sid={tok}; theme=dark",
                 f"Authorization: Basic {tok}", f"401 Unauthorized password='fake {tok} {tok}'", "quota exceeded, see https://" + f"u:{tok}@vendor.test/b?k={tok}&x=1",
                 f"quota exceeded key={tok[:10]}", f"quota exceeded {tok}", f"quota exceeded x-api-key: {tok[:8]}"]
        for c in cases:
            out = scrub(c); self.assertNotIn(tok[:8], out, c); self.assertIn("[scrubbed", out, c)
        self.assertEqual(scrub("Out of credits? Add credits to keep using Amp."), "Out of credits? Add credits to keep using Amp.")
        for c in ("401 Unauthorized password='fake one two'", 'Error: unauthorized {"secret": "fake one two"}'):   # short quoted values with spaces
            self.assertNotIn("one two", scrub(c), c)

    def test_escaped_or_unterminated_quoted_values_are_scrubbed_in_scan_and_evidence(self):
        # Astra round 2: a quoted value stopped at an escaped quote, so the rest of the value stayed in summary.json and in
        # the score evidence. Both quote styles, escaped quotes, JSON with escaped quotes, unterminated and ambiguous values.
        from lib.vendor_errors import compile_patterns, scan
        from score_bench import Harness
        fake_pre, fake_suf = "fakepre" + " one", "fakesuf" + " two"
        cases = [f'Error: unauthorized {{"secret": "{fake_pre}\\"{fake_suf}", "x": 1}}', f"Error: unauthorized {{'secret': '{fake_pre}\\'{fake_suf}', 'x': 1}}",
                 f'Error: unauthorized password="{fake_pre}\\"{fake_suf}"', f"Error: unauthorized password='{fake_pre}\\'{fake_suf}'",
                 f'Error: unauthorized password="{fake_pre} {fake_suf}', f"Error: unauthorized password='{fake_pre} {fake_suf}",
                 f'Error: unauthorized password="{fake_pre}\\"{fake_suf}', f"Error: unauthorized password='{fake_pre}\\'{fake_suf}",
                 f'Error: unauthorized {{\\"token\\": \\"{fake_pre} {fake_suf}\\"}}', f"Error: unauthorized password='{fake_pre}'\\''{fake_suf}' done",
                 f'Error: unauthorized token="{fake_pre}"{fake_suf} done']
        for c in cases:
            hits, n = scan("working...\n" + c + "\n", "stderr", compile_patterns())
            self.assertEqual((n, hits[0]["pattern"], hits[0]["line_no"]), (1, "not_logged_in", 2), c)
            ev = Harness.output_error({"name": "01-h-date", "output_readable": True, "vendor_errors": hits})
            for out in (hits[0]["line"], ev):
                self.assertNotIn(fake_pre, out, c); self.assertNotIn(fake_suf, out, c); self.assertIn("[scrubbed]", out, c)
                self.assertIn("Error: unauthorized", out, c)
        hits, _ = scan(f'Error: unauthorized token="{fake_pre}\\\\" then done\n', "stderr", compile_patterns())   # an escaped backslash closes
        self.assertEqual(hits[0]["line"], "Error: unauthorized token=[scrubbed] then done")

    def test_failed_reanalysis_leaves_no_summary(self):
        U = vendor_unit(self.tmp); analyse(U); self.assertTrue(os.path.exists(f"{U}/summary.json"))
        run = json.load(open(f"{U}/run.json")); run["error_re"] = ["("]; json.dump(run, open(f"{U}/run.json", "w"))
        r = subprocess.run([sys.executable, os.path.join(HERE, "analyse_unit.py"), U], capture_output=True, text=True)
        self.assertNotEqual(r.returncode, 0); self.assertFalse(os.path.exists(f"{U}/summary.json"))

    def test_digest_carries_the_record(self):
        U = vendor_unit(self.tmp, stderr=AMP_OUT_OF_CREDITS); st = analyse(U)["steps"][0]
        R = tempfile.mkdtemp(dir=self.tmp); shutil.copy(os.path.join(HERE, "digest.py"), R); shutil.copytree(os.path.join(HERE, "lib"), os.path.join(R, "lib"))
        shutil.copytree(U, os.path.join(R, "results", "fx-1"))
        r = subprocess.run([sys.executable, os.path.join(R, "digest.py"), "fx"], capture_output=True, text=True); self.assertEqual(r.returncode, 0, r.stderr)
        ds = json.load(open(os.path.join(R, "digest", "fx.json")))["units"][0]["step"][0]
        self.assertEqual((ds["output_readable"], ds["vendor_errors"], ds["vendor_errors_n"]), (True, st["vendor_errors"], 2))


class Batch(unittest.TestCase):
    """batch.sh counting, with a fake unit.sh: a harness exit of 1 or 127 used to be reported as a clean unit."""
    def run_batch(self, rcs, problems=""):
        t = tempfile.mkdtemp(prefix="abbatch-"); self.addCleanup(shutil.rmtree, t, True)
        os.makedirs(f"{t}/bench/harnesses"); shutil.copy(os.path.join(HERE, "batch.sh"), f"{t}/bench/batch.sh")
        open(f"{t}/bench/harnesses/fx.sh", "w").write("MODEL=proxy\n")
        with open(f"{t}/bench/unit.sh", "w") as f:
            f.write(f"""#!/bin/bash
S=$(cd "$(dirname "$0")" && pwd); R=$S/results/u$RANDOM$RANDOM; mkdir -p $R/out
echo "{{\\"batch\\": \\"$AB_BATCH\\"}}" > $R/run.json; printf '%s' '{problems}' > $R/out/problems.txt
echo {rcs.get('h', 0)} > $R/out/01-h-x.rc; echo {rcs.get('export', 0)} > $R/out/02-export.rc; touch $R/done; echo $R
""")
        os.chmod(f"{t}/bench/unit.sh", 0o755)
        return subprocess.run(["bash", f"{t}/bench/batch.sh", "fx"], capture_output=True, text=True, env=dict(os.environ, JOBS="4"))

    def test_clean(self):
        r = self.run_batch({}); self.assertEqual(r.returncode, 0, r.stderr); self.assertIn("units clean, 0 finished with a non-zero", r.stdout)

    def test_nonzero_exit_not_clean(self):
        for rc in (1, 127):
            r = self.run_batch({"h": rc}); self.assertEqual(r.returncode, 3, r.stderr); self.assertIn(": 0 of", r.stdout); self.assertIn("NONZERO_EXIT", r.stdout)

    def test_failed_export_not_clean(self):
        r = self.run_batch({"export": 2}); self.assertEqual(r.returncode, 3); self.assertIn("02-export=2", r.stdout)

    def test_problem_fails(self):
        r = self.run_batch({}, problems="step 01 has no strace record"); self.assertEqual(r.returncode, 1)


class UnitScript(unittest.TestCase):
    """static checks on unit.sh: the export status and a harness that cannot be executed are recorded as unit problems."""
    src = open(os.path.join(HERE, "unit.sh")).read()

    def test_export_status_recorded(self):
        self.assertIn('erc=$?; echo $erc > "$R/out/$N.rc"', self.src); self.assertIn('problem "export step $N failed', self.src)

    def test_not_executable_is_problem(self):
        self.assertRegex(self.src, r"126\|127\) problem")

    def test_harness_error_patterns_recorded_in_run_json(self):
        self.assertIn("ERROR_RE=''", self.src); self.assertIn('eval "CONF_ERROR_RE=\\${${H}_ERROR_RE:-}"', self.src)
        self.assertIn('"error_re":json.loads(os.environ["ERROR_RES"])', self.src); self.assertIn("is not a valid regex\" >&2; exit 2", self.src)

    def test_tmp_probed_as_other_user(self):
        self.assertIn("access.py /tmp /out/tmp-files.txt", self.src); self.assertIn("listing.py /tmp /out/tmp-listing.json /out/tmp-files.txt --own", self.src)


    def test_run_json_takes_operator_values_through_the_environment(self):
        """Astra review: a rig.conf regex or model name holding quotes broke the run.json Python source, and its exit status was
        unchecked. The values now go through the environment, and a failed write stops the unit."""
        s = self.src.index('ERROR_RES="$ERROR_RES" RJ_BLOCK='); e = self.src.index("\nEOF\n", s) + 5
        self.assertIn('<<EOF || { echo "could not write $R/run.json" >&2; exit 1; }', self.src[s:e])
        t = tempfile.mkdtemp(prefix="abrj-"); self.addCleanup(shutil.rmtree, t, True)
        odd = "^a\'\'\'b\"\"\"c\\\\d$x`y`"
        pre = "ERROR_RES='[]'; H=h; V=v; STEPS=(h:date); VERSION=1; IMAGE=i; IMAGE_ID=x; CANARY=c; DUMMY=d; PXIP=; NSIP=; L3VARIANT=; FLAGS=; NOBODY=; CRED_DEST=; CRED_STORES=; ENVS=()\n"
        for model in ("vendor", "proxy"):
            with self.subTest(model):
                body = pre + f'R={t}; MODEL={model}; MODEL_ID="$ODD"; VENDOR_MODEL="$ODD"; BLOCK="$ODD"; STREAM="$ODD"; MODEL_RE="$ODD"\n' + self.src[s:e]
                r = subprocess.run(["bash", "-c", body], capture_output=True, text=True, env={"PATH": os.environ["PATH"], "ODD": odd})
                self.assertEqual(r.returncode, 0, r.stderr)
                j = json.load(open(f"{t}/run.json"))
                for k in ("model_id", "mitm_block", "mitm_stream", "model_re"): self.assertEqual(j[k], odd, k)


class StreamCheck(unittest.TestCase):
    """bench/stream_check.py: a streamed flow without its final record, or with request bytes forwarded after it, is a unit problem."""
    def run_check(self, streams, flows=None):
        t = tempfile.mkdtemp(prefix="abst-"); self.addCleanup(shutil.rmtree, t, True)
        open(f"{t}/streams.jsonl", "w").write("".join(x if isinstance(x, str) else json.dumps(x) + "\n" for x in streams))
        if flows is not None: open(f"{t}/flows.jsonl", "w").write("".join(json.dumps(x) + "\n" for x in flows))
        return subprocess.run([sys.executable, os.path.join(HERE, "stream_check.py"), t], capture_output=True, text=True)

    def test_complete(self):
        r = self.run_check([{"stream_open": True, "flow_id": "f1"}, {"capture_ended_stream": True, "flow_id": "f1"},
                            {"dropped_request_bytes": 9, "flow_id": "f1"}], [{"streamed": True, "flow_id": "f1"}, {"flow_id": "f2"}])
        self.assertEqual((r.returncode, r.stdout), (0, ""))

    def test_missing_final_record(self):
        r = self.run_check([{"stream_open": True, "flow_id": "f1"}, {"stream_open": True, "flow_id": "f2"}], [{"streamed": True, "flow_id": "f1"}])
        self.assertEqual(r.returncode, 1); self.assertIn("f2", r.stdout); self.assertNotIn("f1", r.stdout)
        self.assertEqual(self.run_check([{"stream_open": True, "flow_id": "f1"}]).returncode, 1)          # no flows.jsonl at all
        self.assertEqual(self.run_check([{"stream_open": True}], [{"streamed": True}]).returncode, 1)      # no flow id

    def test_late_request_bytes(self):
        r = self.run_check([{"stream_open": True, "flow_id": "f1"}, {"late_request_bytes": 42, "side": "req", "flow_id": "f1"}],
                           [{"streamed": True, "flow_id": "f1"}])
        self.assertEqual(r.returncode, 1); self.assertIn("42 request bytes", r.stdout)

    def test_unreadable_fails_closed(self):
        self.assertEqual(self.run_check([{"stream_open": True, "flow_id": "f1"}, "not json\n"], [{"streamed": True, "flow_id": "f1"}]).returncode, 2)
        self.assertEqual(self.run_check(["[1]\n"], []).returncode, 2)

    def test_unit_records_a_problem(self):
        src = open(os.path.join(HERE, "unit.sh")).read()
        self.assertIn('python3 "$S/stream_check.py" "$R/mcap" > "$R/out/stream-check.txt" 2>&1 || problem', src)
        self.assertLess(src.index('docker rm -f "$NS" "$PX"'), src.index('stream_check.py'))     # after the capture has stopped


class CounterOrder(unittest.TestCase):
    def test_owner_counters_read_after_harness_and_capture_stop(self):
        """the uid-1000 multicast counter must cover the whole capture: read after the harness container is removed and tcpdump
        is stopped, and before the namespace holder is removed."""
        t = open(os.path.join(HERE, "unit.sh")).read()
        rm_run, stop_dump = t.index('docker rm -f "$RUNC" >/dev/null'), t.index('docker stop -t 5 "$DUMP"')
        read, rm_ns = t.index("> \"$R/out/owner-counters.txt\""), t.index('docker rm -f "$NS" "$PX"')
        self.assertLess(rm_run, read); self.assertLess(stop_dump, read); self.assertLess(read, rm_ns)

class Listing(unittest.TestCase):
    def test_unreadable_file_does_not_abort_listing(self):
        """e2e round 5: a /tmp file the harness user cannot read crashed the listing, so R3 lost its /tmp evidence for the whole unit."""
        t = tempfile.mkdtemp(prefix="ablist-"); self.addCleanup(shutil.rmtree, t, True)
        open(f"{t}/ok.txt", "w").write("x"); open(f"{t}/locked.txt", "w").write("y"); os.chmod(f"{t}/locked.txt", 0)
        r = subprocess.run([sys.executable, os.path.join(HERE, "lib", "listing.py"), t, f"{t}.json", f"{t}.files", "--own"], capture_output=True, text=True)
        self.addCleanup(lambda: [os.remove(x) for x in (f"{t}.json", f"{t}.files") if os.path.exists(x)])
        self.assertEqual(r.returncode, 0, r.stderr)
        ent = {e["path"]: e for e in json.load(open(f"{t}.json"))}
        self.assertIn("sha256", ent["ok.txt"])
        if os.getuid() != 0: self.assertEqual(ent["locked.txt"].get("hash_error"), "PermissionError")
        self.assertEqual(sorted(open(f"{t}.files").read().split()), ["locked.txt", "ok.txt"])


class SeedHome(unittest.TestCase):
    """R3 rig artefact (28 Sep 2026): the rig pre-created harness config directories and widened them with chmod -R a+rwX, so R3
    measured the rig's modes, not the harness's. The config is now seeded with the modes the harness gives those paths itself."""
    def seed(self, calib):
        t = tempfile.mkdtemp(prefix="abseed-"); self.addCleanup(shutil.rmtree, t, True)
        st, home = f"{t}/staged", f"{t}/home"; os.makedirs(f"{st}/.fx/sub"); os.makedirs(f"{st}/.cfg/fx"); os.mkdir(home)
        for f in (".fx/config.json", ".fx/sub/a", ".cfg/fx/auth.json"): open(f"{st}/{f}", "w").write("x")
        os.chmod(f"{st}/.fx", 0o777); os.chmod(f"{st}/.fx/config.json", 0o666)   # wide staged modes never reach HOME
        if calib is not None: json.dump(calib, open(f"{t}/cal.json", "w"))
        tar = subprocess.run(["tar", "-C", st, "-cf", "-", "."], capture_output=True, check=True).stdout
        r = subprocess.run([sys.executable, os.path.join(HERE, "lib", "seed_home.py"), home, f"{t}/cal.json", f"{t}/seed.json"], input=tar, capture_output=True)
        self.assertEqual(r.returncode, 0, r.stderr)
        mode = lambda p: oct(os.stat(f"{home}/{p}").st_mode & 0o7777)
        return mode, json.load(open(f"{t}/seed.json")), home

    def test_harness_modes_used_and_unobserved_paths_closed(self):
        mode, rec, _ = self.seed([{"path": ".fx", "type": "dir", "mode": "0o755"}, {"path": ".fx/config.json", "type": "file", "mode": "0o644"},
                                  {"path": ".fx/sub", "type": "file", "mode": "0o644"}])
        self.assertEqual(mode(".fx"), "0o755"); self.assertEqual(mode(".fx/config.json"), "0o644")
        self.assertEqual(mode(".fx/sub"), "0o700"); self.assertEqual(mode(".fx/sub/a"), "0o600")   # a dir seen only as a file is not observed
        self.assertEqual(mode(".cfg"), "0o700"); self.assertEqual(mode(".cfg/fx/auth.json"), "0o600")
        src = {e["path"]: e["source"] for e in rec["entries"]}
        self.assertEqual(rec["calibration"], "ok"); self.assertEqual(src[".fx"], "harness"); self.assertEqual(src[".cfg/fx"], "rig")

    def test_missing_calibration_closes_everything(self):
        mode, rec, home = self.seed(None)
        self.assertEqual(rec["calibration"], "missing"); self.assertEqual(mode(".fx"), "0o700"); self.assertEqual(mode(".fx/config.json"), "0o600")
        self.assertEqual(open(f"{home}/.fx/sub/a").read(), "x")

    def rigdep(self, seed=None, init=False, modes=None, listing=True, home_seed=None, extra_init=(), cred=None, access=None):
        U = make_unit(self.tmp_())
        modes = modes or {".fx": "0o700", ".fx/s.json": "0o644", ".fx/own": "0o755", ".fx/own/r.json": "0o644"}
        if listing: json.dump([{"path": p, "mode": m, "type": "file" if "." in p.rsplit("/", 1)[-1][1:] else "dir"} for p, m in modes.items()], open(f"{U}/out/home-listing.json", "w"))
        else: os.remove(f"{U}/out/home-listing.json")
        if access is None: access = {p: "readable" for p in modes if "." in p.rsplit("/", 1)[-1][1:]}
        if home_seed if home_seed is not None else seed is not None:
            r = json.load(open(f"{U}/run.json")); r["home_seed"] = 1; json.dump(r, open(f"{U}/run.json", "w"))
        if seed is not None:
            json.dump(seed, open(f"{U}/out/home-seed.json", "w"))
            for e in seed.get("entries", []):   # the staged config the record describes, kept as init/ by unit.sh
                if e.get("type") == "dir": os.makedirs(f"{U}/init/{e['path']}", exist_ok=True)
                elif not e.get("credential"): os.makedirs(os.path.dirname(f"{U}/init/{e['path']}"), exist_ok=True); open(f"{U}/init/{e['path']}", "w").close()
        if init: os.makedirs(f"{U}/init/.fx"); open(f"{U}/init/.fx/conf.json", "w").close()
        for p in extra_init: os.makedirs(f"{U}/init/{p}", exist_ok=True)
        if cred: r = json.load(open(f"{U}/run.json")); r["cred_dest"] = cred; json.dump(r, open(f"{U}/run.json", "w"))
        if access is not None: json.dump({"uid": 1001, "parents": [], "files": access}, open(f"{U}/out/access-1001.json", "w"))
        return analyse(U)

    def tmp_(self):
        t = tempfile.mkdtemp(prefix="abrd-"); self.addCleanup(shutil.rmtree, t, True); return t

    RIGFX = {"calibration": "missing", "entries": [{"path": ".fx", "type": "dir", "mode": "0o700", "source": "rig"}]}

    def test_rig_mode_directory_makes_files_rig_dependent(self):
        s = self.rigdep(self.RIGFX)
        self.assertEqual(s["r3_rig_dependent"], [".fx/own/r.json", ".fx/s.json"]); self.assertEqual(s["home_seed"]["kind"], "seeded")

    def test_harness_mode_directory_is_the_harness_own(self):
        s = self.rigdep({"calibration": "ok", "entries": [{"path": ".fx", "type": "dir", "mode": "0o700", "source": "harness"}]})
        self.assertEqual(s["r3_rig_dependent"], [])

    def test_directory_the_harness_changed_is_its_own(self):
        s = self.rigdep(self.RIGFX, modes={".fx": "0o711", ".fx/s.json": "0o644"})
        self.assertEqual(s["r3_rig_dependent"], [])

    def test_closed_file_or_closed_harness_dir_is_not_rig_dependent(self):
        s = self.rigdep(self.RIGFX, modes={".fx": "0o700", ".fx/s.json": "0o600", ".fx/own": "0o700", ".fx/own/r.json": "0o644"})
        self.assertEqual(s["r3_rig_dependent"], [])

    def test_seeded_file_still_at_rig_mode_is_rig_dependent(self):
        """Astra round 1: session content written into a seeded 0600 config file was protected by the rig's mode, not the harness's."""
        seed = {"calibration": "ok", "entries": [{"path": ".fx", "type": "dir", "mode": "0o755", "source": "harness"},
                                                 {"path": ".fx/s.json", "type": "file", "mode": "0o600", "source": "rig"}]}
        self.assertEqual(self.rigdep(seed, modes={".fx": "0o755", ".fx/s.json": "0o600"})["r3_rig_dependent"], [".fx/s.json"])
        self.assertEqual(self.rigdep(seed, modes={".fx": "0o755", ".fx/s.json": "0o640"})["r3_rig_dependent"], [])   # the harness set its own

    def test_missing_or_malformed_evidence_is_unknown(self):
        """Astra round 1: a missing seed record or listing read as 'nothing depends on the rig', a false pass."""
        self.assertIsNone(self.rigdep(None, home_seed=True)["r3_rig_dependent"])   # run.json says seeded, record missing
        self.assertIsNone(self.rigdep({"entries": [{"path": ".fx", "type": "dir", "mode": "700", "source": "rig"}]})["r3_rig_dependent"])
        self.assertIsNone(self.rigdep({"entries": [{"path": ".fx", "type": "dir", "mode": "0o700", "source": "?"}]})["r3_rig_dependent"])
        self.assertIsNone(self.rigdep(self.RIGFX, listing=False)["r3_rig_dependent"])

    def test_missing_mode_on_a_rig_path_is_rig_dependent(self):
        self.assertEqual(self.rigdep(self.RIGFX, modes={".fx": None, ".fx/s.json": "0o600"})["r3_rig_dependent"], None)   # malformed entry
        self.assertEqual(self.rigdep(self.RIGFX, modes={".fx": "0o700", ".fx/s.json": "0o600"}, access={".fx/s.json": "denied"})["r3_rig_dependent"], [])

    def test_incomplete_listing_is_unknown(self):
        """Astra round 2: a listing without the session file (or its parent, or a type) read as independent, a false pass."""
        self.assertIsNone(self.rigdep(self.RIGFX, modes={".fx": "0o700"}, access={".fx/s.json": "denied"})["r3_rig_dependent"])   # probed file unlisted
        self.assertIsNone(self.rigdep(self.RIGFX, modes={".fx/s.json": "0o644"})["r3_rig_dependent"])              # its parent unlisted
        U = make_unit(self.tmp_()); r = json.load(open(f"{U}/run.json")); r["home_seed"] = 1; json.dump(r, open(f"{U}/run.json", "w"))
        json.dump(self.RIGFX, open(f"{U}/out/home-seed.json", "w")); os.makedirs(f"{U}/init/.fx")
        json.dump([{"path": ".fx", "mode": "0o700", "type": "dir"}, {"path": ".fx/s.json", "mode": "0o644"}], open(f"{U}/out/home-listing.json", "w"))
        self.assertIsNone(analyse(U)["r3_rig_dependent"])                                                          # an entry without a type

    def test_incomplete_or_duplicated_seed_record_is_unknown(self):
        """Astra round 2: a well-formed but empty record hid the rig's directories."""
        self.assertIsNone(self.rigdep({"entries": []}, extra_init=[".fx"])["r3_rig_dependent"])
        self.assertIsNone(self.rigdep({"entries": self.RIGFX["entries"] * 2})["r3_rig_dependent"])
        self.assertIsNone(self.rigdep(self.RIGFX, cred=".fx/auth.json")["r3_rig_dependent"])                        # credential not recorded

    def test_credential_file_mode_is_the_rig_s(self):
        """Astra round 2: the credential file's 0600 is the rig's; content in it must not count as protected by the harness."""
        seed = {"calibration": "ok", "entries": [{"path": ".fx", "type": "dir", "mode": "0o755", "source": "harness"},
                                                 {"path": ".fx/s.json", "type": "file", "mode": "0o600", "source": "rig", "credential": True}]}
        self.assertEqual(self.rigdep(seed, modes={".fx": "0o755", ".fx/s.json": "0o600"}, cred=".fx/s.json")["r3_rig_dependent"], [".fx/s.json"])

    def test_record_adds_credential_with_actual_mode(self):
        t = self.tmp_(); os.makedirs(f"{t}/h/.fx"); open(f"{t}/h/.fx/auth.json", "w").close(); os.chmod(f"{t}/h/.fx/auth.json", 0o600)
        json.dump({"calibration": "ok", "entries": []}, open(f"{t}/seed.json", "w"))
        r = subprocess.run([sys.executable, os.path.join(HERE, "lib", "seed_home.py"), "--record", f"{t}/h", f"{t}/seed.json", ".fx/auth.json"], capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(json.load(open(f"{t}/seed.json"))["entries"], [{"path": ".fx/auth.json", "type": "file", "mode": "0o600", "source": "rig", "credential": True}])

    def test_legacy_unit_widened_init_paths(self):
        s = self.rigdep(init=True, modes={".fx": "0o777", ".fx/s.json": "0o644"})
        self.assertEqual(s["home_seed"]["kind"], "legacy"); self.assertEqual(s["r3_rig_dependent"], [".fx/s.json"])
        s = self.rigdep(init=True, modes={".fx": "0o755", ".fx/conf.json": "0o666"})
        self.assertEqual(s["r3_rig_dependent"], [".fx/conf.json"])


class UnitSeedScript(unittest.TestCase):
    src = open(os.path.join(HERE, "unit.sh")).read()

    def test_home_never_widened(self):
        self.assertNotIn('chmod -R a+rwX "$R"   ', self.src); self.assertNotIn('chmod -R a+rwX "$R"\n', self.src)
        self.assertIn('chmod -R a+rwX "$R/cap" "$R/mcap" "$R/pcap" "$R/out" "$R/work"', self.src)
        self.assertNotIn("/run/init", self.src); self.assertNotIn("cp -a", self.src)

    def test_calibration_offline_and_before_seeding(self):
        c = self.src.index('docker run --rm --name "$CALC"'); seed = self.src.index("seed_home.py /home/lab")
        self.assertIn("--network none", self.src[c:c + 200]); self.assertLess(c, seed)
        self.assertNotIn("CRED", self.src[c:self.src.index("\n", self.src.index("listing.py /home/lab /out/calibration", c))])

    def test_partial_seed_archive_stops_the_unit(self):
        """Astra round 1: without pipefail a failing tar (partial archive) went unnoticed; bash really propagates it here."""
        self.assertIn('( set -o pipefail; tar -C "$R/home" -cf - . | docker exec -i', self.src)
        r = subprocess.run(["bash", "-c", '( set -o pipefail; { tar -cf - --files-from /dev/null; exit 2; } | cat >/dev/null ) || echo stopped'], capture_output=True, text=True)
        self.assertEqual(r.stdout.strip(), "stopped")

    def test_run_json_marks_seeded_units(self):
        self.assertIn('"home_seed":1,', self.src)


if __name__ == "__main__":
    unittest.main()
