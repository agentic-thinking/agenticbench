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

    def test_tmp_probed_as_other_user(self):
        self.assertIn("access.py /tmp /out/tmp-files.txt", self.src); self.assertIn("listing.py /tmp /out/tmp-listing.json /out/tmp-files.txt --own", self.src)


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


if __name__ == "__main__":
    unittest.main()
