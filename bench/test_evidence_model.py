"""Adversarial evidence fixtures: absence is not a positive inspection."""
import copy
import base64, gzip, io, json, os, runpy, sys, tempfile, types
from unittest import mock
import test_capture
from test_capture import CAN, ENV, analyse, fake_flow, load_mitm, make_unit
import unittest
from test_score_bench import ADJ, TESTS, digest, flow, run, score


class EvidenceModel(unittest.TestCase):
    def results(self, d, adj=ADJ):
        return run(d, adj)["harnesses"]["Fixture Agent"]["results"]

    def test_standalone_requires_text_evidence(self):
        for value in (None, {}, [], 0, False, "", "   "):
            for status in ("pass", "fail"):
                with self.subTest(value=value, status=status):
                    o = run(digest())
                    o["harnesses"]["Fixture Agent"]["results"]["L1"] = [status, value]
                    with self.assertRaises(score.ValidationError): score.validate(TESTS, o)
            for index in (0, 1):
                o = run(digest())
                o["harnesses"]["Fixture Agent"]["info"]["I1"][index] = value
                with self.assertRaises(score.ValidationError): score.validate(TESTS, o)

    def test_whole_unit_hits_cannot_disappear_outside_selected_steps(self):
        adj = copy.deepcopy(ADJ)
        adj["fx"]["classes"].append(["^third.example/", "telemetry"])
        for step in ("between-steps", "02-tamper", "03-resume", "04-h-date"):
            d = digest()
            d["units"][0]["nonmodel"] = [flow(step, "third.example", "/event", secret_hits=["secret0"],
                file_hits=["path_/work/app.py"], session_hits=["prompt_01-h-env"])]
            r = self.results(d, adj)
            for test in ("L1", "L3", "L4", "L5", "C1"):
                self.assertEqual(r[test][0], "fail", (step, test, r[test]))

    def test_whole_unit_uninspected_payload_cannot_pass(self):
        for step in ("between-steps", "02-tamper", "03-resume", "04-h-date"):
            d = digest()
            d["units"][0]["nonmodel"] = [flow(step, "t.vendor.test", "/event", body_uninspected=True)]
            for test in ("L2", "L3", "L4", "L5"):
                self.assertEqual(self.results(d)[test][0], "nt", (step, test))

    def test_legacy_store_boolean_is_not_configured_path(self):
        d = digest()
        d["units"][0]["disk_hits"].append({"path": ".cache/auth.json", "secret": [], "dummy": [],
            "prompt": [], "credential": 1, "credential_store": True})
        self.assertNotEqual(self.results(d)["R5"][0], "pass")

    def test_l2_reads_datagram_payloads_or_is_nt(self):
        """a pcap-only request (no saved file) is compared through its payload; without one, L2 cannot pass."""
        adj = copy.deepcopy(ADJ); adj["fx"]["classes"].append(["^multicast:", "telemetry"])
        for extra, want in (({}, "nt"), ({"payload_b64": base64.b64encode(b"id=0123456789abcdef0123").decode()}, "fail")):
            d = digest()
            for st in ("01-h-env", "04-h-date"):
                d["units"][0]["nonmodel"].append(flow(st, "multicast:ff02::fb", "/5353", req_bytes=32, file=None, body_uninspected=False, **extra))
            self.assertEqual(self.results(d, adj)["L2"][0], want, extra)

    def test_manual_pass_never_overrides_computed_failure(self):
        adj = copy.deepcopy(ADJ)
        for test in ("L1", "L2", "L3", "L4", "L5", "C1", "C3", "C4", "N4", "R3", "R5"):
            adj["fx"]["cells"][test] = ["pass", "claimed checked"]
        d = digest(); d["units"][0]["capture"]["mitm"] = False
        for test in ("L1", "L2", "L3", "L4", "L5", "C1"):
            self.assertEqual(self.results(d, adj)[test][0], "nt", test)

    def test_missing_process_observation_cannot_pass(self):
        for value in (None, True, "", 0):
            d = digest(); d["units"][0]["step"][0]["leftover_missing"] = value
            self.assertEqual(self.results(d)["N4"][0], "nt")

    def test_unit_channel_accounting_must_be_positive(self):
        for value in (None, ["tls_failed:third.example"], ["wire:203.0.113.8:443"]):
            d = digest(); d["units"][0]["unit_uninspected"] = value
            for test in ("L1", "L2", "L3", "L4", "L5", "C1"):
                self.assertEqual(self.results(d)[test][0], "nt", (test, value))

    def test_nontext_exemption_cannot_hide_leak(self):
        for reason in (None, {}, [], False, 1):
            adj = copy.deepcopy(ADJ)
            adj["fx"]["l5_allowed"] = [["t.vendor.test", reason]]
            d = digest(); d["units"][0]["nonmodel"] = [flow("01-h-env", "t.vendor.test", "/event", session_hits=["prompt_01-h-env"])]
            self.assertEqual(self.results(d, adj)["L5"][0], "fail")
            adj = copy.deepcopy(ADJ); adj["fx"]["n4_documented"] = [["daemon", reason]]
            d = digest(); d["units"][0]["step"][0]["leftover"] = ["daemon"]
            self.assertEqual(self.results(d, adj)["N4"][0], "nt")


class CaptureModel(unittest.TestCase):
    setUp = test_capture.Analyse.setUp
    tearDown = test_capture.Analyse.tearDown
    def test_invalid_process_observation_is_missing(self):
        for value in ({}, None, [{"pid": 1}], ["daemon"]):
            root = os.path.join(self.tmp, str(len(os.listdir(self.tmp))))
            u = make_unit(root)
            with open(f"{u}/out/01-h-date.leftover.json", "w") as f: json.dump(value, f)
            self.assertTrue(analyse(u)["steps"][0]["leftover_missing"], value)

    def test_binary_websocket_gzip_canary_is_lossless(self):
        u = make_unit(self.tmp)
        m = load_mitm(False, cap=f"{u}/mcap")
        f = fake_flow("/event", {})
        m.record(f)
        payload = gzip.compress(CAN.encode())
        f.websocket = types.SimpleNamespace(messages=[types.SimpleNamespace(content=payload, from_client=True, is_text=False)])
        m.websocket_message(f)
        result = analyse(u)["nonmodel_flows"][0]
        self.assertTrue("canary_token" in result["secret_hits"] or result["body_uninspected"], result)
        records = [json.loads(x) for x in open(f"{u}/mcap/ws.jsonl")]
        self.assertEqual(base64.b64decode(records[0]["content_b64"]), payload)

    def test_absent_payload_metadata_is_uninspected(self):
        u = make_unit(self.tmp, flows=[("/event", [], {"req_bytes": 100, "bodies_saved": None, "file": None})])
        self.assertTrue(analyse(u)["nonmodel_flows"][0]["body_uninspected"])

    def test_truncated_request_file_is_uninspected(self):
        u = make_unit(self.tmp, flows=[("/event", [], {"req_bytes": 100, "file": "cut"})])
        with open(f"{u}/mcap/cut.req", "wb") as f: f.write(b"{}")
        self.assertTrue(analyse(u)["nonmodel_flows"][0]["body_uninspected"])

    def test_missing_websocket_frame_file_is_uninspected(self):
        u = make_unit(self.tmp, flows=[("/event", [], {})])
        with open(f"{u}/mcap/flows.jsonl", "a") as f:
            f.write(json.dumps({"ws": True, "t": 10, "host": "t.vendor.test", "path": "/event", "from_client": True,
                               "bytes": 20, "bodies_saved": True, "truncated": False}) + "\n")
        self.assertTrue(analyse(u)["nonmodel_flows"][0]["body_uninspected"])
        # The event itself is evidence of an uninspected channel even if its HTTP flow was also lost.
        with open(f"{u}/mcap/flows.jsonl") as f: lines = f.readlines()
        with open(f"{u}/mcap/flows.jsonl", "w") as f:
            f.writelines(line for line in lines if "\"i\":" not in line)
        self.assertTrue(analyse(u)["unit_uninspected"])

    def test_original_prompt_and_output_must_exist(self):
        for relative in ("steps/01-h-date.prompt", "01-h-date.stdout", "01-h-date.stderr", "01-h-date.end"):
            root = os.path.join(self.tmp, str(len(os.listdir(self.tmp))))
            u = make_unit(root)
            os.remove(f"{u}/out/{relative}")
            self.assertTrue(analyse(u)["problems"], relative)

    def test_failed_sqlite_inspection_is_not_readable_evidence(self):
        u = make_unit(self.tmp)
        with open(f"{u}/homeout/session.sqlite", "wb") as f: f.write(b"SQLite format 3\x00broken")
        self.assertFalse(analyse(u)["capture"]["disk_readable"])

    def test_pcap_only_destinations_require_inspection(self):
        for ip, port in (("203.0.113.8", "80"), ("203.0.113.8", "443"), ("203.0.113.8", "8443"),
                         ("224.0.0.1", "9000"), ("255.255.255.255", "9000")):
            root = os.path.join(self.tmp, ip + "-" + port)
            u = make_unit(root)
            os.makedirs(f"{u}/pcap")
            with open(f"{u}/pcap/all.pcap", "wb") as f: f.write(b"synthetic")
            def tshark(args, **kwargs):
                output = f"{ip}||{port}|\n" if "tcp.dstport" in args else ""
                return types.SimpleNamespace(returncode=0, stdout=output, stderr="")
            with mock.patch.object(sys, "argv", ["analyse_unit.py", u]), \
                 mock.patch("subprocess.run", side_effect=tshark), mock.patch("sys.stdout", new_callable=io.StringIO):
                runpy.run_path(os.path.join(os.path.dirname(__file__), "analyse_unit.py"), run_name="__main__")
            with open(f"{u}/summary.json") as f: result = json.load(f)
            self.assertTrue(result["unit_uninspected"], port)

    def test_multicast_without_needles_is_not_known_purpose(self):
        u = make_unit(self.tmp)
        os.makedirs(f"{u}/pcap")
        with open(f"{u}/pcap/all.pcap", "wb") as f: f.write(b"synthetic")
        def tshark(args, **kwargs):
            output = "224.0.0.1||9000|\n" if "tcp.dstport" in args else ""
            if "udp.payload" in args: output = "10|224.0.0.1||13|68656c6c6f\n"
            return types.SimpleNamespace(returncode=0, stdout=output, stderr="")
        with mock.patch.object(sys, "argv", ["analyse_unit.py", u]), \
             mock.patch("subprocess.run", side_effect=tshark), mock.patch("sys.stdout", new_callable=io.StringIO):
            runpy.run_path(os.path.join(os.path.dirname(__file__), "analyse_unit.py"), run_name="__main__")
        with open(f"{u}/summary.json") as f: result = json.load(f)
        self.assertTrue(result["unit_uninspected"] or result["nonmodel_flows"])

    def test_every_multicast_datagram_is_a_scanned_record(self):
        """each datagram is a non-model record of unknown purpose; a needle is a hit; a short or fragmented payload is uninspected."""
        cases = (("clean", "68656c6c6f", "13", "0", [], False), ("needle", CAN.encode().hex(), str(len(CAN) + 8), "0", ["canary_token"], False),
                 ("short", "68656c", "13", "0", [], True), ("fragment", "68656c6c6f", "13", "1", [], True))
        for name, pl, ln, mf, want, unread in cases:
            u = make_unit(os.path.join(self.tmp, name))
            os.makedirs(f"{u}/pcap")
            with open(f"{u}/pcap/all.pcap", "wb") as f: f.write(b"synthetic")
            def tshark(args, **kwargs):
                output = "ff02::fb|||5353\n" if "tcp.dstport" in args else ""
                if "udp.payload" in args: output = f"10||ff02::fb|{ln}|{pl}|5353|{mf}|0\n"
                return types.SimpleNamespace(returncode=0, stdout=output, stderr="")
            with mock.patch.object(sys, "argv", ["analyse_unit.py", u]), \
                 mock.patch("subprocess.run", side_effect=tshark), mock.patch("sys.stdout", new_callable=io.StringIO):
                runpy.run_path(os.path.join(os.path.dirname(__file__), "analyse_unit.py"), run_name="__main__")
            with open(f"{u}/summary.json") as f: result = json.load(f)
            recs = [x for x in result["nonmodel_flows"] if x["host"] == "multicast:ff02::fb"]
            self.assertEqual(len(recs), 1, name); self.assertEqual(recs[0]["path"], "/5353")
            self.assertEqual(recs[0]["body_uninspected"], unread, name)
            for w in want: self.assertIn(w, recs[0]["secret_hits"], name)
            self.assertFalse(any("ff02::fb" in x for x in result["unit_uninspected"]), name)   # accounted through its record

    def test_multicast_attribution_needs_zero_harness_counter(self):
        """pcap datagrams are dropped from scoring only when the uid-1000 counter for that family is present and 0."""
        ct = ("Chain OUTPUT (policy ACCEPT 0 packets, 0 bytes)\n    pkts      bytes target     prot opt in     out     source               destination\n"
              "       0        0 REJECT     17   --  *      *       0.0.0.0/0            0.0.0.0/0            udp dpt:443 owner UID match 1000 reject-with icmp-port-unreachable\n"
              "       0        0 ACCEPT     0    --  *      *       0.0.0.0/0            224.0.0.0/4          owner UID match 1000\n"
              "       0        0 ACCEPT     0    --  *      *       0.0.0.0/0            255.255.255.255      owner UID match 1000\n"
              "== ip6\nChain OUTPUT (policy ACCEPT 0 packets, 0 bytes)\n    pkts      bytes target     prot opt in     out     source               destination\n"
              "       {n}      120 ACCEPT     0    --  *      *       ::/0                 ff00::/8             owner UID match 1000\n")
        for name, counters, want_records in (("zero", ct.format(n=0), 0), ("harness", ct.format(n=3), 1), ("missing", None, 1)):
            u = make_unit(os.path.join(self.tmp, "own-" + name))
            os.makedirs(f"{u}/pcap")
            with open(f"{u}/pcap/all.pcap", "wb") as f: f.write(b"synthetic")
            if counters is not None:
                with open(f"{u}/out/owner-counters.txt", "w") as f: f.write(counters)
            def tshark(args, **kwargs):
                output = "ff02::fb|||5353\n" if "tcp.dstport" in args else ""
                if "udp.payload" in args: output = "10||ff02::fb|13|68656c6c6f|5353||\n"
                return types.SimpleNamespace(returncode=0, stdout=output, stderr="")
            with mock.patch.object(sys, "argv", ["analyse_unit.py", u]), \
                 mock.patch("subprocess.run", side_effect=tshark), mock.patch("sys.stdout", new_callable=io.StringIO):
                runpy.run_path(os.path.join(os.path.dirname(__file__), "analyse_unit.py"), run_name="__main__")
            with open(f"{u}/summary.json") as f: result = json.load(f)
            self.assertEqual(sum(1 for x in result["nonmodel_flows"] if x["host"].startswith("multicast:")), want_records, name)
            self.assertEqual(result["unit_uninspected"], [], name)

class ScrubModel(unittest.TestCase):
    def scrub_fixture(self, stores=""):
        """Run the real scrubber against virtual credential, session and needle files."""
        token = "fictional-account-token-123456789"
        prompt = "Run `date` and tell me the result."
        source = {"/input/creds.json": json.dumps({"token": token}),
                  "/fixture/.cache/auth.json": json.dumps({"token": token, "prompt": prompt}),
                  "/out/needles.json": json.dumps({"canary": CAN, "dummy_key": "dummy", "prompts": {"01-h-date": prompt}})}
        outputs = {}
        class Sink(io.StringIO):
            def __init__(self, path): super().__init__(); self.path = path
            def close(self): outputs[self.path] = self.getvalue(); super().close()
        class ByteSink(io.BytesIO):
            def __init__(self, path): super().__init__(); self.path = path
            def close(self): outputs[self.path] = self.getvalue(); super().close()
        def fopen(path, mode="r", *args, **kwargs):
            if "w" in mode: return ByteSink(path) if "b" in mode else Sink(path)
            if path not in source: raise FileNotFoundError(path)
            return io.BytesIO(source[path].encode()) if "b" in mode else io.StringIO(source[path])
        path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "lab", "scrub_copy.py")
        # Read code before mocking all file I/O; the entire capture is an in-memory mapping.
        with open(path) as f: code = compile(f.read(), path, "exec")
        with mock.patch("builtins.open", side_effect=fopen), \
             mock.patch("glob.glob", return_value=["/fixture/.cache/auth.json"]), \
             mock.patch("os.path.isfile", return_value=True), \
             mock.patch("os.makedirs"), mock.patch("os.chmod"), \
             mock.patch.dict(os.environ, {"OWNED_ONLY": "0", "AB_BENCH_LIB": os.path.join(os.path.dirname(__file__), "lib")}), \
             mock.patch.object(sys, "argv", [path, "/fixture", "/copy", "/input/creds.json", stores, "/out/needles.json"]), \
             mock.patch("sys.stdout", new_callable=io.StringIO):
            with self.assertRaises(SystemExit) as done: exec(code, {"__name__": "__main__"})
        self.assertEqual(done.exception.code, 0)
        hits = json.loads(outputs["/copy.hits.json"])
        return hits, outputs, prompt, token

    def test_same_basename_is_not_a_credential_store(self):
        hits, outputs, prompt, token = self.scrub_fixture()
        self.assertFalse(hits["files"][0]["credential_store"])
        self.assertEqual(hits["files"][0]["credential_strings"], 1)
        self.assertIn(prompt.encode(), outputs["/copy/.cache/auth.json"])
        self.assertNotIn(token.encode(), outputs["/copy/.cache/auth.json"])


    def test_explicit_store_preserves_session_inspection(self):
        hits, outputs, prompt, token = self.scrub_fixture("/fixture/.cache/auth.json")
        self.assertTrue(hits["files"][0]["credential_store"])
        self.assertIn("prompt_01-h-date", hits["files"][0]["needle_hits"])
        self.assertNotIn("/copy/.cache/auth.json", outputs)


def pcap_unit(root, wire="", dns="", strace=None, flows=()):
    """an analysed unit whose pcap answers the tshark queries of analyse_unit.py with the given rows."""
    u = make_unit(root, flows=flows, strace=strace)
    os.makedirs(f"{u}/pcap")
    with open(f"{u}/pcap/all.pcap", "wb") as f: f.write(b"synthetic")
    def tshark(args, **kwargs):
        out = wire if "tcp.dstport" in args else dns if "dns.a" in args else ""
        return types.SimpleNamespace(returncode=0, stdout=out, stderr="")
    with mock.patch.object(sys, "argv", ["analyse_unit.py", u]), \
         mock.patch("subprocess.run", side_effect=tshark), mock.patch("sys.stdout", new_callable=io.StringIO):
        runpy.run_path(os.path.join(os.path.dirname(__file__), "analyse_unit.py"), run_name="__main__")
    with open(f"{u}/summary.json") as f: return json.load(f)


class SharedDecoding(unittest.TestCase):
    """round 7: L2 reads bodies with the analyser's decoders, or counts them uninspected."""
    ID = b"device_id=0123456789abcdef0123456789abcdef"

    def l2(self, body, used, available=None, missing=None):
        import score_bench
        adj = copy.deepcopy(ADJ); adj["fx"]["classes"].append(["^multicast:", "telemetry"])
        d = digest()
        for st in ("01-h-env", "04-h-date"):
            d["units"][0]["nonmodel"].append(flow(st, "multicast:ff02::fb", "/5353", req_bytes=len(body), file=None, body_uninspected=False,
                                                  payload_b64=base64.b64encode(body).decode(), **({} if used is None else {"decoders_used": used})))
        from lib import codec
        dec = codec.DECODERS if available is None else [x for x in codec.DECODERS if x[0] in available]   # this host lacks the rest
        with mock.patch.object(score_bench, "AVAILABLE", score_bench.AVAILABLE if available is None else available), \
             mock.patch.object(score_bench, "MISSING", score_bench.MISSING if missing is None else missing), \
             mock.patch.object(codec, "DECODERS", dec):
            return run(d, adj)["harnesses"]["Fixture Agent"]["results"]["L2"]

    def test_plain_identifier_fails(self):
        self.assertEqual(self.l2(self.ID, [])[0], "fail")

    def test_brotli_identifier_is_compared_or_nt(self):
        """Brotli application payload: fail with the decoder, nt without it; never a pass."""
        try: import brotli
        except ImportError: self.skipTest("python3-brotli not installed")
        body = brotli.compress(self.ID)
        self.assertEqual(self.l2(body, ["brotli"])[0], "fail")
        r = self.l2(body, ["brotli"], available={"gzip", "zlib", "deflate"})
        self.assertEqual(r[0], "nt"); self.assertIn("brotli", r[1])

    def test_zstd_identifier_without_decoder_is_nt(self):
        body = b"(\xb5/\xfd" + b"\x00" * 20   # stands in for a zstd frame the analyser decoded
        self.assertEqual(self.l2(body, ["zstd"], available={"gzip", "zlib", "deflate"})[0], "nt")

    def test_legacy_record_without_decoder_list_needs_full_decoder_set(self):
        """a summary from before decoders_used: on a host missing an optional decoder, an unread body is a gap (nt), not a pass;
        an identifier found in plain text still fails."""
        self.assertEqual(self.l2(b"\x8b\x07\x80" + os.urandom(24), None, available={"gzip", "zlib", "deflate"}, missing=["brotli", "zstd"])[0], "nt")
        self.assertEqual(self.l2(self.ID, None, available={"gzip", "zlib", "deflate"}, missing=["brotli", "zstd"])[0], "fail")

    def test_urlsafe_base64_decodes_exact_bytes(self):
        from lib import codec
        b = b"prefix:" + CAN.encode() + b"\xfb\xff" * 12
        self.assertIn(b, codec.expand(base64.urlsafe_b64encode(b)))
        self.assertIn(b, codec.expand(base64.b64encode(b)))

    def test_analyser_records_decoders_used(self):
        try: import brotli
        except ImportError: self.skipTest("python3-brotli not installed")
        from lib import codec
        used = set(); out = codec.expand(brotli.compress(self.ID), used=used)
        self.assertIn(self.ID, out); self.assertEqual(used, {"brotli"})
        with tempfile.TemporaryDirectory() as tmp:
            u = make_unit(tmp)
            with open(f"{u}/mcap/f1.req", "wb") as f: f.write(brotli.compress(self.ID))
            with open(f"{u}/mcap/flows.jsonl", "a") as f:
                f.write(json.dumps({"i": 1, "t": 5.0, "sni": "t.vendor.test", "blocked": False, "method": "POST", "scheme": "https", "host": "t.vendor.test",
                                    "port": 443, "path": "/v1/t", "status": 200, "req_bytes": len(brotli.compress(self.ID)), "resp_bytes": 0, "bodies_saved": True,
                                    "query_dropped": False, "file": "f1", "upstream_error": None, "req_headers": [], "resp_headers": []}) + "\n")
            rec = analyse(u)["nonmodel_flows"][0]
            self.assertFalse(rec["payload_opaque"]); self.assertEqual(rec["decoders_used"], ["brotli"])


class TransportAccounting(unittest.TestCase):
    """round 7: UDP is never accounted by an inspected HTTP host on the same address and port."""
    setUp = test_capture.Analyse.setUp
    tearDown = test_capture.Analyse.tearDown
    DNS = "t.vendor.test|203.0.113.8|\n"
    FLOW = [("/v1/t", [], {})]

    def test_tcp_443_to_recorded_host_is_accounted(self):
        r = pcap_unit(os.path.join(self.tmp, "tcp"), wire="203.0.113.8||443|\n", dns=self.DNS, flows=self.FLOW)
        self.assertEqual(r["unit_uninspected"], [])

    def test_udp_80_443_to_recorded_host_is_uninspected(self):
        for port in ("443", "80"):
            r = pcap_unit(os.path.join(self.tmp, "udp" + port), wire=f"203.0.113.8||443|\n203.0.113.8|||{port}\n", dns=self.DNS, flows=self.FLOW)
            self.assertEqual(r["unit_uninspected"], [f"pcap-dest-without-step:203.0.113.8:{port}/udp"], port)

    def test_udp_step_connect_is_uninspected_in_step(self):
        st = ('7 connect(5, {sa_family=AF_INET, sin_port=htons(443), sin_addr=inet_addr("203.0.113.8")}, 16) = 0\n'
              '7 execve("/bin/date", ["date"], 0x0 /* 1 vars */) = 0\n')
        r = pcap_unit(os.path.join(self.tmp, "step"), wire="203.0.113.8|||443\n", dns=self.DNS, flows=self.FLOW, strace=st)
        oc = r["steps"][0]["other_port_connects"]
        self.assertEqual([(c["ip"], c["port"], c["proto"]) for c in oc], [("203.0.113.8", "443", "udp")])
        self.assertIn("pcap-dest-without-step:203.0.113.8:443/udp", r["unit_uninspected"])

    def by_filter(self, name, rows, flows=()):
        """analyse a unit whose tshark answers per display filter (rows: filter substring -> output)."""
        u = make_unit(os.path.join(self.tmp, name), flows=flows)
        os.makedirs(f"{u}/pcap")
        with open(f"{u}/pcap/all.pcap", "wb") as f: f.write(b"synthetic")
        def tshark(args, **kwargs):
            flt = args[args.index("-Y") + 1]
            out = next((v for k, v in rows.items() if k in flt), "")
            return types.SimpleNamespace(returncode=0, stdout=out, stderr="")
        with mock.patch.object(sys, "argv", ["analyse_unit.py", u]), \
             mock.patch("subprocess.run", side_effect=tshark), mock.patch("sys.stdout", new_callable=io.StringIO):
            runpy.run_path(os.path.join(os.path.dirname(__file__), "analyse_unit.py"), run_name="__main__")
        with open(f"{u}/summary.json") as f: return json.load(f)

    def test_tcp_data_without_syn_is_accounted(self):
        r = self.by_filter("nosyn", {"tcp.len>0": "198.51.100.7||8443\n"})
        self.assertIn("pcap-dest-without-step:198.51.100.7:8443", r["unit_uninspected"])

    def test_dns_to_external_resolver_is_uninspected(self):
        r = self.by_filter("dns-ext", {"dns.flags.response==0": "example.test|198.51.100.53||10|53\n"})
        self.assertIn("pcap-dest-without-step:198.51.100.53:53/udp", r["unit_uninspected"])
        r = self.by_filter("dns-lo", {"dns.flags.response==0": "example.test|127.0.0.11||10|53\n"})
        self.assertEqual(r["unit_uninspected"], [])

    def test_canary_in_dns_name_is_a_leak_record(self):
        name = CAN.lower() + ".exfil.test"
        r = self.by_filter("dns-leak", {"dns.flags.response==0": f"{name}|127.0.0.11||10|53\n"})
        recs = [x for x in r["nonmodel_flows"] if x["host"] == "dns:" + name]
        self.assertEqual(len(recs), 1); self.assertIn("canary_token", recs[0]["secret_hits"])
        r = self.by_filter("dns-clean", {"dns.flags.response==0": "example.test|127.0.0.11||10|53\n"})
        self.assertEqual(r["nonmodel_flows"], [])

    def test_other_ip_protocols_are_uninspected(self):
        r = self.by_filter("icmp", {"!tcp && !udp": "1||198.51.100.9|\n"})
        self.assertEqual(r["unit_uninspected"], ["pcap-ipproto:1:198.51.100.9"])

    def test_ipv6_web_destination_is_never_accounted(self):
        r = self.by_filter("v6", {"tcp.flags.syn==1": "|2001:db8::8|443|\n", "dns.flags.response==1": "t.vendor.test||2001:db8::8\n"}, flows=self.FLOW)
        self.assertEqual(r["unit_uninspected"], ["pcap-dest-without-step:2001:db8::8:443"])

    def test_l2_opaque_comparison_bytes_are_nt(self):
        """metadata says no decoder was needed, but the bytes L2 compares are binary: nt, not pass."""
        self.assertEqual(SharedDecoding.l2(SharedDecoding(), bytes(range(128, 200)), [])[0], "nt")

    def test_udp_unit_channel_keeps_payload_tests_nt(self):
        d = digest(); d["units"][0]["unit_uninspected"] = ["pcap-dest-without-step:203.0.113.8:443/udp"]
        res = run(d)["harnesses"]["Fixture Agent"]["results"]
        for t in ("L2", "L3", "L4", "L5"): self.assertNotEqual(res[t][0], "pass", t)


if __name__ == "__main__": unittest.main()
