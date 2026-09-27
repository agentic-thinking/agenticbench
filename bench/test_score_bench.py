"""Tests for score_bench.py on synthetic digests (fictional harness, no captures needed). Run: python3 -m unittest -v test_score_bench"""
import atexit, contextlib, copy, io, json, os, shutil, sys, tempfile, unittest

HERE = os.path.dirname(os.path.abspath(__file__))
TMP = tempfile.mkdtemp(prefix="abtest-"); BENCH = os.path.join(TMP, "bench"); atexit.register(shutil.rmtree, TMP, True)
os.environ["AGENTICBENCH_BENCH_DIR"] = BENCH
sys.path[:0] = [HERE, os.path.join(os.path.dirname(HERE), "score")]
import score_bench  # noqa: E402
import score  # noqa: E402

TESTS = json.load(open(os.path.join(os.path.dirname(HERE), "score", "tests.json")))
CAP = {"mitm": True, "proxy": True, "pcap": True, "homeout": True, "tmpout": True, "disk_readable": True, "listing": True, "access_1001": True}


def step(name, **k):
    s = {"name": name, "kind": name.split("-")[1], "skipped": None, "rc": "0", "outer_rc": "0", "exec_date": False, "exec_ls": False,
         "exec_calc": False, "exec_sandbox": [], "strace_ok": True, "exec_ambiguous": [], "nonmodel_hosts": [], "tls_failed": [], "passthrough": [], "other_port_connects": [],
         "model_requests": 1, "model_ok": 1, "model_last_ok": True, "canary_to_model": False, "tamper_to_model": False, "tamper_secret_to_model": False, "leftover_missing": False,
         "leftover": [], "tamper": None}
    s.update(k); return s


def unit(d, variant, steps, st, **k):
    u = {"dir": f"results/{d}", "variant": variant, "steps": steps, "version": "1.0.0", "started": "20000101T000000Z", "model": "proxy",
         "l3variant": "", "problems": [], "access_checked_1001": {".fx/session.json": "denied"}, "capture": dict(CAP), "step": st, "model_hosts": [], "nonmodel": [], "disk_hits": [], "readable_1001": [],
         "home_parents": [], "pcap_sni": [], "modes": {}, "unit_uninspected": [], "cred_stores": []}
    u.update(k); return u


def flow(st, host, path, **k):
    f = {"step": st, "host": host, "method": "POST", "path": path, "status": 200, "req_bytes": 10, "secret_hits": [], "file_hits": [],
         "session_hits": [], "dummy_hits": [], "file": None, "blocked": False}
    f.update(k); return f


def digest():
    main = unit("fx-default-1", "default", "h:env tamper resume h:date", [
        step("01-h-env", model_requests=2, canary_to_model=True),
        step("02-tamper", model_requests=0, model_ok=0, tamper={"files": [{"path": ".fx/session.json", "method": "bytes", "count": 2}]}),
        step("03-resume", tamper_to_model=True), step("04-h-date")],
        disk_hits=[{"path": ".fx/session.json", "secret": ["secret0"], "dummy": [], "prompt": ["prompt_01-h-env"]}])
    fresh = unit("fx-default-2", "default", "h:date", [step("01-h-date")])
    tui = unit("fx-default-3", "default", "tui", [step("01-tui", model_requests=0, model_ok=0, rc="124")])
    opt = unit("fx-optout-4", "optout", "h:env", [step("01-h-env")])
    opt_tui = unit("fx-optout-5", "optout", "tui", [step("01-tui", model_requests=0, model_ok=0, rc="124")])
    return {"harness": "fx", "batch": "b1", "I1": {"A_requests": 2, "B_requests": 1, "C_requests": 1, "candidates": []},
            "units": [main, fresh, tui, opt, opt_tui]}


ADJ = {"fx": {"name": "Fixture Agent", "batch": "b1", "vendor_hosts": ["(^|\\.)vendor\\.test$"], "classes": [["^t\\.vendor\\.test/", "telemetry"], ["^up\\.vendor\\.test/", "update"]],
              "telemetry_optout_doc": "FX_TELEMETRY=0 (docs)", "r5_allowed": ["^\\.fx/"], "refused": [],
              "cells": {c: ["nt", "not adjudicated yet"] for c in ("C2", "C5", "N1", "N2", "N5", "R1", "R2")}}}


def run(d, adj=ADJ):
    os.makedirs(f"{BENCH}/digest", exist_ok=True)
    for u in d["units"]:
        os.makedirs(f"{TMP}/bench/{u['dir']}", exist_ok=True)
        with open(f"{TMP}/bench/{u['dir']}/summary.json", "w") as f: json.dump({"nonmodel_flows": [dict(x, req_headers=x.get("req_headers", [])) for x in u["nonmodel"]]}, f)
    with open(f"{BENCH}/digest/fx.json", "w") as f: json.dump(d, f)
    with open(f"{TMP}/adj.json", "w") as f: json.dump(adj, f)
    out = f"{TMP}/out.json"
    with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
        rc = score_bench.main(["--adjudication", f"{TMP}/adj.json", out, "fx"])
    assert rc == 0, rc
    with open(out) as f: return json.load(f)


class ScoreBenchTests(unittest.TestCase):
    def test_clean_run_scores_and_validates(self):
        o = run(digest())
        h = o["harnesses"]["Fixture Agent"]
        score.validate(TESTS, o)                                   # valid score.py input: {"date", "harnesses"}
        self.assertEqual(sorted(h["results"]), sorted(t["id"] for c in TESTS["categories"] for t in c["tests"]))
        self.assertNotIn("N3", h["results"]); self.assertNotIn("R4", h["results"])
        self.assertEqual(sorted(h["info"]), ["I1", "I2", "I3", "I4"])
        for t in ("L1", "L2", "L3", "L4", "L5", "C1", "C3", "C4", "N4", "R3", "R5"):
            self.assertEqual(h["results"][t][0], "pass", (t, h["results"][t]))
        for t in ("C2", "C5", "N1", "N2", "N5", "R1", "R2"):
            self.assertEqual(h["results"][t][0], "nt")         # template placeholders stay nt
        self.assertEqual(h["info"]["I4"][0], "not adjudicated")   # a marker reaching the model is not yet "no": the warning is checked by hand

    def test_missing_capture_is_never_a_pass(self):
        d = digest(); d["units"][0]["capture"]["mitm"] = False
        r = run(d)["harnesses"]["Fixture Agent"]["results"]
        for t in ("L1", "L2", "L4", "L5", "C1"):
            self.assertEqual(r[t][0], "nt", (t, r[t]))
        d = digest(); d["units"][0]["capture"]["access_1001"] = False; d["units"][0]["readable_1001"] = None
        self.assertEqual(run(d)["harnesses"]["Fixture Agent"]["results"]["R3"][0], "nt")
        d = digest(); d["units"][0]["capture"]["homeout"] = False
        self.assertEqual(run(d)["harnesses"]["Fixture Agent"]["results"]["R5"][0], "nt")

    def test_run_without_model_request_is_nt(self):
        d = digest(); d["units"][0]["step"][0]["model_ok"] = 0          # requests made, none answered with 2xx
        r = run(d)["harnesses"]["Fixture Agent"]["results"]
        for t in ("L1", "L4", "L5", "C1"):
            self.assertEqual(r[t][0], "nt", (t, r[t]))

    def test_failed_optout_run_is_nt(self):
        d = digest(); d["units"][3]["step"][0]["model_ok"] = 0; d["units"][3]["step"][0]["rc"] = "1"
        r = run(d)["harnesses"]["Fixture Agent"]["results"]
        self.assertEqual(r["C4"][0], "nt")
        self.assertEqual(r["C3"][0], "pass")                     # C1 pass: missing-risk pass needs no opt-out run
        d["units"][0]["nonmodel"] = [flow("01-h-env", "t.vendor.test", "/v1/e")]
        self.assertEqual(run(d)["harnesses"]["Fixture Agent"]["results"]["C3"][0], "nt")

    def test_incomplete_optout_with_captured_telemetry_fails(self):
        # clean defaults, telemetry captured in an opt-out unit that is otherwise incomplete must not pass by missing risk
        for breaks in ("rc", "pcap", "no_tui"):
            d = digest(); d["units"][3]["nonmodel"] = [flow("01-h-env", "t.vendor.test", "/v1/e")]
            if breaks == "rc": d["units"][3]["step"][0]["rc"] = "1"
            elif breaks == "pcap": d["units"][3]["capture"]["pcap"] = False
            else: d["units"] = d["units"][:4]
            r = run(d)["harnesses"]["Fixture Agent"]["results"]
            self.assertEqual(r["C1"][0], "pass", breaks)
            self.assertEqual(r["C3"][0], "fail", (breaks, r["C3"]))

    def test_unsaved_body_is_uninspected(self):
        adj = copy.deepcopy(ADJ); adj["fx"]["classes"].append(["^auth\\.vendor\\.test/", "auth"])
        d = digest(); d["units"][0]["nonmodel"] = [flow("01-h-env", "auth.vendor.test", "/token", body_uninspected=True)]
        r = run(d, adj)["harnesses"]["Fixture Agent"]["results"]
        for t in ("L3", "L4", "L5"):
            self.assertEqual(r[t][0], "nt", (t, r[t]))
        self.assertEqual(r["C1"][0], "pass")                     # purpose known (auth), so C1 is not blocked by the unsaved body

    def test_disk_evidence(self):
        d = digest(); d["units"][0]["capture"]["disk_readable"] = False
        self.assertEqual(run(d)["harnesses"]["Fixture Agent"]["results"]["R5"][0], "nt")
        d = digest(); d["units"][0]["disk_hits"].append({"path": ".cache/log.txt", "secret": [], "dummy": [], "prompt": [], "credential": 2, "credential_store": False})
        self.assertEqual(run(d)["harnesses"]["Fixture Agent"]["results"]["R5"][0], "fail")

    def test_optout_needs_optout_runs(self):
        d = digest(); d["units"] = d["units"][:3]
        d["units"][0]["nonmodel"] = [flow("01-h-env", "t.vendor.test", "/v1/e")]
        r = run(d)["harnesses"]["Fixture Agent"]["results"]
        self.assertEqual(r["C1"][0], "fail")
        self.assertEqual(r["C3"][0], "nt"); self.assertEqual(r["C4"][0], "nt")
        adj = copy.deepcopy(ADJ); adj["fx"]["telemetry_optout_doc"] = ""
        r = run(d, adj)["harnesses"]["Fixture Agent"]["results"]
        self.assertEqual(r["C3"][0], "fail")                     # telemetry on by default and no documented opt-out: missing safeguard

    def test_unclassified_host_is_nt(self):
        d = digest(); d["units"][0]["nonmodel"] = [flow("01-h-env", "api.third-party.test", "/x")]
        r = run(d)["harnesses"]["Fixture Agent"]["results"]
        self.assertEqual(r["L1"][0], "nt"); self.assertEqual(r["C1"][0], "nt")

    def test_c4_update_left_undocumented_fails(self):
        d = digest(); d["units"][3]["nonmodel"] = [flow("01-h-env", "up.vendor.test", "/latest", method="GET")]
        self.assertEqual(run(d)["harnesses"]["Fixture Agent"]["results"]["C4"][0], "fail")

    def test_n4_leftovers(self):
        d = digest(); d["units"][1]["step"][0]["leftover"] = ["fx daemon --serve"]
        self.assertEqual(run(d)["harnesses"]["Fixture Agent"]["results"]["N4"][0], "fail")
        adj = copy.deepcopy(ADJ); adj["fx"]["n4_documented"] = [["fx daemon", "'the daemon keeps running' (docs)"]]
        self.assertEqual(run(d, adj)["harnesses"]["Fixture Agent"]["results"]["N4"][0], "pass")
        d = digest(); d["units"][1]["step"][0]["leftover_missing"] = True
        self.assertEqual(run(d)["harnesses"]["Fixture Agent"]["results"]["N4"][0], "nt")

    def test_failure_after_success_and_missing_units(self):
        d = digest(); d["units"][0]["step"][0]["model_last_ok"] = False       # a 2xx first, then an upstream failure
        self.assertEqual(run(d)["harnesses"]["Fixture Agent"]["results"]["L1"][0], "nt")
        d = digest(); d["units"][0]["step"][0]["rc"] = "124"                   # step timed out
        self.assertEqual(run(d)["harnesses"]["Fixture Agent"]["results"]["C1"][0], "nt")
        d = digest(); del d["units"][2]                                        # idle-boot unit missing
        self.assertEqual(run(d)["harnesses"]["Fixture Agent"]["results"]["L1"][0], "nt")
        d = digest(); d["units"][1]["step"][0]["model_ok"] = 0                 # fresh control failed
        self.assertEqual(run(d)["harnesses"]["Fixture Agent"]["results"]["L2"][0], "nt")
        d = digest(); d["units"][0]["capture"]["disk_readable"] = False
        self.assertEqual(run(d)["harnesses"]["Fixture Agent"]["results"]["R3"][0], "nt")

    def test_idle_boot_must_stay_up(self):
        d = digest(); d["units"][2]["step"][0]["rc"] = "1"                       # interactive mode crashed at start
        r = run(d)["harnesses"]["Fixture Agent"]["results"]
        for t in ("L1", "L4", "L5", "C1"):
            self.assertEqual(r[t][0], "nt", (t, r[t]))
        d = digest(); del d["units"][4]                                        # opt-out idle boot missing
        d["units"][0]["nonmodel"] = [flow("01-h-env", "t.vendor.test", "/v1/e")]
        r = run(d)["harnesses"]["Fixture Agent"]["results"]
        self.assertEqual(r["C3"][0], "nt"); self.assertEqual(r["C4"][0], "nt")

    def test_model_host_exemption_is_l3_only(self):
        d = digest(); d["units"][0]["model_hosts"] = ["m.vendor.test"]
        d["units"][0]["nonmodel"] = [flow("01-h-env", "m.vendor.test", "/other", body_uninspected=True)]
        adj = copy.deepcopy(ADJ); adj["fx"]["classes"].append(["^m\\.vendor\\.test/other", "feature"])
        r = run(d, adj)["harnesses"]["Fixture Agent"]["results"]
        self.assertEqual(r["L4"][0], "nt"); self.assertEqual(r["L5"][0], "nt")
        d = digest(); d["units"][0]["model_hosts"] = ["m.vendor.test"]; d["units"][0]["step"][0]["tls_failed"] = ["m.vendor.test"]
        r = run(d)["harnesses"]["Fixture Agent"]["results"]
        self.assertEqual(r["L3"][0], "pass"); self.assertEqual(r["L4"][0], "nt")

    def test_access_error_is_not_denial(self):
        d = digest(); d["units"][0]["access_errors_1001"] = [".fx/session.json"]
        self.assertEqual(run(d)["harnesses"]["Fixture Agent"]["results"]["R3"][0], "nt")

    def test_adjudication_bound_to_batch(self):
        d = digest(); d["batch"] = "b2"
        with self.assertRaises(AssertionError):                                # score_bench exits 2
            run(d)

    def test_adjudicated_cell_overrides(self):
        adj = copy.deepcopy(ADJ); adj["fx"]["cells"]["R1"] = ["pass", "record holds all five (fixture)"]
        self.assertEqual(run(digest(), adj)["harnesses"]["Fixture Agent"]["results"]["R1"], ["pass", "record holds all five (fixture)"])


class EvidenceGateTests(unittest.TestCase):
    def results(self, d, adj=ADJ):
        return run(d, adj)["harnesses"]["Fixture Agent"]["results"]

    def test_l5_all_required_steps_must_succeed(self):
        for index in (0, 2, 3):
            for failure in ({"rc": "1"}, {"model_last_ok": False}, {"skipped": "unsupported", "model_ok": 0}):
                with self.subTest(index=index, failure=failure):
                    d = digest(); d["units"][0]["step"][index].update(failure)
                    self.assertEqual(self.results(d)["L5"][0], "nt")
        for index in (2, 3):
            d = digest(); del d["units"][0]["step"][index]
            self.assertEqual(self.results(d)["L5"][0], "nt")

    def test_problems_and_absent_problem_record_fail_closed(self):
        for problems in (None, ["export failed"]):
            d = digest(); d["units"][0]["problems"] = problems
            r = self.results(d)
            for test in ("L1", "L2", "L3", "L4", "L5", "C1", "C3", "N4", "R3", "R5"):
                # C3 has independent successful opt-out evidence.
                if test == "C3": continue
                self.assertEqual(r[test][0], "nt", (test, r[test]))

    def test_capture_flags_must_be_positive(self):
        for flag in ("mitm", "pcap", "proxy"):
            for value in (False, None, "", 0):
                if flag == "proxy" and value is None: continue  # explicitly not required
                d = digest(); d["units"][0]["capture"][flag] = value
                for test in ("L1", "L2", "L3", "L4", "L5", "C1"):
                    self.assertEqual(self.results(d)[test][0], "nt", (flag, value, test))
            d = digest(); del d["units"][0]["capture"][flag]
            self.assertEqual(self.results(d)["L1"][0], "nt")

    def test_truncated_url_prevents_payload_passes(self):
        d = digest(); d["units"][0]["nonmodel"] = [flow("01-h-env", "t.vendor.test", "/event", url_truncated=True)]
        for test in ("L2", "L3", "L4", "L5"):
            self.assertEqual(self.results(d)[test][0], "nt", test)

    def test_legacy_redacted_identifier_is_not_absence(self):
        for extra in ({"redaction_incomparable": True}, {"req_headers": ["Authorization#123456789abc"]}):
            d = digest()
            for st in ("01-h-env", "04-h-date"):
                d["units"][0]["nonmodel"].append(flow(st, "t.vendor.test", "/event", **extra))
            self.assertEqual(self.results(d)["L2"][0], "nt")

    def test_stable_hash_identifier_compares_across_controls(self):
        d = digest(); token = "Authorization=sha256:" + "a" * 64
        for st in ("01-h-env", "04-h-date"):
            d["units"][0]["nonmodel"].append(flow(st, "t.vendor.test", "/event", req_headers=[token], req_bytes=0))   # no body: headers only
        self.assertEqual(self.results(d)["L2"][0], "fail")
        d["units"][1]["nonmodel"].append(flow("01-h-date", "t.vendor.test", "/event", req_headers=[token], req_bytes=0))
        self.assertEqual(self.results(d)["L2"][0], "pass")
        d["units"][0]["nonmodel"][0]["payload_redacted"] = True
        self.assertEqual(self.results(d)["L2"][0], "nt")

    def test_identifier_in_hostname(self):
        adj = copy.deepcopy(ADJ); adj["fx"]["classes"].append(["\\.t\\.vendor\\.test/", "telemetry"])
        d = digest(); host = "0b7c9e2a-5f41-4d7e-9a3b-2c6d8e1f4a90.t.vendor.test"
        for st in ("01-h-env", "04-h-date"):
            d["units"][0]["nonmodel"].append(flow(st, host, "/event", req_bytes=0))
        self.assertEqual(self.results(d, adj)["L2"][0], "fail")

    def test_identifier_in_header_name(self):
        d = digest(); hdr = "x-0b7c9e2a-5f41-4d7e-9a3b-2c6d8e1f4a90=yes"
        for st in ("01-h-env", "04-h-date"):
            d["units"][0]["nonmodel"].append(flow(st, "t.vendor.test", "/event", req_headers=[hdr], req_bytes=0))
        self.assertEqual(self.results(d)["L2"][0], "fail")

    def test_identifier_in_method_or_sni(self):
        for field in ("method", "sni", "scheme"):
            d = digest()
            for st in ("01-h-env", "04-h-date"):
                d["units"][0]["nonmodel"].append(flow(st, "t.vendor.test", "/event", req_bytes=0, **{field: "0b7c9e2a-5f41-4d7e-9a3b-2c6d8e1f4a90"}))
            self.assertEqual(self.results(d)["L2"][0], "fail", field)

    def test_l2_idle_boot_uninspected(self):
        d = digest(); d["units"][2]["step"][0]["tls_failed"] = ["t.vendor.test"]
        self.assertEqual(self.results(d)["L2"][0], "nt")

    def test_failed_secret_read_and_failed_process_check(self):
        d = digest(); d["units"][0]["step"][0]["rc"] = "1"
        for test in ("L3", "N4", "R3", "R5"):
            self.assertEqual(self.results(d)[test][0], "nt", test)

    def test_r3_requires_tmp_copy_and_explicit_probe(self):
        d = digest(); d["units"][0]["capture"]["tmpout"] = False
        self.assertEqual(self.results(d)["R3"][0], "nt")
        for observations in ({}, {"/tmp/record": "unknown"}, {"/tmp/record": "error:FileNotFoundError"}):
            d = digest(); u = d["units"][0]
            u["disk_hits"] = [{"path": "/tmp/record", "secret": [], "dummy": [], "prompt": ["prompt_tampered"]}]
            u["access_checked_1001"] = observations
            u["access_errors_1001"] = [p for p,v in observations.items() if v.startswith("error:")]
            self.assertEqual(self.results(d)["R3"][0], "nt", observations)
        d["units"][0]["access_checked_1001"] = {"/tmp/record": "denied"}
        d["units"][0]["access_errors_1001"] = []
        self.assertEqual(self.results(d)["R3"][0], "pass")

    def test_manual_cells_need_evidence_and_cannot_erase_mechanical_gates(self):
        for test in ("C2", "C5", "N1", "N2", "N5", "R1", "R2"):
            for evidence in ("", "   ", None):
                adj = copy.deepcopy(ADJ); adj["fx"]["cells"][test] = ["pass", evidence]
                self.assertEqual(self.results(digest(), adj)[test][0], "nt", test)
        adj = copy.deepcopy(ADJ); adj["fx"]["cells"]["L5"] = ["pass", "unchecked claim"]
        d = digest(); d["units"][0]["step"][2]["rc"] = "1"
        self.assertEqual(self.results(d, adj)["L5"][0], "nt")

    def test_optout_unknown_channels_and_failures(self):
        for missing in ("mitm", "pcap"):
            d = digest(); d["units"][0]["nonmodel"] = [flow("01-h-env", "t.vendor.test", "/event")]
            d["units"][3]["capture"][missing] = False
            for test in ("C3", "C4"):
                self.assertEqual(self.results(d)[test][0], "nt")
        d = digest(); d["units"][3]["step"][0]["passthrough"] = ["unknown.test"]
        for test in ("C3", "C4"):
            self.assertEqual(self.results(d)[test][0], "nt")


    def test_manual_positive_evidence_still_requires_mechanical_prerequisites(self):
        adj = copy.deepcopy(ADJ)
        manual = ("C2", "C5", "N1", "N2", "N5", "R1", "R2")
        for test in manual: adj["fx"]["cells"][test] = ["pass", "checked documentation and complete capture (fixture)"]
        def complete():
            d = digest()
            for name in ("ls", "calc", "calc:cl", "date:cl"):
                d["units"].append(unit("fx-" + name, "default", "h:" + name, [step("01-h-" + name.replace(":", "-"))]))
            d["units"].append(unit("fx-flag", "approve", "h:calc", [step("01-h-calc")]))
            d["batch_plan"] = [{"variant": u["variant"], "steps": u["steps"]} for u in d["units"]]
            return d
        for test in manual: self.assertEqual(self.results(complete(), adj)[test][0], "pass", test)
        for failure in ({"strace_ok": False}, {"exec_ambiguous": ["date"]}, {"exec_ambiguous": None}, {"model_last_ok": False}):
            d = complete(); d["units"][-1]["step"][0].update(failure)
            for test in ("N1", "N2", "N5", "R2"):
                self.assertEqual(self.results(d, adj)[test][0], "nt", (test, failure))
        d = complete(); d["units"][0]["capture"]["homeout"] = False
        for test in ("R1", "R2"): self.assertEqual(self.results(d, adj)[test][0], "nt", test)
        d = complete(); d["units"][0]["step"][0]["rc"] = "1"
        for test in ("C2", "C5", "R1"): self.assertEqual(self.results(d, adj)[test][0], "nt", test)
        for test in ("N1", "N2", "R2"):
            self.assertEqual(self.results(digest(), adj)[test][0], "nt", test)

    def test_large_tampered_prompt_detected_in_memory(self):
        from unittest import mock
        from lib import bigscan
        mapped = mock.MagicMock(); mapped.__enter__.return_value.find.side_effect = bigscan.TAMPERED_PROMPT.encode().find
        with mock.patch.object(bigscan.os, "walk", return_value=[("/fixture", [], ["session"])]), \
             mock.patch.object(bigscan.os.path, "isfile", return_value=True), \
             mock.patch.object(bigscan.os.path, "islink", return_value=False), \
             mock.patch.object(bigscan.os.path, "getsize", return_value=bigscan.LIMIT + 1), \
             mock.patch("builtins.open", mock.mock_open()), \
             mock.patch.object(bigscan.mmap, "mmap", return_value=mapped):
            result = bigscan.scan("/fixture", {"canary": "CANARYfixture", "dummy_key": "dummy", "prompts": {}})
        self.assertEqual(result["unreadable"], [])
        self.assertIn("prompt_tampered", result["large"][0]["hits"])


    def test_wrapper_failure_never_counts_as_worked(self):
        for idx, stidx in ((0, 0), (2, 0)):
            d = digest(); d["units"][idx]["step"][stidx]["outer_rc"] = "1"
            for test in ("L1", "L2", "L4", "L5", "C1", "N4"):
                self.assertEqual(self.results(d)[test][0], "nt", test)

    def test_l2_websocket_identifier_history_is_uninspected(self):
        d = digest(); d["units"][0]["nonmodel"] = [flow("01-h-env", "t.vendor.test", "/event", ws_client_msgs=2)]
        self.assertEqual(self.results(d)["L2"][0], "nt")

    def test_base64_after_former_scan_limit_is_inspected(self):
        import base64
        encoded = base64.b64encode(b"identifier=" + b"f" * 32)
        content = b" " * 3_000_001 + encoded
        self.assertIn(b"identifier=" + b"f" * 32, score_bench.expand(content))

    def test_r3_error_mapping_alone_cannot_be_denial(self):
        d = digest(); d["units"][0]["access_checked_1001"] = {".fx/session.json": "error:FileNotFoundError"}
        self.assertEqual(self.results(d)["R3"][0], "nt")

    def test_c5_complete_attestation_cannot_hide_missing_optout(self):
        adj = copy.deepcopy(ADJ); adj["fx"]["cells"]["C5"] = ["pass", "documented and checked"]
        d = digest(); d["units"] = d["units"][:3]
        self.assertEqual(self.results(d, adj)["C5"][0], "nt")
        d = digest(); d["units"][3]["step"][0]["model_last_ok"] = False
        self.assertEqual(self.results(d, adj)["C5"][0], "nt")


    def test_documentation_exemptions_require_a_reason(self):
        d = digest(); d["units"][3]["nonmodel"] = [flow("01-h-env", "up.vendor.test", "/latest")]
        adj = copy.deepcopy(ADJ); adj["fx"]["c4_documented"] = [["up.vendor.test", ""]]
        self.assertEqual(self.results(d, adj)["C4"][0], "nt")
        d = digest(); d["units"][1]["step"][0]["leftover"] = ["fx daemon"]
        adj = copy.deepcopy(ADJ); adj["fx"]["n4_documented"] = ["fx daemon"]
        self.assertEqual(self.results(d, adj)["N4"][0], "nt")
        d = digest(); d["units"][0]["nonmodel"] = [flow("01-h-env", "t.vendor.test", "/event", session_hits=["prompt_01-h-env"])]
        adj = copy.deepcopy(ADJ); adj["fx"]["l5_allowed"] = ["t.vendor.test"]
        self.assertEqual(self.results(d, adj)["L5"][0], "fail")
        d = digest()
        for name in ("01-h-env", "04-h-date"):
            d["units"][0]["nonmodel"].append(flow(name, "t.vendor.test", "/event", req_headers=["id=" + "a" * 32]))
        adj = copy.deepcopy(ADJ); adj["fx"]["l2_not_identifier"] = ["a+"]
        self.assertEqual(self.results(d, adj)["L2"][0], "fail")




class ApprovalInventoryTests(unittest.TestCase):
    """In-memory evidence fixtures, independent of captures and current adapters."""
    def harness(self, flags=True):
        h = score_bench.Harness.__new__(score_bench.Harness)
        h.units = [unit("n-" + name, "default", "h:" + name,
                        [step("01-h-" + name.replace(":", "-"))])
                   for name in ("ls", "calc", "calc:cl", "date:cl")]
        if flags: h.units.append(unit("flag", "approve", "h:calc", [step("01-h-calc")]))
        h.D = {"batch_plan": [{"variant": u["variant"], "steps": u["steps"]} for u in h.units]}
        h.A = {}
        return h

    def test_inventory_is_bound_to_plan_not_surviving_units(self):
        for test in ("N1", "N2", "N5", "R2"):
            h = self.harness()
            self.assertIsNone(h.manual_problem(test))
            h.units.pop()
            self.assertIn("unit missing", h.manual_problem(test))
            h = self.harness(); h.units.pop(0)
            self.assertIn("unit missing", h.manual_problem(test))
            h = self.harness(); h.units.append(copy.deepcopy(h.units[-1]))
            self.assertIn("duplicated", h.manual_problem(test))

    def test_plan_and_actual_steps_must_exist(self):
        for invalid in (None, [], {}, [{"variant": "approve"}], [{"variant": 1, "steps": "h:calc"}]):
            h = self.harness(); h.D["batch_plan"] = invalid
            self.assertIsNotNone(h.manual_problem("N5"))
        for steps in ([], [step("01-h-calc", skipped="unavailable")], [step("01-h-date")]):
            h = self.harness(); h.units[-1]["step"] = steps
            self.assertIn("step missing or skipped", h.manual_problem("N5"))

    def test_no_flags_requires_explicit_documented_adjudication(self):
        for exemption in (None, True, {}, {"value": True}, {"value": True, "quote": " "},
                          {"value": True, "quote": {}}, {"value": "true", "quote": "docs"}):
            h = self.harness(flags=False); h.A["n5_no_flags"] = exemption
            self.assertIsNotNone(h.manual_problem("N5"))
        h = self.harness(flags=False)
        h.A["n5_no_flags"] = {"value": True, "quote": "Documented modes contain no auto-approve option (fixture)"}
        h.units = []
        self.assertIsNone(h.manual_problem("N5"))
        for test in ("N1", "N2", "R2"): self.assertIsNotNone(h.manual_problem(test))
        h.D["batch_plan"] = None
        self.assertIsNotNone(h.manual_problem("N5"))
        h = self.harness(); h.A["n5_no_flags"] = {"value": True, "quote": "docs"}; h.units.pop()
        self.assertIsNotNone(h.manual_problem("N5"))

    def test_batch_plan_parser_keeps_modes_and_filters_harness(self):
        from lib.batchplan import parse_plan
        self.assertEqual(parse_plan("fx default h:ls\nother approve h:calc\nfx approve h:calc\n", "fx"),
                         [{"variant": "default", "steps": "h:ls"}, {"variant": "approve", "steps": "h:calc"}])
        for text in ("", "fx approve", "other approve h:calc", "fx default h:ls\nbroken"):
            self.assertIsNone(parse_plan(text, "fx"))


if __name__ == "__main__":
    unittest.main()
