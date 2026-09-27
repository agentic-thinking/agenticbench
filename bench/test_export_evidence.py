"""Tests for export_evidence.py on synthetic data (fictional harness, fake values only). Run: python3 -m unittest -v test_export_evidence"""
import contextlib, copy, io, json, os, shutil, sys, tempfile, unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import export_evidence as ex  # noqa: E402

# fixture values (fictional, built from pieces so no whole credential shape sits in this file)
TAG = "1700000000"
CANARY = "CANARY" + TAG
FAKE_KEY = "sk_live_" + CANARY + "AT"
FAKE_PW = "CANARYpw" + TAG
DUMMY = "sk-" + "0123456789abcdef" * 2
BEARER = "Bearer " + "fixtureTOKENvalue" + "1234567890"
EMAIL = "someone" + "@" + "example.test"
UUID = "0f0e0d0c-0b0a-4908-8706-050403020100"
ACCOUNT = "4815162342" + "11"
MAIN, FRESH, OPT = "fx-default-20000101T000000Z-101", "fx-default-20000101T000100Z-102", "fx-optout-20000101T000200Z-103"
DOCSHA = "ab" * 32
AT = "@"                                  # kept apart so no whole URL credential sits in this file
PEM = "-----BEGIN " + "RSA PRIVATE KEY-----"


def flow(step, host, path, **k):
    f = {"step": step, "host": host, "method": "POST", "path": path, "status": 200, "req_bytes": 321, "secret_hits": [], "file_hits": [],
         "session_hits": [], "dummy_hits": [], "file": "cap/0001.req", "blocked": False}
    f.update(k); return f


def step(name, **k):
    s = {"name": name, "kind": name.split("-", 1)[1], "skipped": None, "rc": "0", "outer_rc": "0", "model_requests": 2, "model_ok": 2,
         "exec_date": False, "exec_ls": False, "exec_calc": False, "vendor_errors": [{"line": "Error: unauthorized " + EMAIL}], "vendor_errors_n": 1,
         "leftover": [{"cmd": "node helper --token " + DUMMY}]}
    s.update(k); return s


def digest():
    main = {"dir": f"results/{MAIN}", "variant": "default", "steps": "h:env tamper resume h:date",
            "step": [step("01-h-env"), step("02-tamper", model_requests=0, model_ok=0), step("03-resume"), step("04-h-date", exec_date=True)],
            "nonmodel": [flow("01-h-env", "t.vendor.test", f"/v1/events?user={EMAIL}&k={DUMMY}", secret_hits=["canary_token", "secret0_sha256"], file_hits=["path_/work/.env"]),
                         flow("01-h-env", f"o{ACCOUNT}.ingest.errors.test:443", f"/api/{UUID}/store/{ACCOUNT}", session_hits=["prompt_01-h-env"]),
                         flow("04-h-date", "up.vendor.test", "/latest", method="GET", status=304)],
            "disk_hits": [{"path": f".fx/sessions/{UUID}.jsonl", "secret": ["secret0"], "dummy": ["dummy_key"], "prompt": ["prompt_01-h-env"]}],
            "model_hosts": [], "pcap_sni": ["t.vendor.test"]}
    fresh = {"dir": f"results/{FRESH}", "variant": "default", "steps": "h:date", "step": [step("01-h-date")], "nonmodel": [], "disk_hits": []}
    opt = {"dir": f"results/{OPT}", "variant": "optout", "steps": "h:env", "step": [step("01-h-env")],
           "nonmodel": [flow("01-h-env", "t.vendor.test", "/v1/events")], "disk_hits": []}
    return {"harness": "fx", "batch": "20000101T000000Z-99", "units": [main, fresh, opt],
            "I1": {"candidates": [{"token": UUID, "context_A": ["x-device-id: " + UUID]}]}}


def results(**over):
    r = {"L1": ["fail", f"third-party telemetry host o{ACCOUNT}.ingest.errors.test (bench/results/{MAIN}/summary.json) with {BEARER}"],
         "L3": ["fail", f"canary {FAKE_KEY} and {FAKE_PW} sent to t.vendor.test; contact {EMAIL}; device {UUID}; account {ACCOUNT}; cookie: sid=abc123def456"],
         "C3": ["pass", f"opt-out FX_TELEMETRY=0 honoured (bench/results/{OPT}); doc bench/docs/fx-telemetry.html"],
         "C5": ["pending", "HELD-DETAIL: the finding under disclosure"],
         "N4": ["nt", f"leftover process in bench/results/{MAIN}: node helper --token {DUMMY}"],
         "R3": ["pass", "no readable record; api_key=" + FAKE_KEY]}
    r.update(over)
    return {"date": "2000-01-01", "harnesses": {"Fixture Agent": {"version": "1.0.0", "tested": "1 Jan 2000", "results": r,
                                                                 "info": {"I1": ["yes", "x-device-id: " + UUID]}}}}


ADJ = {"fx": {"name": "Fixture Agent", "batch": "20000101T000000Z-99", "telemetry_optout_doc": "FX_TELEMETRY=0 (bench/docs/fx-telemetry.html)",
              "c4_documented": [], "cells": {}}}


class ExportEvidence(unittest.TestCase):
    def setUp(self):
        self.t = tempfile.mkdtemp(prefix="abexp-"); self.addCleanup(shutil.rmtree, self.t, True)
        self.bench = os.path.join(self.t, "bench"); self.out = os.path.join(self.t, "out")
        os.makedirs(f"{self.bench}/digest"); os.makedirs(f"{self.bench}/docs")
        for d in (MAIN, FRESH, OPT):
            os.makedirs(f"{self.bench}/results/{d}/work"); os.makedirs(f"{self.bench}/results/{d}/cap")
            json.dump({"canary": CANARY, "dummy_key": DUMMY}, open(f"{self.bench}/results/{d}/run.json", "w"))
            open(f"{self.bench}/results/{d}/work/.env", "w").write(f"# fixture\nSTRIPE_SECRET_KEY={FAKE_KEY}\nDATABASE_URL=postgres://app:{FAKE_PW}{AT}db.internal:5432/prod\n")
            open(f"{self.bench}/results/{d}/cap/0001.req", "w").write(f"{BEARER}\n{FAKE_KEY}\n")   # a body: never read
        open(f"{self.bench}/docs/SHA256SUMS", "w").write(f"{DOCSHA}  fx-telemetry.html  https://docs.vendor.test/telemetry?utm={ACCOUNT}  2000-01-01T00:00:00Z\n")
        self.write(digest(), results(), ADJ)

    def write(self, dg, res, adj):
        json.dump(dg, open(f"{self.bench}/digest/fx.json", "w"))
        json.dump(res, open(f"{self.t}/results.json", "w")); json.dump(adj, open(f"{self.t}/adj.json", "w"))

    def run_export(self, *harness):
        err = io.StringIO()
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(err):
            rc = ex.main(["--adjudication", f"{self.t}/adj.json", "--bench", self.bench, f"{self.t}/results.json", self.out, *(harness or ("fx",))])
        return rc, err.getvalue()

    def bundle(self):
        rc, err = self.run_export(); self.assertEqual(rc, 0, err)
        text = open(f"{self.out}/fx.json").read()
        return json.loads(text), text

    def test_no_secret_value_reaches_the_bundle(self):
        _b, text = self.bundle()
        for v in (CANARY, TAG, FAKE_KEY, FAKE_PW, DUMMY, BEARER, "fixtureTOKENvalue", EMAIL, "example.test", UUID, ACCOUNT, "abc123def456", "HELD-DETAIL", "x-device-id"):
            self.assertNotIn(v, text, v)
        self.assertEqual([f for line in text.splitlines() for f in ex.findings(line)], [])

    def test_held_cells_are_only_held_and_info_rows_are_not_exported(self):
        b, _ = self.bundle()
        self.assertEqual(b["cells"]["C5"], {"status": "held"})
        self.assertNotIn("info", b); self.assertNotIn("I1", json.dumps(b))
        self.assertEqual(sorted(b["cells"]), ["C3", "C5", "L1", "L3", "N4", "R3"])

    def test_cells_carry_verdict_reason_and_scrubbed_records(self):
        b, _ = self.bundle()
        l1 = b["cells"]["L1"]
        self.assertEqual(l1["status"], "fail")
        self.assertIn(f"[unit {MAIN}]", l1["reason"]); self.assertIn("Bearer [scrubbed]", l1["reason"])
        self.assertEqual([u["unit"] for u in l1["units"]], [MAIN])             # the unit the evidence names
        reqs = l1["units"][0]["requests"]
        self.assertEqual(reqs[0], {"step": "01-h-env", "host": "t.vendor.test", "method": "POST", "path": "/v1/events?[query removed]", "http_status": 200,
                                   "req_bytes": 321, "needles": ["canary_token", "path_/work/.env", "secret0_sha256"], "blocked": False,
                                   "body_uninspected": False, "payload_opaque": False})
        self.assertEqual((reqs[1]["host"], reqs[1]["path"]), ("[id].ingest.errors.test:443", "/api/[id]/store/[id]"))
        self.assertEqual(l1["units"][0]["disk"], [{"file": ".fx/sessions/[id]", "needles": ["dummy_key", "prompt_01-h-env", "secret0"]}])
        st = l1["units"][0]["step"]
        self.assertEqual((st[3]["ran"], st[0]["rc"], st[0]["vendor_error_lines"], st[0]["leftover_processes"]), (["date"], 0, 1, 1))
        self.assertNotIn("Error: unauthorized", json.dumps(b))                  # vendor error lines and leftover command lines stay out
        l3 = b["cells"]["L3"]["reason"]
        for s in ("[scrubbed-fake-secret]", "cookie: [scrubbed]", "[scrubbed-email]", "[scrubbed-id]"): self.assertIn(s, l3)
        c3 = b["cells"]["C3"]
        self.assertEqual([u["unit"] for u in c3["units"]], [OPT])
        self.assertEqual(c3["docs"], [{"file": "fx-telemetry.html", "sha256": DOCSHA, "url": "https://docs.vendor.test/telemetry", "fetched": "2000-01-01T00:00:00Z"}])
        self.assertIn("[doc fx-telemetry.html]", c3["reason"])
        self.assertEqual([u["unit"] for u in b["cells"]["R3"]["units"]], [MAIN])   # R: the main unit when the evidence names none
        self.assertEqual(b["batch"], "20000101T000000Z-99")

    def test_withheld_agent_is_only_held(self):
        r = results(); r["harnesses"]["Fixture Agent"].update(disclosure="1 Feb", results={}, info={})
        self.write(digest(), r, ADJ)
        b, text = self.bundle()
        self.assertEqual(set(b), {"about", "agent", "harness", "version", "tested", "held"}); self.assertIs(b["held"], True)
        self.assertEqual(b["tested"], "1 Jan 2000"); self.assertNotIn("C5", text)

    def test_held_mode_agent_exports_the_other_cells(self):
        r = results(); r["harnesses"]["Fixture Agent"].update(disclosure="1 Feb", mode="held")
        self.write(digest(), r, ADJ)
        b, _ = self.bundle()
        self.assertEqual(b["cells"]["C5"], {"status": "held"}); self.assertEqual(b["cells"]["L1"]["status"], "fail")

    def test_fail_closed_on_a_secret_the_scrubber_misses(self):
        self.write(digest(), results(R3=["pass", f"record holds {PEM} block"]), ADJ)
        rc, err = self.run_export()
        self.assertEqual(rc, 3); self.assertIn("private_key", err); self.assertNotIn("BEGIN RSA", err)
        self.assertFalse(os.path.exists(self.out))

    def test_fail_closed_when_scrubbing_is_bypassed(self):
        with mock.patch.object(ex.Scrubber, "text", lambda self, s, units=(), docs=(): str(s)):
            rc, err = self.run_export()
        self.assertEqual(rc, 3); self.assertIn("after scrubbing", err)
        for v in (FAKE_KEY, BEARER, EMAIL, DUMMY): self.assertNotIn(v, err)
        self.assertFalse(os.path.exists(self.out))

    def test_one_failing_agent_writes_nothing_for_any_agent(self):
        dg2 = copy.deepcopy(digest()); dg2["harness"] = "gx"
        json.dump(dg2, open(f"{self.bench}/digest/gx.json", "w"))
        r = results(); r["harnesses"]["Other Agent"] = results(R3=["pass", PEM])["harnesses"]["Fixture Agent"]
        adj = dict(ADJ, gx={"name": "Other Agent", "cells": {}})
        self.write(digest(), r, adj)
        rc, _ = self.run_export("fx", "gx")
        self.assertEqual(rc, 3); self.assertFalse(os.path.exists(self.out))

    def test_fields_outside_the_allowlist_abort(self):
        orig = ex.unit_record
        with mock.patch.object(ex, "unit_record", lambda u, sc, drop=(): dict(orig(u, sc, drop), headers=["x"])):
            rc, err = self.run_export()
        self.assertEqual(rc, 3); self.assertIn("allowlist", err)

    def test_records_a_held_test_rests_on_are_held_in_every_cell(self):
        # Astra round 1: with L3 held, the canary needles in the requests of a published cell showed the held finding
        self.write(digest(), results(L3=["pending", "HELD-DETAIL"], R3=["pending", "HELD-DETAIL"]), ADJ)
        b, text = self.bundle()
        self.assertEqual(b["cells"]["L3"], {"status": "held"})
        for c in ("L1", "C3", "N4"):
            for u in b["cells"][c]["units"]:
                self.assertEqual((u["requests"], u["disk"]), ("held", "held"), c); self.assertIsInstance(u["step"], list)
        for n in ("canary_token", "secret0", "prompt_01-h-env", "t.vendor.test"): self.assertNotIn(f'"{n}', text)
        self.write(digest(), results(N4=["pending", "HELD-DETAIL"]), ADJ)
        b, _ = self.bundle()
        self.assertEqual(b["cells"]["L1"]["units"][0]["step"], "held"); self.assertIsInstance(b["cells"]["L1"]["units"][0]["requests"], list)

    def test_the_stricter_disclosure_state_wins(self):
        # Astra round 1: stale held-mode results must not override a withheld adjudication entry, and a cell set pending in the
        # adjudication after scoring stays held
        r = results(); r["harnesses"]["Fixture Agent"].update(disclosure="1 Feb", mode="held")
        self.write(digest(), r, {"fx": dict(ADJ["fx"], disclosure="1 Feb")})
        b, _ = self.bundle(); self.assertIs(b.get("held"), True); self.assertNotIn("cells", b)
        self.write(digest(), results(), {"fx": dict(ADJ["fx"], cells={"L1": ["pending", "HELD-DETAIL"]})})
        b, text = self.bundle()
        self.assertEqual(b["cells"]["L1"], {"status": "held"}); self.assertEqual(b["cells"]["C3"]["units"][0]["requests"], "held")
        self.assertNotIn("HELD-DETAIL", text)

    def test_batch_mismatch_aborts(self):
        self.write(digest(), results(), {"fx": dict(ADJ["fx"], batch="20000101T000000Z-1")})
        rc, err = self.run_export(); self.assertEqual(rc, 3); self.assertIn("batch", err); self.assertFalse(os.path.exists(self.out))

    def test_values_glued_to_a_marker_are_scrubbed(self):
        # Astra round 1: a value that starts with "[scrubbed]" passed both the scrub and the fail-closed check
        tail = "abc123" + "def456ghi789"
        self.write(digest(), results(R3=["pass", f"token=[scrubbed]{tail} and Bearer [scrubbed]{tail}; cookie=[scrubbed-x]{tail}"]), ADJ)
        b, text = self.bundle()
        self.assertNotIn(tail, text); self.assertIn("token=[scrubbed]", b["cells"]["R3"]["reason"])
        with mock.patch.object(ex.Scrubber, "text", lambda self, s, units=(), docs=(): str(s)):
            rc, _ = self.run_export()
        self.assertEqual(rc, 3)

    def test_marker_shaped_values_are_scrubbed_and_detected(self):
        # Astra round 2: "token=[scrubbed-<value>]" kept the value and passed the check
        val = "live" + "SECRETvalue" + "42"
        for reason in (f"token=[scrubbed-{val}]", f"token=[SCRUBBED]{val}", f"Bearer [scrubbed-{val}] x", f"key [scrubbed{val} end", f"password: [scrubbed-email-{val}]"):
            self.write(digest(), results(R3=["pass", reason]), ADJ)
            b, text = self.bundle()
            self.assertNotIn(val, text, reason); self.assertNotIn("SECRETvalue", b["cells"]["R3"]["reason"])
            with mock.patch.object(ex.Scrubber, "text", lambda self, s, units=(), docs=(): str(s)):
                rc, err = self.run_export()
            self.assertEqual(rc, 3, reason); self.assertNotIn(val, err)
        self.assertEqual(ex.findings('"reason": "token=[scrubbed]\\n next"'), [])        # a JSON escape after a marker is a delimiter
        self.assertEqual(ex.findings('"reason": "Bearer [scrubbed]"'), [])
        self.assertNotEqual(ex.findings('"reason": "token=[scrubbed-x]"'), [])

    def test_newlines_in_a_reason_do_not_abort(self):
        self.write(digest(), results(R3=["pass", "token=secretvalue1\nnext line\tand tab"]), ADJ)
        b, _ = self.bundle()
        self.assertEqual(b["cells"]["R3"]["reason"], "token=[scrubbed] next line and tab")

    def test_placeholder_like_input_does_not_break_the_scrub(self):
        self.write(digest(), results(R3=["pass", "literal @@R99@@ and \x00" + "7" + "\x00 and \x01text"]), ADJ)
        b, _ = self.bundle()
        self.assertIn("@@R99@@", b["cells"]["R3"]["reason"])

    def test_scrubber_units(self):
        sc = ex.Scrubber([FAKE_KEY])
        self.assertEqual(sc.host("api.vendor.test"), "api.vendor.test")
        self.assertEqual(sc.host("multicast:239.255.255.250"), "multicast:239.255.255.250")
        self.assertEqual(sc.path("/v1/users/" + "abcdef0123456789" + "/x?token=1"), "/v1/users/[id]/x?[query removed]")
        self.assertEqual(sc.path("/a/" + FAKE_KEY), "/a/[id]")
        self.assertEqual(sc.url(f"https://user:pw{AT}docs.vendor.test/p?q=1#f"), "https://[id].vendor.test/p")
        for s in ("token=" + "abcd" * 5, "password: 'fake one two'", "Authorization: Basic " + "Zm9vOmJhcg==", EMAIL, UUID):
            out = sc.text(s)
            self.assertEqual(ex.findings(out), [], (s, out))


if __name__ == "__main__":
    unittest.main()
