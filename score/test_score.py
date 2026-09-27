import contextlib
import io
import json
import os
import tempfile
import unittest

import score

TESTS = {"version": "t", "informational": [{"id": "I1", "text": "i1"}], "categories": [
    {"id": "A", "name": "Cat A", "tests": [{"id": "A1", "text": "a1"}, {"id": "A2", "text": "a2"}, {"id": "A3", "text": "a3"}]},
    {"id": "B", "name": "Cat B", "tests": [{"id": "B1", "text": "b1"}]}]}


def res(**h):
    return {"date": "x", "harnesses": h}


class ScoreTests(unittest.TestCase):
    def test_counts_exclude_untested(self):
        r = res(X={"version": "1", "results": {"A1": ["pass", "e"], "A2": ["fail", "e"], "A3": ["nt", ""], "B1": ["na", ""]}})
        score.validate(TESTS, r)
        s = score.score(TESTS, r)["X"]["categories"]
        self.assertEqual((s["A"]["pass"], s["A"]["tested"], s["A"]["untested"]), (1, 2, 1))
        self.assertEqual(s["B"]["tested"], 0)
        self.assertIsNone(s["B"]["ratio"])

    def test_pending_excluded(self):
        r = res(X={"version": "1", "results": {"A1": ["pending", "d"], "A2": ["pass", "e"], "A3": ["pass", "e"], "B1": ["fail", "e"]}})
        s = score.score(TESTS, r)["X"]["categories"]
        self.assertEqual((s["A"]["pass"], s["A"]["tested"]), (2, 2))

    def test_held_counted_separately(self):
        r = res(X={"version": "1", "results": {"A1": ["pending", "d"], "A2": ["pending", "d"], "A3": ["fail", "e"], "B1": ["nt", ""]}})
        s = score.score(TESTS, r)["X"]["categories"]["A"]
        self.assertEqual((s["pass"], s["tested"], s["held"], s["untested"]), (0, 1, 2, 2))

    def test_info_rows_validated_not_scored(self):
        full = {"A1": ["pass", "e"], "A2": ["pass", "e"], "A3": ["pass", "e"], "B1": ["pass", "e"]}
        r = res(X={"version": "1", "results": full, "info": {"I1": ["yes", "ev"]}})
        score.validate(TESTS, r)
        self.assertEqual(score.score(TESTS, r)["X"]["categories"]["A"]["tested"], 3)
        for bad in ({"I9": ["yes", "ev"]}, {"I1": ["", "ev"]}, {"I1": ["yes", ""]}, {"I1": "yes"}):
            with self.assertRaises(score.ValidationError):
                score.validate(TESTS, res(X={"version": "1", "results": full, "info": bad}))

    def test_info_id_clash_rejected(self):
        t = json.loads(json.dumps(TESTS)); t["informational"] = [{"id": "A1", "text": "x"}]
        with self.assertRaises(score.ValidationError):
            score.validate(t, res())

    def test_held_shown_in_outputs(self):
        r = res(X={"version": "1", "results": {"A1": ["pending", "d"], "A2": ["pass", "e"], "A3": ["nt", ""], "B1": ["pass", "e"]}})
        sc = score.score(TESTS, r)
        self.assertIn("1 held", score.render_svg(TESTS, sc))
        self.assertIn("(1 held)", score.render_html(TESTS, sc))

    def test_note_shown_on_chart_row_and_table(self):
        full = {"A1": ["pending", "d"], "A2": ["pass", "e"], "A3": ["pass", "e"], "B1": ["pass", "e"]}
        note = "Disclosure sent to <Vendor>. Held results 1 Jan."
        r = res(X={"version": "1", "results": full, "note": note}, Y={"version": "2", "results": full})
        score.validate(TESTS, r)
        sc = score.score(TESTS, r)
        svg, tab = score.render_svg(TESTS, sc), score.render_html(TESTS, sc)
        esc = "Disclosure sent to &lt;Vendor&gt;. Held results 1 Jan."
        self.assertIn('<text class="t" x="10" y="80" font-weight="600">X</text>', svg)   # a note does not move the row: equal scores sort by name
        self.assertIn(f'<text class="d" x="170" y="110">{esc}</text>', svg)   # under X's bars (row y 70), before Y (row y 124)
        self.assertIn('<text class="t" x="10" y="134" font-weight="600">Y</text>', svg)
        self.assertIn('viewBox="0 0 608 218"', svg)
        self.assertIn(f'<td>X<br><span class="note">{esc}</span></td>', tab)
        self.assertEqual(svg.count(esc), 1)
        no_note = score.render_svg(TESTS, score.score(TESTS, res(X={"version": "1", "results": full})))
        self.assertIn('viewBox="0 0 608 164"', no_note)
        for bad in ("", " ", 5):
            with self.assertRaises(score.ValidationError):
                score.validate(TESTS, res(X={"version": "1", "results": full, "note": bad}))

    def test_disclosure_names_vendor(self):
        r = res(X={"version": "1", "disclosure": "1 Jan", "vendor": "Example Vendor", "results": {}},
                Y={"version": "1", "disclosure": "2 Feb", "results": {}})
        score.validate(TESTS, r)
        sc = score.score(TESTS, r)
        svg, tab = score.render_svg(TESTS, sc), score.render_html(TESTS, sc)
        self.assertIn("Disclosure sent to Example Vendor. Results 1 Jan.", svg)
        self.assertIn("Disclosure sent to Example Vendor. Results 1 Jan.", tab)
        self.assertIn("Disclosure sent to vendor. Results 2 Feb.", svg)

    def test_display_order_neutral(self):
        full = {"A1": ["pass", "e"], "A2": ["pass", "e"], "A3": ["pass", "e"], "B1": ["pass", "e"]}
        r = res(Zeta={"version": "1", "results": full}, alpha={"version": "1", "results": full},
                Held={"version": "1", "disclosure": "1 Jan", "results": {}},
                Part={"version": "1", "results": full, "note": "Disclosure sent to V."})
        self.assertEqual(score.display_order(score.score(TESTS, r)), ["alpha", "Part", "Zeta", "Held"])

    def test_order_by_pass_rate(self):
        hi = {"A1": ["pass", "e"], "A2": ["pass", "e"], "A3": ["pass", "e"], "B1": ["pass", "e"]}
        lo = {"A1": ["fail", "e"], "A2": ["pass", "e"], "A3": ["fail", "e"], "B1": ["fail", "e"]}
        r = res(Low={"version": "1", "results": lo}, High={"version": "1", "results": hi}, Also={"version": "1", "results": hi})
        self.assertEqual(score.display_order(score.score(TESTS, r)), ["Also", "High", "Low"])
        mid = {"A1": ["pass", "e"], "A2": ["pass", "e"], "A3": ["nt", ""], "B1": ["pass", "e"]}
        r2 = res(Fewer={"version": "1", "results": mid}, Full={"version": "1", "results": hi})
        self.assertEqual(score.display_order(score.score(TESTS, r2)), ["Full", "Fewer"])

    def test_overall_shown(self):
        full = {"A1": ["pass", "e"], "A2": ["fail", "e"], "A3": ["pass", "e"], "B1": ["nt", ""]}
        sc = score.score(TESTS, res(X={"version": "1", "results": full}))
        self.assertEqual(score.overall(sc["X"]), (2, 3))
        self.assertEqual(score.overall_fixed(sc["X"], 4), (2, 4, 1, 1))
        self.assertIn(">2/4</text>", score.render_svg(TESTS, sc))
        self.assertIn("1 failed · 1 n/a", score.render_svg(TESTS, sc))
        self.assertIn("<strong>2/4</strong> (1 failed, 1 n/a)", score.render_html(TESTS, sc))

    def test_conflict_of_interest_on_outputs(self):
        full = {"A1": ["pass", "e"], "A2": ["pass", "e"], "A3": ["pass", "e"], "B1": ["pass", "e"]}
        sc = score.score(TESTS, res(X={"version": "1", "results": full}))
        self.assertIn("AgentProtect", score.render_svg(TESTS, sc))
        self.assertIn("AgentProtect", score.render_html(TESTS, sc))

    def test_untested_agent_is_not_labelled_held(self):
        nt = {"A1": ["nt", ""], "A2": ["nt", ""], "A3": ["nt", ""], "B1": ["nt", ""]}
        sc = score.score(TESTS, res(X={"version": "1", "results": nt}, Y={"version": "1", "disclosure": "1 Jan", "results": {}}))
        tab = score.render_html(TESTS, sc)
        self.assertIn("<strong>0/4</strong> (0 failed, 4 n/a)", tab)
        self.assertEqual(tab.count('class="pending">Held<'), 1)          # only the agent with an open disclosure
        self.assertIn(">0/4</text>", score.render_svg(TESTS, sc))

    def test_evidence_and_info_kept(self):
        full = {"A1": ["pass", "e<1>"], "A2": ["fail", "e2"], "A3": ["nt", "limit"], "B1": ["pass", "e4"]}
        sc = score.score(TESTS, res(X={"version": "1", "results": full, "info": {"I1": ["yes", "token in header"]}}))
        self.assertEqual(sc["X"]["results"]["A2"], ["fail", "e2"])
        self.assertEqual(sc["X"]["info"]["I1"], ["yes", "token in header"])
        ev = score.render_evidence_html(TESTS, sc)
        self.assertIn("e&lt;1&gt;", ev); self.assertIn("token in header", ev); self.assertIn("AgentProtect", ev)

    def test_real_files_valid(self):
        here = os.path.dirname(os.path.abspath(__file__))
        t, r = os.path.join(here, "tests.json"), os.path.join(here, "example-results.json")
        if os.path.exists(r):
            score.validate(score.load(t), score.load(r))

    def test_disclosure_hides_scores(self):
        r = res(X={"version": "1", "disclosure": "1 Jan", "results": {}})
        score.validate(TESTS, r)
        self.assertIsNone(score.score(TESTS, r)["X"]["categories"]["A"])

    def test_disclosure_with_results_rejected(self):
        r = res(X={"version": "1", "disclosure": "1 Jan", "results": {"A1": ["pass", "e"]}})
        with self.assertRaises(score.ValidationError):
            score.validate(TESTS, r)

    def test_missing_evidence_rejected(self):
        r = res(X={"version": "1", "results": {"A1": ["pass", " "], "A2": ["nt", ""], "A3": ["nt", ""], "B1": ["nt", ""]}})
        with self.assertRaises(score.ValidationError):
            score.validate(TESTS, r)

    def test_missing_test_rejected(self):
        r = res(X={"version": "1", "results": {"A1": ["pass", "e"]}})
        with self.assertRaises(score.ValidationError):
            score.validate(TESTS, r)

    def test_bad_status_and_unknown_id(self):
        for bad in ({"A1": ["maybe", "e"]}, {"Z9": ["pass", "e"]}):
            full = {"A1": ["nt", ""], "A2": ["nt", ""], "A3": ["nt", ""], "B1": ["nt", ""]}
            full.update(bad)
            with self.assertRaises(score.ValidationError):
                score.validate(TESTS, res(X={"version": "1", "results": full}))

    def test_outputs_written_and_escaped(self):
        r = res(**{"<X>": {"version": "1", "results": {"A1": ["pass", "e"], "A2": ["nt", ""], "A3": ["nt", ""], "B1": ["fail", "e"]}}})
        with tempfile.TemporaryDirectory() as d:
            tp, rp = os.path.join(d, "t.json"), os.path.join(d, "r.json")
            json.dump(TESTS, open(tp, "w")); json.dump(r, open(rp, "w"))
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(score.main(["--tests", tp, "--results", rp, "--out", d]), 0)
            svg = open(os.path.join(d, "scores.svg")).read()
            self.assertIn("&lt;X&gt;", svg)
            self.assertNotIn("<X>", svg)
            self.assertIn("1/3", open(os.path.join(d, "scores.html")).read())

    def test_invalid_returns_2(self):
        with tempfile.TemporaryDirectory() as d:
            tp, rp = os.path.join(d, "t.json"), os.path.join(d, "r.json")
            json.dump(TESTS, open(tp, "w")); json.dump(res(X={"version": ""}), open(rp, "w"))
            with contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(score.main(["--tests", tp, "--results", rp, "--out", d]), 2)


if __name__ == "__main__":
    unittest.main()
