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
        self.assertIn('viewBox="0 0 638 232"', svg)
        self.assertIn(f'<td>X<br><span class="note">{esc}</span></td>', tab)
        self.assertEqual(svg.count(esc), 1)
        no_note = score.render_svg(TESTS, score.score(TESTS, res(X={"version": "1", "results": full})))
        self.assertIn('viewBox="0 0 638 178"', no_note)
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
        self.assertIn('1 failed</tspan> · 1 our limitation</text>', score.render_svg(TESTS, sc))
        self.assertIn("<strong>2/4</strong> (1 failed, 1 our limitation)", score.render_html(TESTS, sc))

    def test_conflict_of_interest_on_outputs(self):
        full = {"A1": ["pass", "e"], "A2": ["pass", "e"], "A3": ["pass", "e"], "B1": ["pass", "e"]}
        sc = score.score(TESTS, res(X={"version": "1", "results": full}))
        self.assertIn("AgentProtect", score.render_svg(TESTS, sc))
        self.assertIn("AgentProtect", score.render_html(TESTS, sc))

    def test_not_tested_and_held_wording(self):
        """The two non-scored outcomes are labelled "Not tested by us" (our limitation) and "Held" (disclosure open)."""
        full = {"A1": ["pending", "d"], "A2": ["fail", "e"], "A3": ["nt", ""], "B1": ["pass", "e"]}
        r = res(X={"version": "1", "results": full})
        sc = score.score(TESTS, r)
        svg, tab = score.render_svg(TESTS, sc), score.render_html(TESTS, sc)
        self.assertIn(f"{score.NOT_TESTED} ({score.NOT_TESTED_NOTE})", svg)
        self.assertIn(f"{score.HELD} ({score.HELD_NOTE})", svg)
        self.assertIn("1 failed</tspan> · 1 our limitation</text>", svg)       # held is not also counted as not tested
        self.assertIn(f'style="fill:{score.GOLD}">1 disclosure open</text>', svg)
        self.assertIn("Key: Not tested by us (grey) = our limitation; Held (gold) = disclosure open. Bars show passes only.", svg)
        self.assertNotIn('<rect x="170" y="44"', svg)                          # no legend swatch in a bar colour
        self.assertIn("Missing safeguards count as failures.", svg)
        self.assertIn("Grey text Not tested by us", svg); self.assertIn("Gold text Held", svg)
        self.assertIn("(1 failed, 1 our limitation, 1 disclosure open)", tab)
        self.assertIn("1 passed, 1 failed, 1 not tested by us, 1 held", tab)
        self.assertEqual(r["harnesses"]["X"]["results"], full)                   # status values in the data are unchanged
        self.assertEqual([sc["X"]["results"][k][0] for k in ("A1", "A3")], ["pending", "nt"])

    def test_overall_column_text_fits(self):
        """every line in the overall column fits its width at the chart's monospace size (about 6.5 px per character)"""
        import re as _re
        worst = {"A1": ["pending", "d"], "A2": ["fail", "e"], "A3": ["nt", ""], "B1": ["na", "e"]}
        many = {"A1": ["fail", "e"], "A2": ["fail", "e"], "A3": ["fail", "e"], "B1": ["fail", "e"]}
        svg = score.render_svg(TESTS, score.score(TESTS, res(X={"version": "1", "results": worst}, Y={"version": "1", "results": many})))
        width = int(_re.search(r'viewBox="0 0 (\d+) ', svg).group(1)); ox = int(_re.search(r'<text class="h" x="(\d+)" y="31">PASSED', svg).group(1))
        lines = [_re.sub(r"<[^>]+>", "", m.group(1)) for m in _re.finditer(rf'<text [^>]*x="{ox}"[^>]*>(.*?)</text>', svg)]
        self.assertTrue(any("our limitation" in x for x in lines) and any("disclosure open" in x for x in lines), lines)
        wide = "18 failed · 18 our limitation"   # the widest sub-line an 18-test suite can produce
        for x in lines + [wide]: self.assertLessEqual(len(x) * 6.5, width - ox - 5, x)

    def test_summary_words(self):
        full = {"A1": ["pending", "d"], "A2": ["fail", "e"], "A3": ["nt", ""], "B1": ["pass", "e"]}
        sc = score.score(TESTS, res(X={"version": "1", "results": full}))
        self.assertEqual(score.summary_words(sc["X"], 4), "1 passed, 1 failed, 1 not tested by us, 1 held")
        self.assertEqual(sum(score.outcome_counts(sc["X"], 4)), 4)              # the four outcomes add up to the suite
        plain = {"A1": ["pass", "e"], "A2": ["pass", "e"], "A3": ["na", "e"], "B1": ["fail", "e"]}
        sc2 = score.score(TESTS, res(Y={"version": "1", "results": plain}))
        self.assertEqual(score.summary_words(sc2["Y"], 4), "2 passed, 1 failed, 1 not tested by us")   # na is not tested by us too
        self.assertIn("2 passed, 1 failed, 1 not tested by us", score.render_html(TESTS, sc2))

    def test_evidence_page_uses_the_labels(self):
        full = {"A1": ["pending", "d"], "A2": ["na", "old"], "A3": ["nt", "limit"], "B1": ["pass", "e"]}
        ev = score.render_evidence_html(TESTS, score.score(TESTS, res(X={"version": "1", "results": full})))
        self.assertIn('<td class="pending">Held</td>', ev); self.assertIn('<td class="nt">Not tested by us</td>', ev)
        self.assertIn('<td class="na">Not tested by us</td>', ev); self.assertIn('<td class="pass">pass</td>', ev)

    def test_untested_agent_is_not_labelled_held(self):
        nt = {"A1": ["nt", ""], "A2": ["nt", ""], "A3": ["nt", ""], "B1": ["nt", ""]}
        sc = score.score(TESTS, res(X={"version": "1", "results": nt}, Y={"version": "1", "disclosure": "1 Jan", "results": {}}))
        tab = score.render_html(TESTS, sc)
        self.assertIn("<strong>0/4</strong> (0 failed, 4 our limitation)", tab)
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

    def test_disclosure_with_results_rejection_names_held_mode(self):
        r = res(X={"version": "1", "disclosure": "1 Jan", "results": {"A1": ["pending", "d"], "A2": ["pass", "e"], "A3": ["nt", ""], "B1": ["fail", "e"]}})
        with self.assertRaisesRegex(score.ValidationError, "mode.*held"):
            score.validate(TESTS, r)

    # held mode: an open disclosure with the other cells published and the held ones (pending) shown as Held
    HELD_FULL = {"A1": ["pending", "HELD-DETAIL-a1"], "A2": ["pass", "e2"], "A3": ["nt", "limit"], "B1": ["fail", "e4"]}

    def held(self, **extra):
        return res(X={"version": "1", "disclosure": "26 Oct", "vendor": "Example Vendor", "mode": "held",
                      "results": dict(self.HELD_FULL), "info": {"I1": ["yes", "HELD-DETAIL-info"]}, **extra})

    def test_held_mode_validates_and_scores_the_other_cells(self):
        r = self.held(); score.validate(TESTS, r)
        sc = score.score(TESTS, r)
        a = sc["X"]["categories"]["A"]
        self.assertEqual((a["pass"], a["tested"], a["held"], a["untested"]), (1, 1, 1, 2))
        self.assertEqual(score.outcome_counts(sc["X"], 4), (1, 1, 1, 1))
        self.assertEqual(sc["X"]["mode"], "held")

    def test_held_mode_never_outputs_held_detail(self):
        r = self.held(); score.validate(TESTS, r)
        sc = score.score(TESTS, r)
        outs = [score.render_svg(TESTS, sc), score.render_html(TESTS, sc), score.render_evidence_html(TESTS, sc), json.dumps(sc)]
        for o in outs:
            self.assertNotIn("HELD-DETAIL", o)
        self.assertEqual(sc["X"]["results"]["A1"], ["pending", ""])
        self.assertEqual(sc["X"]["info"], {})                                  # informational rows can describe a held finding
        ev = outs[2]
        self.assertIn('<td>A1 a1</td><td class="pending">Held</td><td></td>', ev)
        self.assertIn('<td class="fail">fail</td><td>e4</td>', ev)             # the other cells keep their evidence
        self.assertIn("Disclosure sent to Example Vendor. Held results 26 Oct.", ev)
        self.assertIn("Disclosure sent to Example Vendor. Held results 26 Oct.", outs[0])
        self.assertIn("Disclosure sent to Example Vendor. Held results 26 Oct.", outs[1])
        self.assertNotIn('class="disc"', outs[1])                              # scores shown, not the withheld cell
        self.assertIn("<strong>1/4</strong> (1 failed, 1 our limitation, 1 disclosure open)", outs[1])
        self.assertIn("1 passed, 1 failed, 1 not tested by us, 1 held", outs[1])

    def test_pending_evidence_hidden_without_disclosure_too(self):
        full = dict(self.HELD_FULL)
        sc = score.score(TESTS, res(X={"version": "1", "results": full}))
        for o in (score.render_evidence_html(TESTS, sc), json.dumps(sc)):
            self.assertNotIn("HELD-DETAIL", o)

    def test_held_mode_ranked_with_the_others(self):
        hi = {"A1": ["pass", "e"], "A2": ["pass", "e"], "A3": ["pass", "e"], "B1": ["pass", "e"]}
        r = self.held(); r["harnesses"].update(Top={"version": "1", "results": hi}, Low={"version": "1", "results": {k: ["fail", "e"] for k in hi}},
                                               Wait={"version": "1", "disclosure": "1 Jan", "results": {}})
        score.validate(TESTS, r)
        self.assertEqual(score.display_order(score.score(TESTS, r)), ["Top", "X", "Low", "Wait"])

    def test_held_mode_rules(self):
        bad = [dict(mode="held", results=dict(self.HELD_FULL)),                                           # no disclosure
               dict(mode="held", disclosure=" ", results=dict(self.HELD_FULL)),
               dict(mode="held", disclosure="1 Jan", results={k: ["pass", "e"] for k in self.HELD_FULL}),  # nothing held
               dict(mode="held", disclosure="1 Jan", results={"A1": ["pending", ""]}),                   # tests missing
               dict(mode="partial", disclosure="1 Jan", results=dict(self.HELD_FULL))]                   # unknown mode
        for b in bad:
            with self.subTest(b), self.assertRaises(score.ValidationError):
                score.validate(TESTS, res(X={"version": "1", **b}))

    def test_held_mode_aider_shaped_counts_add_up_to_the_suite(self):
        """18 tests (5, 5, 4, 4): 5 pass, 2 fail, 1 nt, 10 held gives 5 + 2 + 1 + 10 = 18, never 1 + 10 counted again as not tested."""
        here = os.path.dirname(os.path.abspath(__file__))
        t = score.load(os.path.join(here, "tests.json"))
        ids = [x["id"] for c in t["categories"] for x in c["tests"]]
        self.assertEqual((len(ids), [len(c["tests"]) for c in t["categories"]]), (18, [5, 5, 4, 4]))
        st = ["pass"] * 5 + ["fail"] * 2 + ["nt"] + ["pending"] * 10
        results = {k: [v, "HELD-DETAIL" if v == "pending" else ("" if v == "nt" else "e")] for k, v in zip(ids, st)}
        r = res(Aider={"version": "0.86.2", "disclosure": "26 Oct", "vendor": "Aider", "mode": "held", "results": results})
        score.validate(t, r)
        sc = score.score(t, r)
        self.assertEqual(score.outcome_counts(sc["Aider"], 18), (5, 2, 1, 10))
        self.assertEqual(sum(score.outcome_counts(sc["Aider"], 18)), 18)
        self.assertEqual(score.summary_words(sc["Aider"], 18), "5 passed, 2 failed, 1 not tested by us, 10 held")
        tab, svg, ev = score.render_html(t, sc), score.render_svg(t, sc), score.render_evidence_html(t, sc)
        self.assertIn("<strong>5/18</strong> (2 failed, 1 our limitation, 10 disclosure open)", tab)
        self.assertIn("1 our limitation</text>", svg); self.assertIn("10 disclosure open</text>", svg)
        self.assertNotIn("11 ", tab + svg)
        self.assertEqual(ev.count('class="pending">Held</td><td></td>'), 10)
        for o in (tab, svg, ev, json.dumps(sc)): self.assertNotIn("HELD-DETAIL", o)

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
