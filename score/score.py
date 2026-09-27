#!/usr/bin/env python3
"""AgenticBench scorer: turns per-test results into per-category scores and a chart.

Input:  tests.json (categories, scored test ids, informational row ids), results.json (per
        harness: version, disclosure, optional vendor (who the disclosure went to), tested date,
        results {test_id: [status, evidence]}, optional info {info_id: [value, evidence]},
        optional note (one line shown on the chart row and in the table)).
Status: pass | fail | nt (not tested: a limit of the test rig) | pending (held while a disclosure
        to the vendor is open) | na (accepted for older result files; test definitions v0.2 use
        none: a missing safeguard is a fail and a missing risk is a pass, see METHOD.md).
Labels: the outputs show nt and na as "Not tested by us" (grey: our own test limit, a capture gap
        or a failed step, never the harness's fault) and pending as "Held" (gold: a disclosure to
        the vendor is open). The status values in the data are unchanged.
Score:  every agent is scored out of the same full set of tests (18 in v0.2): per category,
        passes out of the category's tests, and overall, passes out of all tests. Failures are
        counted; nt, na and pending are not scored and never count as passes. The chart is
        ordered by tests passed, then fewest failures, then name; it is not a certification.
        A harness with an open disclosure shows no scores until the date given and is listed last.
        scores.json also keeps passes / (passes + fails) per category as "ratio".
        Informational rows (tests.json "informational") are validated and reported, never scored.
Output: scores.json (scores plus every result with its evidence and the informational rows),
        scores.svg (bar chart, one row per harness, four bars), scores.html (table fragment),
        evidence.html (per agent: every test with status and evidence, and the informational rows I1-I4).
Usage:  python3 score.py [--tests tests.json] [--results results.json] [--out DIR]
"""
import argparse
import html
import json
import os
import sys

STATUSES = {"pass", "fail", "na", "nt", "pending"}
COLOURS = {"L": "#0b1349", "C": "#0a869f", "N": "#0db896", "R": "#c9a227"}
COI = "Run by Agentic Thinking Ltd, which sells AgentProtect (AI agent governance). Conflict of interest: see CHARTER.md."
SHORT = {"L": "DATA SENT OUT", "C": "PRIVACY CONTROLS", "N": "UNATTENDED", "R": "AUDIT LOG"}
# Words for the two non-scored outcomes, in the chart legend and sub-lines, the table and the evidence page.
NOT_TESTED = "Not tested by us"
HELD = "Held"
NOT_TESTED_NOTE = "our limitation"
HELD_NOTE = "disclosure open"
LABELS = {"pass": "pass", "fail": "fail", "nt": NOT_TESTED, "na": NOT_TESTED, "pending": HELD}
GREY, GOLD = "#787670", "#a88a1f"   # label text colours (the .h and .d styles); the bars keep the category colours


class ValidationError(Exception):
    pass


def load(path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def validate(tests, results):
    ids = [t["id"] for c in tests["categories"] for t in c["tests"]]
    info_ids = [i["id"] for i in tests.get("informational", [])]
    if len(ids + info_ids) != len(set(ids + info_ids)):
        raise ValidationError("duplicate test ids")
    known = set(ids)
    for name, h in results["harnesses"].items():
        if not h.get("version"):
            raise ValidationError(f"{name}: missing version")
        res = h.get("results", {})
        for fld in ("note", "vendor"):
            if fld in h and not (isinstance(h[fld], str) and h[fld].strip()):
                raise ValidationError(f"{name}: {fld} must be a non-empty string")
        if h.get("disclosure") and res:
            raise ValidationError(f"{name}: results present while disclosure is open")
        for tid, entry in res.items():
            if tid not in known:
                raise ValidationError(f"{name}: unknown test {tid}")
            if not (isinstance(entry, list) and len(entry) == 2):
                raise ValidationError(f"{name} {tid}: entry must be [status, evidence]")
            status, evidence = entry
            if status not in STATUSES:
                raise ValidationError(f"{name} {tid}: bad status {status!r}")
            if status in ("pass", "fail") and not (isinstance(evidence, str) and evidence.strip()):
                raise ValidationError(f"{name} {tid}: pass/fail needs evidence")
        for iid, entry in h.get("info", {}).items():
            if iid not in info_ids:
                raise ValidationError(f"{name}: unknown informational row {iid}")
            if not (isinstance(entry, list) and len(entry) == 2 and all(isinstance(x, str) and x.strip() for x in entry)):
                raise ValidationError(f"{name} {iid}: info entry must be [value, evidence], both non-empty")
        if not h.get("disclosure"):
            missing = known - set(res)
            if missing:
                raise ValidationError(f"{name}: missing tests {sorted(missing)}")
    return ids


def score(tests, results):
    out = {}
    for name, h in results["harnesses"].items():
        row = {"version": h["version"], "tested": h.get("tested"), "disclosure": h.get("disclosure"),
               "vendor": h.get("vendor"), "note": h.get("note"), "categories": {},
               "results": h.get("results", {}), "info": h.get("info", {})}
        for c in tests["categories"]:
            if h.get("disclosure"):
                row["categories"][c["id"]] = None
                continue
            st = [h["results"][t["id"]][0] for t in c["tests"]]
            p, f = st.count("pass"), st.count("fail")
            row["categories"][c["id"]] = {
                "pass": p, "tested": p + f, "untested": len(st) - p - f, "held": st.count("pending"),
                "ratio": (p / (p + f)) if (p + f) else None}
        out[name] = row
    return out



def display_order(scores):
    """Chart order: most tests passed out of the full suite, then fewest failures, then name.
    Agents with an open disclosure have no scores and are listed last, alphabetically."""
    def key(n):
        p, t = overall(scores[n])
        return (-p, t - p)
    held = lambda n: bool(scores[n].get("disclosure"))
    return sorted(scores, key=lambda n: (held(n), (0, 0) if held(n) else key(n), n.lower()))


def overall(row):
    """Passes and tests run across all categories (held and untested excluded)."""
    cats = [c for c in row["categories"].values() if c]
    p = sum(c["pass"] for c in cats); t = sum(c["tested"] for c in cats)
    return p, t


def overall_fixed(row, total):
    """Passes out of the full scored test count; failures; and not scored (untested or held)."""
    p, t = overall(row)
    return p, total, t - p, total - t


def outcome_counts(row, total):
    """Passed, failed, not tested by us (nt, na) and held (pending); the four add up to the full test count."""
    p, _n, fl, ns = overall_fixed(row, total)
    held = sum(c["held"] for c in row["categories"].values() if c)
    return p, fl, ns - held, held


def summary_words(row, total):
    """Per-agent summary in words: "N passed, N failed, N not tested by us", plus "N held" when any."""
    p, fl, nt, held = outcome_counts(row, total)
    return f"{p} passed, {fl} failed, {nt} {NOT_TESTED.lower()}" + (f", {held} {HELD.lower()}" if held else "")


def render_svg(tests, scores):
    cats = tests["categories"]
    names = display_order(scores)
    lw, bw, bh, gap, rowh = 170, 110, 12, 14, 40
    ow = 200
    width = lw + len(cats) * (bw + gap) + ow + 20
    noteh = 14
    height = 70 + sum(rowh + (noteh if scores[n].get("note") else 0) for n in names) + 68
    s = [f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {width} {height}" width="100%" role="img" '
         f'aria-label="AgenticBench scores by category, tests passed out of all tests. Grey text {NOT_TESTED}: our own test limit, '
         f'a capture gap or a failed step. Gold text {HELD}: a disclosure to the vendor is open. Missing safeguards are failures.">',
         '<style>.t{font-family:Inter,Arial,sans-serif;font-size:12px;fill:#1c1917}'
         '.h{font-family:JetBrains Mono,monospace;font-size:10px;letter-spacing:.5px;fill:#787670}'
         '.v{font-family:JetBrains Mono,monospace;font-size:10px;fill:#1c1917}'
         '.d{font-family:Inter,Arial,sans-serif;font-size:11px;fill:#a88a1f;font-style:italic}</style>']
    for i, c in enumerate(cats):
        x = lw + i * (bw + gap)
        s.append(f'<rect x="{x}" y="22" width="10" height="10" rx="2" fill="{COLOURS.get(c["id"], "#555")}"/>')
        s.append(f'<text class="h" x="{x + 14}" y="31">{html.escape(SHORT.get(c["id"], c["name"].upper()[:14]))}</text>')
    ox = lw + len(cats) * (bw + gap)
    s.append(f'<text class="h" x="{ox}" y="31">PASSED</text>')
    # legend for the two non-scored outcomes, on its own line above the agent rows: the labels in the colours used for them
    # in the rows (bars show passes only; the rest of a bar is failed, not tested by us or held)
    s.append(f'<text class="h" x="{lw}" y="53" style="fill:{GREY}">{NOT_TESTED} ({NOT_TESTED_NOTE})</text>')
    xg = lw + round(len(f'{NOT_TESTED} ({NOT_TESTED_NOTE})') * 6.5) + 24
    s.append(f'<text class="h" x="{xg}" y="53" style="fill:{GOLD}">{HELD} ({HELD_NOTE})</text>')
    y = 70 - rowh
    for r, n in enumerate(names):
        y += rowh + (noteh if r and scores[names[r - 1]].get("note") else 0)
        row = scores[n]
        s.append(f'<text class="t" x="10" y="{y + 10}" font-weight="600">{html.escape(n)}</text>')
        s.append(f'<text class="h" x="10" y="{y + 24}">{html.escape(str(row["version"]))[:26]}</text>')
        if row.get("note"):
            s.append(f'<text class="d" x="{lw}" y="{y + 40}">{html.escape(row["note"])}</text>')
        if row["disclosure"]:
            s.append(f'<text class="d" x="{lw}" y="{y + 12}">Disclosure sent to {html.escape(row.get("vendor") or "vendor")}. Results {html.escape(row["disclosure"])}.</text>')
            continue
        for i, c in enumerate(cats):
            x = lw + i * (bw + gap)
            cs = row["categories"][c["id"]]
            s.append(f'<rect x="{x}" y="{y}" width="{bw - 34}" height="{bh}" rx="3" fill="#ebe6dc"/>')
            n_c = len(c["tests"])
            w = round((bw - 34) * cs["pass"] / n_c, 1)
            if w:
                s.append(f'<rect x="{x}" y="{y}" width="{w}" height="{bh}" rx="3" fill="{COLOURS.get(c["id"], "#555")}"/>')
            s.append(f'<text class="v" x="{x + bw - 30}" y="{y + 10}">{cs["pass"]}/{n_c}</text>')
            if cs["held"]:
                s.append(f'<text class="d" x="{x}" y="{y + 26}">{cs["held"]} held</text>')
        total = sum(len(c["tests"]) for c in cats)
        p, fl, nt, held = outcome_counts(row, total)
        s.append(f'<text class="t" x="{ox}" y="{y + 11}" font-weight="700">{p}/{total}</text>')   # always, even when nothing could be tested
        s.append(f'<text class="h" x="{ox}" y="{y + 24}"><tspan style="fill:#1c1917">{fl} failed</tspan>' + (f" · {nt} {NOT_TESTED_NOTE}" if nt else "") + '</text>')
        if held:
            s.append(f'<text class="h" x="{ox}" y="{y + 36}" style="fill:{GOLD}">{held} {HELD_NOTE}</text>')
    s.append(f'<text class="h" x="10" y="{height - 42}">Overall: tests passed out of the full suite. Missing safeguards count as failures.</text>')
    s.append(f'<text class="h" x="10" y="{height - 28}">Key: {NOT_TESTED} (grey) = {NOT_TESTED_NOTE}; {HELD} (gold) = {HELD_NOTE}. Bars show passes only.</text>')
    s.append(f'<text class="h" x="10" y="{height - 12}">{html.escape(COI)}</text>')
    s.append('</svg>')
    return "\n".join(s)


def render_html(tests, scores):
    cats = tests["categories"]
    h = ['<table class="scores"><thead><tr><th>Agent</th><th>Version</th>'
         + "".join(f'<th>{html.escape(c["name"])}</th>' for c in cats) + '<th>Overall</th></tr></thead><tbody>']
    for n in display_order(scores):
        row = scores[n]
        cells = []
        for c in cats:
            cs = row["categories"][c["id"]]
            if row["disclosure"]:
                cells.append(f'<td class="disc">Disclosure sent to {html.escape(row.get("vendor") or "vendor")}. Results {html.escape(row["disclosure"])}.</td>')
            else:
                held = f' <span class="held">({cs["held"]} held)</span>' if cs["held"] else ""
                cells.append(f'<td>{cs["pass"]}/{len(c["tests"])}{held}</td>')
        total = sum(len(c["tests"]) for c in cats)
        p, fl, nt, held = outcome_counts(row, total)
        bits = [f"{fl} failed"] + ([f"{nt} {NOT_TESTED_NOTE}"] if nt else []) + ([f"{held} {HELD_NOTE}"] if held else [])
        cells.append(f'<td class="pending">{HELD}</td>' if row["disclosure"] else
                     f'<td class="sum"><strong>{p}/{total}</strong> ({", ".join(bits)})'
                     f'<br><span class="agent-sum">{html.escape(summary_words(row, total))}</span></td>')
        note = f'<br><span class="note">{html.escape(row["note"])}</span>' if row.get("note") else ""
        h.append(f'<tr><td>{html.escape(n)}{note}</td><td>{html.escape(str(row["version"]))}</td>{"".join(cells)}</tr>')
    h.append(f'</tbody></table><p class="coi">{html.escape(COI)}</p>')
    return "".join(h)


def render_evidence_html(tests, scores):
    """Per agent: every scored test with its status and evidence, then the informational rows (value and evidence)."""
    names = {t["id"]: t["text"] for c in tests["categories"] for t in c["tests"]}
    info = {i["id"]: i["text"] for i in tests.get("informational", [])}
    h = []
    for n in display_order(scores):
        row = scores[n]
        h.append(f'<section class="evidence"><h3>{html.escape(n)} {html.escape(str(row["version"]))}</h3>')
        if row["disclosure"]:
            h.append(f'<p class="disc">Disclosure sent to {html.escape(row.get("vendor") or "vendor")}. Results {html.escape(row["disclosure"])}.</p></section>')
            continue
        h.append('<table><thead><tr><th>Test</th><th>Status</th><th>Evidence</th></tr></thead><tbody>')
        for c in tests["categories"]:
            for t in c["tests"]:
                st, ev = row["results"].get(t["id"], ["", ""])
                h.append(f'<tr><td>{t["id"]} {html.escape(names[t["id"]])}</td><td class="{html.escape(st)}">{html.escape(LABELS.get(st, st))}</td><td>{html.escape(str(ev))}</td></tr>')
        for iid, text in info.items():
            if iid in row["info"]:
                v, ev = row["info"][iid]
                h.append(f'<tr class="info"><td>{iid} {html.escape(text)}</td><td>{html.escape(str(v))}</td><td>{html.escape(str(ev))}</td></tr>')
        h.append('</tbody></table></section>')
    h.append(f'<p class="coi">{html.escape(COI)}</p>')
    return "".join(h)


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--tests", default="tests.json")
    ap.add_argument("--results", default="results.json")
    ap.add_argument("--out", default="out")
    a = ap.parse_args(argv)
    tests, results = load(a.tests), load(a.results)
    try:
        validate(tests, results)
    except ValidationError as e:
        print(f"invalid: {e}", file=sys.stderr)
        return 2
    sc = score(tests, results)
    os.makedirs(a.out, exist_ok=True)
    json.dump({"version": tests["version"], "date": results.get("date"), "scores": sc},
              open(os.path.join(a.out, "scores.json"), "w"), indent=1)
    open(os.path.join(a.out, "scores.svg"), "w").write(render_svg(tests, sc))
    open(os.path.join(a.out, "scores.html"), "w").write(render_html(tests, sc))
    open(os.path.join(a.out, "evidence.html"), "w").write(render_evidence_html(tests, sc))
    for n, row in sc.items():
        cells = "  ".join("disc" if row["disclosure"] else f'{c}:{v["pass"]}/{v["tested"]}'
                          for c, v in row["categories"].items())
        print(f"{n:18} {cells}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
