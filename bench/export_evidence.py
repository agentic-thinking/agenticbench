#!/usr/bin/env python3
"""AgenticBench public evidence bundle: one JSON file per agent, built from the scorer output (score_bench.py), the digest
(digest.py) and the adjudication file, for publishing next to the results.

For each cell that is not held: the verdict, the reason (the cell's evidence text) and the scrubbed supporting records of the units
the cell rests on: per unit its variant and steps; per step the exit codes, model request counts and which benign commands ran;
per non-model request the step, host, method, path, status, request size and the needles it matched, by name only; per file on
disk its HOME-relative path and matched needle names; and references to the documentation snapshots the cell or its adjudication
cites (file name, sha256, URL, fetch time from bench/docs/SHA256SUMS). Held cells (pending) are written as {"status": "held"}
and nothing else; an agent whose disclosure is open in the default (withheld) mode is written as {"held": true} only.
Informational rows are not exported.

Redaction, two layers: only the fields listed here are copied (an allowlist; request and response bodies, headers, cookies,
model requests, websocket frames, raw output lines, vendor error lines and identifier candidates are never read into the bundle),
and every copied string is scrubbed by pattern: credential assignments and headers, bearer and basic values, known key shapes,
JWTs, URL credentials and query strings, email addresses, UUIDs, long hex or digit runs and id-like path segments or host labels
(account and device ids), the unit's fake secrets and dummy key (read from run.json and the canary .env) and their generic
shapes. Fail closed: the serialised bundles are checked line by line against the secret patterns after scrubbing; any match
aborts the export with no file written (exit 3). The check names the agent, line and pattern, never the matched text.

Usage:  export_evidence.py [--adjudication FILE] [--bench DIR] RESULTS.json OUT_DIR HARNESS...
        RESULTS.json = score_bench.py output; HARNESS = the adapter names (as for score_bench.py).
"""
import argparse, json, os, re, sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from lib.vendor_errors import SECRET_RX   # noqa: E402  the scrub rules of the recorded error lines

UNIT_RX = re.compile(r"(?:bench/)?results/([A-Za-z0-9._-]+)")
DOC_RX = re.compile(r"(?:bench/)?docs/([A-Za-z0-9][A-Za-z0-9._-]*)")
LABEL_OK = re.compile(r"^[a-z0-9][a-z0-9-]*-\d{8}T\d{6}Z-\d+$")        # unit directory names as unit.sh makes them
NAME_OK = re.compile(r"^[A-Za-z0-9_./:-]{1,80}$")                      # needle and step names
BATCH_OK = re.compile(r"^\d{8}T\d{6}Z-\d+$")
HEX64 = re.compile(r"^[0-9a-f]{64}$")
# the only redaction markers a bundle may hold, exactly as written and followed by a delimiter (a JSON escape counts as one);
# the check replaces them by a control character first, so any other text that starts with "[scrubbed" is still caught
ALLOWED_MARK = re.compile(r"\[scrubbed(?:-email|-id|-fake-secret)?\](?=[\s\"',;&)}\]\\]|$)")
# (name, pattern) of text that must never be in a bundle; the fail-closed check runs these on every serialised line
DETECT = [
    ("key_shape", re.compile(r"\b(?:sk|pk|rk|sgamp|ghp|gho|ghs|ghu|github_pat|glpat|xox[abpr]|AKIA|ASIA|AIza|ya29|rvt)[-_.]?[A-Za-z0-9]{8,}")),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}")),
    ("auth_value", re.compile(r"(?i)\b(?:bearer|basic|digest)\s+\S{6,}")),
    ("credential_assignment", re.compile(r"(?i)\b(?:api[_-]?key|x-api-key|access[_-]?token|refresh[_-]?token|auth[_-]?token|token|secret|client[_-]?secret|password|passwd|pwd|authorization|cookie|set-cookie|session[_-]?id|credential)\b\\?[\"']?\s*[=:]\s*\\?[\"']?[^\s\"',;&)}\]]{4,}")),
    ("marker_shape", re.compile(r"(?i)\[scrubbed")),                    # anything marker-like that is not an exact marker
    ("email", re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")),
    ("url_credentials", re.compile(r"(?i)[a-z][a-z0-9+.-]*://[^/\s:@]+:[^/\s@]+@")),
    ("url_query", re.compile(r"\?[^\s\"#\[]*=")),
    ("uuid", re.compile(r"(?i)\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b")),
    ("long_hex", re.compile(r"(?i)(?<![0-9a-z])[0-9a-f]{24,}(?![0-9a-z])")),
    ("long_token", re.compile(r"(?<![A-Za-z0-9])(?=[A-Za-z0-9]*\d)(?=[A-Za-z0-9]*[A-Za-z])[A-Za-z0-9]{28,}")),
    ("fake_secret_shape", re.compile(r"CANARY[A-Za-z0-9]|TAMPER(?:pw)?[0-9]|sk_live_")),
    ("private_key", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY")),
]
SHA_FIELD = re.compile(r'"sha256": "[0-9a-f]{64}"')                  # the one place a 64-hex value is allowed: a doc snapshot hash
# extra scrub rules for free text, after SECRET_RX
EXTRA_RX = [
    (re.compile(r"(\[scrubbed(?:-email|-id|-fake-secret)?\])[^\s\"',;&)}\]]+"), r"\1"),   # text glued after a marker: part of the value
    (re.compile(r"CANARY[A-Za-z0-9_]*|TAMPER(?:pw)?[A-Za-z0-9_]*"), "[scrubbed-fake-secret]"),
    (re.compile(r"(?i)\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b"), "[scrubbed-id]"),
    (re.compile(r"(?i)(?<![0-9a-z])[0-9a-f]{16,}(?![0-9a-z])"), "[scrubbed-id]"),
    (re.compile(r"(?<![0-9])[0-9]{10,}(?![0-9])"), "[scrubbed-id]"),
    (re.compile(r"(?i)[a-z][a-z0-9+.-]*://[^/\s:@]+:[^/\s@]+@"), "[scrubbed]@"),
    (re.compile(r"(\?)[^\s\"#]+"), r"\1[scrubbed]"),
]
CTRL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f]")
# units a cell rests on when its evidence names none: by test family
FAMILY = {"L": ("default",), "C": ("default", "optout"), "N": None, "R": None}   # None: every unit of the batch
# record groups a held test rests on: while any of these tests is held, the group is written as "held" in every cell, so the
# records of a published cell cannot show a held finding (e.g. canary needles in requests while L3 is held)
HELD_GROUPS = {"requests": {"L1", "L2", "L3", "L4", "L5", "C1", "C3", "C4"}, "disk": {"R1", "R3", "R5"}, "step": {"N1", "N2", "N4", "N5", "R2"}}
ALLOWED = {
    "agent", "harness", "version", "tested", "batch", "tests", "held", "cells", "status", "reason", "units", "docs",
    "unit", "variant", "steps", "step", "name", "kind", "skipped", "rc", "outer_rc", "model_requests", "model_ok", "ran",
    "vendor_error_lines", "leftover_processes", "requests", "host", "method", "path", "http_status", "req_bytes", "needles",
    "blocked", "body_uninspected", "payload_opaque", "disk", "file", "sha256", "url", "fetched", "about"}
ABOUT = ("AgenticBench evidence bundle (bench/export_evidence.py): verdicts, reasons and scrubbed supporting records. Needles are "
         "listed by name only; secrets, tokens, cookies, auth headers, emails, account ids and fake-secret values are redacted; "
         "held cells are omitted. Method: METHOD.md, limits: KNOWN-LIMITATIONS.md.")


class ExportError(Exception):
    pass


class Scrubber:
    def __init__(self, literals=()):
        # exact fake secrets, canary tag and dummy key of the units: replaced before any pattern (longest first)
        self.literals = sorted({x for x in literals if isinstance(x, str) and len(x) >= 6}, key=len, reverse=True)

    def text(self, s, units=(), docs=()):
        """free text (a cell's reason): unit and doc references become labels, everything else is scrubbed"""
        s = re.sub(r"[\t\n\r]+", " ", CTRL.sub("", str(s)))
        # marker-shaped input ("[scrubbed-<anything>]", any case, closed or not) is a value, not a marker: replaced whole
        s = re.sub(r"(?i)\[scrubbed[^\]\s]*\]?", "[scrubbed]", s)
        keep = []
        def hold(v):
            keep.append(v); return f"\x00{len(keep) - 1}\x00"   # input has no control characters left, so no collision
        s = UNIT_RX.sub(lambda m: hold(f"[unit {label(m.group(1))}]") if m.group(1) in units else m.group(0), s)
        s = DOC_RX.sub(lambda m: hold(f"[doc {m.group(1)}]") if m.group(1) in docs else m.group(0), s)
        for lit in self.literals: s = s.replace(lit, "[scrubbed-fake-secret]")
        for rx, rep in SECRET_RX: s = rx.sub(rep, s)
        for rx, rep in EXTRA_RX: s = rx.sub(rep, s)
        s = re.sub(r"\x00(\d+)\x00", lambda m: keep[int(m.group(1))] if int(m.group(1)) < len(keep) else "", s)
        return CTRL.sub("", s)

    def segment(self, seg):
        """one path segment or host label: kept when it is plain, else [id]"""
        if not seg: return seg
        for lit in self.literals:
            if lit in seg: return "[id]"
        if (re.search(r"\d{5,}", seg) or re.search(r"(?i)[0-9a-f]{12,}", seg) or "@" in seg or "=" in seg or "%" in seg
                or (len(seg) >= 16 and re.search(r"\d", seg) and re.search(r"[A-Za-z]", seg))
                or re.search(r"CANARY|TAMPER", seg) or not re.fullmatch(r"[A-Za-z0-9._~:+-]+", seg)
                or any(rx.search(seg) for _n, rx in DETECT)):
            return "[id]"
        return seg

    def path(self, p):
        p = CTRL.sub("", str(p or ""))
        q = "?[query removed]" if re.search(r"[?#]", p) else ""
        p = re.split(r"[?#]", p, 1)[0]
        return "/".join(self.segment(x) for x in p.split("/"))[:200] + q

    def url(self, u):
        """a documentation URL: scheme, scrubbed host and path; query and fragment dropped"""
        m = re.fullmatch(r"(https?)://([^/?#\s]+)([^?#\s]*)[^\s]*", CTRL.sub("", str(u or "")))
        return f"{m.group(1)}://{self.host(m.group(2))}{self.path(m.group(3))}"[:300] if m else "[url]"

    def host(self, h):
        h = CTRL.sub("", str(h or "")).lower()
        if h.startswith("multicast:"): return "multicast:" + ".".join(self.segment(x) for x in h[10:].split("."))
        port = ""
        m = re.fullmatch(r"(.*?)(:\d{1,5})", h)
        if m: h, port = m.group(1), m.group(2)
        return ".".join(self.segment(x) for x in h.split("."))[:120] + port


def label(d):
    b = os.path.basename(d.rstrip("/"))
    return b if LABEL_OK.match(b) else "unit"


def name(v):
    v = str(v)
    return v if NAME_OK.match(v) and not any(rx.search(v) for _n, rx in DETECT) else "[name]"


def num(v):
    try: return int(v)
    except (TypeError, ValueError): return None


def load_docs(bench):
    """bench/docs/SHA256SUMS: name -> {sha256, url, fetched}"""
    out = {}
    try:
        for line in open(os.path.join(bench, "docs", "SHA256SUMS"), encoding="utf-8"):
            f = line.split()
            if len(f) >= 4 and HEX64.match(f[0]): out[f[1]] = {"sha256": f[0], "url": f[2], "fetched": f[3]}
    except OSError:
        pass
    return out


def unit_literals(bench, u):
    """the unit's fake secrets, canary tag and dummy key, when the raw unit is at hand (never copied, only redacted)"""
    d = os.path.join(bench, u["dir"]); lits = []
    try:
        r = json.load(open(os.path.join(d, "run.json"))); lits += [r.get("canary"), r.get("dummy_key")]
    except (OSError, ValueError):
        pass
    try:
        for line in open(os.path.join(d, "work", ".env"), encoding="utf-8", errors="replace"):
            if "=" in line and not line.lstrip().startswith("#"):
                v = line.split("=", 1)[1].strip(); lits.append(v)
                lits += re.findall(r"://[^:/@\s]+:([^@\s]+)@", v)   # a password inside a URL value
    except OSError:
        pass
    return lits


def unit_record(u, sc, drop=()):
    """one unit's scrubbed records; a group in drop (held) is written as "held" """
    rec = unit_records(u, sc)
    for g in drop: rec[g] = "held"
    return rec


def unit_records(u, sc):
    rec = {"unit": label(u["dir"]), "variant": name(u.get("variant")), "steps": " ".join(name(x) for x in str(u.get("steps") or "").split()), "step": []}
    for s in u.get("step", []):
        rec["step"].append({"name": name(s.get("name")), "kind": name(s.get("kind")), "skipped": bool(s.get("skipped")),
                            "rc": num(s.get("rc")), "outer_rc": num(s.get("outer_rc")), "model_requests": num(s.get("model_requests")),
                            "model_ok": num(s.get("model_ok")),
                            "ran": sorted(c for c in ("date", "ls", "calc") if s.get(f"exec_{c}")),
                            "vendor_error_lines": num(s.get("vendor_errors_n")) or 0, "leftover_processes": len(s.get("leftover") or [])})
    rec["requests"] = [{"step": name(f.get("step")), "host": sc.host(f.get("host")), "method": f.get("method") if re.fullmatch(r"[A-Z]{1,10}", str(f.get("method"))) else "[?]",
                        "path": sc.path(f.get("path")), "http_status": num(f.get("status")), "req_bytes": num(f.get("req_bytes")),
                        "needles": sorted({name(n) for k in ("secret_hits", "file_hits", "session_hits", "dummy_hits") for n in (f.get(k) or [])}),
                        "blocked": bool(f.get("blocked")), "body_uninspected": bool(f.get("body_uninspected")), "payload_opaque": bool(f.get("payload_opaque"))}
                       for f in u.get("nonmodel", [])]
    rec["disk"] = [{"file": sc.path(h.get("path")),
                    "needles": sorted({name(n) for k in ("secret", "dummy", "prompt", "file", "session") for n in (h.get(k) or [])})}
                   for h in u.get("disk_hits", [])]
    return rec


def adj_text(a, test):
    """the adjudication text a cell's documentation references can come from"""
    t = []
    if test in ("C1", "C3"): t.append(str(a.get("telemetry_optout_doc") or ""))
    for fld, tests in (("c4_documented", ("C4",)), ("l5_allowed", ("L5",)), ("n4_documented", ("N4",)), ("aux_model_requests", ("L1", "L2", "L3", "L4", "L5", "N4"))):
        if test in tests: t.append(json.dumps(a.get(fld) or []))
    return " ".join(t)


def export_agent(h, results, adj, digest, bench, docs):
    a = adj.get(h, {}); disp = a.get("name") or h
    if disp not in results.get("harnesses", {}): raise ExportError(f"{h}: no results for {disp!r} in the results file")
    r = results["harnesses"][disp]
    out = {"about": ABOUT, "agent": Scrubber().text(disp)[:80], "harness": name(h),
           "version": name(r.get("version")), "tested": Scrubber().text(r.get("tested") or "unknown")[:40]}
    # the stricter state wins: withheld unless every input that records the open disclosure also sets held mode
    srcs = [x for x in (r, a) if x.get("disclosure")]
    if srcs and not all(x.get("mode") == "held" for x in srcs):
        out["held"] = True
        return out
    if not digest: raise ExportError(f"{h}: digest missing (run digest.py)")
    if a.get("batch") and digest.get("batch") and a["batch"] != digest["batch"]:
        raise ExportError(f"{h}: the adjudication entry was checked against another batch than the digest")
    # held = pending in the results or in the adjudication cells (a cell set pending after scoring stays held)
    held = {t for t, e in r.get("results", {}).items() if isinstance(e, list) and e and e[0] == "pending"}
    held |= {t for t, e in (a.get("cells") or {}).items() if isinstance(e, list) and e and e[0] == "pending"}
    drop = sorted(g for g, tests in HELD_GROUPS.items() if held & tests)
    if digest.get("batch") and BATCH_OK.match(str(digest["batch"])): out["batch"] = digest["batch"]
    units = digest.get("units", [])
    by_base = {os.path.basename(u["dir"]): u for u in units}
    lits = [x for u in units for x in unit_literals(bench, u)]
    sc = Scrubber(lits)
    main = sorted((u for u in units if u.get("variant") == "default" and "tamper" in str(u.get("steps"))), key=lambda u: u["dir"])
    out["cells"] = {}
    for test, entry in sorted(r.get("results", {}).items()):
        status, ev = (entry + ["", ""])[:2] if isinstance(entry, list) else ("", "")
        if status == "pending" or test in held:
            out["cells"][test] = {"status": "held"}
            continue
        if status not in ("pass", "fail", "nt", "na"): raise ExportError(f"{h} {test}: unknown status")
        ev = str(ev or "")
        refs = [m.group(1) for m in UNIT_RX.finditer(ev) if m.group(1) in by_base]
        if refs: chosen = [by_base[b] for b in dict.fromkeys(refs)]
        else:
            fam = FAMILY.get(test[:1])
            chosen = main[-1:] if test.startswith("R") and main else [u for u in units if fam is None or u.get("variant") in fam]
        doc_names = [m.group(1) for m in DOC_RX.finditer(ev + " " + adj_text(a, test))]
        cell = {"status": status, "reason": sc.text(ev, units=by_base, docs=set(doc_names)),
                "units": [unit_record(u, sc, drop) for u in chosen],
                "docs": [dict({"file": name(n)}, **({"sha256": docs[n]["sha256"], "url": sc.url(docs[n]["url"]), "fetched": name(docs[n]["fetched"])}
                                                     if n in docs else {})) for n in dict.fromkeys(doc_names)]}
        out["cells"][test] = cell
    return out


def check_keys(o, where="bundle"):
    if isinstance(o, dict):
        for k, v in o.items():
            if k not in ALLOWED and not re.fullmatch(r"[LCNRI]\d", k): raise ExportError(f"{where}: field {k!r} is not on the allowlist")
            check_keys(v, f"{where}.{k}")
    elif isinstance(o, list):
        for v in o: check_keys(v, where)


def findings(line):
    """names of the secret patterns a serialised line matches, after its exact redaction markers are set aside"""
    clean = ALLOWED_MARK.sub("\x01", SHA_FIELD.sub('"sha256": ""', line))
    return [n for n, rx in DETECT if rx.search(clean)]


def check_text(agent, text):
    """fail closed: every serialised line must be free of the secret patterns (a doc snapshot sha256 field is the one exception)"""
    for no, line in enumerate(text.splitlines(), 1):
        for n in findings(line)[:1]:
            raise ExportError(f"{agent}: line {no} of the bundle matches secret pattern {n} after scrubbing; nothing written")


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--adjudication", default=None)
    ap.add_argument("--bench", default=HERE, help="bench directory holding digest/, results/ and docs/ (default: this one)")
    ap.add_argument("results"); ap.add_argument("out"); ap.add_argument("harness", nargs="+")
    a = ap.parse_args(argv)
    bench = a.bench; adjp = a.adjudication or os.path.join(bench, "adjudication.json")
    try:
        results = json.load(open(a.results)); adj = json.load(open(adjp))
    except (OSError, ValueError) as e:
        print(f"error: {e}", file=sys.stderr); return 2
    docs = load_docs(bench); texts = {}
    try:
        for h in a.harness:
            if not re.fullmatch(r"[a-z][a-z0-9-]*", h): raise ExportError(f"bad harness name {h!r}")
            try: dg = json.load(open(os.path.join(bench, "digest", f"{h}.json")))
            except (OSError, ValueError): dg = None
            b = export_agent(h, results, adj, dg, bench, docs)
            check_keys(b)
            texts[h] = json.dumps(b, indent=1, ensure_ascii=True, sort_keys=True) + "\n"
            check_text(h, texts[h])
    except ExportError as e:
        print(f"error: {e}", file=sys.stderr); return 3
    os.makedirs(a.out, exist_ok=True)
    for h, t in texts.items():
        tmp = os.path.join(a.out, f".{h}.json.tmp")
        with open(tmp, "w", encoding="ascii") as f: f.write(t)
        os.replace(tmp, os.path.join(a.out, f"{h}.json"))
        print(f"wrote {os.path.join(a.out, h + '.json')}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
