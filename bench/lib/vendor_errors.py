"""Known vendor account and billing errors in a step's own output (METHOD.md, "worked").

A harness can exit 0 after printing a vendor error instead of doing the task (Amp printed "Error: Out of Credits ... Add
credits to keep using Amp." on stderr, exited 0 and ran nothing, while its model requests were answered). analyse_unit.py
scans the full stdout and stderr of every headless and resume step, line by line and case-insensitively, against PATTERNS
plus the harness-specific patterns of the unit (run.json "error_re": the adapter's ERROR_RE and rig.conf's <harness>_ERROR_RE).
A step with a match, or whose output could not be read, does not count as worked (score_bench.py): tests that need the run
are nt (METHOD.md lists the verdicts a test's own rules can still reach). The list is the one place these patterns live.
It is a list: novel wording is not caught (KNOWN-LIMITATIONS.md).

Each entry is (name, regex). Keep patterns specific to account, plan and billing messages: the step's output also holds
the model's answer, and a match means the step did not work.
"""
import re

PATTERNS = [
    ("out_of_credits", r"\bout of credits?\b|\badd (more )?credits\b|\b(insufficient|not enough|no remaining) (credits?|balance|funds)\b"
                       r"|\bcredit balance (is )?too low\b"),
    ("quota_exceeded", r"\bquota (has been |was )?(exceeded|exhausted|reached)\b|\bexceeded (your|the) (current )?quota\b|\binsufficient_quota\b"
                       r"|\bresource_exhausted\b|\busage limit (has been |was )?(reached|exceeded|hit)\b"
                       r"|\byou('ve| have) (reached|hit|exceeded) (your|the) (\w+ )?(usage |request |message )?limit\b"),
    ("rate_limited", r"\brate[ _-]?limit(ed|s)?\b|\btoo many requests\b|\b429\b.{0,40}\b(too many|rate)\b"),
    ("plan_does_not_allow_model", r"\b(plan|subscription|tier|account) (does not|doesn't|do not|don't) (allow|include|support|have access to|permit)\b"
                                  r"|\bnot (available|allowed|supported|included) (on|for|in|with) (your|the current) (plan|subscription|tier|account)\b"
                                  r"|\brequires? an? (paid|pro|higher|upgraded|different) (plan|subscription|tier)\b"),
    ("not_logged_in", r"\bnot (logged|signed) in\b|\b(log|sign) ?in (again|first|to continue)\b|\bsession (has )?expired\b"
                      r"|\b(token|credentials?|login) (has |have )?expired\b|\b(invalid|expired|missing) (api[ _-]?key|access token|credentials)\b"
                      r"|\b401\b.{0,20}\bunauthori[sz]ed\b|\berror\W{0,3}unauthori[sz]ed\b|\bauthentication (failed|required)\b"),
    ("payment_required", r"\bpayment required\b|\b(http|status|code|error)\W{0,3}402\b|\bbilling (issue|problem|error|required)\b"
                         r"|\b(payment|billing) (method|details|information) (is )?(required|missing|failed|declined)\b"
                         r"|\bsubscription (has )?(expired|lapsed|been cancell?ed)\b"),
]

# Terminal control sequences, parsed without consuming visible text: CSI (ESC [ or the 8-bit CSI, ECMA-48 parameter bytes
# including ":" colour forms), OSC / DCS / SOS / PM / APC strings (up to BEL or ST, never past the next ESC, so the visible
# text of an OSC 8 hyperlink stays), then any other escape sequence.
ANSI = re.compile(r"(?:\x1b\[|\x9b)[0-?]*[ -/]*[@-~]|(?:\x1b[\]PX^_]|[\x90\x98\x9d\x9e\x9f])[^\x07\x1b\x9c]*(?:\x07|\x1b\\|\x9c)?|\x1b[ -/]*[0-~]")
SENSITIVE = r"api[_-]?key|x-api-key|access[_-]?token|refresh[_-]?token|id[_-]?token|auth[_-]?token|token|secret|client[_-]?secret|password|passwd|pwd|authorization|cookie|session(?:[_-]?id)?|sid|credential|signature|sig|key"
# an assigned value: a quoted value with its backslash escapes, closed and followed by a delimiter; else anything that opens
# with a quote (escaped or not) is unterminated or ambiguous and is replaced to the end of the line; else a bare value
VALUE = r"(\"(?:[^\"\\]|\\.)*\"(?=[\s,;&)}\]]|$)|'(?:[^'\\]|\\.)*'(?=[\s,;&)}\]]|$)|\\?[\"'].*|[^\s,;&)}\]]+)"
# secrets a matched line could carry. Order matters: whole header values first, then quoted or bare assignments, then shapes.
SECRET_RX = [
    (re.compile(r"(?i)\b((?:proxy-)?authorization|(?:set-)?cookie|x-api-key|api-key)(\s*[:=]\s*).*$"), r"\1\2[scrubbed]"),
    (re.compile(r"(?i)\b(bearer|basic|token|digest)\s+[A-Za-z0-9._~+/=-]{6,}"), r"\1 [scrubbed]"),
    (re.compile(r"(?i)((?:\\?[\"'])?\b(?:" + SENSITIVE + r")\b(?:\\?[\"'])?\s*[=:]\s*)(?!\[scrubbed)" + VALUE), r"\1[scrubbed]"),
    (re.compile(r"(?i)(https?://)[^/\s:@]+:[^/\s@]+@"), r"\1[scrubbed]@"),                       # user:password in a URL
    (re.compile(r"(?i)(https?://[^\s?#]*\?)[^\s#]*"), r"\1[scrubbed]"),                            # URL query strings
    (re.compile(r"\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}(\.[A-Za-z0-9_-]+)?"), "[scrubbed]"),
    (re.compile(r"\b(sk|pk|rk|sgamp|ghp|gho|ghs|ghu|github_pat|glpat|xox[abpr]|AKIA|ASIA|AIza|ya29|rvt)[-_.A-Za-z0-9]{6,}"), "[scrubbed]"),
    (re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"), "[scrubbed-email]"),
    (re.compile(r"(?<![A-Za-z0-9])(?=[A-Za-z0-9_+/=.-]*[0-9])(?=[A-Za-z0-9_+/=.-]*[A-Za-z])[A-Za-z0-9_+/=.-]{16,}"), "[scrubbed]"),
]
MAX_LINE, MAX_MATCHES = 300, 20
BOMS = [(b"\x00\x00\xfe\xff", "utf-32-be"), (b"\xff\xfe\x00\x00", "utf-32-le"), (b"\xef\xbb\xbf", "utf-8"), (b"\xfe\xff", "utf-16-be"), (b"\xff\xfe", "utf-16-le")]


def compile_patterns(extra=()):
    """PATTERNS plus harness-specific regexes (adapter ERROR_RE, rig.conf <harness>_ERROR_RE). An invalid extra regex raises."""
    out = [(n, re.compile(rx, re.I)) for n, rx in PATTERNS]
    for i, rx in enumerate(extra):
        if not isinstance(rx, str) or not rx.strip(): raise ValueError(f"error_re[{i}] must be a non-empty regex")
        out.append((f"harness_error_re[{i}]", re.compile(rx, re.I)))
    return out


def decode(b):
    """the text of a step's output, or None when it cannot be read as text. A byte-order mark selects UTF-8, UTF-16 or UTF-32
    (strict). Without one, a NUL byte means an encoding the scan cannot read (UTF-16 without BOM, binary): None. Otherwise
    UTF-8, with invalid bytes replaced; the ASCII bytes of every ASCII-compatible encoding are kept, so English error text
    is still found."""
    for bom, enc in BOMS:
        if b.startswith(bom):
            try: return b[len(bom):].decode(enc)
            except UnicodeDecodeError: return None
    if b"\x00" in b: return None
    return b.decode("utf-8", "replace")


def scrub(line):
    """a matched line as recorded in summary.json and in score evidence: control sequences and characters stripped, credential
    values, tokens, URL queries and email addresses replaced, at most MAX_LINE characters."""
    line = re.sub(r"[\x00-\x08\x0b-\x1f\x7f-\x9f]", "", ANSI.sub("", line)).strip()
    for rx, rep in SECRET_RX: line = rx.sub(rep, line)
    return line[:MAX_LINE] + ("..." if len(line) > MAX_LINE else "")


def scan(text, stream, compiled, keep=MAX_MATCHES):
    """(the first `keep` matching lines as [{"pattern", "stream", "line_no", "line"}], number of matching lines). A line is
    tested with its control sequences stripped and as written (either matching counts); the first pattern per line is kept."""
    hits, n = [], 0
    for no, raw in enumerate(text.splitlines(), 1):
        clean = ANSI.sub("", raw)
        for name, rx in compiled:
            if rx.search(clean) or rx.search(raw):
                n += 1
                if len(hits) < keep: hits.append({"pattern": name, "stream": stream, "line_no": no, "line": scrub(raw)})
                break
    return hits, n
