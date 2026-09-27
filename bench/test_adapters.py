#!/usr/bin/env python3
"""Adapter self-test, no Docker and no network: every harnesses.txt row has an adapter that sources cleanly, writes its config for
every variant inside the unit directory only, and yields headless commands that parse; build.sh generates a Dockerfile for every
row (with its sha256 pin where one is given) or finds the repository Dockerfile of kind dockerfile.
Usage: cd bench && python3 -m unittest test_adapters"""
import os, re, subprocess, tempfile, unittest

S = os.path.dirname(os.path.abspath(__file__)); L = os.path.dirname(S)
KINDS = {"npm", "tar", "appimage", "gz", "pypi", "dockerfile"}


def rows():
    out = []
    for line in open(f"{L}/harnesses.txt"):
        if line.strip() and not line.startswith("#"):
            out.append(line.split())
    return out


# sources one adapter with a fictional unit and model; prints FLAGS, then for each variant the files written and the commands
PROBE = r'''set -u   # R = unit directory, A = adapter (environment: some bash wrappers drop positional arguments)
MODEL_ID=model-x; PROXY=http://proxy.test:8080; MODEL_OPENAI_PATH=/v1; MODEL_ANTHROPIC_PATH=/anthropic; DUMMY=sk-dummy
MODEL=proxy; TMO=180; FLAGS=''; L3VARIANT=''; CRED_DEST=''; CRED_STORES=''; ERROR_RE=''; ENVS=()
source "$A"
for f in b_setup b_env b_cmd; do declare -F $f >/dev/null || { echo "missing $f"; exit 3; }; done
echo "FLAGS=$FLAGS"; echo "MODEL=$MODEL"; echo "L3=$L3VARIANT"; echo "ERROR_RE=$ERROR_RE"
for V in default optout $FLAGS $L3VARIANT; do
  rm -rf "$R/home" "$R/out"; mkdir -p "$R/home" "$R/out"; ENVS=()
  b_setup $V || { echo "setup $V failed"; exit 4; }; b_env $V || { echo "env $V failed"; exit 4; }
  echo "VARIANT $V"; echo "CMD $(b_cmd $V)"
  declare -F b_resume >/dev/null && echo "RESUME $(b_resume $V)"
  declare -F b_tui >/dev/null && echo "TUI $(b_tui $V)"
  echo "ENVS ${ENVS[*]:-}"
done
'''


class Adapters(unittest.TestCase):
    def test_rows_are_well_formed(self):
        names = [r[0] for r in rows()]
        self.assertEqual(len(names), len(set(names)), "duplicate harness names")
        for r in rows():
            with self.subTest(r[0]):
                self.assertIn(len(r), (5, 6), r)
                n, k, s, v, e = r[:5]
                self.assertIn(k, KINDS)
                self.assertTrue(re.fullmatch(r"[a-z][a-z0-9-]*", n) and v and e)
                if len(r) == 6: self.assertRegex(r[5], r"^[0-9a-f]{64}$")
                if k == "gz": self.assertEqual(len(r), 6, "kind gz needs a sha256 pin")
                if k in ("tar", "appimage", "gz"): self.assertTrue(s.startswith("https://"), s)
                if k == "dockerfile":
                    self.assertFalse(os.path.isabs(s) or ".." in s.split("/"), s)
                    self.assertTrue(os.path.isfile(f"{L}/{s}/Dockerfile"), s)
                self.assertTrue(os.path.isfile(f"{S}/harnesses/{n}.sh"), f"no adapter for {n}")

    def test_every_adapter_has_a_row(self):
        names = {r[0] for r in rows()}
        for f in os.listdir(f"{S}/harnesses"):
            if f.endswith(".sh"): self.assertIn(f[:-3], names, f)

    def test_adapters_source_and_write_inside_the_unit_only(self):
        for r in rows():
            n = r[0]
            with self.subTest(n), tempfile.TemporaryDirectory() as t:
                R = os.path.join(t, "unit"); os.makedirs(R)
                p = subprocess.run(["bash", "-c", PROBE], capture_output=True, text=True, cwd=t, timeout=60,
                                   env={"PATH": os.environ["PATH"], "HOME": os.path.join(t, "nohome"), "R": R, "A": f"{S}/harnesses/{n}.sh"})
                self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
                self.assertEqual(sorted(os.listdir(t)), ["unit"], "adapter wrote outside the unit directory")
                self.assertIn(p.stdout.split("\n")[1], ("MODEL=proxy", "MODEL=vendor"))
                er = re.search(r"^ERROR_RE=(.*)$", p.stdout, re.M)
                if er and er.group(1): re.compile(er.group(1))
                cmds = re.findall(r"^(?:CMD|RESUME|TUI) (.*)$", p.stdout, re.M)
                self.assertTrue(cmds)
                for c in cmds:
                    self.assertTrue(c.strip(), f"{n}: empty command")
                    chk = subprocess.run(["bash", "-n", "-c", c], capture_output=True, text=True)
                    self.assertEqual(chk.returncode, 0, f"{n}: {c}: {chk.stderr}")
                # no operator paths, account names or real keys in the adapter source
                src = open(f"{S}/harnesses/{n}.sh").read()
                self.assertNotRegex(src, r"(?<![\w}])/home/|/Users/|~/[a-z]|\b(?:sk|ghp|xox[abpr])-?[A-Za-z0-9]{16,}")

    def test_build_generates_a_dockerfile_for_every_row(self):
        gen = r'''set -eu; source "$L/bench/common.sh"
eval "$(sed -n '/^pin(){/,/; }$/p;/^gen(){/,/^}$/p' "$L/build.sh")"
read -r n k s v e p <<< "$(harness_row "$H")"
[ "$k" = dockerfile ] && { cat "$L/$s/Dockerfile"; exit 0; }
gen "$n" "$k" "$s" "$v" "$e" "$p"'''
        for r in rows():
            with self.subTest(r[0]):
                p = subprocess.run(["bash", "-c", gen], capture_output=True, text=True, timeout=60, env={"PATH": os.environ["PATH"], "L": L, "H": r[0]})
                self.assertEqual(p.returncode, 0, p.stderr)
                self.assertRegex(p.stdout, r"(?m)^FROM ")
                if len(r) == 6: self.assertIn(f"echo '{r[5]}  /tmp/", p.stdout)
                if r[1] == "dockerfile":
                    self.assertRegex(p.stdout, r"(?m)^FROM \$\{BASE\}$")
                    self.assertRegex(p.stdout, r"sha256sum -c")

    def test_gz_without_pin_and_bad_pin_are_refused(self):
        gen = r'''eval "$(sed -n '/^pin(){/,/; }$/p;/^gen(){/,/^}$/p' "$L/build.sh")"; BASE=b
gen x gz https://example.test/x.gz 1 x "$PIN"'''
        for pin in ("", "abc"):
            p = subprocess.run(["bash", "-c", gen], capture_output=True, text=True, timeout=60, env={"PATH": os.environ["PATH"], "L": L, "PIN": pin})
            self.assertNotEqual(p.returncode, 0, pin)


if __name__ == "__main__":
    unittest.main()
