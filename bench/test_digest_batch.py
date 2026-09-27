"""digest.py must not fall back to an older batch while the newest batch is unfinished or unanalysed."""
import json, os, shutil, subprocess, sys, tempfile, unittest

HERE = os.path.dirname(os.path.abspath(__file__))


class DigestBatch(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="abdig-")
        shutil.copy(os.path.join(HERE, "digest.py"), self.tmp); shutil.copytree(os.path.join(HERE, "lib"), os.path.join(self.tmp, "lib"))

    def tearDown(self): shutil.rmtree(self.tmp, True)

    def unit(self, name, batch, analysed):
        d = os.path.join(self.tmp, "results", name); os.makedirs(d)
        run = {"harness": "fx", "batch": batch}
        json.dump(run, open(f"{d}/run.json", "w"))
        if analysed: json.dump({"run": run, "steps": [], "model_requests": [], "nonmodel_flows": []}, open(f"{d}/summary.json", "w"))

    def digest(self, *args):
        return subprocess.run([sys.executable, os.path.join(self.tmp, "digest.py"), "fx", *args], capture_output=True, text=True)

    def test_unfinished_newer_batch_is_refused(self):
        self.unit("fx-1", "b1", True); self.unit("fx-2", "b2", False)
        r = self.digest()
        self.assertNotEqual(r.returncode, 0); self.assertIn("name the one to digest", r.stderr)

    def test_partly_analysed_newest_batch_is_refused(self):
        self.unit("fx-1", "b2", True); self.unit("fx-2", "b2", False)
        self.assertIn("unfinished or not analysed", self.digest().stderr)

    def test_planned_batch_that_never_started_is_refused(self):
        self.unit("fx-1", "b1", True)
        os.makedirs(os.path.join(self.tmp, "results"), exist_ok=True)
        open(os.path.join(self.tmp, "results", "runlist-b2.txt"), "w").write("fx default h:env\nother default h:env\n")
        self.assertIn("name the one to digest", self.digest().stderr)
        open(os.path.join(self.tmp, "results", "runlist-b3.txt"), "w").write("other default h:env\n")   # another harness's plan is ignored
        self.assertIn("name the one to digest", self.digest().stderr)

    def test_older_batch_can_be_named(self):
        # a complete, really analysed unit (built by the capture tests' fixture) in b1, plus an unfinished b2
        sys.path.insert(0, HERE); import test_capture as tc
        U = tc.make_unit(tempfile.mkdtemp(dir=self.tmp), flows=[("/e", [], {"url_truncated": False})]); tc.analyse(U)
        dst = os.path.join(self.tmp, "results", "fx-1"); shutil.copytree(U, dst)
        for f in ("run.json", "summary.json"):
            j = json.load(open(f"{dst}/{f}")); (j["run"] if f == "summary.json" else j)["batch"] = "b1"; json.dump(j, open(f"{dst}/{f}", "w"))
        self.unit("fx-2", "b2", False)
        r = self.digest("b1")
        self.assertEqual(r.returncode, 0, r.stderr)
        dg = json.load(open(os.path.join(self.tmp, "digest", "fx.json")))
        self.assertEqual(dg["batch"], "b1")
        self.assertEqual(dg["units"][0]["step"][0]["model_seq"], [])   # the per-request list reaches the scorer (aux_model_requests)

    def test_named_batch_must_be_complete(self):
        self.unit("fx-1", "b2", True); self.unit("fx-2", "b2", False)
        self.assertIn("unfinished or not analysed", self.digest("b2").stderr)

    def test_free_text_batch_names_are_not_ordered(self):
        self.unit("fx-1", "trial", True); self.unit("fx-2", "20260927T072920Z-1", True)
        r = self.digest(); self.assertIn("name the one to digest", r.stderr)


if __name__ == "__main__":
    unittest.main()
