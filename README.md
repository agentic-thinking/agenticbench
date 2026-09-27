# AgenticBench rig

Open test rig for measuring what AI coding agents do on your machine: what leaves the machine and to whom, whether consent and opt-outs work, what happens with no human present, and whether the agent's own record shows what it did.

This repository contains code and method only. It contains no results, captures or verdicts about any agent. Published results are at https://agenticbench.org.

A pass describes one measured run within the implemented procedure. Read [KNOWN-LIMITATIONS.md](KNOWN-LIMITATIONS.md) for detection boundaries, nt gates, human adjudication, logged-in modes and the absence of repeated trials.

## Contents

| Path | What it is |
|---|---|
| `METHOD.md` | Scoring rule, common set-up, per-test procedure and pass/fail definition for every test |
| `KNOWN-LIMITATIONS.md` | Evidence gaps, detection boundaries and possible error directions |
| `THREAT-MODEL.md` | Whose side the tests take and how each data flow is classed |
| `CHARTER.md`, `DISCLOSURE.md` | Governance and vendor disclosure policy |
| `score/tests.json` | The test definitions (v0.2); METHOD.md and the code follow it |
| `harnesses.txt` | Harness versions under test, and where each comes from |
| `rig.conf.example` | Operator configuration: model provider, vendor-hosted harness settings, optional safety block |
| `build.sh`, `docker/` | Builds every image (base, tools, mitm, one per harness) and creates the lab CA |
| `bench/unit.sh`, `bench/batch.sh` | One test unit; the full unit list of METHOD.md for one or more harnesses |
| `bench/harnesses/` | One adapter per harness: headless command, opt-out switches, approval flags (see its README) |
| `bench/analyse_all.sh`, `bench/analyse_unit.py`, `bench/digest.py` | Mechanical facts from the captures |
| `bench/adjudication.example.json`, `bench/adjudication_init.py` | Template and starter for the hand-checked inputs |
| `bench/score_bench.py`, `bench/test_score_bench.py`, `bench/test_evidence_model.py` | Captures plus adjudication to per-test results (the input of `score/score.py`), and its tests |
| `bench/view.py`, `bench/r1check.py`, `bench/recdump.py`, `bench/snapshot_doc.sh` | Adjudication helpers |
| `lab/` | Capture proxy, canary workspace generator, credential scrubber |
| `score/` | Scorer and chart: `score.py`, `test_score.py`, `example-results.json` (fictional) |

## Requirements

- Linux (x86_64) with Docker; your user must be able to run `docker`. Any host uid works: inside the containers the harness runs as uid 1000, your key and credential files are read by your own user, and each unit's files are handed back to your user when it ends.
- Python 3.10 or newer with `brotli` and `zstandard` for full L2 decoding on the scoring host (Debian/Ubuntu packages `python3-brotli` and `python3-zstandard`; missing comparison decoders force nt for affected bodies), `curl`, and about 3 GB of disk for the shared images plus 0.5 to 2 GB per harness image.
- An API key for a model provider with an OpenAI-compatible API (chat completions; Codex also needs the Responses API). Claude Code also needs an Anthropic-compatible endpoint from the same provider. Keep the key in a file outside this repository. It is mounted read-only into the capture proxy container only; the harness holds a random dummy key that the proxy swaps for the real one.
- Vendor-hosted harnesses (`amp`, `auggie`) need your own logged-in account; see `rig.conf.example`.

## Run one agent end to end

The example uses Goose; any name in `harnesses.txt` works the same way. Run every command from the repository root.

**1. Configure.**

```bash
cp rig.conf.example rig.conf
```

Edit `rig.conf`: `MODEL_KEYFILE` (the key file outside this repository), `MODEL_UPSTREAM` (host name of the provider's API), `MODEL_ID`, and the base paths if your provider uses others.

**2. Build** the infrastructure images, the lab CA (first run only, in `ca/`, git-ignored) and the harness image. The script stops with a non-zero exit code if any build fails.

```bash
./build.sh goose
```

**3. Run the full unit list** of METHOD.md for the harness (about 15 units, 4 at a time; set `JOBS` to change that). It usually takes a few minutes, and longer with slow models. Each finished unit writes its directory to `bench/results/batch.log`; the command ends with `BATCH_DONE`, which counts units as clean, non-zero (a harness step such as an export, a headless run or a resume exited non-zero, listed on `NONZERO_EXIT` lines) or failed. It exits 1 if any unit failed or had missing evidence (see `out/problems.txt` in that unit), 3 if no unit failed but some had a non-zero harness exit (check that each is an expected refusal; the scorer never counts such a step as having worked), and 0 only when every unit is clean. Running it again starts a new batch. When a harness has more than one batch, later steps refuse to guess: name the batch to use (`AB_DIGEST_BATCH=<batch> bench/analyse_all.sh`, and the same batch in `adjudication.json`).

```bash
bench/batch.sh goose
```

**4. Analyse** every finished unit and write the per-harness digest (`bench/digest/goose.json`).

```bash
bench/analyse_all.sh
```

**5. Adjudicate.** Create `bench/adjudication.json` from the template. The command lists every non-model endpoint the harness contacted, and ties the entry to the batch you analysed (after a re-run, `score_bench.py` refuses the old entry until you re-check it and update its `batch` field).

```bash
python3 bench/adjudication_init.py goose
```

Then edit the `goose` entry by hand, following `METHOD.md` and the field notes in `bench/adjudication.example.json`: classify each endpoint (`classes`), name the vendor's hosts (`vendor_hosts`), record the documented opt-out (`telemetry_optout_doc`), and replace each `cells` placeholder (C2, C5, N1, N2, N5, R1, R2) with a verdict and its evidence. If the harness ends steps with an auxiliary model request (a session title or summary) that fails after the turn was answered, record it in `aux_model_requests` with a path or body regex and the evidence of its purpose (METHOD.md, "worked"); without such a rule the step did not work. A step whose stdout or stderr holds a known vendor account or billing error (out of credits, quota, rate limit, plan, login, payment; `bench/lib/vendor_errors.py`) did not work either, even when it exited 0 and `BATCH_DONE` counted its unit as clean: `view.py` and each unit's `summary.json` (`vendor_errors`, with the matched line) show it. Add a harness's own wording with `ERROR_RE` in its adapter or `<harness>_ERROR_RE` in rig.conf before the batch. For a no-auto-approve-flags N5 pass, set `n5_no_flags` to `{"value": true, "quote": "documentation citation and finding"}`; the recorded batch plan must also contain no flag units. Keep `bench/results/runlist-BATCH.txt` with the evidence because approval-mode passes are bound to that plan. Helpers: `python3 bench/view.py goose` (all units at a glance), `python3 bench/r1check.py UNITDIR MODEL_ID` (R1), `python3 bench/recdump.py UNITDIR` (R2), and `bench/snapshot_doc.sh URL NAME` (saves a documentation page with its hash). A cell you leave unadjudicated stays nt, and an endpoint you leave unclassified keeps nt every test that depends on its purpose (for L2, only when it carries a candidate identifier); neither can turn into a pass.

**6. Convert** the captures and the adjudication into scorer input.

```bash
python3 bench/score_bench.py bench/scores-input.json goose
```

**7. Score and draw the chart.**

```bash
python3 score/score.py --tests score/tests.json --results bench/scores-input.json --out score/out
```

`score/out/` then holds `scores.json` (scores, every result with its evidence, and the informational rows), `scores.svg` (chart), `scores.html` (table) and `evidence.html` (every test's status and evidence, and I1 to I4, per agent). To score several harnesses together, run steps 2 to 5 for each and name them all in step 6.

Self-tests (no Docker needed): `(cd score && python3 -m unittest -v)` and `(cd bench && python3 -m unittest -v test_score_bench test_capture test_evidence_model test_digest_batch)` (`test_capture` also runs `bench/batch.sh` against a fake unit script; it needs bash).

## Single units and clean-up

`bench/unit.sh HARNESS VARIANT STEP...` runs one unit (variants and steps are listed in its header); with no step it prints its usage. Digests and scores use whole batches only: to digest units you ran by hand, give them a common batch id with `AB_BATCH=<name> bench/unit.sh ...`. Everything the rig starts is labelled `org.agenticbench.rig`: `docker ps -a --filter label=org.agenticbench.rig` lists any container left by an interrupted run.

## Handling results

`bench/results/` holds the captures: your model requests and responses, the canary workspace, and the harness's HOME. It contains only the dummy key and fake secrets, never your model key, but with a vendor-hosted harness it also holds scrubbed account traffic. Review captures before you share them, and never commit them; `.gitignore` excludes `rig.conf`, `ca/`, `bench/results/`, `bench/digest/`, `bench/docs/` and `bench/adjudication.json`.

Before publishing a finding about an agent, follow `DISCLOSURE.md`.

## Licence

Apache-2.0. Copyright Agentic Thinking Ltd.
