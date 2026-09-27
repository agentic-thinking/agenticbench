# Harness adapters

One file per harness, sourced by `bench/unit.sh`. The image and version come from `harnesses.txt`; the model provider comes
from `rig.conf` (`MODEL_ID`, `MODEL_OPENAI_PATH`, `MODEL_ANTHROPIC_PATH`). Available to an adapter: `$R` (unit directory; write
harness config into `$R/home`, which becomes the empty HOME), `$PROXY` (capture proxy URL), `$DUMMY` (per-unit fake key the
proxy swaps for the real one), `ENVS` (extra `-e` arguments for the harness container).

| Name | Meaning |
|---|---|
| `MODEL` | `proxy` (third-party backend through the capture proxy, the default) or `vendor` (vendor-hosted model, logged-in account) |
| `FLAGS` | every documented approval flag or mode, one variant each (N units) |
| `L3VARIANT` | the minimal documented flag that lets the agent read `.env`, used only when both default prompts did not read it |
| `CRED_DEST` | vendor-hosted only: where the harness keeps its credential file, relative to HOME |
| `CRED_STORES` | vendor-hosted only, optional: space-separated HOME-relative paths of every file the vendor documents as its credential store (default: `CRED_DEST`). Only these are skipped by the scrub copy (after a needle scan) and only their account credential strings are exempt in R5; a file is never treated as a store because of its name |
| `VENDOR_MODEL` | vendor-hosted only, optional: the model the adapter selects explicitly; recorded as `model_id` in run.json |
| `TMO` | per-step timeout in seconds (default 180) |
| `ERROR_RE` | optional: a case-insensitive regex for this harness's own account or billing error wording, added to the built-in list in `bench/lib/vendor_errors.py` (and to `<harness>_ERROR_RE` from `rig.conf`). A headless or resume step whose stdout or stderr matches does not count as worked |
| `b_setup V`, `b_env V` | write config for variant V into `$R/home`; add environment for variant V to `ENVS` |
| `b_cmd V` | the documented headless command; the prompt is in `$PROMPT` |
| `b_resume V` | optional: headless resume of the most recent session |
| `b_tui V` | optional: the interactive entry point (no function = no interactive mode; the step is recorded as skipped) |
| `b_export` | optional: the harness's own record export |

Kinds in `harnesses.txt`: `npm`, `pypi` (package at the pinned version), `uv` (a PyPI tool at the pinned version, installed with
uv into its own uv-managed CPython, with optional `+`-joined extras each pinned `pkg==ver`: `openhands`, `pydanticai`), `tar`,
`appimage`, `gz`, `targz` (a downloaded release file; an optional sixth column gives its sha256, required for `gz` and `targz`) and
`dockerfile` (a directory in this repository whose Dockerfile builds
the image, for vendor installers: `docker/hermes`). `python3 -m unittest test_adapters` (from `bench/`) checks every row and adapter
offline.

A variant not in `FLAGS` is not in the batch plan; run it with `bench/unit.sh HARNESS VARIANT STEP...` as an extra unit
(`hermes quiet`, `openclaw local`, `cursor gitrepo`). A harness that documents no headless resume keeps `b_resume` as a step that prints that and
exits non-zero (`dsh`, `openclaw`). A harness with no session to resume at all defines no `b_resume` (`pydanticai`, one-shot
`clai`); the step is recorded as skipped. L5, which needs a working resume, is then nt as with a
failing resume; N4 reads the steps that ran, so a skipped resume does not make it nt, where a failing one does.

Variant `optout` sets every documented telemetry, update and catalogue switch of the harness. Record the documentation
page for each switch in your adjudication file.
