#!/bin/bash
# Run the full unit list of METHOD.md for one or more harnesses, JOBS units at a time (default 4).
# Usage: batch.sh HARNESS [HARNESS...]      (log: results/batch.log; each finished unit prints its directory there)
# All units of one call share a batch id (run.json "batch"); digest.py digests one batch only, and when a harness has several
# it must be named (AB_DIGEST_BATCH=<batch> bench/analyse_all.sh), so a re-run never mixes with older units. Exit 1 (and how many) if any unit failed or has missing evidence; exit 3 if every unit
# finished without evidence problems but some harness step exited non-zero (listed as NONZERO_EXIT; e.g. an expected refusal).
# Units per harness:
#   default h:env [export] tamper resume h:date   main unit (A, tamper, resume, B in one HOME)
#   default h:date                                fresh HOME (C)
#   default tui                                   20 s idle interactive boot
#   default h:catenv                              second, more direct L3 prompt (used only if A did not read the file)
#   optout h:env  /  optout tui                   every documented opt-out set (C3, C4)
#   default h:ls / h:calc / h:calc:cl / h:date:cl no-human runs in the default mode (N, R2)
#   <flag> h:calc                                 one unit per documented approval flag or mode (FLAGS in the adapter)
#   <L3VARIANT> h:env                             minimal documented flag that lets the agent read .env (if the adapter sets one)
set -u
S=$(cd "$(dirname "$0")" && pwd); L=$(cd "$S/.." && pwd); JOBS=${JOBS:-4}
[ $# -ge 1 ] || { sed -n '2,3p' "$0" >&2; exit 2; }
for h in "$@"; do [ -f "$S/harnesses/$h.sh" ] || { echo "no adapter bench/harnesses/$h.sh" >&2; exit 2; }; done
mkdir -p "$S/results"; chmod 700 "$S/results"
export AB_BATCH=$(date -u +%Y%m%dT%H%M%SZ)-$$
LIST=$S/results/runlist-$AB_BATCH.txt
for h in "$@"; do
  read -r FLAGS L3 EXP < <(ADAPTER="$S/harnesses/$h.sh" bash -c 'R=/nonexistent; FLAGS=; L3VARIANT=; source "$ADAPTER" >/dev/null 2>&1
    F=${FLAGS// /,}; echo "${F:--}" "${L3VARIANT:--}" "$(declare -F b_export >/dev/null && echo export || echo -)"')
  [ "$FLAGS" = - ] && FLAGS=''
  [ "$EXP" = - ] && EXP=''
  echo "$h default h:env $EXP tamper resume h:date"; echo "$h default h:date"; echo "$h default tui"; echo "$h default h:catenv"
  echo "$h optout h:env"; echo "$h optout tui"
  for p in h:ls h:calc h:calc:cl h:date:cl; do echo "$h default $p"; done
  for f in ${FLAGS//,/ }; do echo "$h $f h:calc"; done
  [ "$L3" != - ] && echo "$h $L3 h:env"
done > "$LIST"
N=$(wc -l < "$LIST"); echo "batch $AB_BATCH: $N units listed in $LIST"; echo "BATCH_START $AB_BATCH" >> "$S/results/batch.log"
# each unit prints its directory on success or "UNIT_FAILED <args>" (its own messages go to batch.log)
UNIT="$S/unit.sh" xargs -P "$JOBS" -L 1 sh -c '"$UNIT" "$@" || echo "UNIT_FAILED $*"' unit < "$LIST" >> "$S/results/batch.log" 2>&1
XR=$?
# Counted from the results, not from the log. A unit is
#   clean       finished (done marker), empty problem list, and every headless/resume/export step exited 0
#   non-zero    finished with an empty problem list, but a harness step exited non-zero: a refusal can do that on purpose, so it
#               is not an evidence problem, but it is never counted as clean; the scorer only uses a step that exited 0 as "worked"
#   failed      anything else (no done marker, problems recorded, unit.sh failed)
OK=0; NZ=0; NZL=()
for d in "$S"/results/*/; do
  grep -q "\"batch\": \"$AB_BATCH\"" "$d/run.json" 2>/dev/null || continue
  [ -f "$d/done" ] && [ -f "$d/out/problems.txt" ] && [ -z "$(tr -d '[:space:]' < "$d/out/problems.txt")" ] || continue
  nz=$(for f in "$d"/out/*-h-*.rc "$d"/out/*-resume.rc "$d"/out/*-export.rc; do [ -f "$f" ] && [ "$(cat "$f")" != 0 ] && echo "$(basename "$f" .rc)=$(cat "$f")"; done)
  if [ -z "$nz" ]; then OK=$((OK+1)); else NZ=$((NZ+1)); NZL+=("$(basename "$d"): $(echo $nz)"); fi
done
echo "BATCH_DONE $AB_BATCH $*: $OK of $N units clean, $NZ finished with a non-zero harness exit, $((N-OK-NZ)) failed" | tee -a "$S/results/batch.log"
for x in ${NZL[@]+"${NZL[@]}"}; do echo "NONZERO_EXIT $x" | tee -a "$S/results/batch.log"; done
[ $XR -eq 0 ] || { echo "xargs failed (exit $XR): check JOBS=$JOBS" >&2; exit 1; }
[ $((OK+NZ)) -eq "$N" ] || { echo "$((N-OK-NZ)) unit(s) failed or had missing evidence: see UNIT_FAILED lines in $S/results/batch.log and out/problems.txt in each unit" >&2; exit 1; }
[ "$NZ" -eq 0 ] || { echo "$NZ unit(s) had a harness step exit non-zero (NONZERO_EXIT lines above): check each is an expected refusal" >&2; exit 3; }
