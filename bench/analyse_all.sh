#!/bin/bash
# Analyse every finished unit that has no summary yet (-f: all units), then write one digest per harness.
# Usage: analyse_all.sh [-f]
# analyse_unit.py runs in the tools container (python3 + tshark), as the calling user, with no network.
set -u
S=$(cd "$(dirname "$0")" && pwd); L=$(cd "$S/.." && pwd); source "$S/common.sh"; F=${1:-}; bad=0
[ -d "$S/results" ] || { echo "no results yet: run bench/batch.sh first" >&2; exit 2; }
for d in "$S"/results/*/; do d=${d%/}
  [ -f "$d/done" ] || { [ -f "$d/run.json" ] && echo "skipping unfinished unit $d" >&2; continue; }
  [ -z "$F" ] && [ -f "$d/summary.json" ] && continue
  docker run --rm --network none --user "$(id -u):$(id -g)" -e HOME=/tmp -v "$S:/b" "$TOOLS" \
    python3 /b/analyse_unit.py "/b/results/$(basename "$d")" >/dev/null || { echo "FAILED analysis of $d" >&2; bad=1; }
done
for h in $(for d in "$S"/results/*/run.json; do python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["harness"])' "$d"; done | sort -u); do
  python3 "$S/digest.py" "$h" ${AB_DIGEST_BATCH:+"$AB_DIGEST_BATCH"} || bad=1
done
exit $bad
