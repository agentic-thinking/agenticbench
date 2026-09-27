#!/bin/bash
# Save a vendor documentation or privacy page as adjudication evidence (C2, C4, C5, N1, N2, N4, N5, R2).
# Usage: snapshot_doc.sh URL NAME      -> bench/docs/NAME (the page as fetched), plus a line in bench/docs/SHA256SUMS with the URL and
# UTC fetch time. bench/docs/ is git-ignored: publish snapshots with your results, not in this repository.
set -euo pipefail
S=$(cd "$(dirname "$0")" && pwd); [ $# -eq 2 ] || { sed -n '2,4p' "$0" >&2; exit 2; }
case $2 in */*|.*) echo "NAME must be a plain file name" >&2; exit 2;; esac
mkdir -p "$S/docs"; curl -fsSL --max-time 60 -o "$S/docs/$2" "$1"
echo "$(sha256sum "$S/docs/$2" | cut -d' ' -f1)  $2  $1  $(date -u +%FT%TZ)" >> "$S/docs/SHA256SUMS"
echo "saved bench/docs/$2"
