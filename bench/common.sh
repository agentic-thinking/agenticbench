# Shared names for build.sh and bench/*.sh. Sourced, not run. Expects L = repository root.
TAG=20260926
BASE=agenticbench-base:$TAG; TOOLS=agenticbench-tools:$TAG; MITM=agenticbench-mitm:$TAG
NET=agenticbench-net
CA=$L/ca

harness_names(){ awk '!/^#/ && NF {print $1}' "$L/harnesses.txt"; }
harness_row(){ awk -v h="$1" '!/^#/ && $1 == h {print; f=1} END {exit !f}' "$L/harnesses.txt"; }

# Operator configuration (rig.conf.example documents every key).
load_conf(){
  local c=${RIG_CONF:-$L/rig.conf}
  [ -f "$c" ] || { echo "missing $c: copy rig.conf.example to rig.conf and edit it" >&2; return 1; }
  # shellcheck disable=SC1090
  source "$c"
}
