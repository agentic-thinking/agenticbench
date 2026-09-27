# DeepSeek Harness (dsh), headless profile. Its only model backend is the DeepSeek API (DEEPSEEK_BASE_URL, DEEPSEEK_API_KEY; the
# model is not configurable), so rig.conf must point MODEL_UPSTREAM at the DeepSeek API or a compatible one; MODEL_ID is not used.
# The base URL is the capture proxy's root, as the harness appends its own paths.
# Approval is DSH_PERMISSION_MODE (default workspace-write). Opt-out: the documented telemetry switches plus a patch overlay that
# turns off the session-log plugin. The headless profile has no resume option: the resume step records that and exits non-zero.
FLAGS="pm-read-only pm-danger-full-access"
b_setup(){ case $1 in optout) printf -- '- id: session-log-deepseek\n  config:\n    enabled: false\n' > $R/out/optout-patch.yml;; esac; }
b_env(){ ENVS+=(-e DEEPSEEK_BASE_URL=$PROXY -e DEEPSEEK_API_KEY=$DUMMY)
  case $1 in optout) ENVS+=(-e DSH_TELEMETRY_MODE=DISABLED -e DSH_TELEMETRY_DISABLED=1);; pm-*) ENVS+=(-e DSH_PERMISSION_MODE=${1#pm-});; esac; }
b_cmd(){ case $1 in optout) echo 'dsh --profile headless --patch /out/optout-patch.yml "$PROMPT"';; *) echo 'dsh --profile headless "$PROMPT"';; esac; }
b_resume(){ echo 'echo "dsh: the headless profile has no resume option (dsh --profile headless --help)" >&2; (exit 64)'; }
# no TUI profile ships; the interactive surface is the local web profile
b_tui(){ case $1 in optout) echo 'dsh --profile web --patch /out/optout-patch.yml';; *) echo 'dsh --profile web';; esac; }
