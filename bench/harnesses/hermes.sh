# Hermes Agent (NousResearch): named custom provider "lab" (the configured provider, through the capture proxy), model MODEL_ID.
# The image is built from docker/hermes/Dockerfile (the vendor installer at the release commit).
# Headless = `hermes chat --oneshot -q` (stock approvals: approvals.mode smart). TUI = `hermes`.
# Extra variant `quiet` (not in FLAGS; run it with bench/unit.sh as an extra unit): optout plus the documented local security
# scanner and lazy-install switches off.
FLAGS="mode-manual mode-off yolo"
b_setup(){ mkdir -p $R/home/.hermes
  { printf 'model:\n  default: %s\n  provider: lab\n' "$MODEL_ID"
    # context_length is the declared window of the model entry; set it to your provider's value if it differs
    printf 'providers:\n  lab:\n    api: %s%s\n    key_env: RIG_MODEL_KEY\n    transport: chat_completions\n    context_length: 1000000\n    models:\n      %s:\n        context_length: 1000000\n' "$PROXY" "$MODEL_OPENAI_PATH" "$MODEL_ID"
    # optout = documented telemetry, update and catalogue switches (relay-shared-metrics.md, getting-started/updating.md,
    # reference/model-catalog.md). quiet = optout plus security.tirith_enabled / security.allow_lazy_installs off (user-guide/security.md).
    case $1 in optout|quiet) printf 'updates:\n  check: false\nmodel_catalog:\n  enabled: false\ntelemetry:\n  shared_metrics:\n    enabled: false\n    send: false\n'
                             [ $1 != quiet ] || printf 'security:\n  tirith_enabled: false\n  allow_lazy_installs: false\n';;
               mode-*) printf 'approvals:\n  mode: %s\n' "${1#mode-}";; esac
  } > $R/home/.hermes/config.yaml; }
b_env(){ ENVS+=(-e RIG_MODEL_KEY=$DUMMY); }
b_f(){ case $1 in yolo) echo '--yolo';; esac; }
b_cmd(){ echo "hermes chat --oneshot $(b_f $1) -q \"\$PROMPT\""; }
b_resume(){ echo "hermes chat --oneshot --continue $(b_f $1) -q \"\$PROMPT\""; }
b_tui(){ echo 'hermes'; }
