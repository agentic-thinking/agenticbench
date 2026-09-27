# Kimi Code: OpenAI-compatible provider (the configured provider, through the capture proxy).
FLAGS="yolo auto"
b_setup(){ mkdir -p $R/home/.kimi-code; { echo 'default_model = "lab"'; case $1 in optout) echo 'telemetry = false';; esac
  printf '[providers.lab]\ntype = "openai"\nbase_url = "%s%s"\napi_key_env = "RIG_MODEL_KEY"\n[models.lab]\nprovider = "lab"\nmodel = "%s"\nmax_context_size = 131072\n' \
    "$PROXY" "$MODEL_OPENAI_PATH" "$MODEL_ID"; } > $R/home/.kimi-code/config.toml
  case $1 in optout) printf '[upgrade]\nauto_install = false\n' > $R/home/.kimi-code/tui.toml;; esac; }
b_env(){ ENVS+=(-e RIG_MODEL_KEY=$DUMMY); case $1 in optout) ENVS+=(-e KIMI_DISABLE_TELEMETRY=1 -e KIMI_CODE_NO_AUTO_UPDATE=1 -e NO_UPDATE_NOTIFIER=1);; esac; }
b_f(){ case $1 in yolo) echo '--yolo';; auto) echo '--auto';; esac; }
b_cmd(){ echo "kimi --output-format stream-json $(b_f $1) -p \"\$PROMPT\""; }
b_resume(){ echo "kimi -c --output-format stream-json $(b_f $1) -p \"\$PROMPT\""; }
b_tui(){ echo 'kimi'; }
