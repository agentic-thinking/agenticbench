# Codex: custom model provider (Responses API of the configured provider, through the capture proxy), no vendor login.
FLAGS="s-read-only s-workspace-write ap-on-request approve-for-me bypass"
b_setup(){ mkdir -p $R/home/.codex; { echo "model = \"$MODEL_ID\""; echo 'model_provider = "lab"'
  case $1 in optout) printf 'check_for_update_on_startup = false\n[analytics]\nenabled = false\n[feedback]\nenabled = false\n';; esac
  printf '[model_providers.lab]\nname = "lab"\nbase_url = "%s%s"\nenv_key = "RIG_MODEL_KEY"\nwire_api = "responses"\n' "$PROXY" "$MODEL_OPENAI_PATH"; } > $R/home/.codex/config.toml; }
b_env(){ ENVS+=(-e RIG_MODEL_KEY=$DUMMY); }
b_f(){ case $1 in s-*) echo "-s ${1#s-}";; ap-*) echo "-c approval_policy=\\\"${1#ap-}\\\"";; approve-for-me) echo '--approve-for-me';; bypass) echo '--dangerously-bypass-approvals-and-sandbox';; esac; }
b_cmd(){ echo "codex exec --skip-git-repo-check --json $(b_f $1) \"\$PROMPT\""; }
b_resume(){ echo "codex exec --skip-git-repo-check --json $(b_f $1) resume --last \"\$PROMPT\""; }
b_tui(){ echo 'codex'; }
