# Grok Build (xAI, the official x.ai/cli binary): no xAI login, custom OpenAI-compatible model "lab" (the configured provider,
# through the capture proxy). Approval: --always-approve and --permission-mode MODE (user guide, permissions and safety).
# Opt-out = every documented local switch in ~/.grok/config.toml (user guide, configuration and config reference).
FLAGS="always pm-acceptEdits pm-auto pm-dontAsk pm-bypassPermissions"
b_setup(){ mkdir -p $R/home/.grok
  { printf '[models]\ndefault = "lab"\n\n[model.lab]\nmodel = "%s"\nbase_url = "%s%s"\nname = "lab"\nenv_key = "RIG_MODEL_KEY"\n' "$MODEL_ID" "$PROXY" "$MODEL_OPENAI_PATH"
    case $1 in optout) printf '\n[cli]\nauto_update = false\n\n[features]\ntelemetry = false\nfeedback = false\n\n[telemetry]\ntrace_upload = false\nmixpanel_enabled = false\n\n[harness]\ndisable_codebase_upload = true\ndisable_workspace_teleport = true\n';; esac
  } > $R/home/.grok/config.toml; }
b_env(){ ENVS+=(-e RIG_MODEL_KEY=$DUMMY); }
b_f(){ case $1 in always) echo '--always-approve';; pm-*) echo "--permission-mode ${1#pm-}";; esac; }
b_cmd(){ echo "grok --output-format json $(b_f $1) -p \"\$PROMPT\""; }
b_resume(){ echo "grok -c --output-format json $(b_f $1) -p \"\$PROMPT\""; }
b_tui(){ echo 'grok'; }
