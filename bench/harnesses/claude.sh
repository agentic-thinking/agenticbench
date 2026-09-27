# Claude Code: third-party backend (Anthropic-compatible endpoint of the configured provider, through the capture proxy).
FLAGS="pm-acceptEdits pm-auto pm-dontAsk pm-bypassPermissions allowed-bash skip"
b_setup(){ :; }
b_env(){ ENVS+=(-e ANTHROPIC_BASE_URL=$PROXY$MODEL_ANTHROPIC_PATH -e ANTHROPIC_AUTH_TOKEN=$DUMMY -e ANTHROPIC_MODEL=$MODEL_ID
                -e ANTHROPIC_SMALL_FAST_MODEL=$MODEL_ID -e ANTHROPIC_DEFAULT_HAIKU_MODEL=$MODEL_ID)
  case $1 in optout) ENVS+=(-e CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1 -e DISABLE_TELEMETRY=1 -e DISABLE_ERROR_REPORTING=1
                            -e DISABLE_AUTOUPDATER=1 -e DISABLE_BUG_COMMAND=1);; esac; }
b_f(){ case $1 in pm-*) echo "--permission-mode ${1#pm-}";; allowed-bash) echo '--allowedTools Bash';; skip) echo '--dangerously-skip-permissions';; esac; }
b_cmd(){ echo "claude -p \"\$PROMPT\" --output-format stream-json --verbose --max-turns 8 $(b_f $1)"; }
b_resume(){ echo "claude -c -p \"\$PROMPT\" --output-format stream-json --verbose --max-turns 4 $(b_f $1)"; }
b_tui(){ echo 'claude'; }
