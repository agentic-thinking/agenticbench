# Cline CLI: OpenAI-compatible provider (the configured provider, through the capture proxy). `cline auth` is the documented
# provider set-up and runs before every command.
FLAGS="aa-false aa-true"
b_setup(){ case $1 in optout) mkdir -p $R/home/.cline/data/settings; echo '{"telemetryOptOut":true,"autoUpdateEnabled":false}' > $R/home/.cline/data/settings/global-settings.json;; esac; }
b_env(){ :; }
b_f(){ case $1 in aa-false) echo '--auto-approve false';; aa-true) echo '--auto-approve true';; esac; }
AUTH="cline auth -p openai -k \"\$DUMMY\" -m $MODEL_ID -b \"\$PROXY$MODEL_OPENAI_PATH\" >/out/cline-auth.log 2>&1"
b_cmd(){ echo "$AUTH; cline --json -t 150 $(b_f $1) \"\$PROMPT\""; }
b_resume(){ echo "ID=\$(ls -t \$HOME/.cline/data/sessions 2>/dev/null | head -1); echo resume-id=\$ID >&2; cline -t 150 $(b_f $1) --id \"\$ID\" \"\$PROMPT\""; }
b_tui(){ echo "bash -c '$AUTH; exec cline --tui'"; }
