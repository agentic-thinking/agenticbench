# ZCode: the agent CLI bundled in the desktop app, custom OpenAI-compatible provider "lab" (the configured provider, through
# the capture proxy). The bundled CLI is run headless (-p); the adapter defines no interactive mode.
FLAGS="mode-build mode-edit mode-plan"
b_setup(){ mkdir -p $R/home/.zcode/cli; cat > $R/home/.zcode/cli/config.json <<J
{"provider":{"lab":{"kind":"openai-compatible","name":"lab","options":{"apiKey":"$DUMMY","baseURL":"$PROXY$MODEL_OPENAI_PATH"},"models":{"$MODEL_ID":{"name":"$MODEL_ID"}}}},"model":"lab/$MODEL_ID"}
J
}
b_env(){ case $1 in optout) ENVS+=(-e ZCODE_MODEL_TELEMETRY_ENABLED=0);; esac; }
b_f(){ case $1 in mode-*) echo "--mode ${1#mode-}";; esac; }
b_cmd(){ echo "zcode $(b_f $1) -p \"\$PROMPT\""; }
b_resume(){ echo "zcode -c $(b_f $1) -p \"\$PROMPT\""; }
