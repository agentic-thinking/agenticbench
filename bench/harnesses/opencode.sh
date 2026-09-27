# OpenCode: custom OpenAI-compatible provider "lab" (the configured provider, through the capture proxy).
FLAGS="auto perm-ask"; L3VARIANT=auto
ocfg(){ printf '{"provider":{"lab":{"npm":"@ai-sdk/openai-compatible","name":"lab","options":{"baseURL":"%s%s","apiKey":"{env:RIG_MODEL_KEY}"},"models":{"%s":{"name":"%s"}}}}%s}' \
  "$PROXY" "$MODEL_OPENAI_PATH" "$MODEL_ID" "$MODEL_ID" "$1"; }
b_setup(){ :; }
b_env(){ ENVS+=(-e RIG_MODEL_KEY=$DUMMY)
  case $1 in
    optout) ENVS+=(-e "OPENCODE_CONFIG_CONTENT=$(ocfg ',"autoupdate":false,"share":"disabled"')" -e OPENCODE_DISABLE_AUTOUPDATE=1
                   -e OPENCODE_DISABLE_MODELS_FETCH=1 -e OPENCODE_DISABLE_SHARE=1 -e OPENCODE_DISABLE_LSP_DOWNLOAD=1 -e OPENCODE_DISABLE_CLAUDE_CODE=1);;
    perm-ask) ENVS+=(-e "OPENCODE_CONFIG_CONTENT=$(ocfg ',"permission":{"bash":"ask"}')");;   # documented: permission.bash = "ask"
    *) ENVS+=(-e "OPENCODE_CONFIG_CONTENT=$(ocfg '')");; esac; }
b_f(){ case $1 in auto) echo '--auto';; esac; }
b_cmd(){ echo "opencode run -m lab/$MODEL_ID --format json $(b_f $1) \"\$PROMPT\""; }
b_resume(){ echo "opencode run -c -m lab/$MODEL_ID --format json $(b_f $1) \"\$PROMPT\""; }
b_tui(){ echo "opencode -m lab/$MODEL_ID"; }
