# Kilo: custom OpenAI-compatible provider "lab" (the configured provider, through the capture proxy).
FLAGS="auto"; L3VARIANT=auto
kcfg(){ printf '{"provider":{"lab":{"npm":"@ai-sdk/openai-compatible","name":"lab","options":{"baseURL":"%s%s","apiKey":"{env:RIG_MODEL_KEY}"},"models":{"%s":{"name":"%s"}}}}%s}' \
  "$PROXY" "$MODEL_OPENAI_PATH" "$MODEL_ID" "$MODEL_ID" "$1"; }
b_setup(){ :; }
b_env(){ ENVS+=(-e RIG_MODEL_KEY=$DUMMY)
  case $1 in
    optout) ENVS+=(-e "KILO_CONFIG_CONTENT=$(kcfg ',"experimental":{"openTelemetry":false}')" -e KILO_TELEMETRY_LEVEL=off -e KILO_DISABLE_AUTOUPDATE=1
                   -e KILO_DISABLE_MODELS_FETCH=1 -e KILO_DISABLE_SHARE=1 -e KILO_DISABLE_SESSION_INGEST=1 -e KILO_DISABLE_LSP_DOWNLOAD=1);;
    *) ENVS+=(-e "KILO_CONFIG_CONTENT=$(kcfg '')");; esac; }
b_f(){ case $1 in auto) echo '--auto';; esac; }
b_cmd(){ echo "kilo run -m lab/$MODEL_ID --format json $(b_f $1) \"\$PROMPT\""; }
b_resume(){ echo "kilo run -c -m lab/$MODEL_ID --format json $(b_f $1) \"\$PROMPT\""; }
b_tui(){ echo "kilo -m lab/$MODEL_ID"; }
