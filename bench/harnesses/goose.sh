# Goose: OpenAI provider pointed at the configured provider through the capture proxy. Approval behaviour is GOOSE_MODE.
FLAGS="mode-approve mode-smart_approve mode-chat mode-auto"
b_setup(){ case $1 in optout) mkdir -p $R/home/.config/goose; echo 'GOOSE_TELEMETRY_ENABLED: false' > $R/home/.config/goose/config.yaml;; esac; }
b_env(){ ENVS+=(-e GOOSE_PROVIDER=openai -e GOOSE_MODEL=$MODEL_ID -e OPENAI_HOST=$PROXY -e OPENAI_BASE_PATH=${MODEL_OPENAI_PATH#/}/chat/completions
                -e OPENAI_API_KEY=$DUMMY -e GOOSE_DISABLE_KEYRING=1)
  case $1 in optout) ENVS+=(-e GOOSE_TELEMETRY_OFF=1);; mode-*) ENVS+=(-e GOOSE_MODE=${1#mode-});; esac; }
b_cmd(){ echo 'goose run -t "$PROMPT"'; }
b_resume(){ echo 'goose run -r -t "$PROMPT"'; }
b_tui(){ echo 'goose session'; }
