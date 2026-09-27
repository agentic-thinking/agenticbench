# Qwen Code: OpenAI-compatible provider (the configured provider, through the capture proxy). The prompt goes before the
# flags because --allowed-tools is an array option.
FLAGS="am-plan am-auto-edit am-auto yolo allowed-shell"
b_setup(){ mkdir -p $R/home/.qwen; case $1 in
  optout) echo '{"security":{"auth":{"selectedType":"openai"}},"privacy":{"usageStatisticsEnabled":false},"telemetry":{"enabled":false},"general":{"enableAutoUpdate":false}}' ;;
  *) echo '{"security":{"auth":{"selectedType":"openai"}}}' ;; esac > $R/home/.qwen/settings.json; }
b_env(){ ENVS+=(-e OPENAI_API_KEY=$DUMMY -e OPENAI_BASE_URL=$PROXY$MODEL_OPENAI_PATH -e OPENAI_MODEL=$MODEL_ID); }
b_f(){ case $1 in am-*) echo "--approval-mode ${1#am-}";; yolo) echo '--yolo';; allowed-shell) echo '--allowed-tools run_shell_command';; esac; }
b_cmd(){ echo "qwen --output-format stream-json \"\$PROMPT\" $(b_f $1)"; }
b_resume(){ echo "qwen --continue --output-format stream-json \"\$PROMPT\" $(b_f $1)"; }
b_tui(){ echo 'qwen'; }
