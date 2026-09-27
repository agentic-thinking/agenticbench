# OpenHands CLI: OpenAI-compatible provider through the capture proxy, set with the documented LLM_MODEL / LLM_BASE_URL /
# LLM_API_KEY variables and --override-with-envs (docs: cli/command-reference). Documented: headless mode always runs in
# always-approve mode and --llm-approve is not available there (docs: cli/headless); both approval flags still get a unit each.
# The CLI documents no telemetry, update or catalogue switch for a third-party provider, so optout sets nothing extra.
# Export uses the documented `openhands view` on the first conversation in this HOME, i.e. the one step A created.
FLAGS="always-approve llm-approve"
b_setup(){ :; }
b_env(){ ENVS+=(-e LLM_MODEL=openai/$MODEL_ID -e LLM_BASE_URL=$PROXY$MODEL_OPENAI_PATH -e LLM_API_KEY=$DUMMY); }
b_f(){ case $1 in always-approve) echo '--always-approve';; llm-approve) echo '--llm-approve';; esac; }
b_cmd(){ echo "openhands --headless --override-with-envs $(b_f $1) -t \"\$PROMPT\""; }
b_resume(){ echo "openhands --headless --override-with-envs --resume --last $(b_f $1) -t \"\$PROMPT\""; }
b_tui(){ echo "openhands --override-with-envs $(b_f $1)"; }
b_export(){ echo 'CID=$(ls -tr $HOME/.openhands/conversations | head -1); echo "conversation=$CID" >&2; openhands view "$CID" --limit 1000'; }
