# Aider: OpenAI-compatible provider via litellm (the configured provider, through the capture proxy).
# Default has no --yes-always; variant yes adds it. Documented opt-outs are the CLI flags in b_f optout.
FLAGS="yes"
b_setup(){ :; }
b_env(){ ENVS+=(-e OPENAI_API_KEY=$DUMMY -e OPENAI_API_BASE=$PROXY$MODEL_OPENAI_PATH); case $1 in optout) ENVS+=(-e LITELLM_LOCAL_MODEL_COST_MAP=True);; esac; }
b_f(){ case $1 in yes) echo '--yes-always';; optout) echo '--no-analytics --no-check-update --no-show-release-notes';; esac; }
b_cmd(){ echo "aider --model openai/$MODEL_ID $(b_f $1) --message \"\$PROMPT\""; }
b_resume(){ echo "aider --model openai/$MODEL_ID --restore-chat-history $(b_f $1) --message \"\$PROMPT\""; }
b_tui(){ echo "aider --model openai/$MODEL_ID $(b_f $1)"; }
