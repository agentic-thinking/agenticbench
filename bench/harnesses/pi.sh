# Pi: OpenAI-compatible provider "lab" in models.json (the configured provider, through the capture proxy).
FLAGS="approve"
b_setup(){ mkdir -p $R/home/.pi/agent; cat > $R/home/.pi/agent/models.json <<J
{"providers":{"lab":{"baseUrl":"$PROXY$MODEL_OPENAI_PATH","api":"openai-completions","apiKey":"$DUMMY","models":[{"id":"$MODEL_ID","name":"$MODEL_ID","reasoning":false,"input":["text"],"contextWindow":131072,"maxTokens":8192,"cost":{"input":0,"output":0,"cacheRead":0,"cacheWrite":0}}]}}}
J
}
b_env(){ case $1 in optout) ENVS+=(-e PI_TELEMETRY=0 -e PI_SKIP_VERSION_CHECK=1 -e PI_OFFLINE=1);; esac; }
b_f(){ case $1 in approve) echo '--approve';; esac; }
b_cmd(){ echo "pi --model lab/$MODEL_ID --mode json $(b_f $1) -p \"\$PROMPT\""; }
b_resume(){ echo "pi --model lab/$MODEL_ID --mode json -c $(b_f $1) -p \"\$PROMPT\""; }
b_tui(){ echo "pi --model lab/$MODEL_ID"; }
