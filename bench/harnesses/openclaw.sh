# OpenClaw: custom OpenAI-compatible provider "lab" in models.providers (the configured provider, through the capture proxy),
# model MODEL_ID. Default headless = `openclaw agent exec` (a temporary state dir, removed after the run, so it has no resume:
# the resume step records that and exits non-zero). Extra variant `local` (not in FLAGS; run it with bench/unit.sh as an extra
# unit for the record tests) = `openclaw agent --local --session-id`, the embedded path that keeps its sessions.
# contextWindow and maxTokens are declared limits of the model entry; set them to your provider's values if they differ.
FLAGS="mode-ask mode-allowlist mode-deny mode-auto mode-full"
b_setup(){ mkdir -p $R/home/.openclaw; local extra='' ws=''
  [ "$1" = local ] && ws=',"workspace":"/work"'
  case $1 in optout) extra=',"update":{"checkOnStart":false},"telemetry":{"enabled":false}';;
             mode-*) extra=",\"tools\":{\"exec\":{\"mode\":\"${1#mode-}\"}}";; esac
  cat > $R/home/.openclaw/openclaw.json <<J
{"models":{"providers":{"lab":{"baseUrl":"$PROXY$MODEL_OPENAI_PATH","apiKey":"\${RIG_MODEL_KEY}","api":"openai-completions","models":[{"id":"$MODEL_ID","name":"$MODEL_ID","reasoning":false,"input":["text"],"cost":{"input":0,"output":0,"cacheRead":0,"cacheWrite":0},"contextWindow":1000000,"maxTokens":8192}]}}},"agents":{"defaults":{"model":{"primary":"lab/$MODEL_ID"}$ws}}$extra}
J
}
b_env(){ ENVS+=(-e RIG_MODEL_KEY=$DUMMY); case $1 in optout) ENVS+=(-e OPENCLAW_NO_AUTO_UPDATE=1 -e DO_NOT_TRACK=1 -e OPENCLAW_DISABLE_BONJOUR=1);; esac; }
b_cmd(){ case $1 in local) echo 'openclaw agent --local --session-id bench-main --json -m "$PROMPT"';;
         *) echo "openclaw agent exec \"\$PROMPT\" --model lab/$MODEL_ID --json";; esac; }
b_resume(){ case $1 in local) echo 'openclaw agent --local --session-id bench-main --json -m "$PROMPT"';;
            *) echo 'echo "openclaw: agent exec has no resume (each run gets a new temporary state dir)" >&2; (exit 3)';; esac; }
b_tui(){ echo 'openclaw chat'; }
