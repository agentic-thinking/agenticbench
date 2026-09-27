# Pydantic AI Harness coder, run with the documented `clai -a pydantic_ai_harness.coder:coder_agent` (pydantic-ai-harness README;
# pinned clai, pydantic-ai and pydantic-ai-harness[coder] in harnesses.txt). OpenAI-compatible chat completions provider
# ("openai-chat:" model prefix, OPENAI_BASE_URL / OPENAI_API_KEY) through the capture proxy.
# Documented: Coder's shell tool is unrestricted, with no approval system and no approval flags (so FLAGS and L3VARIANT are
# empty); clai one-shot mode has no resume or record export. Pydantic AI sends to Logfire only if logfire is configured and
# instrumentation enabled (docs/logfire.md); clai does neither, and documents no telemetry or update switch, so optout sets
# nothing extra.
FLAGS=""
b_setup(){ :; }
b_env(){ ENVS+=(-e OPENAI_API_KEY=$DUMMY -e OPENAI_BASE_URL=$PROXY$MODEL_OPENAI_PATH); }
b_cmd(){ echo "clai -a pydantic_ai_harness.coder:coder_agent -m openai-chat:$MODEL_ID \"\$PROMPT\""; }
b_tui(){ echo "clai -a pydantic_ai_harness.coder:coder_agent -m openai-chat:$MODEL_ID"; }
