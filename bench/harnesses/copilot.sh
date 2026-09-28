# GitHub Copilot CLI: OpenAI-compatible provider through the capture proxy, set with the documented BYOK variables
# COPILOT_PROVIDER_BASE_URL / COPILOT_PROVIDER_TYPE / COPILOT_PROVIDER_API_KEY / COPILOT_MODEL (docs: copilot help providers,
# concepts/agents/copilot-cli/about-copilot-cli "Using your own model provider"). Documented: with BYOK, GitHub authentication is
# not required (how-tos/copilot-cli/set-up-copilot-cli/authenticate-copilot-cli), so no GitHub account or token is used.
# Headless is `copilot -p`. Documented default: read-only operations (search, file reads, read-only shell commands) are allowed
# automatically; anything else needs approval, which -p cannot ask for, so the default variant runs with no approval flag.
# FLAGS: every documented approval option (cli-command-reference): the allow-all family, scoped --allow-tool / --allow-url, a
# --deny-tool precedence case, the plan / autopilot modes with their aliases, and assisted approval (--assisted-approval or
# COPILOT_ASSISTED_APPROVAL, which require --experimental; also combined with --allow-all-tools, over which it is documented to take
# precedence). Not covered: settings defaultPermissionMode (documented as ignored outside interactive runs). L3VARIANT: file reads need no approval and no scoped
# read permission kind exists (kinds: shell, write, MCP, url), so the smallest option that widens tool approval is used.
# optout: COPILOT_OFFLINE=true (documented: skips GitHub authentication, telemetry, web tools, GitHub MCP server and auto-update),
# COPILOT_AUTO_UPDATE=false, and settings autoUpdate/remoteExport false (cli-config-dir-reference).
# No export: the CLI has no session export command (`copilot sessions` offers only import); --share writes a Markdown file only at
# the end of a programmatic (-p) run, i.e. it needs another model turn.
FLAGS="allow-all-tools allow-all yolo env-allow-all allow-all-paths allow-all-urls allow-url allow-date allow-write deny-python plan mode-plan autopilot mode-autopilot plan-autopilot env-plan-autopilot assisted env-assisted assisted-all-tools"
L3VARIANT=allow-all-tools
b_setup(){ mkdir -p $R/home/.copilot; case $1 in
  optout) echo '{"autoUpdate":false,"remoteExport":false}' ;;
  *) echo '{}' ;; esac > $R/home/.copilot/settings.json; }
b_env(){ ENVS+=(-e COPILOT_PROVIDER_BASE_URL=$PROXY$MODEL_OPENAI_PATH -e COPILOT_PROVIDER_TYPE=openai -e COPILOT_PROVIDER_API_KEY=$DUMMY
    -e COPILOT_MODEL=$MODEL_ID)
  case $1 in optout) ENVS+=(-e COPILOT_OFFLINE=true -e COPILOT_AUTO_UPDATE=false);; env-allow-all) ENVS+=(-e COPILOT_ALLOW_ALL=true);;
    env-plan-autopilot) ENVS+=(-e COPILOT_PLAN_THEN_AUTOPILOT=1);; env-assisted) ENVS+=(-e COPILOT_ASSISTED_APPROVAL=true);; esac; }
b_f(){ case $1 in allow-all-tools) echo '--allow-all-tools';; allow-all) echo '--allow-all';; yolo) echo '--yolo';;
  allow-all-paths) echo '--allow-all-paths';; allow-all-urls) echo '--allow-all-urls';; allow-url) echo '--allow-url=github.com';;
  allow-date) echo "--allow-tool='shell(date)'";; allow-write) echo "--allow-tool=write";;
  deny-python) echo "--allow-all-tools --deny-tool='shell(python3)'";;
  plan) echo '--plan';; mode-plan) echo '--mode plan';; autopilot) echo '--autopilot';; mode-autopilot) echo '--mode autopilot';;
  plan-autopilot) echo '--plan --mode autopilot';; assisted) echo '--experimental --assisted-approval';;
  env-assisted) echo '--experimental';; assisted-all-tools) echo '--experimental --assisted-approval --allow-all-tools';; esac; }
b_cmd(){ echo "copilot $(b_f $1) -p \"\$PROMPT\""; }
b_resume(){ echo "copilot --continue $(b_f $1) -p \"\$PROMPT\""; }
b_tui(){ echo "copilot $(b_f $1)"; }
