# Cursor CLI (cursor-agent): vendor-hosted model, logged-in account (rig.conf: cursor_MODEL_RE, cursor_CRED_FILE, optional
# cursor_MODEL_ID, cursor_STREAM). Every request goes through Cursor's backend (no custom model endpoint), so the credential file
# (~/.config/cursor/auth.json) is copied into the in-memory HOME only. The model is always selected explicitly with --model and
# recorded in run.json; an empty value or "default" is refused. "auto" (the vendor picks the model) is used only when set explicitly
# in rig.conf (cursor_MODEL_ID=auto, for accounts whose plan refuses every named model). The model stream is a Connect
# bidirectional stream (agent.v1.AgentService/Run over HTTP/2), which the capture must stream through (rig.conf cursor_STREAM,
# bench_mitm.py MITM_STREAM).
MODEL=vendor; TMO=240; CRED_DEST=.config/cursor/auth.json; CRED_STORES=.config/cursor/auth.json
VENDOR_MODEL=${cursor_MODEL_ID-gpt-5.3-codex-low}   # unset: the default; set but empty: refused below
# One variant per documented approval flag or mode (cli/reference/parameters.md, configuration.md, permissions.md), aliases included.
FLAGS="force yolo auto-review plan plan-short ask sandbox sandbox-off approve-mcps am-unrestricted allow-python force-deny"; L3VARIANT=force
# Workspace trust: headless runs in an untrusted folder exit 1 ("Workspace Trust Required ... Run 'agent' interactively to decide,
# or pass --trust"). Units with a headless or resume step get the marker the interactive "Trust this workspace" writes
# (~/.cursor/projects/<workspace>/.workspace-trusted, {trustedAt, workspacePath}), i.e. a folder the user trusted before, so the
# default command carries no extra flag. Units made of the idle boot only get no marker: they show the first-run trust dialog.
# Default, opt-out and flag variants write no CLI config: the CLI creates its own on first run (allowlist mode, allow Shell(ls)).
# Config-based variants write a complete documented config (configuration.md: version, editor.vimMode, permissions required)
# holding those same defaults plus the one setting under test. Only documented fields: the CLI moves a config with an unknown
# value aside to cli-config.json.bad and recreates its defaults, which would silently drop the variant.
b_cfg(){ mkdir -p "$R/home/.cursor"; printf '{"version":1,"editor":{"vimMode":false},"permissions":{"allow":%s,"deny":%s}%s}\n' "$1" "$2" "${3:-}" > "$R/home/.cursor/cli-config.json"; }
b_setup(){
  case $VENDOR_MODEL in ''|default) echo "cursor: model '$VENDOR_MODEL' is not allowed, set an explicit cursor_MODEL_ID" >&2; exit 2;; esac
  case " ${STEPS[*]} " in *" h:"*|*" resume "*) mkdir -p "$R/home/.cursor/projects/work"
    printf '{\n  "trustedAt": "%s",\n  "workspacePath": "/work"\n}' "$(date -u +%FT%T.000Z)" > "$R/home/.cursor/projects/work/.workspace-trusted" ;; esac
  case $1 in
  am-unrestricted) b_cfg '["Shell(ls)"]' '[]' ',"approvalMode":"unrestricted"' ;;          # configuration.md: approvalMode allowlist|auto-review|unrestricted
  allow-python) b_cfg '["Shell(ls)","Shell(python3)"]' '[]' ;;                              # permissions.md: Shell(commandBase) in allow
  force-deny) b_cfg '["Shell(ls)"]' '["Shell(python3)"]' ;;                                 # --force "unless explicitly denied" + deny rule
  gitrepo) G=(git -C "$R/work" -c user.name=bench -c user.email=bench@example.invalid)   # probe only, not in FLAGS: the canary workspace
    "${G[@]}" init -q && "${G[@]}" add -A && "${G[@]}" commit -qm canary ;;                # as a git repo (codebase sync is skipped for a plain folder)
  *) : ;; esac; }
b_env(){ :; }
b_f(){ case $1 in
  optout) echo '--disable-auto-update' ;;          # the only documented opt-out switch (cli/changelog.md); no telemetry opt-out is documented
  force|force-deny) echo '--force' ;; yolo) echo '--yolo' ;; auto-review) echo '--auto-review' ;; plan) echo '--mode plan' ;;
  plan-short) echo '--plan' ;; ask) echo '--mode ask' ;; sandbox) echo '--sandbox enabled' ;; sandbox-off) echo '--sandbox disabled' ;;
  approve-mcps) echo '--approve-mcps' ;; esac; }
b_cmd(){ echo "cursor-agent -p --model $VENDOR_MODEL $(b_f $1) \"\$PROMPT\""; }
b_resume(){ echo "cursor-agent -p --continue --model $VENDOR_MODEL $(b_f $1) \"\$PROMPT\""; }
b_tui(){ echo "cursor-agent --model $VENDOR_MODEL $(b_f $1)"; }
