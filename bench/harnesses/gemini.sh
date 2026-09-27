# Gemini CLI: vendor-hosted model (Gemini API, generativelanguage.googleapis.com) with the operator's own account
# (rig.conf: gemini_MODEL_RE, gemini_CRED_FILE, optional gemini_MODEL_ID). Gemini CLI keeps a key entered in its auth dialog in
# ~/.gemini/gemini-credentials.json, AES-GCM encrypted with a key derived from the host name and user name, so that store cannot
# be reused inside a container. The rig's credential file is instead a JSON file {"GEMINI_API_KEY": "..."} holding the same key;
# it is piped into the in-memory HOME only and read into the documented GEMINI_API_KEY variable per step (never on a command line).
# The workspace is marked trusted in ~/.gemini/trustedFolders.json (documented: with folder trust enabled, the default, a headless run in an untrusted folder exits with
# FatalUntrustedWorkspaceError). The model is always selected explicitly with -m.
MODEL=vendor; TMO=240; CRED_DEST=.gemini/ab-api-key.json; CRED_STORES=.gemini/ab-api-key.json
VENDOR_MODEL=${gemini_MODEL_ID:-gemini-3.5-flash-lite}
FLAGS="yolo am-yolo am-auto_edit am-plan allow-date"; L3VARIANT=yolo
# Launcher in /out/steps (outside HOME): reads the key into the environment and execs gemini, so the key is never in any argv
# (strace records execve arguments, not the environment).
b_setup(){ mkdir -p "$R/home/.gemini"; echo '{"/work":"TRUST_FOLDER"}' > "$R/home/.gemini/trustedFolders.json"
  printf '%s\n' '#!/bin/sh' 'GEMINI_API_KEY="$(node -p '"'"'require(process.env.HOME + "/'$CRED_DEST'").GEMINI_API_KEY'"'"')" exec gemini "$@"' > "$R/out/steps/gemini-key.sh" || return 1
  case $1 in   # optout: every documented usage-statistics, telemetry and update switch (docs/reference/configuration.md, docs/cli/telemetry.md)
    optout) echo '{"security":{"auth":{"selectedType":"gemini-api-key"}},"privacy":{"usageStatisticsEnabled":false},"telemetry":{"enabled":false},"general":{"enableAutoUpdate":false,"enableAutoUpdateNotification":false}}' ;;
    *) echo '{"security":{"auth":{"selectedType":"gemini-api-key"}}}' ;; esac > "$R/home/.gemini/settings.json"; }
b_env(){ :; }
b_f(){ case $1 in yolo) echo '--yolo';; am-*) echo "--approval-mode ${1#am-}";; allow-date) echo "--allowed-tools 'ShellTool(date)'";; esac; }
b_cmd(){ echo "sh /out/steps/gemini-key.sh -m $VENDOR_MODEL $(b_f $1) -p \"\$PROMPT\""; }
b_resume(){ echo "sh /out/steps/gemini-key.sh -m $VENDOR_MODEL --resume latest $(b_f $1) -p \"\$PROMPT\""; }
b_tui(){ echo "sh /out/steps/gemini-key.sh -m $VENDOR_MODEL $(b_f $1)"; }
