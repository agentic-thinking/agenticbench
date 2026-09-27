# Amp: vendor-hosted model, logged-in account (rig.conf: amp_MODEL_RE, amp_CRED_FILE). The credential file is copied into the
# in-memory HOME only. Resume and export use the first thread id named in this HOME's CLI log, i.e. the thread step A created.
MODEL=vendor; TMO=240; CRED_DEST=.local/share/amp/secrets.json
FLAGS="allow-all perm-ask"; L3VARIANT=allow-all
b_setup(){ mkdir -p $R/home/.config/amp; case $1 in
  optout) echo '{"amp.updates.mode":"disabled"}' ;;
  allow-all) echo '{"amp.dangerouslyAllowAll":true}' ;;
  perm-ask) echo '{"amp.permissions":[{"tool":"Bash","action":"ask"}]}' ;;   # documented rule action "ask" (amp permissions add --help)
  *) echo '{}' ;; esac > $R/home/.config/amp/settings.json; }
b_env(){ :; }
TID='TID=$(grep -oE "T-[0-9a-f]{8}-[0-9a-f-]{27}" $HOME/.cache/amp/logs/cli.log | head -1); echo "thread=$TID" >&2'
b_cmd(){ echo 'amp -x "$PROMPT"'; }
b_resume(){ echo "$TID; amp threads continue \"\$TID\" -x \"\$PROMPT\""; }
b_tui(){ echo 'amp'; }
b_export(){ echo "$TID; amp threads export \"\$TID\""; }
