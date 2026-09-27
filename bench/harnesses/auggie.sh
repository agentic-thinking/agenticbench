# Auggie: vendor-hosted model, logged-in account (rig.conf: auggie_MODEL_RE, auggie_CRED_FILE). The credential file is copied
# into the in-memory HOME only.
MODEL=vendor; TMO=240; CRED_DEST=.augment/session.json
FLAGS="perm-allow perm-deny perm-ask ask"
b_setup(){ :; }
b_env(){ case $1 in optout) ENVS+=(-e AUGMENT_DISABLE_AUTO_UPDATE=1);; esac; }
b_f(){ case $1 in perm-allow) echo '--permission launch-process:allow';; perm-deny) echo '--permission launch-process:deny';; perm-ask) echo '--permission launch-process:ask-user';; ask) echo '--ask';; esac; }
b_cmd(){ echo "auggie --print $(b_f $1) \"\$PROMPT\""; }
b_resume(){ echo "auggie --print -c $(b_f $1) \"\$PROMPT\""; }
b_tui(){ echo 'auggie'; }
b_export(){ echo 'auggie session list 2>&1'; }
