require ["vnd.dovecot.pipe", "vnd.dovecot.debug", "copy", "imapsieve", "environment", "variables"];

if environment :matches "imap.user" "*" { set "user" "${1}"; }
set "msgid" "noid";
if header :matches "message-id" "*" { set "msgid" "${1}"; }

debug_log "TRAIN: ${user} ${msgid} -> good";
pipe :copy "spamfilter-retrain" ["good"];
