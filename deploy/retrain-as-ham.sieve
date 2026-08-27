require ["vnd.dovecot.pipe", "vnd.dovecot.debug", "copy", "imapsieve", "environment", "variables"];

if environment :matches "imap.user" "*" { set "user" "${1}"; }
set "msgid" "noid";
if header :matches "message-id" "*" { set "msgid" "${1}"; }

set "mbox" "unknown";
if environment :matches "imap.mailbox" "*" { set "mbox" "${1}"; }

# 2026-07-03: only train ham when the message is rescued to INBOX.
# Junk purges / sync jobs move mail to Trash/Junk/archive folders and were
# firing this script, poisoning good corpora (~100 msgs/day fleet-wide).
if not string :is "${mbox}" "INBOX" {
  debug_log "TRAIN-SKIP: ${user} ${msgid} -> good skipped (dest=${mbox})";
  stop;
}

debug_log "TRAIN: ${user} ${msgid} -> good";
pipe :copy "spamfilter-retrain" ["good"];
