# SPDX-FileCopyrightText: 2026 Mark Constable <mc@mixos.dev>
# SPDX-License-Identifier: MIT OR Apache-2.0

require ["vnd.dovecot.pipe", "vnd.dovecot.debug", "copy", "imapsieve", "environment", "variables"];

if environment :matches "imap.user" "*" { set "user" "${1}"; }
set "msgid" "noid";
if header :matches "message-id" "*" { set "msgid" "${1}"; }

debug_log "TRAIN: ${user} ${msgid} -> spam";
pipe :copy "spamfilter-retrain" ["spam"];
