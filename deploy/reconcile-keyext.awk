# SPDX-FileCopyrightText: 2026 Mark Constable <mc@mixos.dev>
# SPDX-License-Identifier: MIT OR Apache-2.0
# reconcile-keyext.awk — one "path|key" line per input file.
# key = Message-ID (lowercased, <>/spaces stripped) or empty (caller applies
# the f:<basename> fallback). Header-only scan: nextfile at the blank line.
FNR == 1 { if (f != "") emit(); f = FILENAME; mid = ""; inh = 1 }
inh && /^\r?$/ { inh = 0; nextfile }
inh && tolower($0) ~ /^message-id:/ {
  l = $0; sub(/^[^:]*:[ \t]*/, "", l); gsub(/[<> \t\r]/, "", l)
  if (mid == "") mid = tolower(l)
}
END { if (f != "") emit() }
function emit() { print f "|" mid }
