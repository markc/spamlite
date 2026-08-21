# reconcile-strip.awk — drop X-Spam-Status/X-SpamProbe headers (train-time
# label leak) and pass the rest of the message through verbatim.
BEGIN { h = 1 }
h && /^\r?$/ { h = 0 }
h && tolower($0) ~ /^x-spam(-status|probe):/ { s = 1; next }
h && s && /^[ \t]/ { next }
{ s = 0; print }
