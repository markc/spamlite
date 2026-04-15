# spamlite deployment artifacts

Production files deployed to `mail.renta.net` (mrn). Keep this directory in
sync with the server so the git repo is authoritative and deployments are
reviewable.

## Files

- **`spamfilter`** — sieve `execute :pipe` wrapper. Installed at
  `/usr/local/bin/spamfilter` on mrn. Dispatches spamlite vs spamprobe per
  user based on `.spamlite/` existence. Runs shadow mode when
  `/etc/spamlite-shadow.allow` is present and matches (or contains `*`).
  Hardcodes `-t 0.6` as the global threshold — injection point for per-user
  threshold overrides (Phase 1.1).

## Companion binaries

Not in this directory (they're built from `src/`):

- **`spamlite`** (primary, production) — must remain at the validated version.
  As of 2026-04-15 this is `spamlite 0.2.0` from 2026-03-11.
- **`spamlite-0.4.0`** (candidate, shadow mode) — staged at
  `/usr/local/bin/spamlite-0.4.0`. Built from this repo's `src/main.rs` and
  installed manually. Read-only in shadow mode (only `score` is invoked).
- **`spamlite-shadow-report`** — installed at
  `/usr/local/bin/spamlite-shadow-report`. Reads `shadow.jsonl` files across
  all users and summarises divergence.

## Shadow mode operations

### Enable cluster-wide

```bash
echo '*' | sudo tee /etc/spamlite-shadow.allow
```

### Restrict to a user list

```bash
sudo tee /etc/spamlite-shadow.allow <<EOF
admin@renta.net
cam@ck20.com
kenelle@auzy.net.au
EOF
```

### Disable shadow mode entirely (rollback to pre-shadow behaviour)

```bash
sudo rm /etc/spamlite-shadow.allow
# OR, if you want to keep the allowlist file but disable shadow:
sudo chmod 000 /etc/spamlite-shadow.allow
```

### Full wrapper rollback

```bash
sudo cp /usr/local/bin/spamfilter.bak-pre-shadow-20260415 /usr/local/bin/spamfilter
```

### Summarise current shadow data

```bash
sudo find /srv -maxdepth 5 -name shadow.jsonl -print0 \
  | sudo xargs -0 /usr/local/bin/spamlite-shadow-report
```

## Lowercase path fix

The wrapper does `DIR="${DIR,,}"` before using `$DIR` because the sieve
script at `/etc/dovecot/sieve/global.sieve` does not lowercase the
`${lhs}`/`${rhs}` variables before building the `/srv/${rhs}/msg/${lhs}`
path. Uppercase-addressed inbound mail (e.g. `SCOTT@PROMANTT.COM.AU`) was
producing `lmtp: Error: caught runtime exception: No such file or directory`
followed by `Terminated with non-zero exit code 1`. 5 such errors in
2026-04-12..2026-04-15 logs. The wrapper fix bypasses the sieve bug without
touching `global.sieve`. The underlying sieve script should still be fixed
with `:lower_case` modifiers when convenient.
