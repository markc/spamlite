# spamlite deployment artifacts

Production files deployed to `mail.renta.net` (mrn). Keep this directory in
sync with the server so the git repo is authoritative and deployments are
reviewable.

Host-specific one-off scripts that embed real user/domain values (review
crons etc.) live in the gitignored `deploy-private/` directory, not here.
Example identities in this file are anonymized.

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
admin@example.com
evan@corp-c.example.com
alice@agency-a.example.net.au
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
path. Uppercase-addressed inbound mail (e.g. `SCOTT@EXAMPLE.COM.AU`) was
producing `lmtp: Error: caught runtime exception: No such file or directory`
followed by `Terminated with non-zero exit code 1`. 5 such errors in
2026-04-12..2026-04-15 logs. The wrapper fix bypasses the sieve bug without
touching `global.sieve`. The underlying sieve script should still be fixed
with `:lower_case` modifiers when convenient.

## Sent-folder ham tooling (0.9.4+)

- **`sent-swap-verify.mix <user@domain> <old-bin> <new-bin> [n]`** — pre-promotion
  gate for a candidate binary, run against copies of a live db so the corpus is
  never touched. Check 1 scores n real INBOX+Junk messages with both binaries and
  requires byte-identical output (`--sent` is default-off, so the delivery path
  must not move). Check 2 trains n real Sent messages into two copies, with and
  without `--sent`, and asserts the user's own ADDRESS gains `h:from:` ham counts
  only without the flag. mdbox hosts only (doveadm staging).
- **`sent-swap-redo.mix <user@domain> <topup-ts> [--commit]`** — undoes a Sent
  top-up performed before `--sent` existed and clears the way to redo it. The
  top-up stamps its whole cohort with one `G <ts> <key>` sidecar timestamp, which
  names it exactly. Backs up the db (`sqlite3 .backup`) and sidecar, untrains each
  message with the same raw geometry it was trained with, then drops the cohort
  from `reconciled.log`. Re-running the top-up is left to the caller. Maildir only.

### 2026-08-27 rollout

0.9.4 promoted on mbx, mrn and mbc (`/usr/local/bin/spamlite`, previous binary
kept as `spamlite.bak-20260827-pre-0.9.4`; every host's
`sieve_execute_bin_dir` entry is a symlink to that path). Delivery-path
regression: 361 real messages across 4 users on 3 hosts, zero divergence.

`--sent` measured on admin@spiderweb.com.au over 40 real Sent messages:
`h:from:admin@spiderweb.com.au` 15 → 51 good without the flag, unchanged with
it; sender tokens moved 4 → 59.

brett@brettclarke.com's 2026-08-23 top-up (cohort `G 1787467991`) was undone and
redone with `--sent`: 1367/1368 untrained (1 message deleted since, its counts
stranded), 1379 retrained. `h:from:brett@brettclarke.com` 1649 → 404. On 150
INBOX + 150 Junk messages, false positives fell 10 → 8 at his threshold of 0.6
and 29 → 23 at 0.5, with false negatives unchanged. **His `threshold = 0.6`
stays** — 0.5 is still far worse for him even after the fix.

The 404 residual is genuine self-correspondence: mail brett sends to himself is
trained once from Sent (recipient = himself under `--sent`) and again from INBOX
by the reconciler. A `To: == From:` guard in the swap would remove that
double-count; not implemented.
