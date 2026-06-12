# Per-user parameter tuning — rollout

Status: **live on mrn since 2026-06-12** (cron `/etc/cron.d/spamlite-tune-nightly`, 02:30 daily).

## Why per-user, not defaults

The v0.4.0 postmortem (`_journal/2026-04-30.md`) established that global default
changes overfit whatever corpus they were measured on. Defaults stay at
spamprobe-equivalents; all per-user gains flow through `<db_dir>/params.toml`,
written exclusively by `spamlite-tune` behind its generalisation gate.

## Pipeline

```
/etc/cron.d/spamlite-tune-nightly          02:30 daily, root
  └─ /usr/local/bin/spamlite-tune-nightly  Mix script (repo: deploy/spamlite-tune-nightly)
       walks /srv/*/msg/*/.spamlite/db.sqlite (glob)
       skips users with < 100 ham (Maildir/cur) or < 50 spam (Maildir/.Junk/cur)
       └─ ionice -c3 nice -n19 /usr/local/bin/spamlite-tune
            -d <user>/.spamlite --ham Maildir/cur --spam Maildir/.Junk/cur
            --baseline-threshold 0.6 --limit 4000 --json --write
       log → /var/log/spamlite-tune.log
```

The tuner (src/bin/tune.rs) does stratified 80/20 split, coordinate descent on
**balanced error** `(fp/ham + fn/spam)/2`, and writes `params.toml` only when
tuned params beat the production baseline (threshold 0.6, default params) on
the held-out test set. Exit 2 = refused, the normal outcome.

The deployed `spamlite` (v0.4.1+) picks `params.toml` up at runtime via
`Params::load_overrides`; v0.5.0 additionally range-validates every value and
keeps defaults for anything out of range.

## Ground truth caveats

- Ham source is `Maildir/cur` (the INBOX). Mail filed into other folders is
  invisible to the tuner; acceptable for now since classification happens at
  INBOX delivery time.
- Spam source is `.Junk/cur`. Users who flag normal mail as spam (jaz) poison
  their own tuning corpus — the gate correctly refuses rather than "fixing" it.
- The skip gate (100 ham / 50 spam) keeps thin corpora from producing noise
  params. ~30 of 212 users are skipped at current thresholds.

## First-run results (2026-06-12, smoke test, 3 users)

| user | outcome | detail |
|------|---------|--------|
| prborder@auzy.net.au | **wrote** | balanced err 0.1276 → 0.1226, max_interesting 150→200; corpus is 40:1 ham:spam and fp-heavy — a data-hygiene case the params can only nudge |
| cam@ck20.com | refused | no generalising gain |
| jaz@ck20.com | refused | known data-hygiene case (mislabeled spam folder) |

georgivs@nospam.com.au, run manually the same day against his **live** corpus
(511 ham / 488 spam): refused — converged at defaults. The 21.6% gain measured
on his April `/tmp/eval` snapshot did not exist in the fresher corpus. The
April params.toml was never deployed; nothing to roll back.

## Monitoring

- `/var/log/spamlite-tune.log` — per-user outcomes + nightly summary line
  (`done= wrote= refused= skipped= failed=`).
- Any `params.toml` a nightly run writes is re-validated the next night against
  fresh data; if it stops generalising the tuner overwrites it with newer
  winning params, or leaves it (it never deletes). Manual deletion is the
  rollback: `rm <user>/.spamlite/params.toml`.
- Watch interaction with the v0.5.0 shadow run: the candidate reads the same
  params.toml as the primary, so tuned users do not register as divergence.

## Dialect warning

`deploy/spamlite-tune-nightly` is written for **mix 0.3.0** as deployed on mrn
at `/usr/local/bin/mix` (`function($x) = expr` lambdas, `$1` positionals, no
newline-`..` continuation). This is NOT the current `~/.mix` dialect (0.16.x)
and mix on mrn is NOT at the canonical `/opt/cosmix/bin/` path.

**Scheduled: at the next shadow switcheroo** (v0.5.0 promotion / next
candidate swap, ~2 weeks from 2026-06-12), install the latest mix at
`/opt/cosmix/bin/mix` on mrn FIRST, then port every mrn Mix script to the
current dialect and switch shebangs (`spamlite-tune-nightly`,
`spamlite-threshold-digest`, anything else
`grep -rl 'usr/local/bin/mix' /usr/local/bin/` finds). Verify each script
manually against the new binary before retiring `/usr/local/bin/mix`.
