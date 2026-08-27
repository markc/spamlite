# spamlite — Project Guide

## What This Is

Per-user Bayesian spam filter in Rust. Drop-in replacement for spamprobe/bogofilter,
integrates with Dovecot via sieve `execute`. SQLite storage with a reusable engine
and a default-on CLI feature.

## Architecture

```
src/
  lib.rs          Engine layers and classifier compatibility alias
  storage.rs      SQLite schema + caller-transaction train/untrain/relabel ops + Database wrapper
  tokenizer.rs    MIME tokenizer; tokenize_for_training is the training entry
  scoring.rs      Robinson-Fisher scoring and DB-free classify_tokens seam
  main.rs         cli-feature binary wiring and policy
```

The modules have clean boundaries:
- `tokenizer` produces `Vec<String>` from raw email bytes
- `tokenize_for_training` strips label headers before every supervised training path
- `storage::schema` initialises SQLite; `storage::ops` owns the SQL and takes
  caller-owned transactions for atomic training and correction units
- `scoring` combines fetched counts, with `classify_tokens` as the pure seam
- without `cli`, the engine has no environment or configuration-file reads;
  filesystem access is limited to SQLite and its parent directory
- the default `cli` feature adds env/`params.toml` readers and the binaries

## Key Design Decisions

- **No async, no daemon** — single-threaded CLI, one invocation per message
- **Per-user tuning** — compiled `Params::default()` values sit underneath
  `<db_dir>/params.toml` overrides provided by the `cli` feature
- **`print!` not `println!`** for `receive` output — sieve captures stdout including newlines,
  trailing `\n` corrupts sieve variable parsing
- **`-d DIR`** flag for per-user database path — sieve passes `/srv/{domain}/msg/{user}/.spamlite`
- **Location-prefixed tokens** — `h:subject:`, `h:from:`, `b:`, `u:` improve accuracy
- **Subject bigrams** — `h:subject:make_money` catches phrase-level spam signals
- **Export/import CSV** — compatible with spamprobe format: `good,spam,flags,"word"`
- **Sent-folder ham needs `train-dir <dir> good --sent`** — Sent mail's header
  geometry is inverted (the user is the sender). Trained raw it gives the user's
  own domain a large `h:from:` ham count that a from-spoofing phish inherits, and
  throws the correspondent away with the `h:to:` header that `expanded_headers`
  leaves off by default. `--sent` emits the recipient under `h:from:` and drops
  the self-side headers (From, Reply-To, Sender, Cc, Received), reproducing the
  token shape that correspondent's inbound mail would produce. Mail the user
  sent to themselves emits no sender at all — the INBOX copy is already trained
  by the reconciler, so emitting it would double-count. It is a corpus
  shape, not a feature flag: deliberately unreachable from `SPAMLITE_*` env, since
  an exported variable inherited by the delivery path would invert live mail.

## Build

```bash
# Native (dev)
cargo build
cargo test

# Release (x86_64)
cargo build --release

```

## Deployment

Binary goes to `/usr/bin/spamlite` on the mail server (where dovecot's `sieve_execute_bin_dir` points).

Sieve scripts on mrn are in `/etc/dovecot/sieve/`:
- `global.sieve` — inbound classification, calls `spamfilter ... receive`
- `retrain-as-spam.sieve` — IMAP move to Junk, calls `spamfilter-retrain spam`
- `retrain-as-ham.sieve` — IMAP move out of Junk, calls `spamfilter-retrain good`

The sieve scripts do **not** invoke `spamlite` directly. They call the `spamfilter`
and `spamfilter-retrain` wrappers at `/usr/local/bin/` which dispatch between
spamlite and spamprobe per-user based on whether `.spamlite/` exists in the user's
Maildir. The `spamfilter` wrapper hardcodes `-t 0.6` as the global threshold —
this is the injection point for per-user threshold overrides, not spamlite itself.

Per-user databases live at `/srv/{domain}/msg/{user}/.spamlite/db.sqlite`. See
the private ops docs for the full wiring and active
improvement plan.

User-correction commands (`good`, `spam`, `untrain`, and `train-dir`) use a
15-second SQLite busy timeout so imapsieve corrections can outwait a reconciler
chunk commit within Dovecot's 20-second execute limit. Delivery-path `receive`
and `score`, other CLI opens, and the library default remain at 5 seconds.
The nightly reconciler trains spam from Junk and its child mailboxes, excluding
similar-looking siblings such as `Junkyard`; its ham source remains only the
ripened INBOX window. mdbox candidates use the saved-time Unix epoch for the
shared cap, and an enumeration failure skips both classes for that user.

## Testing

```bash
cargo test
echo "Subject: test" | cargo run -- receive   # Quick classification test
```

## Things to Watch

- Token length bounds: 3-40 BYTES (not chars — CJK words max out at ~13 chars). Tokens outside this range are silently dropped. Bodies, including URL extraction, share a 50k raw-token cap per message.
- SQLite WAL mode requires the `-wal` and `-shm` files to be writable by the mail user.
- The `receive` command outputs to stdout without a trailing newline (intentional — sieve compat).
- `mail-parser` 0.11's `received()` returns `Option<&Received>` (single), not an iterator.
  Only the most recent Received header is tokenized.

## Future Work

- Command-line flags for tuning parameters (thresholds, interesting token count, strength)
- `dump` command to show token probabilities for a message (debugging)
- Bulk training from Maildir (`spamlite train-dir --spam path/to/.Junk/cur/`)
- Per-domain shared databases (optional, for domains with few users)
- Benchmarking against real spam/ham corpora
