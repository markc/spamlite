# spamlite — Project Guide

## What This Is

Per-user Bayesian spam filter in Rust. Drop-in replacement for spamprobe/bogofilter,
integrates with Dovecot via sieve `execute`. SQLite storage, single static binary,
cross-compiles to OpenWrt (aarch64-musl).

## Architecture

```
src/
  lib.rs          Module declarations
  storage.rs      SQLite layer — schema, WAL mode, CRUD, export/import
  tokenizer.rs    MIME-aware tokenizer via mail-parser, location-prefixed tokens
  classifier.rs   Robinson-Fisher chi-squared Bayesian classifier
  main.rs         CLI — receive, spam, good, counts, cleanup, export, import
```

All four modules are independent with clean boundaries:
- `tokenizer` produces `Vec<String>` from raw email bytes
- `storage` persists token counts in SQLite
- `classifier` combines token probabilities using Robinson-Fisher
- `main` wires them together with CLI arg parsing

## Key Design Decisions

- **No async, no daemon** — single-threaded CLI, one invocation per message
- **No config file** — all tuning via `Params::default()` for now, CLI flags later
- **`print!` not `println!`** for `receive` output — sieve captures stdout including newlines,
  trailing `\n` corrupts sieve variable parsing
- **`-d DIR`** flag for per-user database path — sieve passes `/srv/{domain}/msg/{user}/.spamlite`
- **Location-prefixed tokens** — `h:subject:`, `h:from:`, `b:`, `u:` improve accuracy
- **Subject bigrams** — `h:subject:make_money` catches phrase-level spam signals
- **Export/import CSV** — compatible with spamprobe format: `good,spam,flags,"word"`

## Build

```bash
# Native (dev)
cargo build
cargo test

# Release (x86_64)
cargo build --release

# OpenWrt aarch64 (requires: rustup target add aarch64-unknown-linux-musl, cargo-zigbuild, zig)
cargo zigbuild --release --target aarch64-unknown-linux-musl
```

## Deployment

Binary goes to `/usr/bin/spamlite` on the mail server (where dovecot's `sieve_execute_bin_dir` points).

Sieve scripts are in `/etc/dovecot/sieve/`:
- `global.sieve` — inbound classification via `spamlite receive`
- `retrain-as-spam.sieve` — IMAP move to Junk triggers `spamlite spam`
- `retrain-as-good.sieve` — IMAP move from Junk triggers `spamlite good`
- `train-as-ham.sieve` — IMAP move to TrainHam triggers `spamlite good`

Per-user databases live at `/srv/{domain}/msg/{user}/.spamlite/db.sqlite`.

## Testing

```bash
cargo test                    # 16 unit tests
echo "Subject: test" | cargo run -- receive   # Quick classification test
```

## Things to Watch

- Token length bounds: 3-40 chars. Tokens outside this range are silently dropped.
- SQLite WAL mode requires the `-wal` and `-shm` files to be writable by the mail user.
- The `receive` command outputs to stdout without a trailing newline (intentional — sieve compat).
- `mail-parser` v0.10's `received()` returns `Option<&Received>` (single), not an iterator.
  Only the most recent Received header is tokenized.

## Future Work

- Command-line flags for tuning parameters (thresholds, interesting token count, strength)
- `dump` command to show token probabilities for a message (debugging)
- Bulk training from Maildir (`spamlite train-dir --spam path/to/.Junk/cur/`)
- Per-domain shared databases (optional, for domains with few users)
- Benchmarking against real spam/ham corpora
