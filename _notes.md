# spamlite — Per-User Bayesian Spam Filter in Rust

## Status: Planning / Research (2026-03-03)

## What This Is

A Rust replacement for spamprobe — a per-user Bayesian spam filter that
integrates with Dovecot via sieve pipe/execute. SQLite storage instead of
BerkeleyDB. Single static binary, cross-compiles to OpenWrt (aarch64).

## Why

- spamprobe is orphaned (last upstream release 2007), depends on BDB (also orphaned)
- BDB corruption from crashed sieve processes causes mail delivery failures
- 1.5GB BDB databases must be loaded entirely into memory per message check
- SQLite solves all three: crash-safe, query only needed tokens, widely available
- No maintained alternative exists for per-user Bayesian + sieve integration

## Key Design Goals

1. **Effective from the start** — Robinson-Fisher chi-squared combining with
   Bayesian confidence weighting means even 50 trained messages shift probabilities
2. **Scales to millions** — SQLite indexed lookups are O(log n) per token, only
   reads the ~1000 tokens in the message, not the entire database
3. **Crash-safe** — SQLite WAL mode, no `__db.*` corruption, no stuck processes
4. **Lightweight** — 3-5 MB static binary, 5-8 MB RSS, runs on OpenWrt
5. **Drop-in replacement** — same CLI interface as spamprobe for sieve integration
6. **No daemon** — but WAL mode allows concurrent classify + train without locks

## Architecture

```
spamlite receive < message.eml    # Classify (stdout: SPAM/GOOD + score)
spamlite spam < message.eml       # Train as spam
spamlite good < message.eml       # Train as good/ham
spamlite counts                   # Show database statistics
spamlite cleanup [min_count] [days]  # Purge rare/old tokens
spamlite export > backup.csv      # Export for migration
spamlite import < backup.csv      # Import (from spamprobe export too)
```

### Storage: SQLite

```sql
CREATE TABLE tokens (
    word     TEXT PRIMARY KEY,
    good     INTEGER NOT NULL DEFAULT 0,
    spam     INTEGER NOT NULL DEFAULT 0,
    last_seen INTEGER NOT NULL DEFAULT 0  -- unix timestamp
) WITHOUT ROWID;

CREATE TABLE meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
) WITHOUT ROWID;
-- meta keys: total_good, total_spam, version, created
```

- One `.spamlite/db.sqlite` per user (in mail home directory)
- WAL mode for concurrent reads (classify) during writes (train)
- `PRAGMA cache_size = 500` — ~2 MB page cache, sufficient for hot tokens
- Batch token lookup: `SELECT word, good, spam FROM tokens WHERE word IN (?,...)`

### Algorithm: Robinson-Fisher (same as bogofilter, SpamAssassin)

1. Tokenize message (MIME-aware, HTML-stripped, location-prefixed)
2. Look up token probabilities from SQLite
3. Apply Robinson's Bayesian correction for rare tokens:
   `f(w) = (s * x + n * p(w)) / (s + n)` where s=1, x=0.5
4. Select most "interesting" tokens (furthest from 0.5)
5. Combine via Fisher's chi-squared method (two-tailed)
6. Output verdict + score

### Tokenization (borrow from gonzofilter)

- MIME-aware: decode base64/QP, handle charsets
- Location prefix: `h:subject:`, `h:from:`, `h:received:`, `b:` (body)
- Extract URLs from HTML before stripping tags
- Token bounds: ignore < 3 chars, > 40 chars
- Bigrams for subject line (proven to improve accuracy)

### Rust Crates

| Component | Crate | Why |
|-----------|-------|-----|
| MIME parsing | `mail-parser` | Zero-dep, zero-copy, from Stalwart Labs |
| SQLite | `rusqlite` + `bundled` | Static linking, 40M+ downloads |
| HTML stripping | `nanohtml2text` or custom | Zero-dep, email-focused |
| Algorithm | Hand-rolled | ~150 lines for Robinson-Fisher |

### Cross-Compilation Targets

| Target | Tier | Use Case |
|--------|------|----------|
| `x86_64-unknown-linux-musl` | 2 | Production mail servers |
| `aarch64-unknown-linux-musl` | 2 | OpenWrt (GL-MT6000), ARM servers |
| `x86_64-unknown-linux-gnu` | 1 | Development |

### Binary Size (estimated)

- Release + strip + LTO + `opt-level=z` + `panic=abort`: **~3 MB**
- All dependencies statically linked including SQLite

## Migration Path from spamprobe

```bash
# On each mail server, per user:
spamprobe -d .spamprobe export > tokens.csv
spamlite import < tokens.csv
# Swap sieve script to call spamlite instead of spamprobe
```

The CSV export format is compatible: `goodCount,spamCount,flags,"word"`

## Prior Art

| Project | Language | Storage | Status | Notes |
|---------|----------|---------|--------|-------|
| spamprobe | C++ | BDB | Dead (2007) | Our current tool, clean abstraction |
| bogofilter | C | BDB/SQLite | Dying | Has SQLite variant, single-word only |
| gonzofilter | Go | bbolt | Active | Highest accuracy in benchmarks, good tokenizer |
| DSPAM | C | Various | Dead (2014) | Was the gold standard |
| bayespam | Rust | JSON | Toy | Not production-quality |
| rspamd | C | Redis | Active | Per-user possible but heavy (Redis required) |

## The Memory Problem — Why SQLite Wins

spamprobe with BDB:
- 1.5 GB database → 1.5 GB mmap'd into memory per message check
- Every sieve invocation loads the entire token database
- On a server with 600 mailboxes, concurrent checks = massive memory pressure

spamlite with SQLite:
- 1.5 GB database → query ~1000 tokens → read ~100 KB of index pages
- SQLite page cache bounded at ~2 MB regardless of database size
- WAL mode: concurrent reads don't block, no lock files to corrupt
- Crash during write: SQLite rolls back automatically, no manual recovery needed

## Repository

- GitHub: markc/spamlite (to be created)
- License: MIT or Apache-2.0 (standard Rust dual-license)
