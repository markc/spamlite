# spamlite

Per-user Bayesian spam filter in Rust. Drop-in replacement for
[spamprobe](http://spamprobe.sourceforge.net/) and
[bogofilter](https://bogofilter.sourceforge.io/), designed to integrate
with Dovecot via sieve `execute`.

- **1.8 MB** statically-linked binary (with SQLite embedded)
- **5-8 MB RSS** regardless of database size
- **SQLite WAL** storage — crash-safe, no BerkeleyDB corruption
- **Robinson-Fisher** chi-squared classifier — same proven algorithm as bogofilter and SpamAssassin
- Cross-compiles to **OpenWrt** (aarch64-musl)

## Why

spamprobe was the gold standard for per-user Bayesian filtering with sieve integration,
but it's been dead since 2007 and depends on BerkeleyDB (also orphaned). On a mail server
with hundreds of mailboxes, BDB's memory-mapped databases cause serious problems:

| Problem | BerkeleyDB | SQLite |
|---------|-----------|--------|
| 1.5 GB token database | 1.5 GB mmap per invocation | ~5 MB RSS (indexed lookups) |
| Process crash during training | `__db.*` corruption, manual recovery | Auto-rollback on next open |
| Concurrent classify + train | Lock contention, deadlocks | WAL mode — readers never block |
| OpenWrt (256 MB RAM) | Fails for non-trivial databases | Works fine |

bogofilter can use SQLite but lacks location-prefixed tokenization and is effectively
unmaintained. spamlite takes the best ideas from both (Robinson-Fisher from bogofilter,
location-prefixed tokens from [gonzofilter](https://github.com/jmhodges/gonzofilter))
and packages them in a small, modern Rust binary.

## Install

```bash
cargo install --path .
```

### Cross-compile for OpenWrt (aarch64)

```bash
rustup target add aarch64-unknown-linux-musl
cargo install cargo-zigbuild   # requires zig
cargo zigbuild --release --target aarch64-unknown-linux-musl
# Binary: target/aarch64-unknown-linux-musl/release/spamlite
```

## Usage

```
spamlite 0.1.0 — per-user Bayesian spam filter
Copyright 2026 Mark Constable <mc@netserva.org>
MIT License — https://github.com/markc/spamlite

Usage:
  spamlite [-d DIR] receive          Classify message (stdin → "SPAM 0.999976" / "GOOD 0.000232")
  spamlite [-d DIR] spam             Train message from stdin as spam
  spamlite [-d DIR] good             Train message from stdin as good/ham
  spamlite [-d DIR] counts           Show database statistics
  spamlite [-d DIR] cleanup [N] [D]  Remove tokens with count <= N or not seen in D days
  spamlite [-d DIR] export           Export database to CSV on stdout
  spamlite [-d DIR] import           Import CSV from stdin (spamprobe-compatible format)

Options:
  -d DIR    Database directory (uses DIR/db.sqlite)

Environment:
  SPAMLITE_DB    Database file path (default: ~/.spamlite/db.sqlite)
```

### Quick start

```bash
# Train from existing mail
for msg in ~/Maildir/cur/*; do spamlite good < "$msg"; done
for msg in ~/Maildir/.Junk/cur/*; do spamlite spam < "$msg"; done

# Classify
echo "Subject: Buy cheap pills now" | spamlite receive
# → SPAM 0.997832

spamlite counts
# Good messages:  79
# Spam messages:  16
# Unique tokens:  4409
```

### Migration from spamprobe

```bash
spamprobe -d .spamprobe export > tokens.csv
spamlite import < tokens.csv
```

### Migration from bogofilter

```bash
# Export bogofilter's BDB and convert to spamlite CSV format
bogoutil -d .bogofilter/wordlist.db | awk '{
  word=$1; spam=$2; good=$3
  if (word == ".MSG_COUNT") printf "%s,%s,0,\"__total__\"\n", good, spam
  else if (word !~ /^\./) printf "%s,%s,0,\"%s\"\n", good, spam, word
}' > tokens.csv
spamlite import < tokens.csv
```

Note: bogofilter uses bare tokens while spamlite uses location-prefixed tokens
(`h:subject:`, `b:`, etc.), so imported bogofilter data won't produce good results.
The recommended approach is to bootstrap from existing Maildir instead:

```bash
for msg in ~/Maildir/cur/*; do spamlite good < "$msg"; done
for msg in ~/Maildir/.Junk/cur/*; do spamlite spam < "$msg"; done
```

## Dovecot Sieve Integration

spamlite replaces bogofilter/spamprobe in a standard Dovecot sieve pipeline.

### Inbound classification (`global.sieve`)

```sieve
require ["vnd.dovecot.execute", "fileinto", "envelope", "variables", "editheader"];

if envelope :localpart :matches "to" "*" { set "lhs" "${1}"; }
if envelope :domain :matches "to" "*" { set "rhs" "${1}"; }

execute :pipe :output "SCORE" "spamlite"
  ["-d", "/srv/${rhs}/msg/${lhs}/.spamlite", "receive"];

set "verdict" "UNSURE";
if string :matches "${SCORE}" "SPAM *" { set "verdict" "SPAM"; }
elsif string :matches "${SCORE}" "GOOD *" { set "verdict" "GOOD"; }

addheader :last "X-Spam-Status" "${SCORE} [spamlite]";

if string :is "${verdict}" "SPAM" { fileinto "Junk"; stop; }
if string :is "${verdict}" "UNSURE" { fileinto "Unsure"; stop; }
```

### Retrain on IMAP move

```sieve
# retrain-as-spam.sieve (triggered on COPY into Junk)
require ["vnd.dovecot.execute", "environment", "variables", "imapsieve"];
if environment :matches "imap.user" "*@*" {
  set "lhs" "${1}"; set "rhs" "${2}";
  execute :pipe "spamlite" ["-d", "/srv/${rhs}/msg/${lhs}/.spamlite", "spam"];
}

# retrain-as-good.sieve (triggered on COPY out of Junk)
require ["vnd.dovecot.execute", "environment", "variables", "imapsieve"];
if environment :matches "imap.user" "*@*" {
  set "lhs" "${1}"; set "rhs" "${2}";
  execute :pipe "spamlite" ["-d", "/srv/${rhs}/msg/${lhs}/.spamlite", "good"];
}
```

## Algorithm

spamlite uses the Robinson-Fisher method — the same statistically-proven approach
used by bogofilter and SpamAssassin:

1. **Tokenize** — MIME-aware parsing via `mail-parser`, location-prefixed tokens
   (`h:subject:`, `h:from:`, `b:`, `u:` for URLs), subject bigrams
2. **Lookup** — batch `SELECT` from SQLite for message tokens
3. **Robinson's correction** — `f(w) = (s*x + n*p(w)) / (s+n)` prevents rare tokens
   from dominating (s=1.0, x=0.5)
4. **Select interesting** — top 150 tokens furthest from 0.5
5. **Fisher's chi-squared** — two-tailed combining for final score
6. **Verdict** — SPAM (>0.9), GOOD (<0.1), UNSURE (between)

This works well from the start: even with 50 trained messages, known tokens pull
the score while unknown tokens contribute 0.5 (neutral), not noise.

## How This Project Came About

spamlite was built in a single session on 2026-03-03, driven by years of frustration
with BerkeleyDB-based spam filters on production mail servers.

### The problem

A fleet of Dovecot mail servers used spamprobe (last release 2007) for per-user
Bayesian filtering via sieve. spamprobe depends on BerkeleyDB, which:

- Memory-maps the entire token database (1.5 GB for a mature mailbox) on every
  classification — causing massive memory pressure with concurrent users
- Corrupts its `__db.*` environment files when sieve processes crash, blocking
  all subsequent mail delivery until manual recovery
- Is itself orphaned — Oracle stopped maintaining BerkeleyDB

On an OpenWrt-based mail gateway (GL-MT6000, aarch64, 1 GB RAM), spamprobe wasn't
even available. bogofilter was used as a stopgap, but with equal ham/spam cutoffs
(0.60/0.60) effectively disabling the Unsure band, and no location-prefixed tokenization.

### The build

The design was planned across three documents: architecture overview, SQLite memory
analysis, and Robinson-Fisher algorithm specification. Implementation proceeded in
order:

1. **Cargo project** with `mail-parser`, `rusqlite` (bundled SQLite), `nanohtml2text`
2. **Storage layer** — SQLite schema with WAL mode, batch lookups, export/import
3. **Tokenizer** — MIME decoding, location prefixes, URL extraction, subject bigrams
4. **Classifier** — Robinson's Bayesian correction, Fisher's chi-squared combining
5. **CLI** — matching spamprobe's interface for sieve script compatibility

First build: all 16 tests passed. Classification on synthetic messages:
SPAM 0.999976, GOOD 0.000232, UNSURE 0.500000.

### Cross-compilation

The native x86_64 binary couldn't run on the aarch64 OpenWrt gateway. Cross-compilation
required:

- `rustup target add aarch64-unknown-linux-musl` for the Rust target
- `zig` + `cargo-zigbuild` as the C cross-compiler (the GNU cross-compiler failed
  with glibc/musl symbol mismatches — `open64`, `stat64`, etc. don't exist in musl)
- Result: 1.8 MB statically-linked aarch64 binary

### Deployment

On the gateway, bogofilter was gently moved aside (scripts renamed to `.bogofilter.bak`,
not deleted) and spamlite took over:

- Binary installed to `/usr/bin/spamlite`
- New sieve scripts written for spamlite's output format
- Per-user `.spamlite/` directories created alongside existing `.bogofilter/`
- Training data bootstrapped from existing Maildir (Junk = spam, Inbox = good)
- First issue: sieve's `execute` captures stdout including newlines — `println!` was
  changed to `print!` and the sieve pattern matching was made more robust

First live classification of a real Gmail message:
```
X-Spam-Status: GOOD 0.000003 [spamlite]
```

## Prior Art

| Project | Language | Storage | Status |
|---------|----------|---------|--------|
| [spamprobe](http://spamprobe.sourceforge.net/) | C++ | BerkeleyDB | Dead (2007) |
| [bogofilter](https://bogofilter.sourceforge.io/) | C | BDB/SQLite | Dying |
| [gonzofilter](https://github.com/jmhodges/gonzofilter) | Go | bbolt | Active |
| [DSPAM](https://github.com/dspam/dspam) | C | Various | Dead (2014) |
| [rspamd](https://rspamd.com/) | C | Redis | Active (heavy) |

## License

MIT License — Copyright 2026 Mark Constable <mc@netserva.org>
