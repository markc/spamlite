// Copyright 2026 Mark Constable <mc@netserva.org>
// SPDX-License-Identifier: MIT

use rusqlite::{params, Connection, Result as SqlResult, Transaction, TransactionBehavior};
use std::collections::HashMap;
use std::io::{BufRead, Write};
use std::path::Path;

/// Error type for `export`, which can fail on either side: reading rows
/// (rusqlite) or writing CSV (io — broken pipe, full disk). Both must
/// propagate; a silently truncated export reported as success is how a
/// corpus migration loses tokens.
pub type ExportError = Box<dyn std::error::Error + Send + Sync>;

/// Database statistics
#[derive(Debug)]
pub struct Counts {
    pub total_good: u64,
    pub total_spam: u64,
    pub unique_tokens: u64,
}

/// Extended statistics for the `stats` command. `last_seen_*` are unix epochs
/// over the tokens table (0 when the table is empty); `seen_recent` counts
/// tokens whose last_seen falls inside the caller-supplied window.
/// Training-family writes — train, untrain, and relabel — refresh `last_seen`,
/// so `seen_recent` means touched by supervised training recently, not
/// necessarily grown.
#[derive(Debug)]
pub struct Stats {
    pub total_good: u64,
    pub total_spam: u64,
    pub unique_tokens: u64,
    pub last_seen_min: u64,
    pub last_seen_max: u64,
    pub seen_recent: u64,
}

/// Result of removing one or more messages from a corpus class. The FROM total
/// is decremented once per message, floored at zero, even when every token is
/// stranded: the message leaves the class count regardless of token reach.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Untrained {
    pub decremented: u64,
    pub stranded: u64,
}

fn require_distinct_classes(from_spam: bool, to_spam: bool) -> SqlResult<()> {
    if from_spam == to_spam {
        return Err(rusqlite::Error::InvalidParameterName(
            "relabel: from and to classes must differ".into(),
        ));
    }
    Ok(())
}

pub mod schema {
    use super::*;

    /// Apply the connection pragmas and initialise the version-1 schema.
    /// The engine never reads `labels` in this phase; it exists so consumers
    /// such as maild can keep per-message label bookkeeping in one shared schema.
    pub fn init(conn: &Connection) -> SqlResult<()> {
        conn.execute_batch(
            "PRAGMA journal_mode = WAL;
             PRAGMA synchronous = NORMAL;
             PRAGMA cache_size = 500;
             PRAGMA busy_timeout = 5000;",
        )?;

        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS tokens (
                word      TEXT PRIMARY KEY,
                good      INTEGER NOT NULL DEFAULT 0,
                spam      INTEGER NOT NULL DEFAULT 0,
                last_seen INTEGER NOT NULL DEFAULT 0
            ) WITHOUT ROWID;

            CREATE TABLE IF NOT EXISTS meta (
                key   TEXT PRIMARY KEY,
                value TEXT NOT NULL
            ) WITHOUT ROWID;

            CREATE TABLE IF NOT EXISTS labels (
                stamp_id TEXT PRIMARY KEY,
                label    INTEGER NOT NULL,
                ts       INTEGER NOT NULL
            ) WITHOUT ROWID;",
        )?;

        conn.execute(
            "INSERT OR IGNORE INTO meta (key, value) VALUES ('total_good', '0')",
            [],
        )?;
        conn.execute(
            "INSERT OR IGNORE INTO meta (key, value) VALUES ('total_spam', '0')",
            [],
        )?;
        conn.execute(
            "INSERT OR IGNORE INTO meta (key, value) VALUES ('version', '1')",
            [],
        )?;
        Ok(())
    }
}

/// SQL operations for connections initialised by [`schema::init`]. Consumers
/// that open their own [`Connection`] must call `schema::init` first; the
/// [`Database`] wrapper always does this.
pub mod ops {
    use super::*;

    /// Start a write transaction that acquires SQLite's reserved lock up front.
    /// The connection must first be initialised by [`schema::init`] so the
    /// required pragmas, including `busy_timeout=5000`, are installed.
    pub fn begin_immediate(conn: &Connection) -> SqlResult<Transaction<'_>> {
        Transaction::new_unchecked(conn, TransactionBehavior::Immediate)
    }

    fn get_meta(conn: &Connection, key: &str) -> SqlResult<u64> {
        conn.query_row("SELECT value FROM meta WHERE key = ?1", params![key], |row| {
            let s: String = row.get(0)?;
            Ok(s.parse::<u64>().unwrap_or(0))
        })
    }

    pub fn total_good(conn: &Connection) -> SqlResult<u64> {
        get_meta(conn, "total_good")
    }

    pub fn total_spam(conn: &Connection) -> SqlResult<u64> {
        get_meta(conn, "total_spam")
    }

    pub fn totals(conn: &Connection) -> SqlResult<(u64, u64)> {
        Ok((total_good(conn)?, total_spam(conn)?))
    }

    pub fn increment_total(conn: &Connection, is_spam: bool) -> SqlResult<()> {
        let key = if is_spam { "total_spam" } else { "total_good" };
        conn.execute(
            "UPDATE meta SET value = CAST(CAST(value AS INTEGER) + 1 AS TEXT) WHERE key = ?1",
            params![key],
        )?;
        Ok(())
    }

    pub fn lookup_tokens(
        conn: &Connection,
        words: &[String],
    ) -> SqlResult<HashMap<String, (u64, u64)>> {
        let mut results = HashMap::with_capacity(words.len());
        for chunk in words.chunks(500) {
            let placeholders = vec!["?"; chunk.len()].join(",");
            let sql = format!("SELECT word, good, spam FROM tokens WHERE word IN ({placeholders})");
            let mut stmt = conn.prepare_cached(&sql)?;
            let rows = stmt.query_map(rusqlite::params_from_iter(chunk.iter()), |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, i64>(1)? as u64,
                    row.get::<_, i64>(2)? as u64,
                ))
            })?;
            for row in rows {
                let (word, good, spam) = row?;
                results.insert(word, (good, spam));
            }
        }
        Ok(results)
    }

    /// Increment token counts only, without changing either message total.
    pub fn upsert_tokens(tx: &Transaction<'_>, words: &[String], is_spam: bool) -> SqlResult<()> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;
        let sql = if is_spam {
            "INSERT INTO tokens (word, good, spam, last_seen) VALUES (?1, 0, 1, ?2)
             ON CONFLICT(word) DO UPDATE SET spam = spam + 1, last_seen = ?2"
        } else {
            "INSERT INTO tokens (word, good, spam, last_seen) VALUES (?1, 1, 0, ?2)
             ON CONFLICT(word) DO UPDATE SET good = good + 1, last_seen = ?2"
        };
        let mut stmt = tx.prepare_cached(sql)?;
        for word in words {
            stmt.execute(params![word, now])?;
        }
        Ok(())
    }

    /// Train one message inside the caller's transaction; do not commit it.
    pub fn train(tx: &Transaction<'_>, words: &[String], is_spam: bool) -> SqlResult<()> {
        upsert_tokens(tx, words, is_spam)?;
        let key = if is_spam { "total_spam" } else { "total_good" };
        tx.execute(
            "UPDATE meta SET value = CAST(CAST(value AS INTEGER) + 1 AS TEXT) WHERE key = ?1",
            params![key],
        )?;
        Ok(())
    }

    /// Train a batch inside the caller's transaction; do not commit it.
    pub fn train_batch(
        tx: &Transaction<'_>,
        messages: &[Vec<String>],
        is_spam: bool,
    ) -> SqlResult<()> {
        for words in messages {
            upsert_tokens(tx, words, is_spam)?;
        }
        let key = if is_spam { "total_spam" } else { "total_good" };
        tx.execute(
            "UPDATE meta SET value = CAST(CAST(value AS INTEGER) + ?2 AS TEXT) WHERE key = ?1",
            params![key, messages.len() as i64],
        )?;
        Ok(())
    }

    /// Decrement one message from a corpus class. The class total is decremented
    /// once, floored at zero, even if every token strands. Tokens absent from
    /// the DB or already at zero are stranded; tokens emitted by an older
    /// tokenizer but absent from this stream are deliberately invisible here.
    pub fn untrain(
        tx: &Transaction<'_>,
        words: &[String],
        is_spam: bool,
    ) -> SqlResult<Untrained> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;
        let sql = if is_spam {
            "UPDATE tokens SET spam = spam - 1, last_seen = ?2
             WHERE word = ?1 AND spam > 0"
        } else {
            "UPDATE tokens SET good = good - 1, last_seen = ?2
             WHERE word = ?1 AND good > 0"
        };
        let mut stmt = tx.prepare_cached(sql)?;
        let mut decremented = 0u64;
        for word in words {
            decremented += stmt.execute(params![word, now])? as u64;
        }
        drop(stmt);

        let key = if is_spam { "total_spam" } else { "total_good" };
        tx.execute(
            "UPDATE meta SET value = CAST(MAX(CAST(value AS INTEGER) - 1, 0) AS TEXT)
             WHERE key = ?1",
            params![key],
        )?;

        Ok(Untrained {
            decremented,
            stranded: words.len() as u64 - decremented,
        })
    }

    /// Correct one message by removing the old class and training the new one
    /// inside the caller-owned transaction.
    pub fn relabel(
        tx: &Transaction<'_>,
        words: &[String],
        from_spam: bool,
        to_spam: bool,
    ) -> SqlResult<Untrained> {
        require_distinct_classes(from_spam, to_spam)?;
        let result = untrain(tx, words, from_spam)?;
        train(tx, words, to_spam)?;
        Ok(result)
    }

    /// Untrain a batch inside the caller's transaction, summing outcomes.
    pub fn untrain_batch(
        tx: &Transaction<'_>,
        messages: &[Vec<String>],
        is_spam: bool,
    ) -> SqlResult<Untrained> {
        let mut total = Untrained::default();
        for words in messages {
            let result = untrain(tx, words, is_spam)?;
            total.decremented += result.decremented;
            total.stranded += result.stranded;
        }
        Ok(total)
    }

    /// Relabel a batch inside the caller's transaction, summing outcomes.
    pub fn relabel_batch(
        tx: &Transaction<'_>,
        messages: &[Vec<String>],
        from_spam: bool,
        to_spam: bool,
    ) -> SqlResult<Untrained> {
        require_distinct_classes(from_spam, to_spam)?;
        let mut total = Untrained::default();
        for words in messages {
            let result = relabel(tx, words, from_spam, to_spam)?;
            total.decremented += result.decremented;
            total.stranded += result.stranded;
        }
        Ok(total)
    }

    pub fn stats(conn: &Connection, recent_secs: u64) -> SqlResult<Stats> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;
        let cutoff = now - recent_secs as i64;
        conn.query_row(
            "SELECT COUNT(*),
                    COALESCE(MIN(last_seen), 0),
                    COALESCE(MAX(last_seen), 0),
                    COALESCE(SUM(last_seen >= ?1), 0),
                    COALESCE((SELECT CAST(value AS INTEGER) FROM meta WHERE key = 'total_good'), 0),
                    COALESCE((SELECT CAST(value AS INTEGER) FROM meta WHERE key = 'total_spam'), 0)
             FROM tokens",
            params![cutoff],
            |row| {
                Ok(Stats {
                    unique_tokens: row.get::<_, i64>(0)? as u64,
                    last_seen_min: row.get::<_, i64>(1)? as u64,
                    last_seen_max: row.get::<_, i64>(2)? as u64,
                    seen_recent: row.get::<_, i64>(3)? as u64,
                    total_good: row.get::<_, i64>(4)? as u64,
                    total_spam: row.get::<_, i64>(5)? as u64,
                })
            },
        )
    }

    pub fn counts(conn: &Connection) -> SqlResult<Counts> {
        let unique_tokens = conn.query_row("SELECT COUNT(*) FROM tokens", [], |row| {
            row.get::<_, i64>(0).map(|v| v as u64)
        })?;
        let (total_good, total_spam) = totals(conn)?;
        Ok(Counts {
            total_good,
            total_spam,
            unique_tokens,
        })
    }

    pub fn cleanup(conn: &Connection, min_count: u64, days: u64) -> SqlResult<u64> {
        let cutoff = if days > 0 {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs() as i64;
            now - (days as i64 * 86400)
        } else {
            0
        };
        let deleted = if days > 0 {
            conn.execute(
                "DELETE FROM tokens WHERE (good + spam) <= ?1 OR last_seen < ?2",
                params![min_count as i64, cutoff],
            )?
        } else {
            conn.execute(
                "DELETE FROM tokens WHERE (good + spam) <= ?1",
                params![min_count as i64],
            )?
        };
        Ok(deleted as u64)
    }

    pub fn export<W: Write>(conn: &Connection, writer: &mut W) -> Result<(), ExportError> {
        let (total_good, total_spam) = totals(conn)?;
        writeln!(writer, "{total_good},{total_spam},0,\"__total__\"")?;
        let mut stmt = conn.prepare("SELECT word, good, spam FROM tokens ORDER BY word")?;
        let rows = stmt.query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, i64>(1)? as u64,
                row.get::<_, i64>(2)? as u64,
            ))
        })?;
        for row in rows {
            let (word, good, spam) = row?;
            if word.contains('"') || word.chars().any(|c| c.is_control()) {
                continue;
            }
            writeln!(writer, "{good},{spam},0,\"{word}\"")?;
        }
        Ok(())
    }

    pub fn import<R: BufRead>(tx: &Transaction<'_>, reader: R) -> SqlResult<u64> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;
        let mut count = 0u64;
        let mut stmt = tx.prepare(
            "INSERT INTO tokens (word, good, spam, last_seen) VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(word) DO UPDATE SET good = good + ?2, spam = spam + ?3, last_seen = ?4",
        )?;
        for line in reader.lines() {
            let line = match line {
                Ok(l) => l,
                Err(_) => continue,
            };
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            if let Some((good, spam, word)) = super::parse_csv_line(line) {
                if word == "__total__" {
                    tx.execute(
                        "INSERT INTO meta (key, value) VALUES ('total_good', ?1)
                         ON CONFLICT(key) DO UPDATE SET value = CAST(value AS INTEGER) + ?1",
                        params![good as i64],
                    )?;
                    tx.execute(
                        "INSERT INTO meta (key, value) VALUES ('total_spam', ?1)
                         ON CONFLICT(key) DO UPDATE SET value = CAST(value AS INTEGER) + ?1",
                        params![spam as i64],
                    )?;
                } else {
                    stmt.execute(params![word, good as i64, spam as i64, now])?;
                    count += 1;
                }
            }
        }
        Ok(count)
    }
}

pub struct Database {
    conn: Connection,
}

impl Database {
    /// Open the database at `path`, failing if it does not already exist.
    ///
    /// For the read-only commands (`score`, `explain`, `counts`, `export`). `open()`
    /// creates the file *and* its parent directories, which makes a mistyped `-d` look
    /// like an empty corpus rather than an error: every message scores a neutral
    /// `GOOD 0.500000` and nothing complains. It is worse than cosmetic — running
    /// `counts` against a path that did not exist materialised a whole directory tree
    /// plus an empty db under `/srv`, and the baseline-deploy script guards only with
    /// `[[ -f $BASELINE_DB ]]`, so that empty db would have been copied onto every
    /// newly provisioned user. A read-only command must never bring a database into
    /// existence.
    pub fn open_existing(path: &Path) -> Result<Self, String> {
        // The friendly error first; the OPEN flags below are the actual
        // guarantee — without SQLITE_OPEN_CREATE the open cannot conjure a
        // database even if the file vanishes between this check and the open
        // (backup rotation, a concurrent cleanup).
        if !path.is_file() {
            return Err(format!("no database at {}", path.display()));
        }
        let flags = rusqlite::OpenFlags::default().difference(rusqlite::OpenFlags::SQLITE_OPEN_CREATE);
        let conn = Connection::open_with_flags(path, flags)
            .map_err(|e| format!("failed to open {}: {e}", path.display()))?;
        schema::init(&conn).map_err(|e| format!("failed to open {}: {e}", path.display()))?;
        Ok(Database { conn })
    }

    /// Open (or create) the database at the given path with WAL mode.
    /// Creates the file and its parent directories — use `open_existing` for
    /// anything that only reads.
    pub fn open(path: &Path) -> SqlResult<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).ok();
        }
        let conn = Connection::open(path)?;
        schema::init(&conn)?;
        Ok(Database { conn })
    }

    /// Get total good message count
    pub fn total_good(&self) -> SqlResult<u64> {
        ops::total_good(&self.conn)
    }

    /// Get total spam message count
    pub fn total_spam(&self) -> SqlResult<u64> {
        ops::total_spam(&self.conn)
    }

    /// Increment total good count
    pub fn inc_total_good(&self) -> SqlResult<()> {
        ops::increment_total(&self.conn, false)
    }

    /// Increment total spam count
    pub fn inc_total_spam(&self) -> SqlResult<()> {
        ops::increment_total(&self.conn, true)
    }

    /// Batch-lookup tokens by word. Returns a map of word -> (good, spam)
    /// containing only tokens that exist in the DB.
    pub fn lookup_tokens(&self, words: &[String]) -> SqlResult<HashMap<String, (u64, u64)>> {
        ops::lookup_tokens(&self.conn, words)
    }

    /// Train token counts only: increment good or spam count for each word.
    /// Does NOT bump the message totals — that is what the convergence loop in
    /// `cmd_train` needs (token counts repeat, the corpus ratio stays honest).
    /// For a full one-message training pass use `train_message`.
    pub fn train(&self, words: &[String], is_spam: bool) -> SqlResult<()> {
        let tx = ops::begin_immediate(&self.conn)?;
        ops::upsert_tokens(&tx, words, is_spam)?;
        tx.commit()
    }

    /// Train one message: token counts +1 AND the good/spam message total +1,
    /// in a single transaction. Atomicity matters — a crash or SQLITE_BUSY
    /// between the two would skew the corpus good/spam ratio that feeds every
    /// per-token probability.
    pub fn train_message(&self, words: &[String], is_spam: bool) -> SqlResult<()> {
        let tx = ops::begin_immediate(&self.conn)?;
        ops::train(&tx, words, is_spam)?;
        tx.commit()
    }

    /// Train a batch of messages as one class in a SINGLE transaction: every
    /// message's token counts +1 and the class total +N, atomically. This is
    /// the bulk path for `train-dir` — one commit for the whole batch instead
    /// of one per message, so a nightly reconciler run is a few WAL write
    /// bursts rather than hundreds of tiny commits on the mailstore disk.
    /// All-or-nothing: if the commit fails, NOTHING in this batch trained —
    /// callers must not record per-message success (e.g. a dedupe sidecar)
    /// until this returns Ok. The commit is forced durable (synchronous=FULL
    /// for this connection): under the default WAL+NORMAL a host crash could
    /// lose a committed batch AFTER the caller's sidecar recorded it, and
    /// those messages would never be retrained.
    pub fn train_messages(&self, messages: &[Vec<String>], is_spam: bool) -> SqlResult<()> {
        if messages.is_empty() {
            return Ok(());
        }
        self.conn.execute_batch("PRAGMA synchronous = FULL;")?;
        let tx = ops::begin_immediate(&self.conn)?;
        ops::train_batch(&tx, messages, is_spam)?;
        tx.commit()
    }

    /// Remove one message from a corpus class in one IMMEDIATE transaction.
    pub fn untrain(&self, words: &[String], is_spam: bool) -> SqlResult<Untrained> {
        let tx = ops::begin_immediate(&self.conn)?;
        let result = ops::untrain(&tx, words, is_spam)?;
        tx.commit()?;
        Ok(result)
    }

    /// Correct one message from one class to the other atomically.
    pub fn relabel(
        &self,
        words: &[String],
        from_spam: bool,
        to_spam: bool,
    ) -> SqlResult<Untrained> {
        require_distinct_classes(from_spam, to_spam)?;
        let tx = ops::begin_immediate(&self.conn)?;
        let result = ops::relabel(&tx, words, from_spam, to_spam)?;
        tx.commit()?;
        Ok(result)
    }

    /// Correct a batch durably in one IMMEDIATE transaction. The per-message
    /// results are returned in input order for honest `train-dir` reporting.
    pub fn relabel_messages(
        &self,
        messages: &[Vec<String>],
        from_spam: bool,
        to_spam: bool,
    ) -> SqlResult<Vec<Untrained>> {
        require_distinct_classes(from_spam, to_spam)?;
        if messages.is_empty() {
            return Ok(Vec::new());
        }
        self.conn.execute_batch("PRAGMA synchronous = FULL;")?;
        let tx = ops::begin_immediate(&self.conn)?;
        let mut results = Vec::with_capacity(messages.len());
        for words in messages {
            results.push(ops::relabel(&tx, words, from_spam, to_spam)?);
        }
        tx.commit()?;
        Ok(results)
    }

    /// Extended statistics. `recent_secs` is the window for `seen_recent`
    /// (tokens with last_seen inside the last `recent_secs` seconds). One SQL
    /// statement, so the token aggregates and the meta totals are a single
    /// consistent snapshot even with concurrent training on other connections.
    pub fn stats(&self, recent_secs: u64) -> SqlResult<Stats> {
        ops::stats(&self.conn, recent_secs)
    }

    /// Get database statistics
    pub fn counts(&self) -> SqlResult<Counts> {
        ops::counts(&self.conn)
    }

    /// Cleanup: remove tokens with total count <= min_count or not seen in `days` days
    pub fn cleanup(&self, min_count: u64, days: u64) -> SqlResult<u64> {
        ops::cleanup(&self.conn, min_count, days)
    }

    /// Export all tokens in spamprobe-compatible CSV format:
    /// goodCount,spamCount,flags,"word"
    pub fn export<W: Write>(&self, writer: &mut W) -> Result<(), ExportError> {
        ops::export(&self.conn, writer)
    }

    /// Import from spamprobe-compatible CSV format:
    /// goodCount,spamCount,flags,"word"
    pub fn import<R: BufRead>(&self, reader: R) -> SqlResult<u64> {
        let tx = ops::begin_immediate(&self.conn)?;
        let count = ops::import(&tx, reader)?;
        tx.commit()?;
        Ok(count)
    }
}

/// Parse a single CSV line in spamprobe format: goodCount,spamCount,flags,"word"
fn parse_csv_line(line: &str) -> Option<(u64, u64, String)> {
    let mut parts = line.splitn(4, ',');
    let good: u64 = parts.next()?.trim().parse().ok()?;
    let spam: u64 = parts.next()?.trim().parse().ok()?;
    let _flags = parts.next()?; // skip flags field
    let word = parts.next()?.trim();
    // Strip surrounding quotes if present
    let word = word.strip_prefix('"').unwrap_or(word);
    let word = word.strip_suffix('"').unwrap_or(word);
    // A degenerate line ("10,5,0," or a quote-only field) must not insert an
    // empty-string token — it would be permanent junk in the corpus.
    if word.is_empty() {
        return None;
    }
    Some((good, spam, word.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn test_db() -> Database {
        Database::open(Path::new(":memory:")).unwrap()
    }

    /// `open()` creates parent directories — which is right for training, and wrong for
    /// anything that only reads. A `counts` against a mistyped path once materialised a
    /// whole tree plus an empty db under /srv, and the baseline-deploy script's only
    /// guard is `[[ -f $BASELINE_DB ]]`, so that empty db was one provisioning run away
    /// from being copied onto every new user.
    #[test]
    fn open_existing_refuses_to_create_anything() {
        let root = std::env::temp_dir().join(format!("spamlite-ro-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let db = root.join("nested").join("db.sqlite");

        assert!(Database::open_existing(&db).is_err());
        assert!(!root.exists(), "open_existing created {}", root.display());

        // open() may still create — the training path depends on it.
        Database::open(&db).unwrap();
        assert!(db.is_file());
        // and now that it exists, open_existing is happy.
        assert!(Database::open_existing(&db).is_ok());

        let _ = std::fs::remove_dir_all(&root);
    }

    /// Importing a second corpus must ADD to the totals, not overwrite them. It used to
    /// overwrite: merging a ham-only donor (spam=0) set the target total_spam to 0, and
    /// with no spam corpus every message scores GOOD. Tokens merged, totals lied.
    #[test]
    fn import_merges_totals_additively() {
        let db = test_db();
        db.train_message(&["alpha".to_string()], false).unwrap();   // 1 good
        db.train_message(&["beta".to_string()], true).unwrap();     // 1 spam
        assert_eq!(db.total_good().unwrap(), 1);
        assert_eq!(db.total_spam().unwrap(), 1);

        // a ham-only donor corpus: 50 good, 0 spam
        let donor = "50,0,E,\"__total__\"\n3,0,E,\"gamma\"\n";
        db.import(Cursor::new(donor)).unwrap();

        assert_eq!(db.total_good().unwrap(), 51, "totals must add, not replace");
        assert_eq!(db.total_spam().unwrap(), 1, "a ham-only import must NOT zero total_spam");

        let counts = db.lookup_tokens(&["gamma".to_string()]).unwrap();
        assert_eq!(counts.get("gamma"), Some(&(3, 0)));
    }

    #[test]
    fn test_meta_counts() {
        let db = test_db();
        assert_eq!(db.total_good().unwrap(), 0);
        assert_eq!(db.total_spam().unwrap(), 0);
        db.inc_total_good().unwrap();
        db.inc_total_good().unwrap();
        db.inc_total_spam().unwrap();
        assert_eq!(db.total_good().unwrap(), 2);
        assert_eq!(db.total_spam().unwrap(), 1);
    }

    #[test]
    fn test_train_and_lookup() {
        let db = test_db();
        let words: Vec<String> = vec!["b:hello".into(), "b:world".into(), "h:subject:test".into()];
        db.train(&words, false).unwrap();
        db.train(&words[..2], true).unwrap();

        let found = db.lookup_tokens(&words).unwrap();
        assert_eq!(found.len(), 3);
        assert_eq!(found["b:hello"], (1, 1));
        assert_eq!(found["h:subject:test"], (1, 0));
    }

    #[test]
    fn test_train_message_atomic() {
        let db = test_db();
        let words: Vec<String> = vec!["b:offer".into(), "b:deal".into()];
        db.train_message(&words, true).unwrap();
        db.train_message(&words, false).unwrap();

        assert_eq!(db.total_spam().unwrap(), 1);
        assert_eq!(db.total_good().unwrap(), 1);
        let found = db.lookup_tokens(&words).unwrap();
        assert_eq!(found["b:offer"], (1, 1));
    }

    #[test]
    fn test_counts() {
        let db = test_db();
        let words: Vec<String> = vec!["a:one".into(), "a:two".into()];
        db.train(&words, false).unwrap();

        let c = db.counts().unwrap();
        assert_eq!(c.unique_tokens, 2);
    }

    #[test]
    fn test_cleanup() {
        let db = test_db();
        let words: Vec<String> = vec!["b:rare".into()];
        db.train(&words, false).unwrap();

        let deleted = db.cleanup(1, 0).unwrap();
        assert_eq!(deleted, 1); // good=1, total=1 <= 1

        let c = db.counts().unwrap();
        assert_eq!(c.unique_tokens, 0);
    }

    #[test]
    fn test_export_import() {
        let db = test_db();
        let words: Vec<String> = vec!["b:hello".into(), "b:world".into()];
        db.train(&words, false).unwrap();
        db.inc_total_good().unwrap();

        let mut buf = Vec::new();
        db.export(&mut buf).unwrap();
        let csv = String::from_utf8(buf.clone()).unwrap();
        assert!(csv.contains("\"b:hello\""));
        assert!(csv.contains("\"__total__\""));

        // Import into fresh db
        let db2 = test_db();
        let reader = Cursor::new(buf);
        let count = db2.import(std::io::BufReader::new(reader)).unwrap();
        assert_eq!(count, 2);
        assert_eq!(db2.total_good().unwrap(), 1);
    }

    /// Bulk training: one transaction, token counts per message, class total +N.
    #[test]
    fn test_train_messages_bulk() {
        let db = test_db();
        let msgs: Vec<Vec<String>> = vec![
            vec!["b:one".into(), "b:two".into()],
            vec!["b:two".into()],
        ];
        db.train_messages(&msgs, true).unwrap();
        assert_eq!(db.total_spam().unwrap(), 2);
        assert_eq!(db.total_good().unwrap(), 0);
        let found = db
            .lookup_tokens(&["b:one".to_string(), "b:two".to_string()])
            .unwrap();
        assert_eq!(found["b:one"], (0, 1));
        assert_eq!(found["b:two"], (0, 2));
        // Empty batch is a no-op, not an error.
        db.train_messages(&[], false).unwrap();
        assert_eq!(db.total_good().unwrap(), 0);
    }

    #[test]
    fn relabel_reverses_counts_and_totals() {
        let db = test_db();
        let words = vec!["b:alpha".to_string(), "b:beta".to_string()];
        db.train_message(&words, true).unwrap();

        let result = db.relabel(&words, true, false).unwrap();

        assert_eq!(result, Untrained { decremented: 2, stranded: 0 });
        assert_eq!((db.total_good().unwrap(), db.total_spam().unwrap()), (1, 0));
        let found = db.lookup_tokens(&words).unwrap();
        assert_eq!(found["b:alpha"], (1, 0));
        assert_eq!(found["b:beta"], (1, 0));
    }

    #[test]
    fn relabel_floors_missing_from_counts_and_still_lands() {
        let db = test_db();
        let words = vec!["b:alpha".to_string(), "b:beta".to_string()];

        let result = db.relabel(&words, true, false).unwrap();

        assert_eq!(result, Untrained { decremented: 0, stranded: 2 });
        assert_eq!((db.total_good().unwrap(), db.total_spam().unwrap()), (1, 0));
        let found = db.lookup_tokens(&words).unwrap();
        assert_eq!(found["b:alpha"], (1, 0));
        assert_eq!(found["b:beta"], (1, 0));
    }

    #[test]
    fn relabel_rejects_equal_classes_without_panicking() {
        let db = test_db();
        let error = db.relabel(&[], true, true).unwrap_err();
        match error {
            rusqlite::Error::InvalidParameterName(message) => assert_eq!(
                message,
                "relabel: from and to classes must differ"
            ),
            other => panic!("unexpected relabel error: {other}"),
        }
    }

    #[test]
    fn untrain_reports_partial_stranding() {
        let db = test_db();
        let trained = vec!["b:alpha".to_string(), "b:beta".to_string()];
        let message = vec![
            "b:alpha".to_string(),
            "b:beta".to_string(),
            "b:gamma".to_string(),
            "b:delta".to_string(),
        ];
        db.train_message(&trained, true).unwrap();

        let result = db.untrain(&message, true).unwrap();

        assert_eq!(result, Untrained { decremented: 2, stranded: 2 });
        assert_eq!(db.total_spam().unwrap(), 0);
    }

    #[test]
    fn relabel_only_reverses_tokens_in_current_stream() {
        let db = test_db();
        let frozen = vec![
            "b:style".to_string(),
            "b:nbsp".to_string(),
            "b:helvetica".to_string(),
            "b:meeting".to_string(),
            "b:agenda".to_string(),
        ];
        let current = vec!["b:meeting".to_string(), "b:agenda".to_string()];
        db.train_message(&frozen, true).unwrap();

        let result = db.relabel(&current, true, false).unwrap();

        assert_eq!(result, Untrained { decremented: 2, stranded: 0 });
        let found = db.lookup_tokens(&frozen).unwrap();
        for markup in ["b:style", "b:nbsp", "b:helvetica"] {
            assert_eq!(found[markup], (0, 1), "{markup} must remain spam-side");
        }
        for content in ["b:meeting", "b:agenda"] {
            assert_eq!(found[content], (1, 0), "{content} must move classes");
        }
    }

    #[test]
    fn relabel_messages_returns_real_per_message_outcomes() {
        let db = test_db();
        let first = vec!["b:alpha".to_string()];
        let second_trained = vec!["b:beta".to_string()];
        let second_corrected = vec!["b:beta".to_string(), "b:missing".to_string()];
        db.train_message(&first, true).unwrap();
        db.train_message(&second_trained, true).unwrap();

        let results = db
            .relabel_messages(&[first.clone(), second_corrected.clone()], true, false)
            .unwrap();

        assert_eq!(
            results,
            vec![
                Untrained { decremented: 1, stranded: 0 },
                Untrained { decremented: 1, stranded: 1 },
            ]
        );
        assert_eq!((db.total_good().unwrap(), db.total_spam().unwrap()), (2, 0));
        let found = db.lookup_tokens(&[first, second_corrected].concat()).unwrap();
        assert_eq!(found["b:alpha"], (1, 0));
        assert_eq!(found["b:beta"], (1, 0));
        assert_eq!(found["b:missing"], (1, 0));
    }

    #[test]
    fn immediate_transactions_serialize_two_connections_without_busy_snapshot() {
        use std::sync::mpsc;
        use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

        struct TempDirGuard(std::path::PathBuf);

        impl Drop for TempDirGuard {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }

        let root = std::env::temp_dir().join(format!(
            "spamlite-immediate-{}-{}",
            std::process::id(),
            SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos(),
        ));
        let _guard = TempDirGuard(root.clone());
        let path = root.join("db.sqlite");
        let db_a = Database::open(&path).unwrap();
        let db_b = Database::open(&path).unwrap();
        let tx_a = ops::begin_immediate(&db_a.conn).unwrap();
        let (started_tx, started_rx) = mpsc::channel();
        let (done_tx, done_rx) = mpsc::channel();

        let handle = std::thread::spawn(move || {
            started_tx.send(()).unwrap();
            let attempt_at = Instant::now();
            let result = ops::begin_immediate(&db_b.conn).and_then(|tx| tx.commit());
            done_tx.send((attempt_at, attempt_at.elapsed(), result)).unwrap();
        });

        started_rx.recv().unwrap();
        std::thread::sleep(Duration::from_millis(300));
        assert!(
            matches!(done_rx.try_recv(), Err(mpsc::TryRecvError::Empty)),
            "connection B silently proceeded while A held the reserved lock"
        );
        let release_at = Instant::now();
        tx_a.commit().unwrap();

        let (attempt_at, elapsed, result) = done_rx.recv().unwrap();
        assert!(
            attempt_at < release_at,
            "connection B did not attempt BEGIN IMMEDIATE before A released"
        );
        if let Err(rusqlite::Error::SqliteFailure(error, _)) = &result {
            assert_ne!(
                error.extended_code,
                rusqlite::ffi::SQLITE_BUSY_SNAPSHOT,
                "IMMEDIATE transaction must never fail with SQLITE_BUSY_SNAPSHOT"
            );
            assert_eq!(error.code, rusqlite::ErrorCode::DatabaseBusy);
            assert!(
                elapsed >= Duration::from_millis(4900),
                "SQLITE_BUSY returned before busy_timeout elapsed: {elapsed:?}"
            );
        } else {
            result.unwrap();
            assert!(
                elapsed >= Duration::from_millis(275),
                "connection B did not wait for A: {elapsed:?}"
            );
        }
        handle.join().unwrap();
        drop(db_a);
    }

    #[test]
    fn frozen_v090_ddl_interoperates_both_directions() {
        use crate::scoring::{classify, Params, Verdict};
        use std::time::{SystemTime, UNIX_EPOCH};

        const V090_DDL: &str = "CREATE TABLE IF NOT EXISTS tokens (
                word      TEXT PRIMARY KEY,
                good      INTEGER NOT NULL DEFAULT 0,
                spam      INTEGER NOT NULL DEFAULT 0,
                last_seen INTEGER NOT NULL DEFAULT 0
            ) WITHOUT ROWID;

            CREATE TABLE IF NOT EXISTS meta (
                key   TEXT PRIMARY KEY,
                value TEXT NOT NULL
            ) WITHOUT ROWID;";
        const V090_META: [&str; 3] = [
            "INSERT OR IGNORE INTO meta (key, value) VALUES ('total_good', '0')",
            "INSERT OR IGNORE INTO meta (key, value) VALUES ('total_spam', '0')",
            "INSERT OR IGNORE INTO meta (key, value) VALUES ('version', '1')",
        ];
        const V090_GET_META: &str = "SELECT value FROM meta WHERE key = ?1";
        const V090_LOOKUP_ONE: &str =
            "SELECT word, good, spam FROM tokens WHERE word IN (?)";
        const V090_UPSERT_GOOD: &str =
            "INSERT INTO tokens (word, good, spam, last_seen) VALUES (?1, 1, 0, ?2)
             ON CONFLICT(word) DO UPDATE SET good = good + 1, last_seen = ?2";
        const V090_INC_META: &str =
            "UPDATE meta SET value = CAST(CAST(value AS INTEGER) + 1 AS TEXT) WHERE key = ?1";

        let root = std::env::temp_dir().join(format!(
            "spamlite-v090-interop-{}-{}",
            std::process::id(),
            SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos(),
        ));
        std::fs::create_dir_all(&root).unwrap();

        let old_path = root.join("old.db");
        let old = Connection::open(&old_path).unwrap();
        old.execute_batch(V090_DDL).unwrap();
        for sql in V090_META {
            old.execute(sql, []).unwrap();
        }
        drop(old);

        let upgraded = Database::open(&old_path).unwrap();
        let old_to_new_version: String = upgraded
            .conn
            .query_row(V090_GET_META, params!["version"], |row| row.get(0))
            .unwrap();
        assert_eq!(old_to_new_version, "1");
        let word = vec!["b:legacy".to_string()];
        upgraded.train_message(&word, true).unwrap();
        let (verdict, score) = classify(&upgraded, &word, &Params::default()).unwrap();
        assert_eq!(verdict, Verdict::Spam);
        assert!(score > 0.5);
        drop(upgraded);

        let new_path = root.join("new.db");
        let current = Database::open(&new_path).unwrap();
        current.train_message(&word, true).unwrap();
        drop(current);

        let old_binary = Connection::open(&new_path).unwrap();
        let counts: (String, i64, i64) = old_binary
            .query_row(
                V090_LOOKUP_ONE,
                params!["b:legacy"],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap();
        assert_eq!(counts, ("b:legacy".to_string(), 0, 1));
        let total_spam: String = old_binary
            .query_row(V090_GET_META, params!["total_spam"], |row| row.get(0))
            .unwrap();
        assert_eq!(total_spam, "1");
        let new_to_old_version: String = old_binary
            .query_row(V090_GET_META, params!["version"], |row| row.get(0))
            .unwrap();
        assert_eq!(new_to_old_version, "1");
        old_binary
            .execute(V090_UPSERT_GOOD, params!["b:legacy", 1_i64])
            .unwrap();
        old_binary
            .execute(V090_INC_META, params!["total_good"])
            .unwrap();
        drop(old_binary);

        let reopened = Database::open(&new_path).unwrap();
        assert_eq!(reopened.lookup_tokens(&word).unwrap()["b:legacy"], (1, 1));
        assert_eq!((reopened.total_good().unwrap(), reopened.total_spam().unwrap()), (1, 1));
        drop(reopened);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn test_stats() {
        let db = test_db();
        let s = db.stats(86400).unwrap();
        assert_eq!(s.unique_tokens, 0);
        assert_eq!(s.last_seen_min, 0);
        assert_eq!(s.last_seen_max, 0);
        assert_eq!(s.seen_recent, 0);

        db.train_message(&["b:x".to_string()], false).unwrap();
        let s = db.stats(86400).unwrap();
        assert_eq!(s.total_good, 1);
        assert_eq!(s.unique_tokens, 1);
        assert_eq!(s.seen_recent, 1, "a just-trained token is inside any sane window");
        assert!(s.last_seen_min > 0 && s.last_seen_max >= s.last_seen_min);
    }

    #[test]
    fn test_parse_csv_line() {
        let result = parse_csv_line("10,5,0,\"h:subject:test\"");
        assert!(result.is_some());
        let (good, spam, word) = result.unwrap();
        assert_eq!(good, 10);
        assert_eq!(spam, 5);
        assert_eq!(word, "h:subject:test");

        // Degenerate lines must not produce empty-string tokens
        assert!(parse_csv_line("10,5,0,").is_none());
        assert!(parse_csv_line("10,5,0,\"\"").is_none());
    }
}
