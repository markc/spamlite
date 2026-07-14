// Copyright 2026 Mark Constable <mc@netserva.org>
// SPDX-License-Identifier: MIT

use rusqlite::{params, Connection, Result as SqlResult};
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
        if !path.is_file() {
            return Err(format!("no database at {}", path.display()));
        }
        Database::open(path).map_err(|e| format!("failed to open {}: {e}", path.display()))
    }

    /// Open (or create) the database at the given path with WAL mode.
    /// Creates the file and its parent directories — use `open_existing` for
    /// anything that only reads.
    pub fn open(path: &Path) -> SqlResult<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).ok();
        }
        let conn = Connection::open(path)?;

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
            ) WITHOUT ROWID;",
        )?;

        // Initialize meta if missing
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

        Ok(Database { conn })
    }

    /// Get a meta value
    fn get_meta(&self, key: &str) -> SqlResult<u64> {
        self.conn
            .query_row("SELECT value FROM meta WHERE key = ?1", params![key], |row| {
                let s: String = row.get(0)?;
                Ok(s.parse::<u64>().unwrap_or(0))
            })
    }

    /// Get total good message count
    pub fn total_good(&self) -> SqlResult<u64> {
        self.get_meta("total_good")
    }

    /// Get total spam message count
    pub fn total_spam(&self) -> SqlResult<u64> {
        self.get_meta("total_spam")
    }

    /// Atomically increment a meta counter. A single UPDATE avoids the
    /// read-modify-write lost-update race when two deliveries for the same
    /// user run concurrently (dovecot lmtp can and does parallelise).
    fn inc_meta(&self, key: &str) -> SqlResult<()> {
        self.conn.execute(
            "UPDATE meta SET value = CAST(CAST(value AS INTEGER) + 1 AS TEXT) WHERE key = ?1",
            params![key],
        )?;
        Ok(())
    }

    /// Increment total good count
    pub fn inc_total_good(&self) -> SqlResult<()> {
        self.inc_meta("total_good")
    }

    /// Increment total spam count
    pub fn inc_total_spam(&self) -> SqlResult<()> {
        self.inc_meta("total_spam")
    }

    /// Batch-lookup tokens by word. Returns a map of word -> (good, spam)
    /// containing only tokens that exist in the DB.
    pub fn lookup_tokens(&self, words: &[String]) -> SqlResult<HashMap<String, (u64, u64)>> {
        let mut results = HashMap::with_capacity(words.len());

        // Build parameterized IN clause in chunks to avoid SQLite variable limits.
        // prepare_cached means the common 500-placeholder statement is compiled
        // once per connection even for multi-chunk messages.
        for chunk in words.chunks(500) {
            let placeholders = vec!["?"; chunk.len()].join(",");
            let sql = format!("SELECT word, good, spam FROM tokens WHERE word IN ({placeholders})");
            let mut stmt = self.conn.prepare_cached(&sql)?;

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

    /// Upsert the per-token counts for one training pass. Runs inside the
    /// caller's transaction (`Transaction` derefs to `Connection`).
    fn upsert_tokens(conn: &Connection, words: &[String], is_spam: bool) -> SqlResult<()> {
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
        let mut stmt = conn.prepare_cached(sql)?;
        for word in words {
            stmt.execute(params![word, now])?;
        }
        Ok(())
    }

    /// Train token counts only: increment good or spam count for each word.
    /// Does NOT bump the message totals — that is what the convergence loop in
    /// `cmd_train` needs (token counts repeat, the corpus ratio stays honest).
    /// For a full one-message training pass use `train_message`.
    pub fn train(&self, words: &[String], is_spam: bool) -> SqlResult<()> {
        let tx = self.conn.unchecked_transaction()?;
        Self::upsert_tokens(&tx, words, is_spam)?;
        tx.commit()
    }

    /// Train one message: token counts +1 AND the good/spam message total +1,
    /// in a single transaction. Atomicity matters — a crash or SQLITE_BUSY
    /// between the two would skew the corpus good/spam ratio that feeds every
    /// per-token probability.
    pub fn train_message(&self, words: &[String], is_spam: bool) -> SqlResult<()> {
        let tx = self.conn.unchecked_transaction()?;
        Self::upsert_tokens(&tx, words, is_spam)?;
        let key = if is_spam { "total_spam" } else { "total_good" };
        tx.execute(
            "UPDATE meta SET value = CAST(CAST(value AS INTEGER) + 1 AS TEXT) WHERE key = ?1",
            params![key],
        )?;
        tx.commit()
    }

    /// Get database statistics
    pub fn counts(&self) -> SqlResult<Counts> {
        let unique_tokens: u64 = self.conn.query_row(
            "SELECT COUNT(*) FROM tokens",
            [],
            |row| row.get::<_, i64>(0).map(|v| v as u64),
        )?;

        Ok(Counts {
            total_good: self.total_good()?,
            total_spam: self.total_spam()?,
            unique_tokens,
        })
    }

    /// Cleanup: remove tokens with total count <= min_count or not seen in `days` days
    pub fn cleanup(&self, min_count: u64, days: u64) -> SqlResult<u64> {
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
            self.conn.execute(
                "DELETE FROM tokens WHERE (good + spam) <= ?1 OR last_seen < ?2",
                params![min_count as i64, cutoff],
            )?
        } else {
            self.conn.execute(
                "DELETE FROM tokens WHERE (good + spam) <= ?1",
                params![min_count as i64],
            )?
        };

        Ok(deleted as u64)
    }

    /// Export all tokens in spamprobe-compatible CSV format:
    /// goodCount,spamCount,flags,"word"
    pub fn export<W: Write>(&self, writer: &mut W) -> Result<(), ExportError> {
        // First line: meta counts as a special token
        let total_good = self.total_good()?;
        let total_spam = self.total_spam()?;
        writeln!(writer, "{total_good},{total_spam},0,\"__total__\"")?;

        let mut stmt = self
            .conn
            .prepare("SELECT word, good, spam FROM tokens ORDER BY word")?;

        let rows = stmt.query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, i64>(1)? as u64,
                row.get::<_, i64>(2)? as u64,
            ))
        })?;

        for row in rows {
            let (word, good, spam) = row?;
            // Skip tokens that would corrupt the CSV line format. A `"` can
            // reach the db via a single-quoted href URL; control chars never
            // should but cost nothing to guard. Such tokens are junk signal.
            if word.contains('"') || word.chars().any(|c| c.is_control()) {
                continue;
            }
            writeln!(writer, "{good},{spam},0,\"{word}\"")?;
        }

        Ok(())
    }

    /// Import from spamprobe-compatible CSV format:
    /// goodCount,spamCount,flags,"word"
    pub fn import<R: BufRead>(&self, reader: R) -> SqlResult<u64> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;

        let tx = self.conn.unchecked_transaction()?;
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

            // Parse: goodCount,spamCount,flags,"word"
            if let Some((good, spam, word)) = parse_csv_line(line) {
                if word == "__total__" {
                    // Totals ADD, matching the token rows above (`good = good + ?2`).
                    //
                    // These used to be INSERT OR REPLACE, which is only correct when
                    // importing into an empty database. Importing to MERGE a second corpus
                    // — the obvious way to give a user extra ham coverage — kept every
                    // merged token count but overwrote the totals with the incoming file's,
                    // so a ham-only donor (spam=0) set the target's `total_spam` to 0 and
                    // every message scored GOOD. Adding is correct in both cases: a restore
                    // into an empty db is 0 + N = N.
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

        drop(stmt);
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
