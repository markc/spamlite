// Copyright 2026 Mark Constable <mc@netserva.org>
// SPDX-License-Identifier: MIT

use rusqlite::{params, Connection, Result as SqlResult};
use std::io::{BufRead, Write};
use std::path::Path;

/// Token record from the database
#[derive(Debug, Clone)]
pub struct Token {
    pub word: String,
    pub good: u64,
    pub spam: u64,
}

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
    /// Open (or create) the database at the given path with WAL mode
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

    /// Set a meta value
    fn set_meta(&self, key: &str, value: u64) -> SqlResult<()> {
        self.conn.execute(
            "INSERT OR REPLACE INTO meta (key, value) VALUES (?1, ?2)",
            params![key, value.to_string()],
        )?;
        Ok(())
    }

    /// Get total good message count
    pub fn total_good(&self) -> SqlResult<u64> {
        self.get_meta("total_good")
    }

    /// Get total spam message count
    pub fn total_spam(&self) -> SqlResult<u64> {
        self.get_meta("total_spam")
    }

    /// Increment total good count
    pub fn inc_total_good(&self) -> SqlResult<()> {
        let n = self.total_good()? + 1;
        self.set_meta("total_good", n)
    }

    /// Increment total spam count
    pub fn inc_total_spam(&self) -> SqlResult<()> {
        let n = self.total_spam()? + 1;
        self.set_meta("total_spam", n)
    }

    /// Batch-lookup tokens by word. Returns only tokens that exist in the DB.
    pub fn lookup_tokens(&self, words: &[String]) -> SqlResult<Vec<Token>> {
        if words.is_empty() {
            return Ok(Vec::new());
        }

        // Build parameterized IN clause in chunks to avoid SQLite variable limits
        let mut results = Vec::new();
        for chunk in words.chunks(500) {
            let placeholders: Vec<&str> = chunk.iter().map(|_| "?").collect();
            let sql = format!(
                "SELECT word, good, spam FROM tokens WHERE word IN ({})",
                placeholders.join(",")
            );
            let mut stmt = self.conn.prepare(&sql)?;

            let params: Vec<&dyn rusqlite::types::ToSql> = chunk
                .iter()
                .map(|w| w as &dyn rusqlite::types::ToSql)
                .collect();

            let rows = stmt.query_map(params.as_slice(), |row| {
                Ok(Token {
                    word: row.get(0)?,
                    good: row.get::<_, i64>(1)? as u64,
                    spam: row.get::<_, i64>(2)? as u64,
                })
            })?;

            for row in rows {
                results.push(row?);
            }
        }

        Ok(results)
    }

    /// Train tokens: increment good or spam count for each word
    pub fn train(&self, words: &[String], is_spam: bool) -> SqlResult<()> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;

        let tx = self.conn.unchecked_transaction()?;

        if is_spam {
            let mut stmt = tx.prepare(
                "INSERT INTO tokens (word, good, spam, last_seen) VALUES (?1, 0, 1, ?2)
                 ON CONFLICT(word) DO UPDATE SET spam = spam + 1, last_seen = ?2",
            )?;
            for word in words {
                stmt.execute(params![word, now])?;
            }
        } else {
            let mut stmt = tx.prepare(
                "INSERT INTO tokens (word, good, spam, last_seen) VALUES (?1, 1, 0, ?2)
                 ON CONFLICT(word) DO UPDATE SET good = good + 1, last_seen = ?2",
            )?;
            for word in words {
                stmt.execute(params![word, now])?;
            }
        }

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
    pub fn export<W: Write>(&self, writer: &mut W) -> SqlResult<()> {
        // First line: meta counts as a special token
        let total_good = self.total_good()?;
        let total_spam = self.total_spam()?;
        writeln!(writer, "{total_good},{total_spam},0,\"__total__\"").ok();

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
            writeln!(writer, "{good},{spam},0,\"{word}\"").ok();
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
                    // Set meta totals from export
                    tx.execute(
                        "INSERT OR REPLACE INTO meta (key, value) VALUES ('total_good', ?1)",
                        params![good.to_string()],
                    )?;
                    tx.execute(
                        "INSERT OR REPLACE INTO meta (key, value) VALUES ('total_spam', ?1)",
                        params![spam.to_string()],
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
    Some((good, spam, word.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn test_db() -> Database {
        Database::open(Path::new(":memory:")).unwrap()
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
        db.train(&words[..2].to_vec(), true).unwrap();

        let found = db.lookup_tokens(&words).unwrap();
        assert_eq!(found.len(), 3);

        let hello = found.iter().find(|t| t.word == "b:hello").unwrap();
        assert_eq!(hello.good, 1);
        assert_eq!(hello.spam, 1);

        let test = found.iter().find(|t| t.word == "h:subject:test").unwrap();
        assert_eq!(test.good, 1);
        assert_eq!(test.spam, 0);
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
    }
}
