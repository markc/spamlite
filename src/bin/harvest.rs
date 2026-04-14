// Copyright 2026 Mark Constable <mc@netserva.org>
// SPDX-License-Identifier: MIT
//
// spamlite-harvest — Parse dovecot sieve TRAIN debug lines out of mail.log
// files and emit one JSONL record per event. Output goes to stdout; summary
// counts go to stderr. Reads file paths from argv, or stdin if none given.
//
// Reads plain-text logs only. For rotated .gz logs, `gunzip -c` them first and
// pipe through stdin. Designed as the first pass of the Phase 1.7 feedback-
// event benchmark harness — it produces the event stream that a later pass
// will correlate against per-user Maildir timestamps to recover the message
// bodies.
//
// Expected input line format (from /etc/dovecot/sieve/retrain-as-{ham,spam}.sieve):
//
//   2026-04-14T18:36:24.600+10:00 mail dovecot: imap(user@dom)<pid><sess>: \
//       sieve: DEBUG: TRAIN: user@dom -> good
//
// Output JSONL schema:
//
//   {"t":"<timestamp>","u":"<user>","v":"good"|"spam","sess":"<session>"}

use std::collections::BTreeMap;
use std::env;
use std::fs::File;
use std::io::{self, BufRead, BufReader, Write};
use std::process;

const MARKER: &str = "sieve: DEBUG: TRAIN: ";

struct TrainEvent<'a> {
    timestamp: &'a str,
    user: &'a str,
    verdict: &'a str,
    session: &'a str,
}

/// Parse a single log line. Returns None if it is not a TRAIN event or does
/// not match the expected shape. Be lenient — malformed lines are skipped.
fn parse_line(line: &str) -> Option<TrainEvent<'_>> {
    let marker_idx = line.find(MARKER)?;

    // Timestamp is the first whitespace-delimited token.
    let timestamp_end = line.find(' ')?;
    let timestamp = &line[..timestamp_end];

    // Extract session id from `<sess>:` just before the marker. Format is
    // `imap(user)<pid><session>:` so we locate the last `<` before the marker.
    let session = {
        let prefix = &line[..marker_idx];
        let rb = prefix.rfind('>')?;
        let lb = prefix[..rb].rfind('<')?;
        &prefix[lb + 1..rb]
    };

    // After the marker: "user -> direction"
    let rest = &line[marker_idx + MARKER.len()..];
    let arrow = rest.find(" -> ")?;
    let user = &rest[..arrow];
    let direction = rest[arrow + 4..].trim_end();

    let verdict = match direction {
        "good" => "good",
        "spam" => "spam",
        _ => return None,
    };

    Some(TrainEvent {
        timestamp,
        user,
        verdict,
        session,
    })
}

/// Minimal JSON string escaping — only handles the characters that appear
/// in dovecot log output (ASCII, quotes, backslashes).
fn write_json_string<W: Write>(w: &mut W, s: &str) -> io::Result<()> {
    w.write_all(b"\"")?;
    for c in s.chars() {
        match c {
            '"' => w.write_all(b"\\\"")?,
            '\\' => w.write_all(b"\\\\")?,
            '\n' => w.write_all(b"\\n")?,
            '\r' => w.write_all(b"\\r")?,
            '\t' => w.write_all(b"\\t")?,
            c if (c as u32) < 0x20 => write!(w, "\\u{:04x}", c as u32)?,
            c => {
                let mut buf = [0u8; 4];
                w.write_all(c.encode_utf8(&mut buf).as_bytes())?;
            }
        }
    }
    w.write_all(b"\"")?;
    Ok(())
}

fn emit_event<W: Write>(w: &mut W, ev: &TrainEvent<'_>) -> io::Result<()> {
    w.write_all(b"{\"t\":")?;
    write_json_string(w, ev.timestamp)?;
    w.write_all(b",\"u\":")?;
    write_json_string(w, ev.user)?;
    w.write_all(b",\"v\":")?;
    write_json_string(w, ev.verdict)?;
    w.write_all(b",\"sess\":")?;
    write_json_string(w, ev.session)?;
    w.write_all(b"}\n")?;
    Ok(())
}

#[derive(Default)]
struct Stats {
    lines_read: u64,
    events_emitted: u64,
    parse_failures: u64,
    by_user: BTreeMap<String, (u64, u64)>, // (good, spam)
    by_date: BTreeMap<String, u64>,        // YYYY-MM-DD -> count
}

impl Stats {
    fn record(&mut self, ev: &TrainEvent<'_>) {
        self.events_emitted += 1;
        let entry = self.by_user.entry(ev.user.to_string()).or_insert((0, 0));
        if ev.verdict == "good" {
            entry.0 += 1;
        } else {
            entry.1 += 1;
        }
        if let Some(date) = ev.timestamp.get(..10) {
            *self.by_date.entry(date.to_string()).or_insert(0) += 1;
        }
    }

    fn print_summary<W: Write>(&self, w: &mut W) -> io::Result<()> {
        writeln!(w, "# harvest summary")?;
        writeln!(w, "# lines read:      {}", self.lines_read)?;
        writeln!(w, "# events emitted:  {}", self.events_emitted)?;
        writeln!(w, "# parse failures:  {}", self.parse_failures)?;
        writeln!(w, "# unique users:    {}", self.by_user.len())?;
        writeln!(w, "# dates covered:   {}", self.by_date.len())?;
        if !self.by_date.is_empty() {
            writeln!(w, "# events by date:")?;
            for (date, count) in &self.by_date {
                writeln!(w, "#   {date}  {count}")?;
            }
        }
        if !self.by_user.is_empty() {
            // Top 15 users by total events.
            let mut users: Vec<_> = self.by_user.iter().collect();
            users.sort_by(|a, b| (b.1 .0 + b.1 .1).cmp(&(a.1 .0 + a.1 .1)));
            writeln!(w, "# top users by event count:")?;
            for (user, (g, s)) in users.iter().take(15) {
                writeln!(w, "#   {:<40} good={g} spam={s}", user)?;
            }
        }
        Ok(())
    }
}

fn process_reader<R: BufRead, W: Write>(
    reader: R,
    out: &mut W,
    stats: &mut Stats,
) -> io::Result<()> {
    for line in reader.lines() {
        let line = line?;
        stats.lines_read += 1;
        if !line.contains(MARKER) {
            continue;
        }
        match parse_line(&line) {
            Some(ev) => {
                emit_event(out, &ev)?;
                stats.record(&ev);
            }
            None => stats.parse_failures += 1,
        }
    }
    Ok(())
}

fn main() {
    let args: Vec<String> = env::args().skip(1).collect();
    let stdout = io::stdout();
    let mut out = stdout.lock();
    let mut stats = Stats::default();

    let result = if args.is_empty() {
        let stdin = io::stdin();
        let reader = stdin.lock();
        process_reader(reader, &mut out, &mut stats)
    } else {
        let mut last = Ok(());
        for path in &args {
            match File::open(path) {
                Ok(f) => {
                    let reader = BufReader::new(f);
                    if let Err(e) = process_reader(reader, &mut out, &mut stats) {
                        eprintln!("spamlite-harvest: error reading {path}: {e}");
                        last = Err(e);
                    }
                }
                Err(e) => {
                    eprintln!("spamlite-harvest: cannot open {path}: {e}");
                    last = Err(e);
                }
            }
        }
        last
    };

    let _ = out.flush();
    let _ = stats.print_summary(&mut io::stderr());

    if result.is_err() {
        process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_basic_line() {
        let line = "2026-04-14T18:36:24.600202+10:00 mail dovecot: imap(sandy@gardinermail.com.au)<3881567><wtaHdmdPPoXLGYQI>: sieve: DEBUG: TRAIN: sandy@gardinermail.com.au -> good";
        let ev = parse_line(line).expect("should parse");
        assert_eq!(ev.timestamp, "2026-04-14T18:36:24.600202+10:00");
        assert_eq!(ev.user, "sandy@gardinermail.com.au");
        assert_eq!(ev.verdict, "good");
        assert_eq!(ev.session, "wtaHdmdPPoXLGYQI");
    }

    #[test]
    fn test_parse_spam_verdict() {
        let line = "2026-04-14T18:36:24.600+10:00 mail dovecot: imap(x@y.com)<1><sessABC>: sieve: DEBUG: TRAIN: x@y.com -> spam";
        let ev = parse_line(line).expect("should parse");
        assert_eq!(ev.verdict, "spam");
        assert_eq!(ev.session, "sessABC");
    }

    #[test]
    fn test_parse_rejects_non_train() {
        assert!(parse_line("2026-04-14 mail dovecot: imap-login: ...").is_none());
        assert!(parse_line("arbitrary text").is_none());
    }

    #[test]
    fn test_parse_rejects_unknown_verdict() {
        let line = "2026-04-14T18:36:24.600+10:00 mail dovecot: imap(x@y.com)<1><s>: sieve: DEBUG: TRAIN: x@y.com -> maybe";
        assert!(parse_line(line).is_none());
    }

    #[test]
    fn test_json_escape_quotes() {
        let mut buf = Vec::new();
        write_json_string(&mut buf, "has \"quote\" and \\slash").unwrap();
        assert_eq!(
            std::str::from_utf8(&buf).unwrap(),
            r#""has \"quote\" and \\slash""#
        );
    }

    #[test]
    fn test_emit_event() {
        let ev = TrainEvent {
            timestamp: "2026-04-14T18:36:24.600+10:00",
            user: "a@b.com",
            verdict: "good",
            session: "sess1",
        };
        let mut buf = Vec::new();
        emit_event(&mut buf, &ev).unwrap();
        let s = std::str::from_utf8(&buf).unwrap();
        assert!(s.starts_with('{') && s.ends_with("}\n"));
        assert!(s.contains("\"t\":\"2026-04-14T18:36:24.600+10:00\""));
        assert!(s.contains("\"u\":\"a@b.com\""));
        assert!(s.contains("\"v\":\"good\""));
        assert!(s.contains("\"sess\":\"sess1\""));
    }

    #[test]
    fn test_process_reader_integration() {
        let input = "2026-04-14T18:36:24.600+10:00 mail dovecot: imap(a@b.com)<1><s1>: sieve: DEBUG: TRAIN: a@b.com -> good
unrelated line that does not match
2026-04-14T18:36:25.000+10:00 mail dovecot: imap(c@d.com)<2><s2>: sieve: DEBUG: TRAIN: c@d.com -> spam
";
        let reader = io::BufReader::new(input.as_bytes());
        let mut out = Vec::new();
        let mut stats = Stats::default();
        process_reader(reader, &mut out, &mut stats).unwrap();
        assert_eq!(stats.lines_read, 3);
        assert_eq!(stats.events_emitted, 2);
        assert_eq!(stats.parse_failures, 0);
        assert_eq!(stats.by_user.len(), 2);
        let output = String::from_utf8(out).unwrap();
        assert_eq!(output.lines().count(), 2);
    }
}
