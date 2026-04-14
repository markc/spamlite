// Copyright 2026 Mark Constable <mc@netserva.org>
// SPDX-License-Identifier: MIT
//
// spamlite-harvest — Parse dovecot mail.log files for spamlite-relevant
// events and emit one JSONL record per event. Output goes to stdout; summary
// counts go to stderr. Reads file paths from argv, or stdin if none given.
//
// Reads plain-text logs only. For rotated .gz logs, `gunzip -c` them first
// and pipe through stdin (or use `zcat -f file1 file2.gz ...`).
//
// Two event types are emitted:
//
// 1. TRAIN events, fired by retrain-as-{ham,spam}.sieve on IMAP folder moves.
//    One line per event, no session-level pairing required.
//
//      2026-04-14T18:36:24.600+10:00 mail dovecot: imap(user)<pid><sess>: \
//          sieve: DEBUG: TRAIN: user -> good
//
//    →  {"type":"train","t":"<ts>","u":"<user>","v":"good","sess":"<sess>"}
//
// 2. DELIVERY events, fired by global.sieve on inbound LMTP delivery. These
//    log the spamlite score and verdict on every inbound message and are
//    paired by session id with a subsequent `sieve: msgid=...: stored mail
//    into mailbox 'X'` line to recover the Message-Id. The two lines arrive
//    within milliseconds of each other on the same session.
//
//      ... sieve: DEBUG: DELIVERY: user -> Inbox (GOOD 0.102534)
//      ... sieve: msgid=<0101...@us-west-2.amazonses.com>: stored mail into mailbox 'INBOX'
//
//    →  {"type":"delivery","t":"<ts>","u":"<user>","verdict":"GOOD","score":0.102534,
//          "folder":"Inbox","msgid":"<...>","sess":"<sess>"}
//
//    If the msgid line does not arrive (e.g. rejected delivery) the pending
//    DELIVERY is still emitted at end-of-input without a msgid field.
//
// DELIVERY records are the primary data source for the Phase 1.7 benchmark
// corpus: cross-referencing per-user delivery verdicts against current
// Maildir folder state gives the full fp/fn confusion matrix without
// needing the TRAIN event stream at all. TRAIN events remain useful as a
// secondary signal and for user-behaviour taxonomy.

use std::collections::{BTreeMap, HashMap};
use std::env;
use std::fs::File;
use std::io::{self, BufRead, BufReader, Write};
use std::process;

const TRAIN_MARKER: &str = "sieve: DEBUG: TRAIN: ";
const DELIVERY_MARKER: &str = "sieve: DEBUG: DELIVERY: ";
const MSGID_MARKER: &str = "sieve: msgid=";
const STORED_MARKER: &str = ": stored mail into mailbox '";

enum ParsedLine<'a> {
    Train(TrainEvent<'a>),
    Delivery(DeliveryStart<'a>),
    Msgid(MsgidLine<'a>),
    None,
}

struct TrainEvent<'a> {
    timestamp: &'a str,
    user: &'a str,
    verdict: &'a str,
    session: &'a str,
}

struct DeliveryStart<'a> {
    timestamp: &'a str,
    user: &'a str,
    verdict: &'a str,
    score: &'a str,
    folder: &'a str,
    session: &'a str,
}

struct MsgidLine<'a> {
    msgid: &'a str,
    session: &'a str,
}

#[derive(Clone)]
struct PendingDelivery {
    timestamp: String,
    user: String,
    verdict: String,
    score: String,
    folder: String,
}

/// Extract the session id from the prefix `imap(user)<pid><sess>:` or
/// `lmtp(user)<pid><sess>:`. Returns the string inside the LAST angle-bracket
/// pair before the first `:` outside the brackets.
fn extract_session(prefix: &str) -> Option<&str> {
    let close = prefix.rfind('>')?;
    let open = prefix[..close].rfind('<')?;
    Some(&prefix[open + 1..close])
}

fn parse_line(line: &str) -> ParsedLine<'_> {
    // Timestamp is the first whitespace-delimited token (all three line
    // types share this).
    let Some(ts_end) = line.find(' ') else {
        return ParsedLine::None;
    };
    let timestamp = &line[..ts_end];

    // TRAIN line
    if let Some(idx) = line.find(TRAIN_MARKER) {
        let Some(session) = extract_session(&line[..idx]) else {
            return ParsedLine::None;
        };
        let rest = &line[idx + TRAIN_MARKER.len()..];
        let Some(arrow) = rest.find(" -> ") else {
            return ParsedLine::None;
        };
        let user = &rest[..arrow];
        let direction = rest[arrow + 4..].trim_end();
        let verdict = match direction {
            "good" | "spam" => direction,
            _ => return ParsedLine::None,
        };
        return ParsedLine::Train(TrainEvent {
            timestamp,
            user,
            verdict,
            session,
        });
    }

    // DELIVERY line
    //   ...: sieve: DEBUG: DELIVERY: user -> Folder (VERDICT SCORE)
    if let Some(idx) = line.find(DELIVERY_MARKER) {
        let Some(session) = extract_session(&line[..idx]) else {
            return ParsedLine::None;
        };
        let rest = &line[idx + DELIVERY_MARKER.len()..];
        let Some(arrow) = rest.find(" -> ") else {
            return ParsedLine::None;
        };
        let user = &rest[..arrow];
        let after = &rest[arrow + 4..];
        let Some(paren) = after.find(" (") else {
            return ParsedLine::None;
        };
        let folder = &after[..paren];
        let Some(close) = after.rfind(')') else {
            return ParsedLine::None;
        };
        let inner = &after[paren + 2..close];
        let Some(space) = inner.find(' ') else {
            return ParsedLine::None;
        };
        let verdict = &inner[..space];
        let score = inner[space + 1..].trim();
        return ParsedLine::Delivery(DeliveryStart {
            timestamp,
            user,
            verdict,
            score,
            folder,
            session,
        });
    }

    // msgid stored-into-mailbox line (pairs with DELIVERY by session)
    //   ...: sieve: msgid=<...>: [...] stored mail into mailbox 'XXX'
    // We only need msgid + session; the folder comes from the DELIVERY line.
    if let Some(idx) = line.find(MSGID_MARKER) {
        let Some(session) = extract_session(&line[..idx]) else {
            return ParsedLine::None;
        };
        // Sanity-check that the line really is a "stored mail into mailbox"
        // variant and not some other sieve msgid= line we don't know about.
        if !line.contains(STORED_MARKER) {
            return ParsedLine::None;
        }
        let after = &line[idx + MSGID_MARKER.len()..];
        let Some(colon) = after.find(':') else {
            return ParsedLine::None;
        };
        let msgid = &after[..colon];
        let _ = timestamp; // reserved in case we want to emit msgid-only rows later
        return ParsedLine::Msgid(MsgidLine { msgid, session });
    }

    ParsedLine::None
}

/// Minimal JSON string escaping — handles the characters that appear in
/// dovecot log output.
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

fn emit_train<W: Write>(w: &mut W, ev: &TrainEvent<'_>) -> io::Result<()> {
    w.write_all(b"{\"type\":\"train\",\"t\":")?;
    write_json_string(w, ev.timestamp)?;
    w.write_all(b",\"u\":")?;
    write_json_string(w, ev.user)?;
    w.write_all(b",\"v\":")?;
    write_json_string(w, ev.verdict)?;
    w.write_all(b",\"sess\":")?;
    write_json_string(w, ev.session)?;
    w.write_all(b"}\n")
}

fn emit_delivery<W: Write>(
    w: &mut W,
    d: &PendingDelivery,
    session: &str,
    msgid: Option<&str>,
) -> io::Result<()> {
    w.write_all(b"{\"type\":\"delivery\",\"t\":")?;
    write_json_string(w, &d.timestamp)?;
    w.write_all(b",\"u\":")?;
    write_json_string(w, &d.user)?;
    w.write_all(b",\"verdict\":")?;
    write_json_string(w, &d.verdict)?;
    w.write_all(b",\"score\":")?;
    // score is already a numeric string (e.g. "0.102534"); emit as JSON number
    // — dovecot always prints a decimal here, but defensively fall back to
    // a string if it fails to parse.
    if d.score.parse::<f64>().is_ok() {
        w.write_all(d.score.as_bytes())?;
    } else {
        write_json_string(w, &d.score)?;
    }
    w.write_all(b",\"folder\":")?;
    write_json_string(w, &d.folder)?;
    if let Some(mid) = msgid {
        w.write_all(b",\"msgid\":")?;
        write_json_string(w, mid)?;
    }
    w.write_all(b",\"sess\":")?;
    write_json_string(w, session)?;
    w.write_all(b"}\n")
}

#[derive(Default)]
struct Stats {
    lines_read: u64,
    train_emitted: u64,
    delivery_emitted: u64,
    delivery_with_msgid: u64,
    delivery_orphan: u64,
    parse_failures: u64,
    by_user_train: BTreeMap<String, (u64, u64)>, // (good, spam)
    by_user_delivery: BTreeMap<String, (u64, u64)>, // (good, spam)
    by_date: BTreeMap<String, u64>,              // YYYY-MM-DD -> total events
}

impl Stats {
    fn record_train(&mut self, ev: &TrainEvent<'_>) {
        self.train_emitted += 1;
        let entry = self.by_user_train.entry(ev.user.to_string()).or_insert((0, 0));
        if ev.verdict == "good" {
            entry.0 += 1;
        } else {
            entry.1 += 1;
        }
        if let Some(d) = ev.timestamp.get(..10) {
            *self.by_date.entry(d.to_string()).or_insert(0) += 1;
        }
    }

    fn record_delivery(&mut self, d: &PendingDelivery, has_msgid: bool) {
        self.delivery_emitted += 1;
        if has_msgid {
            self.delivery_with_msgid += 1;
        } else {
            self.delivery_orphan += 1;
        }
        let entry = self
            .by_user_delivery
            .entry(d.user.clone())
            .or_insert((0, 0));
        if d.verdict == "GOOD" {
            entry.0 += 1;
        } else {
            entry.1 += 1;
        }
        if let Some(date) = d.timestamp.get(..10) {
            *self.by_date.entry(date.to_string()).or_insert(0) += 1;
        }
    }

    fn print_summary<W: Write>(&self, w: &mut W) -> io::Result<()> {
        writeln!(w, "# harvest summary")?;
        writeln!(w, "# lines read:           {}", self.lines_read)?;
        writeln!(w, "# train events:         {}", self.train_emitted)?;
        writeln!(w, "# delivery events:      {}", self.delivery_emitted)?;
        writeln!(w, "#   with msgid:         {}", self.delivery_with_msgid)?;
        writeln!(w, "#   orphaned (no msgid):{}", self.delivery_orphan)?;
        writeln!(w, "# parse failures:       {}", self.parse_failures)?;
        writeln!(w, "# train users:          {}", self.by_user_train.len())?;
        writeln!(w, "# delivery users:       {}", self.by_user_delivery.len())?;
        writeln!(w, "# dates covered:        {}", self.by_date.len())?;
        if !self.by_date.is_empty() {
            writeln!(w, "# events by date:")?;
            for (date, count) in &self.by_date {
                writeln!(w, "#   {date}  {count}")?;
            }
        }
        if !self.by_user_delivery.is_empty() {
            let mut users: Vec<_> = self.by_user_delivery.iter().collect();
            users.sort_by(|a, b| (b.1 .0 + b.1 .1).cmp(&(a.1 .0 + a.1 .1)));
            writeln!(w, "# top delivery users (verdict counts):")?;
            for (user, (g, s)) in users.iter().take(15) {
                writeln!(w, "#   {:<40} good={g:<6} spam={s}", user)?;
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
    // Pending DELIVERY records awaiting their paired msgid line. Keyed on
    // session id. Unbounded; in practice the map is small because LMTP
    // sessions are short-lived.
    let mut pending: HashMap<String, PendingDelivery> = HashMap::new();

    for line in reader.lines() {
        let line = line?;
        stats.lines_read += 1;

        // Fast reject for lines that don't contain any of our markers.
        // Avoids the cost of parse_line on non-sieve lines (~99% of the log).
        if !line.contains(" sieve: ") {
            continue;
        }

        match parse_line(&line) {
            ParsedLine::Train(ev) => {
                stats.record_train(&ev);
                emit_train(out, &ev)?;
            }
            ParsedLine::Delivery(d) => {
                let pd = PendingDelivery {
                    timestamp: d.timestamp.to_string(),
                    user: d.user.to_string(),
                    verdict: d.verdict.to_string(),
                    score: d.score.to_string(),
                    folder: d.folder.to_string(),
                };
                pending.insert(d.session.to_string(), pd);
            }
            ParsedLine::Msgid(m) => {
                if let Some(pd) = pending.remove(m.session) {
                    emit_delivery(out, &pd, m.session, Some(m.msgid))?;
                    stats.record_delivery(&pd, true);
                }
            }
            ParsedLine::None => {
                // Line contains ' sieve: ' but didn't match any known shape;
                // don't count as parse failure — could be a sieve debug_log
                // for a rule we don't care about.
            }
        }
    }

    // Flush any remaining pending deliveries as orphans.
    for (sess, pd) in pending.drain() {
        emit_delivery(out, &pd, &sess, None)?;
        stats.record_delivery(&pd, false);
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
    fn test_parse_train_line() {
        let line = "2026-04-14T18:36:24.600202+10:00 mail dovecot: imap(sandy@gardinermail.com.au)<3881567><wtaHdmdPPoXLGYQI>: sieve: DEBUG: TRAIN: sandy@gardinermail.com.au -> good";
        match parse_line(line) {
            ParsedLine::Train(ev) => {
                assert_eq!(ev.timestamp, "2026-04-14T18:36:24.600202+10:00");
                assert_eq!(ev.user, "sandy@gardinermail.com.au");
                assert_eq!(ev.verdict, "good");
                assert_eq!(ev.session, "wtaHdmdPPoXLGYQI");
            }
            _ => panic!("expected Train variant"),
        }
    }

    #[test]
    fn test_parse_delivery_line() {
        let line = "2026-04-12T00:24:10.067207+10:00 mail dovecot: lmtp(admin@mcclintocks.com.au)<3174350><KzEVOYlZ2mnObzAAmhYRNg>: sieve: DEBUG: DELIVERY: admin@mcclintocks.com.au -> Inbox (GOOD 0.078958)";
        match parse_line(line) {
            ParsedLine::Delivery(d) => {
                assert_eq!(d.timestamp, "2026-04-12T00:24:10.067207+10:00");
                assert_eq!(d.user, "admin@mcclintocks.com.au");
                assert_eq!(d.verdict, "GOOD");
                assert_eq!(d.score, "0.078958");
                assert_eq!(d.folder, "Inbox");
                assert_eq!(d.session, "KzEVOYlZ2mnObzAAmhYRNg");
            }
            _ => panic!("expected Delivery variant"),
        }
    }

    #[test]
    fn test_parse_delivery_spam_to_junk() {
        let line = "2026-04-12T00:28:22.157192+10:00 mail dovecot: lmtp(georgivs@nospam.com.au)<3174747><nhZqAoVa2mlbcTAAmhYRNg>: sieve: DEBUG: DELIVERY: georgivs@nospam.com.au -> Junk (SPAM 1.000000)";
        match parse_line(line) {
            ParsedLine::Delivery(d) => {
                assert_eq!(d.verdict, "SPAM");
                assert_eq!(d.score, "1.000000");
                assert_eq!(d.folder, "Junk");
            }
            _ => panic!("expected Delivery variant"),
        }
    }

    #[test]
    fn test_parse_msgid_line() {
        let line = "2026-04-12T00:42:49.530876+10:00 mail dovecot: lmtp(admin@renta.net)<3176081><ZEMTJ+dd2mmRdjAAmhYRNg>: sieve: msgid=<0101019d7cfe7db7-92de4b04-b1f0-4732-b32e-367970ba66aa-000000@us-west-2.amazonses.com>: stored mail into mailbox 'INBOX'";
        match parse_line(line) {
            ParsedLine::Msgid(m) => {
                assert_eq!(
                    m.msgid,
                    "<0101019d7cfe7db7-92de4b04-b1f0-4732-b32e-367970ba66aa-000000@us-west-2.amazonses.com>"
                );
                assert_eq!(m.session, "ZEMTJ+dd2mmRdjAAmhYRNg");
            }
            _ => panic!("expected Msgid variant"),
        }
    }

    #[test]
    fn test_parse_msgid_fileinto_variant() {
        // fileinto action path (system-sender filtering) also has the same
        // "stored mail into mailbox" tail shape.
        let line = "2026-04-12T00:27:20.400443+10:00 mail dovecot: lmtp(admin@renta.net)<3174648><CKcZKkda2mn4cDAAmhYRNg>: sieve: msgid=<20260411142711.AD36363E42@pve5.goldcoast.org>: fileinto action: stored mail into mailbox 'Trash'";
        match parse_line(line) {
            ParsedLine::Msgid(m) => {
                assert_eq!(m.msgid, "<20260411142711.AD36363E42@pve5.goldcoast.org>");
            }
            _ => panic!("expected Msgid variant"),
        }
    }

    #[test]
    fn test_parse_rejects_non_sieve_lines() {
        assert!(matches!(
            parse_line("2026-04-14 mail postfix/smtps/smtpd[123]: connect from ..."),
            ParsedLine::None
        ));
        assert!(matches!(parse_line("arbitrary text"), ParsedLine::None));
    }

    #[test]
    fn test_session_pairing_integration() {
        // DELIVERY followed by matching msgid → one combined delivery record.
        // TRAIN standalone → one train record.
        // DELIVERY with no matching msgid → orphan delivery record.
        // msgid without preceding DELIVERY → ignored.
        let input = "\
2026-04-12T00:24:10.067207+10:00 mail dovecot: lmtp(a@b.com)<1><sessA>: sieve: DEBUG: DELIVERY: a@b.com -> Inbox (GOOD 0.100000)
2026-04-12T00:24:10.067208+10:00 mail dovecot: lmtp(a@b.com)<1><sessA>: sieve: msgid=<msg-1@b.com>: stored mail into mailbox 'INBOX'
2026-04-12T00:24:11.000000+10:00 mail dovecot: imap(a@b.com)<2><sessB>: sieve: DEBUG: TRAIN: a@b.com -> spam
2026-04-12T00:24:12.000000+10:00 mail dovecot: lmtp(c@d.com)<3><sessC>: sieve: DEBUG: DELIVERY: c@d.com -> Junk (SPAM 0.999)
2026-04-12T00:24:13.000000+10:00 mail dovecot: lmtp(e@f.com)<4><sessD>: sieve: msgid=<orphan@f.com>: fileinto action: stored mail into mailbox 'Trash'
";
        let reader = io::BufReader::new(input.as_bytes());
        let mut out = Vec::new();
        let mut stats = Stats::default();
        process_reader(reader, &mut out, &mut stats).unwrap();
        assert_eq!(stats.train_emitted, 1);
        assert_eq!(stats.delivery_emitted, 2);
        assert_eq!(stats.delivery_with_msgid, 1);
        assert_eq!(stats.delivery_orphan, 1);
        let output = String::from_utf8(out).unwrap();
        let lines: Vec<_> = output.lines().collect();
        assert_eq!(lines.len(), 3);
        assert!(lines[0].contains("\"type\":\"delivery\""));
        assert!(lines[0].contains("\"msgid\":\"<msg-1@b.com>\""));
        assert!(lines[0].contains("\"score\":0.100000"));
        assert!(lines[1].contains("\"type\":\"train\""));
        assert!(lines[1].contains("\"v\":\"spam\""));
        assert!(lines[2].contains("\"type\":\"delivery\""));
        assert!(lines[2].contains("\"verdict\":\"SPAM\""));
        // orphan delivery has no msgid field
        assert!(!lines[2].contains("\"msgid\":"));
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
}
