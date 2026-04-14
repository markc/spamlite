// Copyright 2026 Mark Constable <mc@netserva.org>
// SPDX-License-Identifier: MIT
//
// spamlite-correlate — Cross-reference spamlite-harvest delivery records
// against a user's current Maildir state to recover labelled fp/fn/tp/tn
// events. Produces the Phase 1.7 benchmark corpus by joining logged
// delivery verdicts with the user's eventual classification (whichever
// folder they ended up moving the message to).
//
// Usage:
//
//   spamlite-correlate --events FILE --user USER --maildir DIR [--out DIR]
//
// Reads the harvester output from --events, filters delivery records for
// --user, builds a msgid → (delivery_verdict, delivery_score) map, then
// walks --maildir and its `.*/cur/` subdirectories extracting the
// Message-Id: header from each file. For every file whose msgid matches a
// known delivery, emits one JSONL record with the confusion-matrix label:
//
//   tp — delivery=SPAM  AND current=Junk        (classifier caught it, user agreed)
//   tn — delivery=GOOD  AND current=INBOX/Sent/Archive (classifier passed, user agreed)
//   fp — delivery=SPAM  AND current=INBOX/...   (classifier false-positive, user rescued)
//   fn — delivery=GOOD  AND current=Junk        (classifier false-negative, user flagged)
//
// Messages that were deleted (moved to Trash and then expunged, or direct
// delete) are unrecoverable and don't appear in the output.
//
// Output JSONL schema:
//
//   {"label":"fp","msgid":"<...>","score":0.92,"delivery_verdict":"SPAM",
//    "delivery_folder":"Junk","current_folder":".Junk","file":"<path>"}

use std::collections::HashMap;
use std::env;
use std::fs::{self, File};
use std::io::{self, BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::process;

#[derive(Clone)]
struct Delivery {
    verdict: String,
    score: String,
    folder: String,
}

fn usage_and_exit() -> ! {
    eprintln!(
        "spamlite-correlate — build labelled fp/fn corpus from harvest events + Maildir

Usage:
  spamlite-correlate --events FILE --user USER --maildir DIR

Options:
  --events FILE     JSONL file from spamlite-harvest (stdin if omitted)
  --user  USER      user@domain to filter delivery events for (required)
  --maildir DIR     path to the user's Maildir root (required). Must contain
                    `cur/` (inbox) and `.Junk/cur/`; other `.X/cur/` folders
                    are scanned as ham-classified unless they are `.Trash`.
"
    );
    process::exit(2);
}

/// Extract a JSON string value from a line by simple textual search.
/// `line` must be a single JSON object per line. Handles the two escapes
/// we actually emit (`\"` and `\\`); anything else is ignored. Returns
/// a `Cow` because most values have no escapes and can be borrowed.
fn extract_string<'a>(line: &'a str, key: &str) -> Option<String> {
    let needle = format!("\"{key}\":\"");
    let idx = line.find(&needle)?;
    let start = idx + needle.len();
    let bytes = line.as_bytes();
    let mut i = start;
    let mut out = String::new();
    while i < bytes.len() {
        let b = bytes[i];
        if b == b'\\' && i + 1 < bytes.len() {
            match bytes[i + 1] {
                b'"' => out.push('"'),
                b'\\' => out.push('\\'),
                b'n' => out.push('\n'),
                b'r' => out.push('\r'),
                b't' => out.push('\t'),
                other => out.push(other as char),
            }
            i += 2;
            continue;
        }
        if b == b'"' {
            return Some(out);
        }
        out.push(b as char);
        i += 1;
    }
    None
}

/// Extract a JSON numeric value by the same textual search.
fn extract_number<'a>(line: &'a str, key: &str) -> Option<&'a str> {
    let needle = format!("\"{key}\":");
    let idx = line.find(&needle)?;
    let start = idx + needle.len();
    let rest = &line[start..];
    // Stop at the next comma or closing brace. Numbers here are unquoted.
    let end = rest.find([',', '}'])?;
    let v = rest[..end].trim();
    if v.starts_with('"') {
        // Quoted — not a number.
        return None;
    }
    Some(v)
}

/// Read a message file and extract the Message-Id header value. Returns None
/// if the header is missing or unreadable. We only scan the first 16 KiB of
/// the file — Message-Id always lives in the top headers.
fn read_msgid(path: &Path) -> Option<String> {
    let mut f = File::open(path).ok()?;
    let mut buf = vec![0u8; 16 * 1024];
    let n = f.read(&mut buf).ok()?;
    let data = &buf[..n];
    // Header block ends at first blank line (\r\n\r\n or \n\n).
    let end = {
        let mut e = data.len();
        if let Some(i) = find_subseq(data, b"\r\n\r\n") {
            e = e.min(i);
        }
        if let Some(i) = find_subseq(data, b"\n\n") {
            e = e.min(i);
        }
        e
    };
    let headers = &data[..end];
    let text = std::str::from_utf8(headers).ok().unwrap_or_else(|| {
        // Fallback — drop invalid bytes.
        "" // quiet fallback; msgid will be None
    });

    // Case-insensitive search for `Message-Id:` at line starts, including
    // the top of the file (no preceding newline).
    let needle_b = b"message-id:";
    let lower: Vec<u8> = text
        .as_bytes()
        .iter()
        .map(|b| b.to_ascii_lowercase())
        .collect();
    let mut start_idx: Option<usize> = None;
    if lower.starts_with(needle_b) {
        start_idx = Some(0);
    } else if let Some(i) = find_subseq(&lower, b"\nmessage-id:") {
        start_idx = Some(i + 1);
    }
    let start = start_idx?;
    let rest = &text.as_bytes()[start + needle_b.len()..];
    // Extract until newline; handle folded continuations (lines starting
    // with whitespace).
    let mut value = Vec::new();
    let mut i = 0;
    let mut at_line_start = false;
    while i < rest.len() {
        let c = rest[i];
        if at_line_start {
            if c == b' ' || c == b'\t' {
                value.push(b' ');
                i += 1;
                at_line_start = false;
                continue;
            } else {
                break;
            }
        }
        if c == b'\n' {
            at_line_start = true;
            i += 1;
            continue;
        }
        if c == b'\r' {
            i += 1;
            continue;
        }
        value.push(c);
        i += 1;
    }
    let s = String::from_utf8(value).ok()?;
    let trimmed = s.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

fn find_subseq(hay: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || needle.len() > hay.len() {
        return None;
    }
    hay.windows(needle.len()).position(|w| w == needle)
}

/// Load a harvest JSONL file and return the msgid → Delivery map for a
/// single user.
fn load_deliveries<R: BufRead>(reader: R, want_user: &str) -> io::Result<HashMap<String, Delivery>> {
    let mut map = HashMap::new();
    for line in reader.lines() {
        let line = line?;
        if !line.contains("\"type\":\"delivery\"") {
            continue;
        }
        let Some(user) = extract_string(&line, "u") else {
            continue;
        };
        if user != want_user {
            continue;
        }
        let Some(msgid) = extract_string(&line, "msgid") else {
            continue;
        };
        let Some(verdict) = extract_string(&line, "verdict") else {
            continue;
        };
        let Some(folder) = extract_string(&line, "folder") else {
            continue;
        };
        let score = extract_number(&line, "score").unwrap_or("0").to_string();
        map.insert(
            msgid,
            Delivery {
                verdict,
                score,
                folder,
            },
        );
    }
    Ok(map)
}

/// Walk a Maildir root and enumerate `(folder_label, file_path)` pairs.
/// folder_label is `"INBOX"` for `Maildir/cur/`, or `".X"` for each
/// IMAP subfolder under `Maildir/.X/cur/`. Trash is skipped because it
/// is an unreliable signal (messages are not lost-labelled; they're
/// just deleted).
fn walk_maildir(root: &Path) -> io::Result<Vec<(String, PathBuf)>> {
    let mut out = Vec::new();
    // Top-level cur/
    let top_cur = root.join("cur");
    if top_cur.is_dir() {
        for entry in fs::read_dir(&top_cur)? {
            let entry = entry?;
            if entry.file_type()?.is_file() {
                out.push(("INBOX".to_string(), entry.path()));
            }
        }
    }
    // Subfolders: root/.X/cur/
    for entry in fs::read_dir(root)? {
        let entry = entry?;
        if !entry.file_type()?.is_dir() {
            continue;
        }
        let name = match entry.file_name().to_str() {
            Some(n) if n.starts_with('.') && n.len() > 1 => n.to_string(),
            _ => continue,
        };
        if name.eq_ignore_ascii_case(".Trash") {
            continue;
        }
        let sub_cur = entry.path().join("cur");
        if !sub_cur.is_dir() {
            continue;
        }
        for e in fs::read_dir(&sub_cur)? {
            let e = e?;
            if e.file_type()?.is_file() {
                out.push((name.clone(), e.path()));
            }
        }
    }
    Ok(out)
}

/// Decide the fp/fn/tp/tn label from a delivery verdict + the user's
/// current folder. Returns the string label.
fn label(delivery_verdict: &str, current_folder: &str) -> &'static str {
    let is_junk = current_folder.eq_ignore_ascii_case(".Junk");
    match (delivery_verdict, is_junk) {
        ("SPAM", true) => "tp",
        ("SPAM", false) => "fp",
        ("GOOD", true) => "fn",
        ("GOOD", false) => "tn",
        _ => "unknown",
    }
}

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

fn main() {
    let args: Vec<String> = env::args().skip(1).collect();
    let mut events_path: Option<String> = None;
    let mut user: Option<String> = None;
    let mut maildir: Option<String> = None;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--events" => {
                i += 1;
                events_path = args.get(i).cloned();
            }
            "--user" => {
                i += 1;
                user = args.get(i).cloned();
            }
            "--maildir" => {
                i += 1;
                maildir = args.get(i).cloned();
            }
            "--help" | "-h" => usage_and_exit(),
            other => {
                eprintln!("spamlite-correlate: unknown argument '{other}'");
                usage_and_exit();
            }
        }
        i += 1;
    }

    let Some(user) = user else {
        eprintln!("spamlite-correlate: --user is required");
        usage_and_exit();
    };
    let Some(maildir) = maildir else {
        eprintln!("spamlite-correlate: --maildir is required");
        usage_and_exit();
    };

    // Load deliveries
    let deliveries = if let Some(path) = events_path {
        match File::open(&path) {
            Ok(f) => load_deliveries(BufReader::new(f), &user),
            Err(e) => {
                eprintln!("spamlite-correlate: cannot open {path}: {e}");
                process::exit(1);
            }
        }
    } else {
        let stdin = io::stdin();
        load_deliveries(stdin.lock(), &user)
    };
    let deliveries = match deliveries {
        Ok(m) => m,
        Err(e) => {
            eprintln!("spamlite-correlate: error reading events: {e}");
            process::exit(1);
        }
    };

    eprintln!(
        "# loaded {} delivery records for {}",
        deliveries.len(),
        user
    );

    // Walk the Maildir
    let maildir_path = PathBuf::from(&maildir);
    let files = match walk_maildir(&maildir_path) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("spamlite-correlate: cannot read maildir {maildir}: {e}");
            process::exit(1);
        }
    };
    eprintln!("# scanning {} files under {}", files.len(), maildir);

    let stdout = io::stdout();
    let mut out = stdout.lock();

    let mut files_total = 0u64;
    let mut files_no_msgid = 0u64;
    let mut files_unknown_msgid = 0u64;
    let mut counts: HashMap<&'static str, u64> = HashMap::new();

    for (folder, path) in files {
        files_total += 1;
        let msgid = match read_msgid(&path) {
            Some(m) => m,
            None => {
                files_no_msgid += 1;
                continue;
            }
        };
        let Some(delivery) = deliveries.get(&msgid) else {
            files_unknown_msgid += 1;
            continue;
        };

        let lbl = label(&delivery.verdict, &folder);
        *counts.entry(lbl).or_insert(0) += 1;

        // Emit record
        out.write_all(b"{\"label\":")
            .and_then(|_| write_json_string(&mut out, lbl))
            .ok();
        out.write_all(b",\"msgid\":")
            .and_then(|_| write_json_string(&mut out, &msgid))
            .ok();
        out.write_all(b",\"score\":").ok();
        out.write_all(delivery.score.as_bytes()).ok();
        out.write_all(b",\"delivery_verdict\":")
            .and_then(|_| write_json_string(&mut out, &delivery.verdict))
            .ok();
        out.write_all(b",\"delivery_folder\":")
            .and_then(|_| write_json_string(&mut out, &delivery.folder))
            .ok();
        out.write_all(b",\"current_folder\":")
            .and_then(|_| write_json_string(&mut out, &folder))
            .ok();
        out.write_all(b",\"file\":")
            .and_then(|_| write_json_string(&mut out, path.to_string_lossy().as_ref()))
            .ok();
        out.write_all(b"}\n").ok();
    }

    let _ = out.flush();

    eprintln!("# correlation summary for {user}");
    eprintln!("# files scanned:           {files_total}");
    eprintln!("# files without msgid:     {files_no_msgid}");
    eprintln!("# files msgid not in logs: {files_unknown_msgid}");
    let matched: u64 = counts.values().sum();
    eprintln!("# files matched:           {matched}");
    for (label, count) in [
        ("tp", counts.get("tp").copied().unwrap_or(0)),
        ("tn", counts.get("tn").copied().unwrap_or(0)),
        ("fp", counts.get("fp").copied().unwrap_or(0)),
        ("fn", counts.get("fn").copied().unwrap_or(0)),
    ] {
        eprintln!("#   {label}: {count}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_string_basic() {
        let line = r#"{"type":"delivery","u":"a@b.com","verdict":"GOOD"}"#;
        assert_eq!(extract_string(line, "u"), Some("a@b.com".to_string()));
        assert_eq!(extract_string(line, "verdict"), Some("GOOD".to_string()));
        assert_eq!(extract_string(line, "missing"), None);
    }

    #[test]
    fn test_extract_string_handles_escaped_quote() {
        let line = r#"{"msgid":"<has\"quote>"}"#;
        assert_eq!(extract_string(line, "msgid"), Some("<has\"quote>".to_string()));
    }

    #[test]
    fn test_extract_number() {
        let line = r#"{"score":0.102534,"folder":"Inbox"}"#;
        assert_eq!(extract_number(line, "score"), Some("0.102534"));
        let line2 = r#"{"score":1}"#;
        assert_eq!(extract_number(line2, "score"), Some("1"));
    }

    #[test]
    fn test_label_matrix() {
        assert_eq!(label("SPAM", ".Junk"), "tp");
        assert_eq!(label("GOOD", "INBOX"), "tn");
        assert_eq!(label("SPAM", "INBOX"), "fp");
        assert_eq!(label("GOOD", ".Junk"), "fn");
        assert_eq!(label("SPAM", ".Archive"), "fp");
        assert_eq!(label("GOOD", ".Sent"), "tn");
    }

    #[test]
    fn test_load_deliveries_filters_by_user() {
        let input = r#"{"type":"train","u":"a@b.com","v":"good"}
{"type":"delivery","u":"a@b.com","verdict":"GOOD","score":0.1,"folder":"Inbox","msgid":"<m1>","sess":"s1"}
{"type":"delivery","u":"c@d.com","verdict":"SPAM","score":0.9,"folder":"Junk","msgid":"<m2>","sess":"s2"}
{"type":"delivery","u":"a@b.com","verdict":"SPAM","score":0.8,"folder":"Junk","msgid":"<m3>","sess":"s3"}
"#;
        let reader = BufReader::new(input.as_bytes());
        let map = load_deliveries(reader, "a@b.com").unwrap();
        assert_eq!(map.len(), 2);
        assert_eq!(map.get("<m1>").unwrap().verdict, "GOOD");
        assert_eq!(map.get("<m3>").unwrap().verdict, "SPAM");
        assert!(map.get("<m2>").is_none());
    }

    #[test]
    fn test_read_msgid_basic() {
        let tmp = std::env::temp_dir().join("spamlite-test-msgid.eml");
        fs::write(
            &tmp,
            "From: a@b.com\r\nTo: c@d.com\r\nMessage-Id: <test-1@example.com>\r\nSubject: x\r\n\r\nbody",
        )
        .unwrap();
        let got = read_msgid(&tmp);
        assert_eq!(got, Some("<test-1@example.com>".to_string()));
        let _ = fs::remove_file(&tmp);
    }

    #[test]
    fn test_read_msgid_top_of_file() {
        let tmp = std::env::temp_dir().join("spamlite-test-msgid-top.eml");
        fs::write(
            &tmp,
            "Message-Id: <first-header@x>\r\nFrom: a@b.com\r\n\r\nbody",
        )
        .unwrap();
        assert_eq!(read_msgid(&tmp), Some("<first-header@x>".to_string()));
        let _ = fs::remove_file(&tmp);
    }

    #[test]
    fn test_read_msgid_missing() {
        let tmp = std::env::temp_dir().join("spamlite-test-msgid-missing.eml");
        fs::write(&tmp, "From: a@b.com\r\nSubject: x\r\n\r\nbody").unwrap();
        assert_eq!(read_msgid(&tmp), None);
        let _ = fs::remove_file(&tmp);
    }
}
