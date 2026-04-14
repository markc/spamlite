// Copyright 2026 Mark Constable <mc@netserva.org>
// SPDX-License-Identifier: MIT

use std::io::{self, BufReader, Read};
use std::path::PathBuf;
use std::process;
use std::sync::OnceLock;

use spamlite::classifier::{self, Params};
use spamlite::storage::Database;
use spamlite::tokenizer;

/// Database directory set via -d flag
static DB_DIR: OnceLock<String> = OnceLock::new();

/// Spam threshold set via -t flag (default 0.5)
static THRESHOLD: OnceLock<f64> = OnceLock::new();

/// TOE confidence gate set via -g flag (default 0.2). In `receive` mode, the
/// classifier only trains when the score falls OUTSIDE the dead band
/// `(gate, 1.0 - gate)` — i.e. training fires when `score <= gate || score >= (1.0 - gate)`.
///
/// Semantic (read as "trusted region width"):
/// - `0.0` — trusted region is empty → training fully disabled (read-only)
/// - `0.2` (default) — trusted = `[0, 0.2] ∪ [0.8, 1]` → train confident verdicts, skip uncertain
/// - `0.5` — trusted region covers `[0, 1]` → pure TOE, train on everything
///
/// Default `0.2` is a reasonable starting point but should be revisited once
/// the explain command exists and we can measure the actual score distribution
/// on `admin_maildir/` and the production cluster. The right gate width
/// depends on how well-calibrated spamlite's scores are on this mail mix,
/// which is an empirical question, not a guess.
static TOE_GATE: OnceLock<f64> = OnceLock::new();

const TOE_GATE_DEFAULT: f64 = 0.2;

fn db_path() -> PathBuf {
    // -d flag takes priority
    if let Some(dir) = DB_DIR.get() {
        return PathBuf::from(dir).join("db.sqlite");
    }
    if let Ok(path) = std::env::var("SPAMLITE_DB") {
        return PathBuf::from(path);
    }
    if let Ok(home) = std::env::var("HOME") {
        return PathBuf::from(home).join(".spamlite").join("db.sqlite");
    }
    PathBuf::from(".spamlite").join("db.sqlite")
}

fn read_stdin() -> Vec<u8> {
    let mut buf = Vec::new();
    io::stdin().read_to_end(&mut buf).unwrap_or_else(|e| {
        eprintln!("spamlite: failed to read stdin: {e}");
        process::exit(1);
    });
    buf
}

fn open_db() -> Database {
    let path = db_path();
    Database::open(&path).unwrap_or_else(|e| {
        eprintln!("spamlite: failed to open database {}: {e}", path.display());
        process::exit(1);
    })
}

fn cmd_score() {
    let raw = read_stdin();
    let tokens = tokenizer::tokenize(&raw);
    let db = open_db();
    let mut params = Params::default();
    if let Some(&t) = THRESHOLD.get() {
        params.threshold = t;
    }

    match classifier::classify(&db, &tokens, &params) {
        Ok((verdict, score)) => {
            print!("{verdict} {score:.6}");
        }
        Err(e) => {
            eprintln!("spamlite: classification error: {e}");
            process::exit(1);
        }
    }
}

/// receive = classify + confidence-gated training. After scoring, train on the
/// classifier's own verdict ONLY if the score is outside the uncertainty band
/// `(gate, 1.0 - gate)`, where `gate` defaults to `TOE_GATE_DEFAULT` and is
/// configurable via `-g` or `SPAMLITE_TOE_GATE`. This is a third mode between
/// spamprobe's pure TOE (`receive`) and TONE (`train`): "train on confidence."
/// It is the safest cold-start mechanism for a frozen corpus because it
/// restores training signal without reinforcing borderline errors.
///
/// The SPAM/GOOD score is printed to stdout BEFORE training runs, so the sieve
/// contract is preserved even if the training write fails. Training failures
/// are logged to stderr but do not exit non-zero — mail delivery must not break
/// because the classifier couldn't persist counts.
fn cmd_receive() {
    let raw = read_stdin();
    let tokens = tokenizer::tokenize(&raw);
    let db = open_db();
    let mut params = Params::default();
    if let Some(&t) = THRESHOLD.get() {
        params.threshold = t;
    }
    let gate = TOE_GATE.get().copied().unwrap_or(TOE_GATE_DEFAULT);

    match classifier::classify(&db, &tokens, &params) {
        Ok((verdict, score)) => {
            print!("{verdict} {score:.6}");

            if score > gate && score < (1.0 - gate) {
                return;
            }

            let is_spam = matches!(verdict, classifier::Verdict::Spam);
            if let Err(e) = db.train(&tokens, is_spam) {
                eprintln!("spamlite: training error (non-fatal): {e}");
                return;
            }
            let meta_result = if is_spam {
                db.inc_total_spam()
            } else {
                db.inc_total_good()
            };
            if let Err(e) = meta_result {
                eprintln!("spamlite: meta update error (non-fatal): {e}");
            }
        }
        Err(e) => {
            eprintln!("spamlite: classification error: {e}");
            process::exit(1);
        }
    }
}

fn cmd_train(is_spam: bool) {
    let raw = read_stdin();
    let tokens = tokenizer::tokenize(&raw);
    let db = open_db();

    if let Err(e) = db.train(&tokens, is_spam) {
        eprintln!("spamlite: training error: {e}");
        process::exit(1);
    }

    if is_spam {
        db.inc_total_spam().unwrap_or_else(|e| {
            eprintln!("spamlite: meta update error: {e}");
        });
    } else {
        db.inc_total_good().unwrap_or_else(|e| {
            eprintln!("spamlite: meta update error: {e}");
        });
    }
}

/// explain = classify + verbose breakdown of top interesting tokens. Read-only.
/// Intended for debugging individual messages — e.g. "why is this ham scoring
/// as spam?" The output shows the Robinson-corrected probability f(w) for
/// each token that made the top-N interesting set, sorted most-interesting
/// first. A bar visualises direction (left = ham-indicative, right = spam).
fn cmd_explain() {
    let raw = read_stdin();
    let tokens = tokenizer::tokenize(&raw);
    let db = open_db();
    let mut params = Params::default();
    if let Some(&t) = THRESHOLD.get() {
        params.threshold = t;
    }

    let expl = match classifier::classify_explain(&db, &tokens, &params) {
        Ok(e) => e,
        Err(e) => {
            eprintln!("spamlite: classification error: {e}");
            process::exit(1);
        }
    };

    println!("spamlite explain");
    println!();
    println!(
        "Message:  {} tokens total, {} known to DB, {} unknown",
        expl.msg_tokens,
        expl.known_tokens,
        expl.msg_tokens.saturating_sub(expl.known_tokens)
    );
    println!(
        "Database: good={}  spam={}",
        expl.total_good, expl.total_spam
    );
    println!(
        "Verdict:  {} score={:.6}  (threshold={:.3})",
        expl.verdict, expl.score, params.threshold
    );
    println!(
        "Fisher:   H_spam={:.2}  H_ham={:.2}  P_spam={:.4}  P_ham={:.4}",
        expl.h_spam, expl.h_ham, expl.p_spam, expl.p_ham
    );
    println!();

    if expl.top_tokens.is_empty() {
        println!("(no known tokens in message — nothing to explain)");
        return;
    }

    let display_limit = 40.min(expl.top_tokens.len());
    println!(
        "Top {} interesting tokens (of {} used in Fisher combining):",
        display_limit,
        expl.top_tokens.len()
    );
    println!();
    println!(
        "  {:<44}  {:>6}  {:>6}  {:>7}  direction",
        "word", "good", "spam", "f(w)"
    );
    println!("  {:-<44}  {:-<6}  {:-<6}  {:-<7}  ---------", "", "", "", "");

    for tok in expl.top_tokens.iter().take(display_limit) {
        // Bar: 11 cells, centre is 0.5. Left half = ham, right half = spam.
        let bar = {
            let pos = (tok.fw * 10.0).round() as i32;
            let pos = pos.clamp(0, 10) as usize;
            let mut s = [' '; 11];
            s[pos] = if tok.fw >= 0.5 { '>' } else { '<' };
            s[5] = if s[5] == ' ' { '|' } else { s[5] };
            s.iter().collect::<String>()
        };
        let word_trunc: String = tok.word.chars().take(44).collect();
        println!(
            "  {:<44}  {:>6}  {:>6}  {:>7.4}  {}",
            word_trunc, tok.good, tok.spam, tok.fw, bar
        );
    }

    if expl.top_tokens.len() > display_limit {
        println!();
        println!(
            "(...{} more tokens in Fisher set, not shown)",
            expl.top_tokens.len() - display_limit
        );
    }
}

fn cmd_counts() {
    let db = open_db();
    match db.counts() {
        Ok(c) => {
            println!("Good messages:  {}", c.total_good);
            println!("Spam messages:  {}", c.total_spam);
            println!("Unique tokens:  {}", c.unique_tokens);
        }
        Err(e) => {
            eprintln!("spamlite: error reading counts: {e}");
            process::exit(1);
        }
    }
}

fn cmd_cleanup(args: &[String]) {
    let min_count: u64 = args.first().and_then(|s| s.parse().ok()).unwrap_or(1);
    let days: u64 = args.get(1).and_then(|s| s.parse().ok()).unwrap_or(0);

    let db = open_db();
    match db.cleanup(min_count, days) {
        Ok(deleted) => {
            println!("Deleted {deleted} tokens");
        }
        Err(e) => {
            eprintln!("spamlite: cleanup error: {e}");
            process::exit(1);
        }
    }
}

fn cmd_export() {
    let db = open_db();
    let mut stdout = io::stdout().lock();
    if let Err(e) = db.export(&mut stdout) {
        eprintln!("spamlite: export error: {e}");
        process::exit(1);
    }
}

fn cmd_import() {
    let db = open_db();
    let reader = BufReader::new(io::stdin());
    match db.import(reader) {
        Ok(count) => {
            println!("Imported {count} tokens");
        }
        Err(e) => {
            eprintln!("spamlite: import error: {e}");
            process::exit(1);
        }
    }
}

fn usage() {
    eprintln!(
        "spamlite 0.4.0 — per-user Bayesian spam filter
Copyright 2026 Mark Constable <mc@netserva.org>
MIT License — https://github.com/markc/spamlite

Usage:
  spamlite [-d DIR] [-t THRESHOLD] [-g GATE] receive   Classify + train on confident verdicts
  spamlite [-d DIR] [-t THRESHOLD] score               Classify only (read-only, no training)
  spamlite [-d DIR] [-t THRESHOLD] explain             Verbose token-level breakdown (debug)
  spamlite [-d DIR] spam                               Train message from stdin as spam
  spamlite [-d DIR] good                               Train message from stdin as good/ham
  spamlite [-d DIR] counts                             Show database statistics
  spamlite [-d DIR] cleanup [N] [D]                    Remove tokens: count <= N or unseen in D days
  spamlite [-d DIR] export                             Export database to CSV on stdout
  spamlite [-d DIR] import                             Import CSV from stdin (spamprobe format)

Options:
  -d DIR        Database directory (uses DIR/db.sqlite)
  -t THRESHOLD  Spam threshold 0.0-1.0 (default: 0.5, higher = less aggressive)
  -g GATE       TOE confidence gate 0.0-0.5 for `receive` (default: 0.2)
                `receive` trains only if score <= gate || score >= (1.0 - gate)
                0.0 = disable training, 0.5 = pure TOE (train everything)

Environment:
  SPAMLITE_DB               Database file path (default: ~/.spamlite/db.sqlite)
  SPAMLITE_THRESHOLD        Spam threshold (default: 0.5)
  SPAMLITE_TOE_GATE         TOE confidence gate for `receive` (default: 0.2)

Priority: -t flag > SPAMLITE_THRESHOLD env > 0.5
          -g flag > SPAMLITE_TOE_GATE env > 0.2
          -d flag > SPAMLITE_DB env > ~/.spamlite/db.sqlite"
    );
}

/// Parse args, extracting -d and -t flags, returning remaining args
fn parse_args() -> Vec<String> {
    let args: Vec<String> = std::env::args().collect();
    let mut remaining = Vec::new();
    let mut i = 1; // skip argv[0]

    while i < args.len() {
        if args[i] == "-d" {
            if i + 1 < args.len() {
                let _ = DB_DIR.set(args[i + 1].clone());
                i += 2;
                continue;
            } else {
                eprintln!("spamlite: -d requires a directory argument");
                process::exit(1);
            }
        }
        if args[i] == "-t" {
            if i + 1 < args.len() {
                match args[i + 1].parse::<f64>() {
                    Ok(t) if (0.0..=1.0).contains(&t) => {
                        let _ = THRESHOLD.set(t);
                    }
                    _ => {
                        eprintln!("spamlite: -t requires a number between 0.0 and 1.0");
                        process::exit(1);
                    }
                }
                i += 2;
                continue;
            } else {
                eprintln!("spamlite: -t requires a threshold argument");
                process::exit(1);
            }
        }
        if args[i] == "-g" {
            if i + 1 < args.len() {
                match args[i + 1].parse::<f64>() {
                    Ok(g) if (0.0..=0.5).contains(&g) => {
                        let _ = TOE_GATE.set(g);
                    }
                    _ => {
                        eprintln!("spamlite: -g requires a number between 0.0 and 0.5");
                        process::exit(1);
                    }
                }
                i += 2;
                continue;
            } else {
                eprintln!("spamlite: -g requires a gate argument");
                process::exit(1);
            }
        }
        remaining.push(args[i].clone());
        i += 1;
    }

    // Also check environment variable for threshold
    if THRESHOLD.get().is_none() {
        if let Ok(val) = std::env::var("SPAMLITE_THRESHOLD") {
            if let Ok(t) = val.parse::<f64>() {
                if (0.0..=1.0).contains(&t) {
                    let _ = THRESHOLD.set(t);
                }
            }
        }
    }

    if TOE_GATE.get().is_none() {
        if let Ok(val) = std::env::var("SPAMLITE_TOE_GATE") {
            if let Ok(g) = val.parse::<f64>() {
                if (0.0..=0.5).contains(&g) {
                    let _ = TOE_GATE.set(g);
                }
            }
        }
    }

    remaining
}

fn main() {
    let args = parse_args();

    if args.is_empty() {
        usage();
        process::exit(1);
    }

    match args[0].as_str() {
        "receive" => cmd_receive(),
        "score" => cmd_score(),
        "explain" => cmd_explain(),
        "spam" => cmd_train(true),
        "good" => cmd_train(false),
        "counts" => cmd_counts(),
        "cleanup" => cmd_cleanup(&args[1..]),
        "export" => cmd_export(),
        "import" => cmd_import(),
        "-h" | "--help" | "help" => usage(),
        other => {
            eprintln!("spamlite: unknown command '{other}'");
            usage();
            process::exit(1);
        }
    }
}
