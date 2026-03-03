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

fn cmd_receive() {
    let raw = read_stdin();
    let tokens = tokenizer::tokenize(&raw);
    let db = open_db();
    let params = Params::default();

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
        "spamlite 0.1.0 — per-user Bayesian spam filter
Copyright 2026 Mark Constable <mc@netserva.org>
MIT License — https://github.com/markc/spamlite

Usage:
  spamlite [-d DIR] receive          Classify message from stdin (prints SPAM/GOOD/UNSURE + score)
  spamlite [-d DIR] spam             Train message from stdin as spam
  spamlite [-d DIR] good             Train message from stdin as good/ham
  spamlite [-d DIR] counts           Show database statistics
  spamlite [-d DIR] cleanup [N] [D]  Remove tokens with count <= N or not seen in D days
  spamlite [-d DIR] export           Export database to CSV on stdout
  spamlite [-d DIR] import           Import CSV from stdin (spamprobe-compatible format)

Options:
  -d DIR    Database directory (uses DIR/db.sqlite)

Environment:
  SPAMLITE_DB               Database file path (default: ~/.spamlite/db.sqlite)

Priority: -d flag > SPAMLITE_DB env > ~/.spamlite/db.sqlite"
    );
}

/// Parse args, extracting -d flag, returning remaining args
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
        remaining.push(args[i].clone());
        i += 1;
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
