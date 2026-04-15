// Copyright 2026 Mark Constable <mc@netserva.org>
// SPDX-License-Identifier: MIT
//
// spamlite-shadow-report — summarise shadow.jsonl divergence logs.
//
// Reads one or more `shadow.jsonl` files written by the shadow-mode
// `spamfilter` wrapper, computes per-user agree/disagree counts, score
// delta distribution, and flags interesting divergences (crossed the
// threshold in either direction).
//
// Usage:
//   spamlite-shadow-report [--threshold T] [--json] FILE [FILE ...]
//   find /srv -name shadow.jsonl -print0 | xargs -0 spamlite-shadow-report

use std::collections::BTreeMap;
use std::env;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::PathBuf;
use std::process;

#[derive(Default)]
struct UserStats {
    n: usize,
    agree: usize,
    disagree: usize,
    primary_spam: usize,
    cand_spam: usize,
    /// primary=GOOD, cand=SPAM (would have flagged as spam)
    cand_stricter: usize,
    /// primary=SPAM, cand=GOOD (would have let through as ham)
    cand_laxer: usize,
    primary_scores: Vec<f64>,
    cand_scores: Vec<f64>,
    deltas: Vec<f64>,
}

struct Args {
    threshold: f64,
    json: bool,
    files: Vec<PathBuf>,
}

fn parse_args() -> Args {
    let argv: Vec<String> = env::args().collect();
    let mut threshold = 0.6;
    let mut json = false;
    let mut files = Vec::new();
    let mut i = 1;
    while i < argv.len() {
        match argv[i].as_str() {
            "--threshold" | "-t" => {
                threshold = argv
                    .get(i + 1)
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(0.6);
                i += 2;
            }
            "--json" => {
                json = true;
                i += 1;
            }
            "-h" | "--help" => {
                eprintln!(
                    "spamlite-shadow-report — summarise shadow.jsonl divergence\n\n\
                     Usage: spamlite-shadow-report [--threshold T] [--json] FILE [FILE ...]"
                );
                process::exit(0);
            }
            other => {
                files.push(PathBuf::from(other));
                i += 1;
            }
        }
    }
    if files.is_empty() {
        eprintln!("spamlite-shadow-report: at least one file required");
        process::exit(2);
    }
    Args {
        threshold,
        json,
        files,
    }
}

/// Extract `"key":"value"` or `"key":value` from a minimal JSON line.
/// Good enough for our fixed-shape shadow.jsonl records.
fn extract(line: &str, key: &str) -> Option<String> {
    let needle = format!("\"{}\":", key);
    let pos = line.find(&needle)?;
    let rest = &line[pos + needle.len()..];
    let rest = rest.trim_start();
    if let Some(rest) = rest.strip_prefix('"') {
        let end = rest.find('"')?;
        Some(rest[..end].to_string())
    } else {
        let end = rest.find(|c: char| c == ',' || c == '}').unwrap_or(rest.len());
        Some(rest[..end].trim().to_string())
    }
}

/// Parse "SPAM 0.123456" or "GOOD 0.789" into (verdict, score).
fn parse_verdict(s: &str) -> Option<(bool, f64)> {
    let (v, rest) = s.split_once(' ')?;
    let score: f64 = rest.parse().ok()?;
    Some((v == "SPAM", score))
}

fn percentile(sorted: &[f64], p: f64) -> f64 {
    if sorted.is_empty() {
        return f64::NAN;
    }
    let idx = ((sorted.len() - 1) as f64 * p).round() as usize;
    sorted[idx.min(sorted.len() - 1)]
}

fn main() {
    let args = parse_args();
    let mut per_user: BTreeMap<String, UserStats> = BTreeMap::new();
    let mut total_lines = 0usize;
    let mut parse_fails = 0usize;

    for path in &args.files {
        let Ok(file) = File::open(path) else {
            eprintln!("shadow-report: cannot open {}", path.display());
            continue;
        };
        for line in BufReader::new(file).lines().map_while(Result::ok) {
            total_lines += 1;
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            let Some(user) = extract(line, "user") else {
                parse_fails += 1;
                continue;
            };
            let Some(primary_raw) = extract(line, "primary") else {
                parse_fails += 1;
                continue;
            };
            let Some(cand_raw) = extract(line, "cand") else {
                parse_fails += 1;
                continue;
            };
            let Some((p_spam, p_score)) = parse_verdict(&primary_raw) else {
                parse_fails += 1;
                continue;
            };
            let Some((c_spam, c_score)) = parse_verdict(&cand_raw) else {
                parse_fails += 1;
                continue;
            };

            let s = per_user.entry(user).or_default();
            s.n += 1;
            if p_spam == c_spam {
                s.agree += 1;
            } else {
                s.disagree += 1;
                if !p_spam && c_spam {
                    s.cand_stricter += 1;
                } else {
                    s.cand_laxer += 1;
                }
            }
            if p_spam {
                s.primary_spam += 1;
            }
            if c_spam {
                s.cand_spam += 1;
            }
            // Policy-level divergence against args.threshold
            // (the `p_spam`/`c_spam` values are the binary's own verdict at
            // its invoked threshold, which is the same 0.6 for both)
            let _ = args.threshold; // threshold reserved for future rescoring
            s.primary_scores.push(p_score);
            s.cand_scores.push(c_score);
            s.deltas.push(c_score - p_score);
        }
    }

    // Aggregate
    let mut total_n = 0usize;
    let mut total_agree = 0usize;
    let mut total_disagree = 0usize;
    let mut total_stricter = 0usize;
    let mut total_laxer = 0usize;
    for s in per_user.values() {
        total_n += s.n;
        total_agree += s.agree;
        total_disagree += s.disagree;
        total_stricter += s.cand_stricter;
        total_laxer += s.cand_laxer;
    }

    if args.json {
        let agree_pct = if total_n > 0 {
            total_agree as f64 / total_n as f64
        } else {
            f64::NAN
        };
        println!(
            "{{\"total_n\":{total_n},\"agree\":{total_agree},\"disagree\":{total_disagree},\
             \"cand_stricter\":{total_stricter},\"cand_laxer\":{total_laxer},\
             \"agree_rate\":{:.6},\"users\":{},\"parse_fails\":{parse_fails}}}",
            agree_pct,
            per_user.len()
        );
        return;
    }

    println!("spamlite-shadow-report  ({} lines read, {} parse fails)", total_lines, parse_fails);
    println!();
    println!("Aggregate:");
    println!("  total:          {total_n}");
    println!(
        "  agree:          {total_agree}  ({:.2}%)",
        if total_n > 0 {
            100.0 * total_agree as f64 / total_n as f64
        } else {
            0.0
        }
    );
    println!(
        "  disagree:       {total_disagree}  ({:.2}%)",
        if total_n > 0 {
            100.0 * total_disagree as f64 / total_n as f64
        } else {
            0.0
        }
    );
    println!("    cand stricter (GOOD -> SPAM):  {total_stricter}");
    println!("    cand laxer    (SPAM -> GOOD):  {total_laxer}");
    println!();
    println!("Per-user (sorted by disagree count):");
    let mut users: Vec<_> = per_user.iter().collect();
    users.sort_by(|a, b| b.1.disagree.cmp(&a.1.disagree).then(b.1.n.cmp(&a.1.n)));

    println!(
        "  {:<32}  {:>6}  {:>6}  {:>6}  {:>7}  {:>7}  {:>9}  {:>9}",
        "user", "n", "agree", "disag", "p_spam", "c_spam", "delta_p50", "delta_p99"
    );
    println!("  {:-<32}  {:->6}  {:->6}  {:->6}  {:->7}  {:->7}  {:->9}  {:->9}", "", "", "", "", "", "", "", "");

    for (u, s) in &users {
        let mut deltas = s.deltas.clone();
        deltas.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
        println!(
            "  {:<32}  {:>6}  {:>6}  {:>6}  {:>7}  {:>7}  {:>9.4}  {:>9.4}",
            u,
            s.n,
            s.agree,
            s.disagree,
            s.primary_spam,
            s.cand_spam,
            percentile(&deltas, 0.5),
            percentile(&deltas, 0.99)
        );
    }
}
