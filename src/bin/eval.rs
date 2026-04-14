// Copyright 2026 Mark Constable <mc@netserva.org>
// SPDX-License-Identifier: MIT
//
// spamlite-eval — offline accuracy harness.
//
// Walks a maildir with user-supplied ham/spam folder labels, classifies every
// message against an existing spamlite database under configurable parameters,
// and reports a confusion matrix + score distribution. Read-only — never
// writes to the database. Used to measure Phase 2 parameter changes against
// the `admin_maildir/` ground-truth corpus before committing.
//
// Usage:
//   spamlite-eval -d DB_DIR --ham PATH[,PATH...] --spam PATH[,PATH...]
//                 [--max-interesting N] [--unknown-prob P] [--good-bias B]
//                 [--min-word-count N] [--threshold T]
//                 [--min-len N] [--max-len N] [--expanded-headers]
//                 [--json] [--limit N]

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process;
use std::time::Instant;

use spamlite::classifier::{self, Params, Verdict};
use spamlite::storage::Database;
use spamlite::tokenizer::{tokenize_with_config, TokenizerConfig};

struct Args {
    db_dir: PathBuf,
    ham_paths: Vec<PathBuf>,
    spam_paths: Vec<PathBuf>,
    params: Params,
    tok: TokenizerConfig,
    json: bool,
    limit: Option<usize>,
    show_errors: usize,
}

fn usage_and_exit() -> ! {
    eprintln!(
        "spamlite-eval — offline accuracy harness\n\
         \n\
         Usage:\n  \
         spamlite-eval -d DB_DIR --ham PATH[,PATH...] --spam PATH[,PATH...] [options]\n\
         \n\
         Classifier options (default in parens):\n  \
         --max-interesting N    top-N interesting tokens (150)\n  \
         --unknown-prob P       probability for unknown tokens (0.5)\n  \
         --good-bias B          weight on ham evidence (1.0)\n  \
         --min-word-count N     min (good+spam) to trust a token (0)\n  \
         --strength S           Robinson strength parameter (1.0)\n  \
         --threshold T          spam threshold (0.5)\n  \
         \n\
         Tokenizer options:\n  \
         --min-len N            min token length (3)\n  \
         --max-len N            max token length (40)\n  \
         --expanded-headers     add h:to/h:cc and split received chain\n  \
         \n\
         Reporting options:\n  \
         --json                 emit a single JSON line (for scripting)\n  \
         --limit N              stop after N messages per folder\n  \
         --show-errors N        print up to N mis-classified files to stderr (0)"
    );
    process::exit(2);
}

fn parse_args() -> Args {
    let argv: Vec<String> = std::env::args().collect();
    let mut db_dir: Option<PathBuf> = None;
    let mut ham_paths: Vec<PathBuf> = Vec::new();
    let mut spam_paths: Vec<PathBuf> = Vec::new();
    let mut params = Params::default();
    let mut tok = TokenizerConfig::default();
    let mut json = false;
    let mut limit: Option<usize> = None;
    let mut show_errors = 0usize;

    let mut i = 1;
    let need = |i: usize, flag: &str| -> String {
        if i + 1 >= argv.len() {
            eprintln!("spamlite-eval: {flag} requires an argument");
            process::exit(2);
        }
        argv[i + 1].clone()
    };

    while i < argv.len() {
        let a = argv[i].as_str();
        match a {
            "-d" | "--db-dir" => {
                db_dir = Some(PathBuf::from(need(i, a)));
                i += 2;
            }
            "--ham" => {
                for p in need(i, a).split(',') {
                    ham_paths.push(PathBuf::from(p));
                }
                i += 2;
            }
            "--spam" => {
                for p in need(i, a).split(',') {
                    spam_paths.push(PathBuf::from(p));
                }
                i += 2;
            }
            "--max-interesting" => {
                params.max_interesting = need(i, a).parse().expect("usize");
                i += 2;
            }
            "--unknown-prob" => {
                params.unknown_prob = need(i, a).parse().expect("f64");
                i += 2;
            }
            "--good-bias" => {
                params.good_bias = need(i, a).parse().expect("f64");
                i += 2;
            }
            "--min-word-count" => {
                params.min_word_count = need(i, a).parse().expect("u64");
                i += 2;
            }
            "--strength" => {
                params.strength = need(i, a).parse().expect("f64");
                i += 2;
            }
            "--threshold" | "-t" => {
                params.threshold = need(i, a).parse().expect("f64");
                i += 2;
            }
            "--min-len" => {
                tok.min_len = need(i, a).parse().expect("usize");
                i += 2;
            }
            "--max-len" => {
                tok.max_len = need(i, a).parse().expect("usize");
                i += 2;
            }
            "--expanded-headers" => {
                tok.expanded_headers = true;
                i += 1;
            }
            "--json" => {
                json = true;
                i += 1;
            }
            "--limit" => {
                limit = Some(need(i, a).parse().expect("usize"));
                i += 2;
            }
            "--show-errors" => {
                show_errors = need(i, a).parse().expect("usize");
                i += 2;
            }
            "-h" | "--help" | "help" => usage_and_exit(),
            other => {
                eprintln!("spamlite-eval: unknown argument '{other}'");
                usage_and_exit();
            }
        }
    }

    let db_dir = db_dir.unwrap_or_else(|| {
        eprintln!("spamlite-eval: -d DB_DIR required");
        process::exit(2);
    });
    if ham_paths.is_empty() && spam_paths.is_empty() {
        eprintln!("spamlite-eval: at least one of --ham / --spam required");
        process::exit(2);
    }

    Args {
        db_dir,
        ham_paths,
        spam_paths,
        params,
        tok,
        json,
        limit,
        show_errors,
    }
}

struct FolderResult {
    label: &'static str,
    path: PathBuf,
    total: usize,
    agree: usize,
    disagree: usize,
    scores: Vec<f64>,
    errors: Vec<(PathBuf, f64)>,
}

fn walk_cur(path: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let Ok(entries) = fs::read_dir(path) else {
        return out;
    };
    for entry in entries.flatten() {
        let p = entry.path();
        if p.is_file() {
            out.push(p);
        }
    }
    out
}

fn percentile(sorted: &[f64], pct: f64) -> f64 {
    if sorted.is_empty() {
        return f64::NAN;
    }
    let idx = ((sorted.len() - 1) as f64 * pct).round() as usize;
    sorted[idx.min(sorted.len() - 1)]
}

fn evaluate_folder(
    label: &'static str,
    path: &Path,
    truth_is_spam: bool,
    db: &Database,
    params: &Params,
    tok: &TokenizerConfig,
    limit: Option<usize>,
) -> FolderResult {
    let mut files = walk_cur(path);
    files.sort();
    if let Some(n) = limit {
        files.truncate(n);
    }

    let mut result = FolderResult {
        label,
        path: path.to_path_buf(),
        total: 0,
        agree: 0,
        disagree: 0,
        scores: Vec::with_capacity(files.len()),
        errors: Vec::new(),
    };

    for f in files {
        let Ok(raw) = fs::read(&f) else { continue };
        let tokens = tokenize_with_config(&raw, tok);
        let (verdict, score) = match classifier::classify(db, &tokens, params) {
            Ok(x) => x,
            Err(_) => continue,
        };
        result.total += 1;
        result.scores.push(score);
        let agrees = matches!(verdict, Verdict::Spam) == truth_is_spam;
        if agrees {
            result.agree += 1;
        } else {
            result.disagree += 1;
            if result.errors.len() < 1000 {
                result.errors.push((f, score));
            }
        }
    }

    result
}

fn main() {
    let args = parse_args();

    let db_path = args.db_dir.join("db.sqlite");
    let db = Database::open(&db_path).unwrap_or_else(|e| {
        eprintln!("spamlite-eval: open {}: {e}", db_path.display());
        process::exit(1);
    });

    let t0 = Instant::now();

    let mut ham_results = Vec::new();
    for p in &args.ham_paths {
        ham_results.push(evaluate_folder(
            "ham",
            p,
            false,
            &db,
            &args.params,
            &args.tok,
            args.limit,
        ));
    }
    let mut spam_results = Vec::new();
    for p in &args.spam_paths {
        spam_results.push(evaluate_folder(
            "spam",
            p,
            true,
            &db,
            &args.params,
            &args.tok,
            args.limit,
        ));
    }

    let elapsed = t0.elapsed().as_secs_f64();

    // Aggregate: tn = ham agrees, fp = ham disagrees, tp = spam agrees, fn = spam disagrees
    let mut tn = 0usize;
    let mut fp = 0usize;
    let mut tp = 0usize;
    let mut fn_ = 0usize;
    for r in &ham_results {
        tn += r.agree;
        fp += r.disagree;
    }
    for r in &spam_results {
        tp += r.agree;
        fn_ += r.disagree;
    }
    let ham_total = tn + fp;
    let spam_total = tp + fn_;
    let total = ham_total + spam_total;

    let mut all_ham_scores: Vec<f64> = ham_results.iter().flat_map(|r| r.scores.clone()).collect();
    let mut all_spam_scores: Vec<f64> =
        spam_results.iter().flat_map(|r| r.scores.clone()).collect();
    all_ham_scores.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    all_spam_scores.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));

    let fp_rate = if ham_total > 0 {
        fp as f64 / ham_total as f64
    } else {
        f64::NAN
    };
    let fn_rate = if spam_total > 0 {
        fn_ as f64 / spam_total as f64
    } else {
        f64::NAN
    };
    let err_rate = if total > 0 {
        (fp + fn_) as f64 / total as f64
    } else {
        f64::NAN
    };

    if args.json {
        // Single-line JSON for scripting. Fields chosen for easy diffing.
        let params = &args.params;
        let tok = &args.tok;
        let mut fields: BTreeMap<&str, String> = BTreeMap::new();
        fields.insert("ham_n", ham_total.to_string());
        fields.insert("spam_n", spam_total.to_string());
        fields.insert("tp", tp.to_string());
        fields.insert("tn", tn.to_string());
        fields.insert("fp", fp.to_string());
        fields.insert("fn", fn_.to_string());
        fields.insert("fp_rate", format!("{fp_rate:.6}"));
        fields.insert("fn_rate", format!("{fn_rate:.6}"));
        fields.insert("err_rate", format!("{err_rate:.6}"));
        fields.insert("max_interesting", params.max_interesting.to_string());
        fields.insert("unknown_prob", format!("{}", params.unknown_prob));
        fields.insert("good_bias", format!("{}", params.good_bias));
        fields.insert("min_word_count", params.min_word_count.to_string());
        fields.insert("strength", format!("{}", params.strength));
        fields.insert("threshold", format!("{}", params.threshold));
        fields.insert("min_len", tok.min_len.to_string());
        fields.insert("max_len", tok.max_len.to_string());
        fields.insert("expanded_headers", tok.expanded_headers.to_string());
        fields.insert("ham_p50", format!("{:.6}", percentile(&all_ham_scores, 0.5)));
        fields.insert("ham_p95", format!("{:.6}", percentile(&all_ham_scores, 0.95)));
        fields.insert("ham_p99", format!("{:.6}", percentile(&all_ham_scores, 0.99)));
        fields.insert(
            "spam_p01",
            format!("{:.6}", percentile(&all_spam_scores, 0.01)),
        );
        fields.insert("spam_p05", format!("{:.6}", percentile(&all_spam_scores, 0.05)));
        fields.insert("spam_p50", format!("{:.6}", percentile(&all_spam_scores, 0.5)));
        fields.insert("elapsed_s", format!("{elapsed:.3}"));
        let pairs: Vec<String> = fields
            .iter()
            .map(|(k, v)| {
                if v.chars().all(|c| c.is_ascii_digit() || c == '.' || c == '-')
                    && !v.is_empty()
                    && v != "true"
                    && v != "false"
                {
                    format!("\"{k}\":{v}")
                } else if v == "true" || v == "false" {
                    format!("\"{k}\":{v}")
                } else {
                    format!("\"{k}\":\"{v}\"")
                }
            })
            .collect();
        println!("{{{}}}", pairs.join(","));
    } else {
        println!("spamlite-eval  ({:.2}s)", elapsed);
        println!();
        println!(
            "Params:    max_interesting={}  unknown_prob={}  good_bias={}  min_word_count={}  threshold={}",
            args.params.max_interesting,
            args.params.unknown_prob,
            args.params.good_bias,
            args.params.min_word_count,
            args.params.threshold
        );
        println!(
            "Tokenizer: min_len={}  max_len={}  expanded_headers={}",
            args.tok.min_len, args.tok.max_len, args.tok.expanded_headers
        );
        println!();
        println!("Folder-level breakdown:");
        for r in ham_results.iter().chain(spam_results.iter()) {
            println!(
                "  [{}] {:<60}  n={:5}  agree={:5}  disagree={:5}",
                r.label,
                r.path.display(),
                r.total,
                r.agree,
                r.disagree
            );
        }
        println!();
        println!("Confusion matrix (ground truth × classifier verdict):");
        println!("                predicted-ham  predicted-spam");
        println!("  actual-ham       {tn:7}       {fp:7}        (fp rate {fp_rate:.4})");
        println!("  actual-spam      {fn_:7}       {tp:7}        (fn rate {fn_rate:.4})");
        println!();
        println!(
            "Totals: ham={ham_total} spam={spam_total} err={err_rate:.4} ({} / {total})",
            fp + fn_
        );
        println!();
        println!(
            "Ham scores:  p50={:.4}  p95={:.4}  p99={:.4}",
            percentile(&all_ham_scores, 0.5),
            percentile(&all_ham_scores, 0.95),
            percentile(&all_ham_scores, 0.99)
        );
        println!(
            "Spam scores: p01={:.4}  p05={:.4}  p50={:.4}",
            percentile(&all_spam_scores, 0.01),
            percentile(&all_spam_scores, 0.05),
            percentile(&all_spam_scores, 0.5)
        );

        if args.show_errors > 0 {
            eprintln!();
            eprintln!("First {} mis-classifications:", args.show_errors);
            let mut count = 0;
            for r in ham_results.iter().chain(spam_results.iter()) {
                for (f, s) in &r.errors {
                    if count >= args.show_errors {
                        break;
                    }
                    eprintln!("  [{}] score={:.4}  {}", r.label, s, f.display());
                    count += 1;
                }
            }
        }
    }
}
