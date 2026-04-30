// Copyright 2026 Mark Constable <mc@netserva.org>
// SPDX-License-Identifier: MIT
//
// spamlite-tune — per-user parameter tuner.
//
// Walks a user's ham/spam corpus, fetches token counts once, then sweeps
// classifier parameters in memory to find the combination that minimises
// total errors on that specific user. Optionally writes the result to
// `<db_dir>/params.toml` so the deployed `spamlite` binary picks it up
// without code changes.
//
// Strategy: build a per-message cache of (good, spam) tuples by bulk-loading
// every unique token across the corpus in one SQL pass, then do coordinate
// descent over the parameter space using `classify_from_counts` (pure CPU).
// This collapses the ~minute-per-eval cost into ~ms-per-eval, making per-user
// tuning practical.
//
// Usage:
//   spamlite-tune -d DB_DIR --ham PATH[,PATH...] --spam PATH[,PATH...]
//                 [--baseline-threshold T] [--write] [--json] [--limit N]

use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::process;
use std::time::Instant;

use spamlite::classifier::{
    self, classify_from_counts, CountedTokens, Params, Verdict,
};
use spamlite::storage::{Database, Token};
use spamlite::tokenizer::{tokenize_with_config, TokenizerConfig};

struct Args {
    db_dir: PathBuf,
    ham_paths: Vec<PathBuf>,
    spam_paths: Vec<PathBuf>,
    baseline_threshold: f64,
    holdout: f64,
    write: bool,
    json: bool,
    limit: Option<usize>,
}

fn usage_and_exit() -> ! {
    eprintln!(
        "spamlite-tune — per-user classifier parameter tuner\n\
         \n\
         Usage:\n  \
         spamlite-tune -d DB_DIR --ham PATH[,PATH...] --spam PATH[,PATH...] [options]\n\
         \n\
         Options:\n  \
         --baseline-threshold T   threshold to compare against (production = 0.6)\n  \
         --write                  write best params to <db_dir>/params.toml\n  \
         --json                   single-line JSON output\n  \
         --limit N                stop after N messages per folder"
    );
    process::exit(2);
}

fn parse_args() -> Args {
    let argv: Vec<String> = std::env::args().collect();
    let mut db_dir: Option<PathBuf> = None;
    let mut ham_paths: Vec<PathBuf> = Vec::new();
    let mut spam_paths: Vec<PathBuf> = Vec::new();
    let mut baseline_threshold = 0.6;
    let mut holdout = 0.20;
    let mut write = false;
    let mut json = false;
    let mut limit: Option<usize> = None;

    let mut i = 1;
    let need = |i: usize, flag: &str| -> String {
        if i + 1 >= argv.len() {
            eprintln!("spamlite-tune: {flag} requires an argument");
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
            "--baseline-threshold" => {
                baseline_threshold = need(i, a).parse().expect("f64");
                i += 2;
            }
            "--holdout" => {
                holdout = need(i, a).parse().expect("f64");
                i += 2;
            }
            "--write" => {
                write = true;
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
            "-h" | "--help" | "help" => usage_and_exit(),
            other => {
                eprintln!("spamlite-tune: unknown argument '{other}'");
                usage_and_exit();
            }
        }
    }

    let db_dir = db_dir.unwrap_or_else(|| {
        eprintln!("spamlite-tune: -d DB_DIR required");
        process::exit(2);
    });
    if ham_paths.is_empty() || spam_paths.is_empty() {
        eprintln!("spamlite-tune: --ham AND --spam are both required");
        process::exit(2);
    }

    Args {
        db_dir,
        ham_paths,
        spam_paths,
        baseline_threshold,
        holdout,
        write,
        json,
        limit,
    }
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

/// Per-message cached tokens, ready for classify_from_counts.
struct Sample {
    is_spam_truth: bool,
    counts: CountedTokens,
}

/// Tokenize every file in the given paths; build a cached corpus where each
/// message is a vector of (good, spam) tuples already resolved against the db.
fn build_cache(
    db: &Database,
    ham_paths: &[PathBuf],
    spam_paths: &[PathBuf],
    limit: Option<usize>,
) -> Result<(Vec<Sample>, u64, u64), String> {
    let tok = TokenizerConfig::default();

    // Phase 1: tokenize all messages, collect all tokens by message
    let mut messages: Vec<(bool, Vec<String>)> = Vec::new();
    for (paths, is_spam) in [(ham_paths, false), (spam_paths, true)] {
        for p in paths {
            let mut files = walk_cur(p);
            files.sort();
            if let Some(n) = limit {
                files.truncate(n);
            }
            for f in files {
                let Ok(raw) = fs::read(&f) else { continue };
                let toks = tokenize_with_config(&raw, &tok);
                messages.push((is_spam, toks));
            }
        }
    }

    if messages.is_empty() {
        return Err("no messages to evaluate".into());
    }

    // Phase 2: collect unique vocabulary across the corpus
    let mut vocab: HashSet<String> = HashSet::new();
    for (_, toks) in &messages {
        for t in toks {
            vocab.insert(t.clone());
        }
    }
    let vocab_vec: Vec<String> = vocab.into_iter().collect();
    eprintln!(
        "spamlite-tune: {} messages, {} unique tokens; loading counts...",
        messages.len(),
        vocab_vec.len()
    );

    // Phase 3: bulk SQL load — one pass over the vocabulary
    let known: Vec<Token> = db
        .lookup_tokens(&vocab_vec)
        .map_err(|e| format!("token lookup failed: {e}"))?;
    let count_map: HashMap<String, (u64, u64)> = known
        .into_iter()
        .map(|t| (t.word, (t.good, t.spam)))
        .collect();
    eprintln!(
        "spamlite-tune: {} of {} tokens are known to the db",
        count_map.len(),
        vocab_vec.len()
    );

    // Phase 4: assemble samples (per-message Vec<Option<(good, spam)>>)
    let samples: Vec<Sample> = messages
        .into_iter()
        .map(|(is_spam, toks)| {
            let counts: CountedTokens = toks
                .into_iter()
                .map(|t| count_map.get(&t).copied())
                .collect();
            Sample {
                is_spam_truth: is_spam,
                counts,
            }
        })
        .collect();

    let total_good = db
        .total_good()
        .map_err(|e| format!("total_good failed: {e}"))?;
    let total_spam = db
        .total_spam()
        .map_err(|e| format!("total_spam failed: {e}"))?;

    Ok((samples, total_good, total_spam))
}

#[derive(Clone, Copy)]
struct EvalResult {
    fp: u32,
    fn_: u32,
    tp: u32,
    tn: u32,
}

impl EvalResult {
    fn errors(&self) -> u32 {
        self.fp + self.fn_
    }
    fn total(&self) -> u32 {
        self.fp + self.fn_ + self.tp + self.tn
    }
    fn ham_n(&self) -> u32 {
        self.fp + self.tn
    }
    fn spam_n(&self) -> u32 {
        self.fn_ + self.tp
    }
    /// Balanced error rate: (fp_rate + fn_rate) / 2. Treats the two error
    /// classes as equally costly regardless of class sizes — required when the
    /// corpus is imbalanced (e.g. jaz has 31k ham vs 200 spam, where raw error
    /// minimisation collapses to "always predict ham"). Lower is better; range
    /// [0, 1].
    fn balanced_err(&self) -> f64 {
        let h = self.ham_n().max(1) as f64;
        let s = self.spam_n().max(1) as f64;
        (self.fp as f64 / h + self.fn_ as f64 / s) / 2.0
    }
}

fn evaluate(
    samples: &[Sample],
    total_good: u64,
    total_spam: u64,
    params: &Params,
) -> EvalResult {
    let mut r = EvalResult {
        fp: 0,
        fn_: 0,
        tp: 0,
        tn: 0,
    };
    for s in samples {
        let (verdict, _) = classify_from_counts(&s.counts, total_good, total_spam, params);
        let pred_spam = matches!(verdict, Verdict::Spam);
        match (s.is_spam_truth, pred_spam) {
            (true, true) => r.tp += 1,
            (true, false) => r.fn_ += 1,
            (false, true) => r.fp += 1,
            (false, false) => r.tn += 1,
        }
    }
    r
}

/// Coordinate descent: for each parameter, sweep its candidates while the rest
/// stay at the running best. Repeat until a full pass produces no improvement.
/// Order matters — `threshold` first (highest-leverage knob in production), then
/// the classifier shape parameters.
///
/// The objective is **balanced error rate** (`(fp/ham + fn/spam)/2`), not raw
/// total errors. This keeps the tuner from collapsing to "always predict the
/// majority class" on imbalanced corpora — which is exactly what bit the first
/// version of this tool on jaz's 31k-ham / 38-spam train split.
fn tune(samples: &[Sample], total_good: u64, total_spam: u64) -> (Params, EvalResult) {
    let threshold_grid = [0.50, 0.55, 0.60, 0.65, 0.70, 0.75, 0.80, 0.85];
    let good_bias_grid = [1.0, 1.5, 2.0, 2.5, 3.0];
    let strength_grid = [0.3, 0.5, 1.0, 1.5, 2.0];
    let unknown_prob_grid = [0.40, 0.45, 0.50, 0.55];
    let max_int_grid = [27usize, 50, 100, 150, 200];
    let mwc_grid = [0u64, 2, 5];

    let mut best = Params::default();
    let mut best_r = evaluate(samples, total_good, total_spam, &best);

    for round in 0..3 {
        let mut improved = false;

        for &t in &threshold_grid {
            let mut p = clone_params(&best);
            p.threshold = t;
            let r = evaluate(samples, total_good, total_spam, &p);
            if r.balanced_err() < best_r.balanced_err() {
                best = p;
                best_r = r;
                improved = true;
            }
        }
        for &g in &good_bias_grid {
            let mut p = clone_params(&best);
            p.good_bias = g;
            let r = evaluate(samples, total_good, total_spam, &p);
            if r.balanced_err() < best_r.balanced_err() {
                best = p;
                best_r = r;
                improved = true;
            }
        }
        for &s in &strength_grid {
            let mut p = clone_params(&best);
            p.strength = s;
            let r = evaluate(samples, total_good, total_spam, &p);
            if r.balanced_err() < best_r.balanced_err() {
                best = p;
                best_r = r;
                improved = true;
            }
        }
        for &u in &unknown_prob_grid {
            let mut p = clone_params(&best);
            p.unknown_prob = u;
            let r = evaluate(samples, total_good, total_spam, &p);
            if r.balanced_err() < best_r.balanced_err() {
                best = p;
                best_r = r;
                improved = true;
            }
        }
        for &m in &max_int_grid {
            let mut p = clone_params(&best);
            p.max_interesting = m;
            let r = evaluate(samples, total_good, total_spam, &p);
            if r.balanced_err() < best_r.balanced_err() {
                best = p;
                best_r = r;
                improved = true;
            }
        }
        for &mwc in &mwc_grid {
            let mut p = clone_params(&best);
            p.min_word_count = mwc;
            let r = evaluate(samples, total_good, total_spam, &p);
            if r.balanced_err() < best_r.balanced_err() {
                best = p;
                best_r = r;
                improved = true;
            }
        }

        if !improved {
            eprintln!("spamlite-tune: converged after round {round}");
            break;
        }
    }

    (best, best_r)
}

/// Stratified split: separately partition ham and spam, then merge. Uses a
/// fixed-step interleave (every k-th element to test) so the result is
/// deterministic without an RNG dependency. Preserves the global ham:spam
/// ratio in both halves, which is what makes balanced-loss tuning meaningful.
fn stratified_split(samples: Vec<Sample>, holdout: f64) -> (Vec<Sample>, Vec<Sample>) {
    if holdout <= 0.0 {
        return (samples, Vec::new());
    }
    let mut ham: Vec<Sample> = Vec::new();
    let mut spam: Vec<Sample> = Vec::new();
    for s in samples {
        if s.is_spam_truth {
            spam.push(s);
        } else {
            ham.push(s);
        }
    }
    let split_class = |class: Vec<Sample>| -> (Vec<Sample>, Vec<Sample>) {
        let n = class.len();
        if n == 0 {
            return (Vec::new(), Vec::new());
        }
        let test_n = ((n as f64) * holdout).round() as usize;
        let test_n = test_n.max(1).min(n - 1).min(n);
        let step = if test_n == 0 { usize::MAX } else { n / test_n };
        let mut train = Vec::new();
        let mut test = Vec::new();
        for (i, s) in class.into_iter().enumerate() {
            if step != usize::MAX && i % step == 0 && test.len() < test_n {
                test.push(s);
            } else {
                train.push(s);
            }
        }
        (train, test)
    };
    let (ham_tr, ham_te) = split_class(ham);
    let (spam_tr, spam_te) = split_class(spam);
    let mut train = ham_tr;
    train.extend(spam_tr);
    let mut test = ham_te;
    test.extend(spam_te);
    (train, test)
}

fn clone_params(p: &Params) -> Params {
    Params {
        strength: p.strength,
        unknown_prob: p.unknown_prob,
        max_interesting: p.max_interesting,
        threshold: p.threshold,
        good_bias: p.good_bias,
        min_word_count: p.min_word_count,
    }
}

fn write_params_toml(db_dir: &Path, params: &Params) -> std::io::Result<()> {
    let path = db_dir.join("params.toml");
    let body = format!(
        "# spamlite per-user params (generated by spamlite-tune)\n\
         strength = {}\n\
         unknown_prob = {}\n\
         max_interesting = {}\n\
         threshold = {}\n\
         good_bias = {}\n\
         min_word_count = {}\n",
        params.strength,
        params.unknown_prob,
        params.max_interesting,
        params.threshold,
        params.good_bias,
        params.min_word_count
    );
    fs::write(&path, body)?;
    Ok(())
}

fn fmt_params_inline(p: &Params) -> String {
    format!(
        "threshold={} strength={} unknown_prob={} max_interesting={} good_bias={} min_word_count={}",
        p.threshold, p.strength, p.unknown_prob, p.max_interesting, p.good_bias, p.min_word_count
    )
}

fn fmt_eval_inline(r: &EvalResult) -> String {
    format!(
        "fp={} fn={} balanced_err={:.4} (raw {} / {})",
        r.fp,
        r.fn_,
        r.balanced_err(),
        r.errors(),
        r.total()
    )
}

fn main() {
    let args = parse_args();
    let db_path = args.db_dir.join("db.sqlite");
    let db = Database::open(&db_path).unwrap_or_else(|e| {
        eprintln!("spamlite-tune: open {}: {e}", db_path.display());
        process::exit(1);
    });

    let t0 = Instant::now();
    let (samples, total_good, total_spam) =
        build_cache(&db, &args.ham_paths, &args.spam_paths, args.limit).unwrap_or_else(|e| {
            eprintln!("spamlite-tune: {e}");
            process::exit(1);
        });
    eprintln!("spamlite-tune: cache built in {:.2}s", t0.elapsed().as_secs_f64());

    let (train, test) = stratified_split(samples, args.holdout);
    let train_ham = train.iter().filter(|s| !s.is_spam_truth).count();
    let train_spam = train.iter().filter(|s| s.is_spam_truth).count();
    let test_ham = test.iter().filter(|s| !s.is_spam_truth).count();
    let test_spam = test.iter().filter(|s| s.is_spam_truth).count();
    eprintln!(
        "spamlite-tune: train ham={train_ham} spam={train_spam} | test ham={test_ham} spam={test_spam}",
    );

    // Baseline = Params::default() with production threshold (0.6 by default).
    // Reported on TEST set — the only set whose numbers actually mean anything.
    let mut baseline = Params::default();
    baseline.threshold = args.baseline_threshold;
    let baseline_test = evaluate(&test, total_good, total_spam, &baseline);

    let t1 = Instant::now();
    let (best, best_train) = tune(&train, total_good, total_spam);
    let tune_elapsed = t1.elapsed().as_secs_f64();
    let best_test = evaluate(&test, total_good, total_spam, &best);

    // Decision: did tuning actually generalise? If test balanced-error didn't
    // improve, the "best" params are an overfit and we refuse to write them.
    let generalised = best_test.balanced_err() < baseline_test.balanced_err();

    if args.json {
        println!(
            "{{\"holdout\":{},\"train\":{{\"ham\":{},\"spam\":{}}},\"test\":{{\"ham\":{},\"spam\":{}}},\"baseline\":{{\"threshold\":{},\"strength\":{},\"unknown_prob\":{},\"max_interesting\":{},\"good_bias\":{},\"min_word_count\":{},\"test_fp\":{},\"test_fn\":{},\"test_balanced_err\":{:.6}}},\"best\":{{\"threshold\":{},\"strength\":{},\"unknown_prob\":{},\"max_interesting\":{},\"good_bias\":{},\"min_word_count\":{},\"train_fp\":{},\"train_fn\":{},\"train_balanced_err\":{:.6},\"test_fp\":{},\"test_fn\":{},\"test_balanced_err\":{:.6}}},\"generalised\":{},\"tune_elapsed_s\":{:.3}}}",
            args.holdout,
            train_ham, train_spam, test_ham, test_spam,
            baseline.threshold, baseline.strength, baseline.unknown_prob,
            baseline.max_interesting, baseline.good_bias, baseline.min_word_count,
            baseline_test.fp, baseline_test.fn_, baseline_test.balanced_err(),
            best.threshold, best.strength, best.unknown_prob,
            best.max_interesting, best.good_bias, best.min_word_count,
            best_train.fp, best_train.fn_, best_train.balanced_err(),
            best_test.fp, best_test.fn_, best_test.balanced_err(),
            generalised,
            tune_elapsed,
        );
    } else {
        println!("spamlite-tune  ({:.2}s sweep)", tune_elapsed);
        println!();
        println!(
            "Train: {train_ham} ham / {train_spam} spam   Test: {test_ham} ham / {test_spam} spam   (holdout = {:.0}%)",
            args.holdout * 100.0
        );
        println!();
        println!("Baseline params: {}", fmt_params_inline(&baseline));
        println!("  test:  {}", fmt_eval_inline(&baseline_test));
        println!();
        println!("Best params (after tune on train):");
        println!("  {}", fmt_params_inline(&best));
        println!("  train: {}", fmt_eval_inline(&best_train));
        println!("  test:  {}", fmt_eval_inline(&best_test));
        println!();
        let baseline_be = baseline_test.balanced_err();
        let best_be = best_test.balanced_err();
        let pct = if baseline_be > 0.0 {
            (1.0 - best_be / baseline_be) * 100.0
        } else {
            0.0
        };
        if generalised {
            println!(
                "Cross-validated improvement: balanced_err {:.4} → {:.4} ({:+.1}%)",
                baseline_be, best_be, pct
            );
        } else {
            println!(
                "Tuned params do NOT generalise (test balanced_err {:.4} → {:.4}, {:+.1}%) — refusing to recommend.",
                baseline_be, best_be, pct
            );
        }
    }

    if args.write {
        if !generalised {
            eprintln!(
                "spamlite-tune: refusing to write params.toml — tuned params did not improve held-out test set"
            );
            process::exit(2);
        }
        if let Err(e) = write_params_toml(&args.db_dir, &best) {
            eprintln!("spamlite-tune: write params.toml failed: {e}");
            process::exit(1);
        }
        eprintln!("spamlite-tune: wrote {}/params.toml", args.db_dir.display());
    }
    let _ = classifier::Verdict::Good; // keep `classifier` use anchored
}
