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
use spamlite::storage::Database;
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
    fp_weight: f64,
    min_test_spam: usize,
}

/// Relative cost of a false positive against a false negative in the objective.
///
/// 1.0 reproduces plain balanced error exactly, and that is the default ON PURPOSE.
/// Raising it is tempting — an FP really is worse than an FN — but the only FP
/// signal available here is the held-out Maildir count, and that number does not
/// track reality: the user whose holdout shows 280 FPs is running at 278 GOOD /
/// 73 SPAM in production with zero rescues in eight days. Tuning harder against a
/// metric that disagrees with the live filter is how you break a working system.
///
/// Raising this also degenerates on a thin spam holdout: at w=10 with 11 held-out
/// spam, the sweep picks a config with 0 FPs that catches 1 spam in 11. Use
/// `--fp-weight` to experiment, but validate against real TRAIN corrections — not
/// against this corpus — before changing the default.
const DEFAULT_FP_WEIGHT: f64 = 1.0;

/// Minimum held-out spam before a parameter change is allowed. 0 = no floor,
/// matching prior behaviour. Worth raising only alongside `--fp-weight`, for the
/// reason above: a thin spam holdout can't estimate a false-negative rate.
const DEFAULT_MIN_TEST_SPAM: usize = 0;

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
    let mut fp_weight = DEFAULT_FP_WEIGHT;
    let mut min_test_spam = DEFAULT_MIN_TEST_SPAM;

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
            "--fp-weight" => {
                fp_weight = need(i, a).parse().expect("f64");
                i += 2;
            }
            "--min-test-spam" => {
                min_test_spam = need(i, a).parse().expect("usize");
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
        fp_weight,
        min_test_spam,
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
    let count_map: HashMap<String, (u64, u64)> = db
        .lookup_tokens(&vocab_vec)
        .map_err(|e| format!("token lookup failed: {e}"))?;
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
    /// Balanced error rate: (fp_rate + fn_rate) / 2. Reported, but NOT the
    /// tuning objective — see `weighted_err`. Kept because the JSON log has
    /// always carried it and the history is worth being able to compare against.
    fn balanced_err(&self) -> f64 {
        let h = self.ham_n().max(1) as f64;
        let s = self.spam_n().max(1) as f64;
        (self.fp as f64 / h + self.fn_ as f64 / s) / 2.0
    }

    /// The tuning objective: class-rate-normalised error with an explicit false
    /// positive penalty.
    ///
    ///     (w·fp_rate + fn_rate) / (w + 1)
    ///
    /// Normalising by class size (rather than using raw counts) stops the search
    /// collapsing to "always predict the majority class" on a lopsided corpus —
    /// that was the original reason for `balanced_err`, and it still holds.
    ///
    /// But plain balanced error sets the FP/FN exchange rate to the *sample's*
    /// class ratio, and that ratio is an artefact of mailbox hygiene, not of the
    /// user's real mail. The corpus comes from the live Maildir: INBOX/cur
    /// accumulates forever while .Junk/cur is expunged after 7 days, so a typical
    /// holdout lands around 800 ham / 11 spam. Balanced error therefore prices one
    /// spam catch at ~73 false positives, and the tuner duly bought them — it
    /// accepted a config taking one user from 92 to 281 held-out FPs to clear 7 FNs,
    /// and logged it as an improvement.
    ///
    /// `w` states the real cost ratio instead of inheriting an accidental one.
    fn weighted_err(&self, fp_weight: f64) -> f64 {
        let h = self.ham_n().max(1) as f64;
        let s = self.spam_n().max(1) as f64;
        let fp_rate = self.fp as f64 / h;
        let fn_rate = self.fn_ as f64 / s;
        (fp_weight * fp_rate + fn_rate) / (fp_weight + 1.0)
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
fn tune(
    samples: &[Sample],
    total_good: u64,
    total_spam: u64,
    fp_weight: f64,
) -> (Params, EvalResult) {
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
            if r.weighted_err(fp_weight) < best_r.weighted_err(fp_weight) {
                best = p;
                best_r = r;
                improved = true;
            }
        }
        for &g in &good_bias_grid {
            let mut p = clone_params(&best);
            p.good_bias = g;
            let r = evaluate(samples, total_good, total_spam, &p);
            if r.weighted_err(fp_weight) < best_r.weighted_err(fp_weight) {
                best = p;
                best_r = r;
                improved = true;
            }
        }
        for &s in &strength_grid {
            let mut p = clone_params(&best);
            p.strength = s;
            let r = evaluate(samples, total_good, total_spam, &p);
            if r.weighted_err(fp_weight) < best_r.weighted_err(fp_weight) {
                best = p;
                best_r = r;
                improved = true;
            }
        }
        for &u in &unknown_prob_grid {
            let mut p = clone_params(&best);
            p.unknown_prob = u;
            let r = evaluate(samples, total_good, total_spam, &p);
            if r.weighted_err(fp_weight) < best_r.weighted_err(fp_weight) {
                best = p;
                best_r = r;
                improved = true;
            }
        }
        for &m in &max_int_grid {
            let mut p = clone_params(&best);
            p.max_interesting = m;
            let r = evaluate(samples, total_good, total_spam, &p);
            if r.weighted_err(fp_weight) < best_r.weighted_err(fp_weight) {
                best = p;
                best_r = r;
                improved = true;
            }
        }
        for &mwc in &mwc_grid {
            let mut p = clone_params(&best);
            p.min_word_count = mwc;
            let r = evaluate(samples, total_good, total_spam, &p);
            if r.weighted_err(fp_weight) < best_r.weighted_err(fp_weight) {
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
        combine_mode: p.combine_mode,
        new_word_score: p.new_word_score,
        min_distance: p.min_distance,
        min_array_size: p.min_array_size,
        train_max_reps: p.train_max_reps,
        rail: p.rail,
        rail_min_spam: p.rail_min_spam,
        rail_strong_spam: p.rail_strong_spam,
        rail_floor: p.rail_floor,
        rail_require_coflag: p.rail_require_coflag,
    }
}

/// The six keys the tuner sweeps. Everything else in a params.toml was put there
/// by a human and is none of the tuner's business.
const MANAGED_KEYS: [&str; 6] = [
    "strength",
    "unknown_prob",
    "max_interesting",
    "threshold",
    "good_bias",
    "min_word_count",
];

/// Rewrite only the managed keys, preserving every other line — hand-written
/// keys, comments, and blank lines — verbatim and in place.
///
/// This used to be an unconditional `fs::write` of the six managed keys, which
/// silently deleted anything else in the file. `combine_mode` and `train_max_reps`
/// are not tunable and so were not in the six: a user hand-tuned onto the
/// non-saturating geometric combiner (with the reasoning written up in comments
/// above it) would have had that quietly reverted the first night they had enough
/// corpus for the tuner to run on them, taking the comments with it.
fn write_params_toml(db_dir: &Path, params: &Params) -> std::io::Result<()> {
    let path = db_dir.join("params.toml");

    let managed_value = |k: &str| -> String {
        match k {
            "strength" => params.strength.to_string(),
            "unknown_prob" => params.unknown_prob.to_string(),
            "max_interesting" => params.max_interesting.to_string(),
            "threshold" => params.threshold.to_string(),
            "good_bias" => params.good_bias.to_string(),
            "min_word_count" => params.min_word_count.to_string(),
            _ => unreachable!("managed_value called with unmanaged key {k}"),
        }
    };

    let existing = fs::read_to_string(&path).unwrap_or_default();
    let mut out: Vec<String> = Vec::new();
    let mut seen: HashSet<&str> = HashSet::new();

    if existing.trim().is_empty() {
        out.push("# spamlite per-user params (generated by spamlite-tune)".to_string());
    }

    for raw in existing.lines() {
        // Match on the key only; keep the line untouched if it isn't one of ours.
        let key = raw
            .split('#')
            .next()
            .unwrap_or("")
            .split_once('=')
            .map(|(k, _)| k.trim());
        match key {
            Some(k) if MANAGED_KEYS.contains(&k) => {
                out.push(format!("{k} = {}", managed_value(k)));
                seen.insert(MANAGED_KEYS.iter().find(|m| **m == k).unwrap());
            }
            _ => out.push(raw.to_string()),
        }
    }

    // Any managed key the file didn't already carry gets appended.
    for k in MANAGED_KEYS {
        if !seen.contains(k) {
            out.push(format!("{k} = {}", managed_value(k)));
        }
    }

    let mut body = out.join("\n");
    body.push('\n');
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

    // Baseline = the params this user is ACTUALLY RUNNING, which is an installed
    // params.toml if they have one, else the defaults at the production threshold.
    // Comparing against `Params::default()` regardless — as this did — meant a
    // re-tune never checked its candidate against the config it was about to
    // overwrite, so it could replace a good params.toml with a worse one and still
    // report an improvement.
    let mut baseline = Params {
        threshold: args.baseline_threshold,
        ..Default::default()
    };
    baseline.load_overrides(&args.db_dir);
    let baseline_test = evaluate(&test, total_good, total_spam, &baseline);

    let t1 = Instant::now();
    let (best, best_train) = tune(&train, total_good, total_spam, args.fp_weight);
    let tune_elapsed = t1.elapsed().as_secs_f64();
    let best_test = evaluate(&test, total_good, total_spam, &best);

    // Three independent conditions, all of which must hold to write.
    //
    // 1. The objective improved on held-out data (not an overfit).
    // 2. False positives did not go up. A pure objective win is not enough: the
    //    weighting says what we'd *trade*, this says what we won't *regress*. Junking
    //    a user's legitimate mail to catch more spam is not an improvement we accept
    //    silently, whatever the arithmetic says.
    // 3. The holdout carries enough spam to estimate a false-negative rate at all.
    let improved = best_test.weighted_err(args.fp_weight) < baseline_test.weighted_err(args.fp_weight);
    let no_fp_regression = best_test.fp <= baseline_test.fp;
    let enough_spam = test_spam >= args.min_test_spam;
    let generalised = improved && no_fp_regression && enough_spam;

    // Why we refused, so the log says something more useful than "generalised: false".
    let refused = if generalised {
        String::new()
    } else if !enough_spam {
        format!("test_spam {test_spam} < min_test_spam {}", args.min_test_spam)
    } else if !no_fp_regression {
        format!(
            "fp regression {} -> {} (+{})",
            baseline_test.fp,
            best_test.fp,
            best_test.fp - baseline_test.fp
        )
    } else {
        "no held-out improvement".to_string()
    };

    if args.json {
        println!(
            "{{\"holdout\":{},\"fp_weight\":{},\"train\":{{\"ham\":{},\"spam\":{}}},\"test\":{{\"ham\":{},\"spam\":{}}},\"baseline\":{{\"threshold\":{},\"strength\":{},\"unknown_prob\":{},\"max_interesting\":{},\"good_bias\":{},\"min_word_count\":{},\"test_fp\":{},\"test_fn\":{},\"test_balanced_err\":{:.6},\"test_weighted_err\":{:.6}}},\"best\":{{\"threshold\":{},\"strength\":{},\"unknown_prob\":{},\"max_interesting\":{},\"good_bias\":{},\"min_word_count\":{},\"train_fp\":{},\"train_fn\":{},\"train_balanced_err\":{:.6},\"test_fp\":{},\"test_fn\":{},\"test_balanced_err\":{:.6},\"test_weighted_err\":{:.6}}},\"generalised\":{},\"refused_because\":\"{}\",\"tune_elapsed_s\":{:.3}}}",
            args.holdout,
            args.fp_weight,
            train_ham, train_spam, test_ham, test_spam,
            baseline.threshold, baseline.strength, baseline.unknown_prob,
            baseline.max_interesting, baseline.good_bias, baseline.min_word_count,
            baseline_test.fp, baseline_test.fn_, baseline_test.balanced_err(),
            baseline_test.weighted_err(args.fp_weight),
            best.threshold, best.strength, best.unknown_prob,
            best.max_interesting, best.good_bias, best.min_word_count,
            best_train.fp, best_train.fn_, best_train.balanced_err(),
            best_test.fp, best_test.fn_, best_test.balanced_err(),
            best_test.weighted_err(args.fp_weight),
            generalised,
            refused,
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
            eprintln!("spamlite-tune: refusing to write params.toml — {refused}");
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

#[cfg(test)]
mod tests {
    use super::*;

    fn ev(fp: u32, fn_: u32, tp: u32, tn: u32) -> EvalResult {
        EvalResult { fp, fn_, tp, tn }
    }

    /// The default must not silently change the objective: w=1 IS balanced error.
    #[test]
    fn default_fp_weight_reproduces_balanced_err() {
        for r in [ev(92, 7, 4, 708), ev(281, 0, 11, 519), ev(0, 38, 0, 31_000)] {
            assert!((r.weighted_err(DEFAULT_FP_WEIGHT) - r.balanced_err()).abs() < 1e-12);
        }
    }

    /// The FP-weighting mechanism works when asked for. On a 800-ham/11-spam holdout
    /// balanced error prices one spam catch at ~73 false positives, and will trade
    /// 189 extra FPs for 7 FNs. At w=10 it won't. (Not the default — see the const.)
    #[test]
    fn fp_weight_can_reject_a_bad_fp_trade() {
        let installed = ev(92, 7, 4, 708);
        let tuned = ev(281, 0, 11, 519);
        assert!(tuned.balanced_err() < installed.balanced_err());
        assert!(tuned.weighted_err(10.0) > installed.weighted_err(10.0));
    }

    /// Whatever the weight, the objective must not collapse to "always predict the
    /// majority class" on a lopsided corpus — the failure balanced_err was introduced
    /// to prevent (jaz: 31k ham, 38 spam).
    #[test]
    fn weighted_err_still_beats_always_predict_ham() {
        let always_ham = ev(0, 38, 0, 31_000);
        let sensible = ev(100, 10, 28, 30_900);
        for w in [1.0, 10.0] {
            assert!(sensible.weighted_err(w) < always_ham.weighted_err(w), "w={w}");
        }
    }

    #[test]
    fn write_params_toml_preserves_unmanaged_keys_and_comments() {
        let dir = std::env::temp_dir().join(format!("spamlite-tune-test-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("params.toml");
        fs::write(
            &path,
            "# hand-written, do not clobber\ncombine_mode = geometric\ntrain_max_reps = 5\nthreshold = 0.9\n",
        )
        .unwrap();

        let p = Params { threshold: 0.65, ..Default::default() };
        write_params_toml(&dir, &p).unwrap();
        let got = fs::read_to_string(&path).unwrap();

        // Unmanaged keys and the comment survive untouched.
        assert!(got.contains("# hand-written, do not clobber"));
        assert!(got.contains("combine_mode = geometric"));
        assert!(got.contains("train_max_reps = 5"));
        // The managed key is updated in place, not duplicated.
        assert!(got.contains("threshold = 0.65"));
        assert!(!got.contains("threshold = 0.9"));
        assert_eq!(got.matches("threshold =").count(), 1);

        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn write_params_toml_creates_a_fresh_file_when_none_exists() {
        let dir = std::env::temp_dir().join(format!("spamlite-tune-fresh-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();

        write_params_toml(&dir, &Params::default()).unwrap();
        let got = fs::read_to_string(dir.join("params.toml")).unwrap();
        for k in MANAGED_KEYS {
            assert!(got.contains(&format!("{k} =")), "missing {k} in {got:?}");
        }

        fs::remove_dir_all(&dir).ok();
    }
}
