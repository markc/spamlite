// Copyright 2026 Mark Constable <mc@netserva.org>
// SPDX-License-Identifier: MIT

use crate::storage::Database;

/// Classification result
#[derive(Debug, PartialEq)]
pub enum Verdict {
    Spam,
    Good,
}

impl std::fmt::Display for Verdict {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Verdict::Spam => write!(f, "SPAM"),
            Verdict::Good => write!(f, "GOOD"),
        }
    }
}

/// Clamp bounds for per-token probabilities in the geometric combiner. Mirrors
/// spamprobe's `MIN_PROB`/`MAX_PROB` (`SpamFilter.cc:42-43`): clamping each f(w)
/// away from 0.0/1.0 is what stops a single extreme token from pinning the whole
/// message at 0 or 1 under the geometric mean — the anti-saturation invariant.
const MIN_PROB: f64 = 0.000001;
const MAX_PROB: f64 = 0.999999;

/// How per-token probabilities are combined into a final score.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CombineMode {
    /// Fisher chi-squared combining. Spreads scores toward the extremes; a field
    /// of many weakly-spammy tokens (e.g. shared bulk-ESP infrastructure) drives
    /// the score to a saturated 1.0 that no threshold can rescue.
    Fisher,
    /// Robinson's nth-root geometric mean (spamprobe's `normalScoreMessage`,
    /// `SpamFilter.cc:367-387`): `score = S/(S+G)` where `S = (∏f)^(1/n)`,
    /// `G = (∏(1-f))^(1/n)`. Scale-invariant — a uniform field of 0.7 tokens
    /// scores 0.7 regardless of token count, leaving a margin retraining can move.
    Geometric,
}

/// Tuning parameters for the classifier.
pub struct Params {
    /// Robinson strength parameter — how strongly we pull toward `unknown_prob`
    pub strength: f64,
    /// Robinson centre `x` — the value a thinly-observed token's probability is
    /// pulled toward by the strength correction. Neutral at 0.5. NOTE: this is
    /// distinct from `new_word_score` (the fallback for tokens below the gate /
    /// not in the DB at all); spamprobe conflated the two, we split them.
    pub unknown_prob: f64,
    /// Number of most interesting tokens to use
    pub max_interesting: usize,
    /// Score at or above which we classify as spam (default 0.5)
    pub threshold: f64,
    /// Weight applied to ham evidence when computing per-token raw probability.
    /// `raw_p = spam / (spam + good_bias * good)`. `1.0` disables the bias
    /// (symmetric). Spamprobe uses `2.0` (`SpamFilter.cc:117`) to favour ham and
    /// cut false-positives; we default to `1.0`.
    pub good_bias: f64,
    /// Minimum (good + spam) occurrences for a token to contribute its computed
    /// probability. Tokens below this fall back to `new_word_score`. Reduces
    /// noise from thinly-observed tokens. `0` disables the gate. Spamprobe
    /// defaults to `5` (`FilterConfig.cc:36`).
    pub min_word_count: u64,
    /// How per-token probabilities are combined. Defaults to `Fisher` to preserve
    /// historical behaviour; `Geometric` is the spamprobe-faithful non-saturating
    /// combiner (the fix for unretrainable bulk-ESP false-positives).
    pub combine_mode: CombineMode,
    /// Fallback probability for a token that is unknown to the DB or below the
    /// `min_word_count` gate. Spamprobe uses a ham-leaning `0.3`
    /// (`FilterConfig.cc:39`, `newWordScore`); we default to `0.5` (neutral, =
    /// historical behaviour). Lower values lean cold/thin mail toward ham.
    pub new_word_score: f64,
    /// Minimum distance from 0.5 a token must have to contribute, after the top-N
    /// selection. `0.0` disables (default). Mirrors spamprobe's
    /// `removeTokensBelowMinDistance` (`SpamFilter.cc:212-226`): strips near-0.5
    /// filler so a few real signals dominate under the geometric mean.
    pub min_distance: f64,
    /// When `min_distance > 0`, always keep at least this many tokens even if they
    /// fall below the distance floor (spamprobe `minArraySize`).
    pub min_array_size: usize,
    /// Supervised-training convergence cap (used by `cmd_train`, not scoring).
    /// `1` = single +1 per retrain (historical). `>1` re-adds the message's token
    /// counts until it scores confidently on the trained side, capped here —
    /// spamprobe's `classifyMessage` loop (`SpamFilter.cc:460-491`, cap 25). This
    /// is what makes "one ham retrain flips the sender" work. Message totals are
    /// bumped once; only token counts repeat, so the corpus ratio stays honest.
    pub train_max_reps: u64,
}

impl Default for Params {
    fn default() -> Self {
        Params {
            strength: 1.0,
            unknown_prob: 0.5,
            max_interesting: 150,
            threshold: 0.5,
            good_bias: 1.0,
            min_word_count: 0,
            combine_mode: CombineMode::Fisher,
            new_word_score: 0.5,
            min_distance: 0.0,
            min_array_size: 0,
            train_max_reps: 1,
        }
    }
}

impl Params {
    /// Load per-user overrides from `<db_dir>/params.toml`. Unknown keys are
    /// ignored. Missing file is silently treated as defaults. Parse errors
    /// emit a warning but fall back to defaults — never break delivery.
    ///
    /// File format is intentionally simple key=value:
    ///
    /// ```text
    /// # comments allowed
    /// strength = 0.5
    /// unknown_prob = 0.45
    /// max_interesting = 50
    /// threshold = 0.7
    /// good_bias = 1.0
    /// min_word_count = 0
    /// combine_mode = geometric   # fisher (default) | geometric
    /// new_word_score = 0.3
    /// min_distance = 0.1
    /// min_array_size = 15
    /// train_max_reps = 5
    /// ```
    pub fn load_overrides(&mut self, db_dir: &std::path::Path) {
        let path = db_dir.join("params.toml");
        let body = match std::fs::read_to_string(&path) {
            Ok(s) => s,
            Err(_) => return,
        };
        for (lineno, raw) in body.lines().enumerate() {
            let line = raw.split('#').next().unwrap_or("").trim();
            if line.is_empty() {
                continue;
            }
            let Some((k, v)) = line.split_once('=') else {
                eprintln!(
                    "spamlite: {}:{}: expected key = value, got {raw:?}",
                    path.display(),
                    lineno + 1
                );
                continue;
            };
            let k = k.trim();
            let v = v.trim();
            let parse_f = |v: &str, field: &str| {
                v.parse::<f64>().map_err(|e| {
                    eprintln!(
                        "spamlite: {}:{}: {field}: bad number {v:?}: {e}",
                        path.display(),
                        lineno + 1
                    );
                })
            };
            let parse_u = |v: &str, field: &str| {
                v.parse::<u64>().map_err(|e| {
                    eprintln!(
                        "spamlite: {}:{}: {field}: bad integer {v:?}: {e}",
                        path.display(),
                        lineno + 1
                    );
                })
            };
            // Range guards: an out-of-range value is rejected (default kept),
            // not clamped — silently "repairing" a corrupt file hides the
            // problem. Out-of-range params don't crash the classifier but they
            // produce nonsense scores that fail open, which is worse than
            // ignoring the file.
            let reject = |field: &str, v: &str, range: &str| {
                eprintln!(
                    "spamlite: {}:{}: {field} = {v} out of range ({range}); keeping default",
                    path.display(),
                    lineno + 1
                );
            };
            match k {
                "strength" => {
                    if let Ok(x) = parse_f(v, k) {
                        if (0.0..=100.0).contains(&x) {
                            self.strength = x;
                        } else {
                            reject(k, v, "0.0..=100.0");
                        }
                    }
                }
                "unknown_prob" => {
                    if let Ok(x) = parse_f(v, k) {
                        if (0.0..=1.0).contains(&x) {
                            self.unknown_prob = x;
                        } else {
                            reject(k, v, "0.0..=1.0");
                        }
                    }
                }
                "max_interesting" => {
                    if let Ok(x) = parse_u(v, k) {
                        if (1..=10_000).contains(&x) {
                            self.max_interesting = x as usize;
                        } else {
                            reject(k, v, "1..=10000");
                        }
                    }
                }
                "threshold" => {
                    if let Ok(x) = parse_f(v, k) {
                        if (0.0..=1.0).contains(&x) {
                            self.threshold = x;
                        } else {
                            reject(k, v, "0.0..=1.0");
                        }
                    }
                }
                "good_bias" => {
                    if let Ok(x) = parse_f(v, k) {
                        if x > 0.0 && x <= 100.0 {
                            self.good_bias = x;
                        } else {
                            reject(k, v, ">0.0..=100.0");
                        }
                    }
                }
                "min_word_count" => {
                    if let Ok(x) = parse_u(v, k) {
                        if x <= 1_000_000 {
                            self.min_word_count = x;
                        } else {
                            reject(k, v, "0..=1000000");
                        }
                    }
                }
                "combine_mode" => match v.to_ascii_lowercase().as_str() {
                    "fisher" => self.combine_mode = CombineMode::Fisher,
                    "geometric" | "geo" | "robinson" => self.combine_mode = CombineMode::Geometric,
                    _ => reject(k, v, "fisher|geometric"),
                },
                "new_word_score" => {
                    if let Ok(x) = parse_f(v, k) {
                        if (0.0..=1.0).contains(&x) {
                            self.new_word_score = x;
                        } else {
                            reject(k, v, "0.0..=1.0");
                        }
                    }
                }
                "min_distance" => {
                    if let Ok(x) = parse_f(v, k) {
                        if (0.0..=0.5).contains(&x) {
                            self.min_distance = x;
                        } else {
                            reject(k, v, "0.0..=0.5");
                        }
                    }
                }
                "min_array_size" => {
                    if let Ok(x) = parse_u(v, k) {
                        if x <= 10_000 {
                            self.min_array_size = x as usize;
                        } else {
                            reject(k, v, "0..=10000");
                        }
                    }
                }
                "train_max_reps" => {
                    if let Ok(x) = parse_u(v, k) {
                        if (1..=25).contains(&x) {
                            self.train_max_reps = x;
                        } else {
                            reject(k, v, "1..=25");
                        }
                    }
                }
                _ => eprintln!(
                    "spamlite: {}:{}: unknown key {k:?} (ignored)",
                    path.display(),
                    lineno + 1
                ),
            }
        }
    }
}

/// Per-token spam probability f(w) for a token KNOWN to the DB with the given
/// counts. Unknown tokens use `params.new_word_score` directly at the call site.
/// This is the single authoritative per-token formula — `classify`,
/// `classify_from_counts` and `classify_explain` all route through it so they
/// can never drift.
fn score_token(good: u64, spam: u64, total_good: f64, total_spam: f64, p: &Params) -> f64 {
    let n = good + spam;
    if n < p.min_word_count {
        return p.new_word_score;
    }
    let pw = spam as f64 / total_spam;
    let qw = good as f64 / total_good;
    let denom = pw + p.good_bias * qw;
    let raw_p = if denom > 0.0 { pw / denom } else { 0.5 };
    let nf = n as f64;
    // Robinson's Bayesian correction toward the centre `unknown_prob`.
    (p.strength * p.unknown_prob + nf * raw_p) / (p.strength + nf)
}

/// Given probabilities already sorted by descending distance from 0.5 and
/// truncated to `max_interesting`, return how many to keep after the optional
/// min-distance floor (spamprobe `removeTokensBelowMinDistance`). Keeps at least
/// `min_array_size` even when entries fall below the floor.
fn min_distance_keep(sorted: &[f64], p: &Params) -> usize {
    if p.min_distance <= 0.0 {
        return sorted.len();
    }
    match sorted.iter().position(|&f| (f - 0.5).abs() < p.min_distance) {
        Some(pos) => pos.max(p.min_array_size).min(sorted.len()),
        None => sorted.len(),
    }
}

/// Select the interesting token set: indices of `fws` sorted by descending
/// distance from 0.5, truncated to `max_interesting`, then the min-distance
/// floor. Returning INDICES (not values) is what lets `classify` and
/// `classify_explain` share this selection verbatim — explain maps the same
/// indices back to per-token detail, so the two can never drift.
fn select_interesting_indices(fws: &[f64], params: &Params) -> Vec<usize> {
    let mut idx: Vec<usize> = (0..fws.len()).collect();
    idx.sort_by(|&a, &b| {
        let da = (fws[a] - 0.5).abs();
        let db = (fws[b] - 0.5).abs();
        db.total_cmp(&da)
    });
    idx.truncate(params.max_interesting);
    let sorted: Vec<f64> = idx.iter().map(|&i| fws[i]).collect();
    let keep = min_distance_keep(&sorted, params);
    idx.truncate(keep);
    idx
}

/// Result of combining per-token probabilities into a message score. The Fisher
/// intermediates (`h_*`, `p_*`) are populated only in Fisher mode; in Geometric
/// mode `h_spam`/`h_ham` carry the spamness/goodness nth-roots and `p_*` are 0.
struct Combined {
    score: f64,
    h_spam: f64,
    h_ham: f64,
    p_spam: f64,
    p_ham: f64,
}

/// Combine selected per-token probabilities into a final spam score per
/// `params.combine_mode`. `fws` must be non-empty.
fn combine(fws: &[f64], params: &Params) -> Combined {
    let n = fws.len();
    match params.combine_mode {
        CombineMode::Fisher => {
            let h_spam: f64 =
                -2.0 * fws.iter().map(|&f| (1.0 - f).max(1e-200).ln()).sum::<f64>();
            let h_ham: f64 = -2.0 * fws.iter().map(|&f| f.max(1e-200).ln()).sum::<f64>();
            let p_spam = 1.0 - chi2_survival(h_spam, 2 * n);
            let p_ham = 1.0 - chi2_survival(h_ham, 2 * n);
            let score = ((1.0 + p_spam - p_ham) / 2.0).clamp(0.0, 1.0);
            Combined { score, h_spam, h_ham, p_spam, p_ham }
        }
        CombineMode::Geometric => {
            // nth-root geometric mean via exp(mean(ln f)) for numerical stability
            // (a raw product of hundreds of sub-1.0 terms underflows). Each f is
            // clamped to [MIN_PROB, MAX_PROB] so one extreme token can't force the
            // score to 0/1 — spamprobe's `normalScoreMessage` anti-saturation.
            let nf = n as f64;
            let mut log_s = 0.0;
            let mut log_g = 0.0;
            for &f in fws {
                let f = f.clamp(MIN_PROB, MAX_PROB);
                log_s += f.ln();
                log_g += (1.0 - f).ln();
            }
            let spamness = (log_s / nf).exp();
            let goodness = (log_g / nf).exp();
            let denom = spamness + goodness;
            let score = if denom > 0.0 {
                (spamness / denom).clamp(0.0, 1.0)
            } else {
                0.5
            };
            Combined { score, h_spam: spamness, h_ham: goodness, p_spam: 0.0, p_ham: 0.0 }
        }
    }
}

/// Outcome of the shared classification core: the selected interesting
/// indices into the caller's `fws` slice, the combined result, and the
/// thresholded verdict.
struct Scored {
    selected: Vec<usize>,
    combined: Combined,
    verdict: Verdict,
}

/// The single classification tail shared by `classify`, `classify_from_counts`
/// and `classify_explain`: select the interesting set, combine, threshold.
/// Returns `None` when nothing survives selection — callers fall back to a
/// neutral GOOD 0.5. Sharing this (and `score_token` for the per-token step)
/// makes agreement between the three entry points structural rather than a
/// convention enforced by comments.
fn score_fws(fws: &[f64], params: &Params) -> Option<Scored> {
    let selected = select_interesting_indices(fws, params);
    if selected.is_empty() {
        return None;
    }
    let chosen: Vec<f64> = selected.iter().map(|&i| fws[i]).collect();
    let combined = combine(&chosen, params);
    let verdict = if combined.score >= params.threshold {
        Verdict::Spam
    } else {
        Verdict::Good
    };
    Some(Scored {
        selected,
        combined,
        verdict,
    })
}

/// Classify a set of tokens against the database.
/// Returns (verdict, score) where score is 0.0 (definitely good) to 1.0 (definitely spam).
pub fn classify(
    db: &Database,
    token_words: &[String],
    params: &Params,
) -> rusqlite::Result<(Verdict, f64)> {
    let total_good = db.total_good()? as f64;
    let total_spam = db.total_spam()? as f64;

    // Need at least some training data
    if total_good < 1.0 && total_spam < 1.0 {
        return Ok((Verdict::Good, 0.5));
    }

    // Use 1.0 as minimum to avoid division by zero
    let total_good = total_good.max(1.0);
    let total_spam = total_spam.max(1.0);

    // Per-token probability for every message token (known → formula, unknown →
    // new_word_score), then the shared select/combine/threshold tail.
    let known = db.lookup_tokens(token_words)?;
    let fws: Vec<f64> = token_words
        .iter()
        .map(|word| match known.get(word.as_str()) {
            Some(&(good, spam)) => score_token(good, spam, total_good, total_spam, params),
            None => params.new_word_score,
        })
        .collect();

    Ok(match score_fws(&fws, params) {
        Some(s) => (s.verdict, s.combined.score),
        None => (Verdict::Good, 0.5),
    })
}

/// One message represented as the per-token (good_count, spam_count) pairs
/// already fetched from the database. `None` means the token is unknown.
/// Used by `spamlite-tune` to sweep parameters in memory without re-hitting
/// the database for every combination — the SQL phase costs ~ms/message and
/// dominates a parameter sweep otherwise.
pub type CountedTokens = Vec<Option<(u64, u64)>>;

/// Compute spam probability from already-fetched per-token (good, spam) counts.
/// Math is identical to `classify`'s inner loop — the only difference is that
/// the SQL lookup has been hoisted out so this function runs in pure CPU time.
/// If `classify_from_counts` and `classify` ever drift, `classify` is the
/// authoritative implementation.
pub fn classify_from_counts(
    counts: &CountedTokens,
    total_good: u64,
    total_spam: u64,
    params: &Params,
) -> (Verdict, f64) {
    if total_good < 1 && total_spam < 1 {
        return (Verdict::Good, 0.5);
    }
    let total_good = (total_good as f64).max(1.0);
    let total_spam = (total_spam as f64).max(1.0);

    let fws: Vec<f64> = counts
        .iter()
        .map(|c| match *c {
            Some((good, spam)) => score_token(good, spam, total_good, total_spam, params),
            None => params.new_word_score,
        })
        .collect();

    match score_fws(&fws, params) {
        Some(s) => (s.verdict, s.combined.score),
        None => (Verdict::Good, 0.5),
    }
}

/// One token's contribution to a classification decision, as returned by
/// `classify_explain`. `fw` is the Robinson-corrected spam probability
/// (0.0 = definitely ham, 1.0 = definitely spam, 0.5 = uninformative).
#[derive(Debug, Clone)]
pub struct TokenDetail {
    pub word: String,
    pub good: u64,
    pub spam: u64,
    pub fw: f64,
}

/// Full breakdown of a classification decision, returned by `classify_explain`.
/// Intended for debugging individual messages — e.g. why a balanced-corpus
/// user gets false positives on specific messages. Do not call from the sieve
/// hot path; use `classify` instead.
#[derive(Debug)]
pub struct Explanation {
    pub verdict: Verdict,
    pub score: f64,
    pub total_good: u64,
    pub total_spam: u64,
    pub msg_tokens: usize,
    pub known_tokens: usize,
    /// Interesting tokens (farthest from 0.5), sorted by distance descending,
    /// truncated to `params.max_interesting`. Excludes unknown tokens — their
    /// `fw` is always `unknown_prob` and they contribute zero discrimination.
    pub top_tokens: Vec<TokenDetail>,
    pub h_spam: f64,
    pub h_ham: f64,
    pub p_spam: f64,
    pub p_ham: f64,
}

/// Like `classify`, but retains per-token detail for debugging. Returns an
/// `Explanation` with the full breakdown. The per-token probabilities come
/// from the same `score_token` and the select/combine/threshold tail is the
/// same `score_fws` that `classify` uses, so the two agree by construction.
pub fn classify_explain(
    db: &Database,
    token_words: &[String],
    params: &Params,
) -> rusqlite::Result<Explanation> {
    let total_good_raw = db.total_good()?;
    let total_spam_raw = db.total_spam()?;

    let neutral = |total_good, total_spam, known_tokens| Explanation {
        verdict: Verdict::Good,
        score: 0.5,
        total_good,
        total_spam,
        msg_tokens: token_words.len(),
        known_tokens,
        top_tokens: Vec::new(),
        h_spam: 0.0,
        h_ham: 0.0,
        p_spam: 0.0,
        p_ham: 0.0,
    };

    if total_good_raw < 1 && total_spam_raw < 1 {
        return Ok(neutral(0, 0, 0));
    }
    let total_good = (total_good_raw as f64).max(1.0);
    let total_spam = (total_spam_raw as f64).max(1.0);

    let known = db.lookup_tokens(token_words)?;
    let known_count = known.len();

    // One fw per input token — identical to `classify` — plus a parallel
    // detail slot for display. Unknown tokens and known tokens below the
    // `min_word_count` gate contribute `new_word_score` with no detail
    // (there is nothing useful to show for a fallback probability).
    let mut fws: Vec<f64> = Vec::with_capacity(token_words.len());
    let mut details: Vec<Option<TokenDetail>> = Vec::with_capacity(token_words.len());
    for word in token_words {
        match known.get(word.as_str()) {
            Some(&(good, spam)) if good + spam >= params.min_word_count => {
                let fw = score_token(good, spam, total_good, total_spam, params);
                fws.push(fw);
                details.push(Some(TokenDetail {
                    word: word.clone(),
                    good,
                    spam,
                    fw,
                }));
            }
            _ => {
                fws.push(params.new_word_score);
                details.push(None);
            }
        }
    }

    let Some(s) = score_fws(&fws, params) else {
        return Ok(neutral(total_good_raw, total_spam_raw, known_count));
    };

    // For display, map the selected indices back to their known-token details,
    // in selection order (most interesting first). Unknowns are skipped —
    // they'd clutter the output at a constant fallback probability.
    let top_tokens: Vec<TokenDetail> = s
        .selected
        .iter()
        .filter_map(|&i| details[i].take())
        .collect();

    Ok(Explanation {
        verdict: s.verdict,
        score: s.combined.score,
        total_good: total_good_raw,
        total_spam: total_spam_raw,
        msg_tokens: token_words.len(),
        known_tokens: known_count,
        top_tokens,
        h_spam: s.combined.h_spam,
        h_ham: s.combined.h_ham,
        p_spam: s.combined.p_spam,
        p_ham: s.combined.p_ham,
    })
}

/// Chi-squared survival function (upper tail, `P(X > x)`) — NOT the CDF,
/// despite the old name. For even `df` this is the closed-form series
/// `exp(-x/2) * Σ (x/2)^i / i!` — exact, no approximation needed.
fn chi2_survival(x: f64, df: usize) -> f64 {
    if df < 2 || x <= 0.0 {
        return if x <= 0.0 { 1.0 } else { 0.0 };
    }
    let m = x / 2.0;
    let mut sum = (-m).exp();
    let mut term = sum;
    for i in 1..=(df / 2 - 1) {
        term *= m / i as f64;
        sum += term;
    }
    sum.min(1.0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    fn setup_db() -> Database {
        let db = Database::open(Path::new(":memory:")).unwrap();
        // Train some good messages
        for _ in 0..10 {
            db.inc_total_good().unwrap();
        }
        let good_words: Vec<String> = vec![
            "h:subject:meeting".into(),
            "h:subject:tomorrow".into(),
            "b:agenda".into(),
            "b:discuss".into(),
            "h:from:colleague@work.com".into(),
        ];
        for _ in 0..10 {
            db.train(&good_words, false).unwrap();
        }

        // Train some spam messages
        for _ in 0..10 {
            db.inc_total_spam().unwrap();
        }
        let spam_words: Vec<String> = vec![
            "h:subject:buy".into(),
            "h:subject:now".into(),
            "b:viagra".into(),
            "b:discount".into(),
            "u:http://spamsite.com".into(),
        ];
        for _ in 0..10 {
            db.train(&spam_words, true).unwrap();
        }

        db
    }

    #[test]
    fn test_classify_spam() {
        let db = setup_db();
        let params = Params::default();
        let spam_msg: Vec<String> = vec![
            "h:subject:buy".into(),
            "h:subject:now".into(),
            "b:viagra".into(),
            "b:discount".into(),
        ];
        let (verdict, score) = classify(&db, &spam_msg, &params).unwrap();
        assert_eq!(verdict, Verdict::Spam);
        assert!(score > 0.8, "score was {score}");
    }

    #[test]
    fn test_classify_good() {
        let db = setup_db();
        let params = Params::default();
        let good_msg: Vec<String> = vec![
            "h:subject:meeting".into(),
            "h:subject:tomorrow".into(),
            "b:agenda".into(),
            "b:discuss".into(),
        ];
        let (verdict, score) = classify(&db, &good_msg, &params).unwrap();
        assert_eq!(verdict, Verdict::Good);
        assert!(score < 0.2, "score was {score}");
    }

    #[test]
    fn test_classify_empty_db() {
        let db = Database::open(Path::new(":memory:")).unwrap();
        let params = Params::default();
        let tokens: Vec<String> = vec!["b:hello".into()];
        let (verdict, score) = classify(&db, &tokens, &params).unwrap();
        assert_eq!(verdict, Verdict::Good);
        assert!((score - 0.5).abs() < 0.01);
    }

    #[test]
    fn test_classify_explain_matches_classify() {
        let db = setup_db();
        let params = Params::default();
        let msgs: Vec<Vec<String>> = vec![
            vec![
                "h:subject:buy".into(),
                "h:subject:now".into(),
                "b:viagra".into(),
                "b:discount".into(),
            ],
            vec![
                "h:subject:meeting".into(),
                "b:agenda".into(),
                "b:discuss".into(),
            ],
            vec!["b:totally_unknown".into(), "b:another_unknown".into()],
        ];
        for msg in msgs {
            let (v1, s1) = classify(&db, &msg, &params).unwrap();
            let expl = classify_explain(&db, &msg, &params).unwrap();
            assert_eq!(v1, expl.verdict, "verdict mismatch for {msg:?}");
            assert!(
                (s1 - expl.score).abs() < 1e-9,
                "score mismatch for {msg:?}: classify={s1} explain={}",
                expl.score
            );
        }
    }

    #[test]
    fn test_classify_explain_retains_token_details() {
        let db = setup_db();
        let params = Params::default();
        let msg: Vec<String> = vec![
            "b:viagra".into(),
            "b:discount".into(),
            "b:never_seen".into(),
        ];
        let expl = classify_explain(&db, &msg, &params).unwrap();
        assert_eq!(expl.msg_tokens, 3);
        assert_eq!(expl.known_tokens, 2); // "b:never_seen" is unknown
        assert_eq!(expl.top_tokens.len(), 2);
        for tok in &expl.top_tokens {
            assert!(tok.spam > 0 || tok.good > 0);
            assert!(tok.word == "b:viagra" || tok.word == "b:discount");
        }
    }

    #[test]
    fn test_load_overrides_rejects_out_of_range() {
        let dir = std::env::temp_dir().join(format!("spamlite-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("params.toml"),
            "strength = -1.0\nunknown_prob = 2.0\nthreshold = 5.0\ngood_bias = 0.0\nmax_interesting = 0\nmin_word_count = 99\n",
        )
        .unwrap();
        let mut p = Params::default();
        p.load_overrides(&dir);
        // All out-of-range values rejected — defaults kept
        assert_eq!(p.strength, 1.0);
        assert_eq!(p.unknown_prob, 0.5);
        assert_eq!(p.threshold, 0.5);
        assert_eq!(p.good_bias, 1.0);
        assert_eq!(p.max_interesting, 150);
        // In-range value accepted
        assert_eq!(p.min_word_count, 99);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn test_chi2_survival() {
        // For df=2, chi2_survival(x, 2) = exp(-x/2)
        let result = chi2_survival(2.0, 2);
        let expected = (-1.0_f64).exp();
        assert!((result - expected).abs() < 1e-10);
    }

    #[test]
    fn test_geometric_combine_no_saturation() {
        // The core fix: a uniform field of weakly-spammy tokens saturates under
        // Fisher (→1.0, unretrainable) but the geometric mean stays put — exactly
        // the supplier-FP failure mode. spamprobe's normalScoreMessage property.
        let mut p = Params::default();
        let fws = vec![0.7_f64; 100];

        p.combine_mode = CombineMode::Fisher;
        let fisher = combine(&fws, &p).score;
        assert!(fisher > 0.95, "Fisher should saturate high, got {fisher}");

        p.combine_mode = CombineMode::Geometric;
        let geo = combine(&fws, &p).score;
        assert!((geo - 0.7).abs() < 1e-6, "geometric should stay ~0.7, got {geo}");

        // Scale-invariance: same score at 20 and 200 tokens.
        let geo_20 = combine(&[0.7_f64; 20], &p).score;
        let geo_200 = combine(&vec![0.7_f64; 200], &p).score;
        assert!((geo_20 - geo_200).abs() < 1e-9);
    }

    #[test]
    fn test_geometric_single_extreme_token_clamped() {
        // One f=1.0 token among weak-ham tokens must NOT pin the score to 1.0
        // under geometric (the clamp). Under Fisher it would dominate.
        let p = Params {
            combine_mode: CombineMode::Geometric,
            ..Default::default()
        };
        let mut fws = vec![0.3_f64; 50];
        fws.push(1.0);
        let geo = combine(&fws, &p).score;
        assert!(geo < 0.6, "one extreme token must not saturate geometric, got {geo}");
    }

    #[test]
    fn test_min_word_count_gate_uses_new_word_score() {
        let p = Params {
            min_word_count: 5,
            new_word_score: 0.3,
            ..Default::default()
        };
        // 1 observation → below gate → ham-leaning new_word_score
        assert!((score_token(0, 1, 100.0, 100.0, &p) - 0.3).abs() < 1e-9);
        // 10 observations → real formula (spam-leaning here)
        assert!(score_token(0, 10, 100.0, 100.0, &p) > 0.5);
    }

    #[test]
    fn test_min_distance_keeps_min_array_size() {
        let mut p = Params {
            min_distance: 0.2,
            min_array_size: 3,
            ..Default::default()
        };
        // sorted by distance desc: two strong, rest near 0.5
        let sorted = vec![0.95, 0.9, 0.52, 0.51, 0.5];
        // first below-distance (|f-0.5|<0.2) is index 2; keep max(2,3)=3
        assert_eq!(min_distance_keep(&sorted, &p), 3);
        // floor off → keep all
        p.min_distance = 0.0;
        assert_eq!(min_distance_keep(&sorted, &p), 5);
    }
}
