// Copyright 2026 Mark Constable <mc@netserva.org>
// SPDX-License-Identifier: MIT

use crate::storage::{Database, Token};

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

/// Tuning parameters for the Robinson-Fisher classifier
pub struct Params {
    /// Robinson strength parameter — how strongly we pull toward unknown_prob
    pub strength: f64,
    /// Assumed probability for unknown tokens
    pub unknown_prob: f64,
    /// Number of most interesting tokens to use
    pub max_interesting: usize,
    /// Score at or above which we classify as spam (default 0.5)
    pub threshold: f64,
}

impl Default for Params {
    fn default() -> Self {
        Params {
            strength: 1.0,
            unknown_prob: 0.5,
            max_interesting: 150,
            threshold: 0.5,
        }
    }
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

    // Lookup known tokens
    let known_tokens = db.lookup_tokens(token_words)?;

    // Build a map of word -> (good, spam)
    let known_map: std::collections::HashMap<&str, &Token> =
        known_tokens.iter().map(|t| (t.word.as_str(), t)).collect();

    // Calculate Robinson's corrected probability for each message token
    let mut probs: Vec<f64> = Vec::with_capacity(token_words.len());

    for word in token_words {
        let fw = if let Some(token) = known_map.get(word.as_str()) {
            let pw = token.spam as f64 / total_spam;
            let qw = token.good as f64 / total_good;
            let denom = pw + qw;
            let raw_p = if denom > 0.0 { pw / denom } else { 0.5 };

            let n = (token.good + token.spam) as f64;
            // Robinson's Bayesian correction
            (params.strength * params.unknown_prob + n * raw_p) / (params.strength + n)
        } else {
            // Unknown token — use unknown_prob
            params.unknown_prob
        };

        probs.push(fw);
    }

    // Select most interesting tokens (furthest from 0.5)
    let mut interesting: Vec<f64> = probs.clone();
    interesting.sort_by(|a, b| {
        let da = (a - 0.5).abs();
        let db = (b - 0.5).abs();
        db.partial_cmp(&da).unwrap_or(std::cmp::Ordering::Equal)
    });
    interesting.truncate(params.max_interesting);

    if interesting.is_empty() {
        return Ok((Verdict::Good, 0.5));
    }

    // Fisher's chi-squared combining
    let n = interesting.len();

    // H_spam = -2 * sum(ln(1 - f(w)))
    let h_spam: f64 = -2.0 * interesting.iter().map(|&f| (1.0 - f).max(1e-200).ln()).sum::<f64>();

    // H_ham = -2 * sum(ln(f(w)))
    let h_ham: f64 = -2.0 * interesting.iter().map(|&f| f.max(1e-200).ln()).sum::<f64>();

    // Inverse chi-squared CDF
    let p_spam = 1.0 - chi2_cdf(h_spam, 2 * n);
    let p_ham = 1.0 - chi2_cdf(h_ham, 2 * n);

    // Final score
    let score = (1.0 + p_spam - p_ham) / 2.0;
    let score = score.clamp(0.0, 1.0);

    let verdict = if score >= params.threshold {
        Verdict::Spam
    } else {
        Verdict::Good
    };

    Ok((verdict, score))
}

/// Chi-squared cumulative distribution function (survival function).
/// Simple series expansion — accurate for the degrees of freedom we use.
fn chi2_cdf(x: f64, df: usize) -> f64 {
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
    fn test_chi2_cdf() {
        // For df=2, chi2_cdf(x, 2) = exp(-x/2)
        let result = chi2_cdf(2.0, 2);
        let expected = (-1.0_f64).exp();
        assert!((result - expected).abs() < 1e-10);
    }
}
