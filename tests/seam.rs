// Copyright 2026 Mark Constable <mc@netserva.org>
// SPDX-License-Identifier: MIT

use spamlite::classifier::{self, Params as AliasParams};
use spamlite::scoring::{
    classify, classify_explain, classify_from_counts, classify_tokens, score_token, CombineMode,
    Params, Verdict,
};
use spamlite::storage::Database;
use std::collections::HashMap;
use std::path::Path;

struct Lcg(u64);

impl Lcg {
    fn next(&mut self) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        self.0
    }

    fn below(&mut self, upper: usize) -> usize {
        (self.next() as usize) % upper
    }
}

fn random_tokens(rng: &mut Lcg, vocab: &[String], max_len: usize) -> Vec<String> {
    let mut tokens = Vec::new();
    for _ in 0..rng.below(max_len + 1) {
        tokens.push(vocab[rng.below(vocab.len())].clone());
    }
    tokens.sort_unstable();
    tokens.dedup();
    tokens
}

fn params_variants() -> Vec<Params> {
    vec![
        Params::default(),
        Params {
            combine_mode: CombineMode::Geometric,
            ..Default::default()
        },
        Params {
            min_word_count: 3,
            ..Default::default()
        },
        Params {
            min_distance: 0.1,
            min_array_size: 5,
            ..Default::default()
        },
        Params {
            rail: true,
            ..Default::default()
        },
    ]
}

#[test]
fn classifier_compatibility_alias_compiles() {
    let params = AliasParams::default();
    assert_eq!(params.threshold.to_bits(), 0.5_f64.to_bits());
    assert_eq!(classifier::Verdict::Good.to_string(), "GOOD");
}

#[test]
fn duplicated_and_zero_count_tokens_match_counts_seam() {
    let message = vec![
        "b:word01".to_string(),
        "b:word01".to_string(),
        "b:word05".to_string(),
        "b:absent".to_string(),
    ];
    let known = HashMap::from([
        ("b:word01".to_string(), (2, 8)),
        ("b:word05".to_string(), (0, 0)),
    ]);
    let total_good = 10;
    let total_spam = 10;
    let params = Params {
        unknown_prob: 0.37,
        new_word_score: 0.71,
        ..Default::default()
    };
    let classified = classify_tokens(&message, &known, total_good, total_spam, &params);
    let counts = message.iter().map(|t| known.get(t).copied()).collect();
    let counted = classify_from_counts(&counts, total_good, total_spam, &params);

    assert_eq!(classified.score.to_bits(), counted.1.to_bits());
    assert_eq!(classified.fws.len(), message.len());
    let zero_count_fw = score_token(0, 0, total_good as f64, total_spam as f64, &params);
    assert_eq!(classified.fws[2].to_bits(), zero_count_fw.to_bits());
    assert_eq!(zero_count_fw.to_bits(), params.unknown_prob.to_bits());
    assert_eq!(classified.fws[3].to_bits(), params.new_word_score.to_bits());
}

#[test]
fn classify_database_and_pure_seam_are_bit_identical() -> rusqlite::Result<()> {
    let mut rng = Lcg(0x5eed_f00d_dead_beef);
    let vocab: Vec<String> = (0..32).map(|i| format!("b:word{i:02}")).collect();

    for pair in 0..200 {
        let db = Database::open(Path::new(":memory:"))?;
        if pair % 10 != 0 {
            for _ in 0..(1 + rng.below(12)) {
                let training = random_tokens(&mut rng, &vocab, 12);
                db.train_message(&training, rng.below(2) == 0)?;
            }
            if pair % 2 == 0 {
                let abuse = vec!["x:tld:life".to_string()];
                db.train_message(&abuse, true)?;
                db.train_message(&abuse, true)?;
            }
        }

        let mut message = random_tokens(&mut rng, &vocab, 16);
        message.push("x:tld:life".to_string());
        message.push("x:confusable".to_string());
        message.sort_unstable();
        message.dedup();

        let known = db.lookup_tokens(&message)?;
        let total_good = db.total_good()?;
        let total_spam = db.total_spam()?;
        for params in params_variants() {
            let via_db = classify(&db, &message, &params)?;
            let pure = classify_tokens(&message, &known, total_good, total_spam, &params);
            assert_eq!(via_db.0, pure.verdict, "pair {pair}");
            assert_eq!(via_db.1.to_bits(), pure.score.to_bits(), "pair {pair}");

            if !params.rail {
                let counts = message.iter().map(|t| known.get(t).copied()).collect();
                let count_score = classify_from_counts(&counts, total_good, total_spam, &params);
                assert_eq!(count_score.0, pure.verdict, "pair {pair}");
                assert_eq!(count_score.1.to_bits(), pure.score.to_bits(), "pair {pair}");
            }
        }
    }
    Ok(())
}

#[test]
fn explain_matches_classify_with_rail_and_empty_selection() -> rusqlite::Result<()> {
    let db = Database::open(Path::new(":memory:"))?;
    let abuse = vec!["x:tld:life".to_string()];
    db.train_message(&abuse, true)?;
    db.train_message(&abuse, true)?;
    let message = vec![
        "x:tld:life".to_string(),
        "x:confusable".to_string(),
        "b:unknown".to_string(),
    ];
    let params = Params {
        rail: true,
        min_distance: 0.5,
        min_array_size: 0,
        ..Default::default()
    };

    let classified = classify(&db, &message, &params)?;
    let explained = classify_explain(&db, &message, &params)?;
    assert_eq!(classified.0, Verdict::Spam);
    assert_eq!(classified.0, explained.verdict);
    assert_eq!(classified.1.to_bits(), explained.score.to_bits());
    assert!(explained.rail.is_some());
    assert!(explained.top_tokens.is_empty());
    Ok(())
}
