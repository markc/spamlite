# Algorithm Design: Robinson-Fisher Bayesian Classification

## Why Robinson-Fisher (not plain Naive Bayes)

Paul Graham's original 2002 "A Plan for Spam" used naive Bayes product combining.
Gary Robinson improved this in two critical ways:

1. **Bayesian confidence correction** — prevents rare tokens from dominating
2. **Chi-squared combining** — statistically robust, handles varying token counts

Both bogofilter and SpamAssassin use Robinson-Fisher. spamprobe uses a variant
of Robinson's approach. This is the proven production algorithm.

## Step 1: Token Probability

For each token `w` in the message:

```
pw = spam_count(w) / total_spam
qw = good_count(w) / total_good
raw_p(w) = pw / (pw + qw)
```

## Step 2: Robinson's Confidence Correction

Rare tokens (seen 1-2 times) shouldn't have the same weight as tokens seen
thousands of times. Robinson's correction:

```
f(w) = (s * x + n * raw_p(w)) / (s + n)
```

Where:
- `s` = strength parameter (typically 1.0)
- `x` = assumed probability for unknown tokens (0.5 = neutral)
- `n` = total times token was seen (good_count + spam_count)

When `n` is small, `f(w)` stays close to 0.5 (uncertain).
When `n` is large, `f(w)` approaches the raw probability.

**This is why spamlite works from the start:** even with a small database,
tokens that ARE present pull the score, while unknown tokens contribute 0.5
(neutral), not noise. As the database grows, more tokens contribute meaningful
probabilities.

## Step 3: Select Interesting Tokens

From all message tokens, select the N most "interesting" — those whose
`f(w)` is furthest from 0.5 in either direction.

spamprobe uses N=27, bogofilter uses N=252. The optimal value depends on
tokenization strategy. Start with N=150 and tune.

## Step 4: Fisher's Chi-Squared Combining

Compute two hypotheses:

```
H_spam = -2 * sum(ln(1 - f(w)))  for all interesting tokens
H_ham  = -2 * sum(ln(f(w)))      for all interesting tokens
```

Convert to probabilities using inverse chi-squared CDF:

```
P_spam = 1 - chi2_cdf(H_spam, 2 * n_tokens)
P_ham  = 1 - chi2_cdf(H_ham, 2 * n_tokens)
```

Final score:

```
score = (1 + P_spam - P_ham) / 2
```

- score > 0.9 → SPAM
- score < 0.1 → GOOD
- between → UNSURE

## The chi-squared inverse CDF

This is the only "math" in the entire algorithm. It's a simple series:

```rust
fn chi2_cdf(x: f64, df: usize) -> f64 {
    let m = x / 2.0;
    let mut sum = (-m).exp();
    let mut term = sum;
    for i in 1..=(df / 2 - 1) {
        term *= m / i as f64;
        sum += term;
    }
    sum.min(1.0)
}
```

~10 lines of Rust. The entire scoring engine is ~100-150 lines.

## Thresholds and Tuning

| Parameter | spamprobe | bogofilter | spamlite (initial) |
|-----------|-----------|------------|-------------------|
| Spam threshold | 0.9 | 0.99 | 0.9 |
| Ham threshold | 0.1 | 0.01 | 0.1 |
| Interesting tokens | 27 | 252 | 150 |
| Strength (s) | 1.0 | 0.45 | 1.0 |
| Unknown prob (x) | 0.4 | 0.42 | 0.5 |
| Min token length | 3 | 3 | 3 |
| Max token length | 40 | 30 | 40 |

These should be configurable via command-line flags and/or config file.
Tune against real mail corpora (export from existing spamprobe databases).

## Tokenization Strategy

### Location prefixing (from gonzofilter — proven to improve accuracy)

```
h:subject:meeting tomorrow     # Subject header tokens
h:from:john@example.com       # From header
h:received:google.com         # Received chain
b:click here now              # Body tokens
u:http://spamsite.com/offer   # URLs extracted from HTML
```

Subject and From headers are the most discriminative. Body tokens are noisier.
URL tokens catch phishing/spam domains.

### Bigrams for subject line

Single tokens miss context. "Make money fast" as individual words is ambiguous.
As bigrams: `h:subject:make_money`, `h:subject:money_fast` — highly discriminative.

### What NOT to tokenize

- Message-IDs, boundaries, content-type parameters
- Dates and timestamps
- Very common words (the, is, and) — handled by Robinson's correction naturally
- Base64-encoded attachment content (except filenames)
