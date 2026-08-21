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

/// Hard cap on message bytes read from stdin. Real mail is bounded well below
/// this by the MTA's message_size_limit; the cap only protects against a
/// misconfigured pipe feeding unbounded data. Truncation at this size does not
/// meaningfully affect classification — the discriminating tokens of any real
/// message appear long before 64 MiB.
const MAX_STDIN_BYTES: u64 = 64 * 1024 * 1024;

fn read_stdin() -> Vec<u8> {
    let mut buf = Vec::new();
    io::stdin()
        .take(MAX_STDIN_BYTES)
        .read_to_end(&mut buf)
        .unwrap_or_else(|e| {
            eprintln!("spamlite: failed to read stdin: {e}");
            process::exit(1);
        });
    if buf.len() as u64 == MAX_STDIN_BYTES {
        eprintln!("spamlite: stdin truncated at {MAX_STDIN_BYTES} bytes");
    }
    buf
}

/// Neutral verdict emitted when the sieve hot path fails open. A panic
/// anywhere in tokenize/classify must NOT abort the process: sieve captures
/// stdout, and an empty capture means the message is delivered unfiltered
/// with a logged exit 134 (exactly how the v0.2.0 CJK-URL tokenizer panic
/// presented in production for six weeks).
const FAIL_OPEN_VERDICT: &str = "GOOD 0.500000";

fn open_db() -> Database {
    let path = db_path();
    Database::open(&path).unwrap_or_else(|e| {
        eprintln!("spamlite: failed to open database {}: {e}", path.display());
        process::exit(1);
    })
}

/// Open for the read-only commands. Never creates the database — a mistyped `-d`
/// must be an error, not a silently-conjured empty corpus that scores every message
/// a neutral `GOOD 0.500000`. Returns Err so the caller decides: the sieve hot path
/// (`score`) fails open and delivers the message; the diagnostic commands exit 1.
fn open_db_ro() -> Result<Database, String> {
    Database::open_existing(&db_path())
}

/// Exit-1-on-missing wrapper for the diagnostic commands (counts/explain/export),
/// which have no delivery to protect and should fail loudly.
fn open_db_ro_or_exit() -> Database {
    open_db_ro().unwrap_or_else(|e| {
        eprintln!("spamlite: {e}");
        process::exit(1);
    })
}

/// Build runtime params. Threshold priority, weakest first:
/// compiled default < SPAMLITE_THRESHOLD env < `<db_dir>/params.toml`
/// per-user override < `-t` CLI flag. The env var is applied BEFORE the
/// per-user file so a wrapper exporting it cannot silently defeat per-user
/// thresholds the way a hardcoded `-t` does.
fn make_params() -> Params {
    let mut params = Params::default();
    if let Ok(val) = std::env::var("SPAMLITE_THRESHOLD") {
        if let Ok(t) = val.parse::<f64>() {
            if (0.0..=1.0).contains(&t) {
                params.threshold = t;
            }
        }
    }
    // Abuse-TLD hard-rail env flags. Applied BEFORE params.toml so a per-user
    // file can still override, mirroring the SPAMLITE_THRESHOLD precedence. All
    // default-off / default-value, so unset env = unchanged behaviour.
    // Same truthy/falsy vocabulary as params.toml's bool keys.
    let as_bool = |v: &str| -> Option<bool> {
        match v.to_ascii_lowercase().as_str() {
            "1" | "true" | "yes" | "on" => Some(true),
            "0" | "false" | "no" | "off" => Some(false),
            _ => None,
        }
    };
    if let Ok(val) = std::env::var("SPAMLITE_RAIL") {
        if let Some(b) = as_bool(&val) {
            params.rail = b;
        }
    }
    if let Ok(val) = std::env::var("SPAMLITE_RAIL_MIN_SPAM") {
        if let Ok(n) = val.parse::<u64>() {
            if (1..=1_000_000).contains(&n) {
                params.rail_min_spam = n;
            }
        }
    }
    if let Ok(val) = std::env::var("SPAMLITE_RAIL_STRONG_SPAM") {
        if let Ok(n) = val.parse::<u64>() {
            if (1..=1_000_000).contains(&n) {
                params.rail_strong_spam = n;
            }
        }
    }
    if let Ok(val) = std::env::var("SPAMLITE_RAIL_FLOOR") {
        if let Ok(f) = val.parse::<f64>() {
            if (0.5..=1.0).contains(&f) {
                params.rail_floor = f;
            }
        }
    }
    // SPAMLITE_RAIL_COFLAG=0/false/no/off relaxes the co-flag requirement (gate
    // lever). Default (unset) keeps the weak-tier co-flag mandatory.
    if let Ok(val) = std::env::var("SPAMLITE_RAIL_COFLAG") {
        if let Some(b) = as_bool(&val) {
            params.rail_require_coflag = b;
        }
    }
    if let Some(parent) = db_path().parent() {
        params.load_overrides(parent);
    }
    if let Some(&t) = THRESHOLD.get() {
        params.threshold = t;
    }
    params
}

fn cmd_score() {
    let raw = read_stdin();
    let result = std::panic::catch_unwind(move || {
        let tokens = tokenizer::tokenize_env(&raw);
        // A missing db is now an error rather than an empty one conjured on the spot.
        // Fail open: deliver the message unfiltered and say so loudly, exactly as for
        // a panic — never junk mail because the corpus went walkabout.
        let db = open_db_ro().map_err(|e| {
            eprintln!("spamlite: {e} (fail-open, message delivered unfiltered)");
            e
        })?;
        let params = make_params();
        classifier::classify(&db, &tokens, &params).map_err(|e| e.to_string())
    });
    match result {
        Ok(Ok((verdict, score))) => print!("{verdict} {score:.6}"),
        Ok(Err(_)) => print!("{FAIL_OPEN_VERDICT}"),
        Err(_) => {
            eprintln!("spamlite: internal panic (fail-open, message scored neutral)");
            print!("{FAIL_OPEN_VERDICT}");
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
    let gate = TOE_GATE.get().copied().unwrap_or(TOE_GATE_DEFAULT);

    // Phase 1 — tokenize + classify, panic-isolated. Nothing is printed
    // inside the guarded region, so a fail-open can never double-print.
    let classified = std::panic::catch_unwind(move || {
        let tokens = tokenizer::tokenize_env(&raw);
        let db = open_db();
        let params = make_params();
        classifier::classify(&db, &tokens, &params).map(|(verdict, score)| {
            let is_spam = matches!(verdict, classifier::Verdict::Spam);
            (format!("{verdict} {score:.6}"), score, is_spam, tokens, db)
        })
    });

    let (output, score, is_spam, tokens, db) = match classified {
        Ok(Ok(parts)) => parts,
        Ok(Err(e)) => {
            eprintln!("spamlite: classification error (fail-open): {e}");
            print!("{FAIL_OPEN_VERDICT}");
            return;
        }
        Err(_) => {
            eprintln!("spamlite: internal panic (fail-open, message scored neutral)");
            print!("{FAIL_OPEN_VERDICT}");
            return;
        }
    };

    // The SPAM/GOOD score is printed BEFORE training runs, so the sieve
    // contract is preserved even if the training write fails.
    print!("{output}");

    // gate <= 0.0 means the trusted region is empty — training fully
    // disabled. Checked explicitly because a Fisher-saturated score of
    // exactly 0.0 or 1.0 falls OUTSIDE the open band below and would
    // otherwise still train, and saturated verdicts are precisely the ones
    // a read-only gate must not auto-train on.
    if gate <= 0.0 || (score > gate && score < (1.0 - gate)) {
        return;
    }

    // Phase 2 — confidence-gated training, also panic-isolated. The verdict
    // is already on stdout; a training panic must not turn rc 0 into SIGABRT.
    // train_message bumps token counts AND the message total in one
    // transaction, so a crash can't skew the corpus good/spam ratio.
    let trained = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        if let Err(e) = db.train_message(&tokens, is_spam) {
            eprintln!("spamlite: training error (non-fatal): {e}");
        }
    }));
    if trained.is_err() {
        eprintln!("spamlite: training panic (non-fatal, verdict already emitted)");
    }
}

fn cmd_train(is_spam: bool) {
    let raw = read_stdin();
    let tokens = tokenizer::tokenize_env(&raw);
    let db = open_db();
    let params = make_params();

    // First pass: token counts +1 AND the message total +1, atomically.
    if let Err(e) = db.train_message(&tokens, is_spam) {
        eprintln!("spamlite: training error: {e}");
        process::exit(1);
    }

    // Convergence (spamprobe TONE/TUNE, SpamFilter.cc:460-491): if configured,
    // re-add only the message's TOKEN counts — NOT the message total, so the
    // corpus good/spam ratio stays honest — until the message scores confidently
    // on the trained side, capped at train_max_reps. This is what makes one ham
    // retrain flip a stuck bulk-ESP sender. Bounded by the cap → no runaway
    // poisoning. Off by default (train_max_reps = 1).
    if params.train_max_reps > 1 {
        let confident = |score: f64| if is_spam { score >= 0.9 } else { score <= 0.1 };
        let mut reps = 1;
        while reps < params.train_max_reps {
            match classifier::classify(&db, &tokens, &params) {
                Ok((_, score)) if confident(score) => break,
                Ok(_) => {}
                Err(e) => {
                    eprintln!("spamlite: convergence score error (non-fatal): {e}");
                    break;
                }
            }
            if let Err(e) = db.train(&tokens, is_spam) {
                eprintln!("spamlite: convergence training error (non-fatal): {e}");
                break;
            }
            reps += 1;
        }
    }
}

/// explain = classify + verbose breakdown of top interesting tokens. Read-only.
/// Intended for debugging individual messages — e.g. "why is this ham scoring
/// as spam?" The output shows the Robinson-corrected probability f(w) for
/// each token that made the top-N interesting set, sorted most-interesting
/// first. A bar visualises direction (left = ham-indicative, right = spam).
fn cmd_explain() {
    let raw = read_stdin();
    let tokens = tokenizer::tokenize_env(&raw);
    let db = open_db_ro_or_exit();
    let params = make_params();

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
    if let Some(hit) = &expl.rail {
        let tier = if hit.strong { "strong" } else { "weak" };
        // State the floor value rather than claim the score was lowered — with a
        // score already above the floor `apply_rail` is a no-op (see Verdict line).
        println!(
            "Hard-rail: FIRED [{tier}] — {} (spam={}, good=0) + co-flag {}; floor={:.2}",
            hit.tld_token, hit.tld_spam, hit.co_flag, params.rail_floor
        );
    }
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
    let db = open_db_ro_or_exit();
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
    let db = open_db_ro_or_exit();
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

/// Remove the filter's own label headers (X-Spam-Status, X-SpamProbe — plus
/// their folded continuation lines) from a raw message before training. The
/// structured tokenizer never reads these headers, but the fallback tokenizer
/// for unparseable messages tokenizes ALL raw text — and a "SPAM"/"GOOD" label
/// stamped by a previous classification is exactly the label leak a trainer
/// must never learn from. Done in the binary so the safety rule cannot be
/// forgotten by a caller (it replaces the reconciler's reconcile-strip.awk).
fn strip_label_headers(raw: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(raw.len());
    let mut skipping = false;
    let mut in_headers = true;
    for line in raw.split_inclusive(|&b| b == b'\n') {
        if in_headers {
            let is_blank = line == b"\r\n" || line == b"\n";
            if is_blank {
                in_headers = false;
                skipping = false;
            } else if line[0] == b' ' || line[0] == b'\t' {
                // Folded continuation belongs to the previous header.
                if skipping {
                    continue;
                }
            } else {
                let lower: Vec<u8> = line
                    .iter()
                    .take(16)
                    .map(|b| b.to_ascii_lowercase())
                    .collect();
                skipping = lower.starts_with(b"x-spam-status:")
                    || lower.starts_with(b"x-spamprobe:");
                if skipping {
                    continue;
                }
            }
        }
        out.extend_from_slice(line);
    }
    out
}

/// Read one message file, bounded by the same cap as stdin. A file above the
/// cap is truncated with a warning (matching the stdin path) — the prefix
/// still carries the discriminating tokens of any real message.
fn read_message_file(path: &std::path::Path) -> io::Result<Vec<u8>> {
    let f = std::fs::File::open(path)?;
    let mut buf = Vec::new();
    f.take(MAX_STDIN_BYTES + 1).read_to_end(&mut buf)?;
    if buf.len() as u64 > MAX_STDIN_BYTES {
        buf.truncate(MAX_STDIN_BYTES as usize);
        eprintln!(
            "spamlite: {} truncated at {MAX_STDIN_BYTES} bytes",
            path.display()
        );
    }
    Ok(buf)
}

/// Directory scan result: regular message files (sorted), per-path stat
/// failures, and the count of unreadable directory entries (no name known).
struct DirScan {
    files: Vec<PathBuf>,
    stat_errors: Vec<(PathBuf, String)>,
    entry_errors: u64,
}

/// List the regular files directly inside `dir`, sorted by filename for a
/// deterministic report order. Subdirectories are NOT descended — the intended
/// input is a flat staging dir (or a Maildir cur/new), never a Maildir root.
/// Symlinks are followed (staging dirs are built from symlinks), so metadata
/// failures and unreadable entries are surfaced rather than silently dropped:
/// on a flaky mailstore a partial scan reported as complete would make the
/// caller mark unscanned messages as handled.
fn list_message_files(dir: &str) -> DirScan {
    let rd = match std::fs::read_dir(dir) {
        Ok(rd) => rd,
        Err(e) => {
            eprintln!("spamlite: cannot read directory {dir}: {e}");
            process::exit(1);
        }
    };
    let mut scan = DirScan {
        files: Vec::new(),
        stat_errors: Vec::new(),
        entry_errors: 0,
    };
    for entry in rd {
        let path = match entry {
            Ok(e) => e.path(),
            Err(_) => {
                scan.entry_errors += 1;
                continue;
            }
        };
        // fs::metadata follows symlinks — a staging symlink to a mail file
        // counts as a regular file. Non-file types (dirs, fifos) are skipped
        // by design; only a failed stat is an error.
        match std::fs::metadata(&path) {
            Ok(m) if m.is_file() => scan.files.push(path),
            Ok(_) => {}
            Err(e) => scan.stat_errors.push((path, e.to_string())),
        }
    }
    scan.files.sort();
    scan
}

/// Make a string safe as one TSV column: squeeze out tab/newline/CR, which
/// would otherwise let a hostile filename forge report rows.
fn tsv_safe(s: String) -> String {
    if s.contains(['\t', '\n', '\r']) {
        s.chars()
            .map(|c| if matches!(c, '\t' | '\n' | '\r') { '?' } else { c })
            .collect()
    } else {
        s
    }
}

/// Extract the Message-ID (without angle brackets) from raw message bytes,
/// with tabs/newlines squeezed out so it is always safe in a TSV column.
fn extract_msgid(raw: &[u8]) -> Option<String> {
    let parser = mail_parser::MessageParser::default();
    let message = parser.parse(raw)?;
    let id = message.message_id()?.trim().trim_matches(['<', '>']).to_string();
    let id: String = id.chars().filter(|c| !c.is_whitespace()).collect();
    if id.is_empty() {
        None
    } else {
        Some(id)
    }
}

/// train-dir = bulk-train every message file in a directory as ONE class.
/// Replaces the per-message exec loop (fork + db open + commit per message)
/// with a single process and one durable transaction per chunk of
/// `TRAIN_CHUNK` messages — chunking bounds memory (tokens are held only for
/// the current chunk; a directory of huge messages cannot balloon the
/// process) while keeping commits rare.
///
/// stdout: one TSV line per file — `ok\t<msgid|->\t<path>` for messages in a
/// committed chunk, `err\t<reason>\t<path>` for files that could not be read
/// or tokenized (excluded from the batch, never fatal). The msgid column is
/// the message's identity for dedupe purposes; the path column is
/// informational only (tab/newline sanitised, lossy for non-UTF-8 names).
/// Each chunk's report is printed AFTER its commit, so every `ok` line ever
/// printed is durably trained — callers may record them (e.g. a reconciler
/// sidecar) as they stream. Exit 0 additionally means the directory scan was
/// complete. The one gap callers must own: if this process dies after a
/// commit but before its report lands (broken pipe, kill), those messages
/// trained unrecorded, and a retry trains them a second time — a report-fed
/// sidecar gives at-least-once, not exactly-once, so callers must tolerate an
/// occasional duplicate training (bounded: one extra count per message per
/// crash, the same tolerance the reconciler already extends to imapsieve).
/// Refuses to create a database: bulk training into a mistyped -d must be an
/// error, not a silently-conjured corpus (cold starts use the stdin verbs).
const TRAIN_CHUNK: usize = 500;

/// Additional flush trigger: commit the current chunk early once its
/// accumulated token count crosses this budget, so 500 pathological
/// max-token messages cannot hold tens of millions of Strings resident.
/// Real mail runs well under 10k raw tokens; this only bites synthetic input.
const TRAIN_CHUNK_TOKEN_BUDGET: usize = 1_000_000;

fn cmd_train_dir(args: &[String]) {
    let (dir, class) = match (args.first(), args.get(1)) {
        (Some(d), Some(c)) if c == "spam" || c == "good" => (d.as_str(), c.as_str()),
        _ => {
            eprintln!("spamlite: usage: train-dir <dir> spam|good");
            process::exit(1);
        }
    };
    let is_spam = class == "spam";
    let db = open_db_ro_or_exit();

    let scan = list_message_files(dir);
    let mut ok = 0u64;
    let mut failed = 0u64;

    for (path, e) in &scan.stat_errors {
        failed += 1;
        println!("err\tstat: {e}\t{}", tsv_safe(path.display().to_string()));
    }

    // (trained?, msgid-or-reason, tsv-safe path) — tokens live only until the
    // next flush; a flush commits then prints, so ok lines are always durable.
    let mut report: Vec<(bool, String, String)> = Vec::new();
    let mut batch: Vec<Vec<String>> = Vec::new();
    let mut batch_tokens = 0usize;

    let flush = |batch: &mut Vec<Vec<String>>,
                     report: &mut Vec<(bool, String, String)>,
                     ok: &mut u64,
                     failed: &mut u64| {
        if let Err(e) = db.train_messages(batch, is_spam) {
            // Prior chunks are committed and reported — those ok lines stand.
            eprintln!(
                "spamlite: train-dir transaction failed, this chunk NOT trained \
                 (earlier ok lines remain valid): {e}"
            );
            process::exit(1);
        }
        for (trained, info, path) in report.iter() {
            if *trained {
                *ok += 1;
                println!("ok\t{info}\t{path}");
            } else {
                *failed += 1;
                println!("err\t{info}\t{path}");
            }
        }
        batch.clear();
        report.clear();
    };

    for path in &scan.files {
        let safe_path = tsv_safe(path.display().to_string());
        let raw = match read_message_file(path) {
            Ok(r) => r,
            Err(e) => {
                report.push((false, format!("read: {e}"), safe_path));
                continue;
            }
        };
        let stripped = strip_label_headers(&raw);
        let msgid = extract_msgid(&stripped).unwrap_or_else(|| "-".to_string());
        // Panic-isolated per message: one pathological file must not sink
        // the batch (the v0.2.0 tokenizer panic shipped that failure mode).
        let toks = std::panic::catch_unwind(|| tokenizer::tokenize_env(&stripped));
        match toks {
            Ok(tokens) if !tokens.is_empty() => {
                batch_tokens += tokens.len();
                batch.push(tokens);
                report.push((true, msgid, safe_path));
            }
            Ok(_) => report.push((false, "no tokens".to_string(), safe_path)),
            Err(_) => report.push((false, "tokenizer panic".to_string(), safe_path)),
        }
        if batch.len() >= TRAIN_CHUNK || batch_tokens >= TRAIN_CHUNK_TOKEN_BUDGET {
            flush(&mut batch, &mut report, &mut ok, &mut failed);
            batch_tokens = 0;
        }
    }
    flush(&mut batch, &mut report, &mut ok, &mut failed);

    eprintln!("spamlite: trained {ok} {class} ({failed} failed)");
    if scan.entry_errors > 0 {
        eprintln!(
            "spamlite: {} unreadable directory entries — the scan was INCOMPLETE, \
             do not treat this directory as fully handled",
            scan.entry_errors
        );
        process::exit(1);
    }
}

/// msgids = header scan of every message file in a directory. Read-only, no
/// database. stdout: `<msgid|->\t<from|->\t<path>` per file. Replaces the
/// reconciler's reconcile-keyext.awk (and its From-sampling grep) with a
/// parser that actually understands folding and encoded words.
fn cmd_msgids(args: &[String]) {
    let Some(dir) = args.first() else {
        eprintln!("spamlite: usage: msgids <dir>");
        process::exit(1);
    };
    // Headers only — 64 KiB covers any sane header block, and mail-parser
    // handles a truncated body without complaint.
    const HEADER_READ_BYTES: u64 = 64 * 1024;
    let parser = mail_parser::MessageParser::default();
    let scan = list_message_files(dir);
    let mut incomplete = scan.entry_errors > 0;
    for (path, e) in &scan.stat_errors {
        eprintln!("spamlite: cannot stat {}: {e}", path.display());
        incomplete = true;
    }
    for path in &scan.files {
        let raw = match std::fs::File::open(path).and_then(|f| {
            let mut buf = Vec::new();
            f.take(HEADER_READ_BYTES).read_to_end(&mut buf)?;
            Ok(buf)
        }) {
            Ok(r) => r,
            Err(e) => {
                eprintln!("spamlite: skipping {}: {e}", path.display());
                incomplete = true;
                continue;
            }
        };
        let msgid = extract_msgid(&raw).unwrap_or_else(|| "-".to_string());
        let from = parser
            .parse(&raw)
            .and_then(|m| {
                m.from()
                    .and_then(|f| f.first())
                    .and_then(|a| a.address.as_deref().map(|s| s.to_lowercase()))
            })
            .unwrap_or_else(|| "-".to_string());
        let from: String = from.chars().filter(|c| !c.is_whitespace()).collect();
        println!("{msgid}\t{from}\t{}", tsv_safe(path.display().to_string()));
    }
    // A partial listing must not exit 0 — a caller diffing it against a
    // sidecar would treat the unlisted files as absent.
    if incomplete {
        process::exit(1);
    }
}

/// stats = machine-readable database statistics, one `key value` per line.
/// The `counts` verb stays as the human-facing view; this one is for scripts
/// (replaces ad-hoc `sqlite3` queries against the db). `seen_30d` counts
/// tokens trained in the last 30 days — score/receive never write last_seen,
/// so it is an exact "own vocabulary is growing" marker.
fn cmd_stats() {
    let db = open_db_ro_or_exit();
    let s = match db.stats(30 * 86400) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("spamlite: error reading stats: {e}");
            process::exit(1);
        }
    };
    let path = db_path();
    let db_bytes = std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
    println!("db {}", path.display());
    println!("good {}", s.total_good);
    println!("spam {}", s.total_spam);
    println!("tokens {}", s.unique_tokens);
    println!("db_bytes {db_bytes}");
    println!("last_seen_min {}", s.last_seen_min);
    println!("last_seen_max {}", s.last_seen_max);
    println!("seen_30d {}", s.seen_recent);
}

fn usage() {
    eprintln!(
        "spamlite {} — per-user Bayesian spam filter
Copyright 2026 Mark Constable <mc@netserva.org>
MIT License — https://github.com/markc/spamlite

Usage:
  spamlite [-d DIR] [-t THRESHOLD] [-g GATE] receive   Classify + train on confident verdicts
  spamlite [-d DIR] [-t THRESHOLD] score               Classify only (read-only, no training)
  spamlite [-d DIR] [-t THRESHOLD] explain             Verbose token-level breakdown (debug)
  spamlite [-d DIR] spam                               Train message from stdin as spam
  spamlite [-d DIR] good                               Train message from stdin as good/ham
  spamlite [-d DIR] train-dir <MSGDIR> spam|good       Bulk-train every file in MSGDIR (durable
                                                       transaction per 500-message chunk; label
                                                       headers stripped; TSV report on stdout,
                                                       printed post-commit; db must exist)
  spamlite msgids <MSGDIR>                             Print msgid/from/path TSV per file
  spamlite [-d DIR] stats                              Machine-readable stats (key value lines)
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

Priority: -t flag > params.toml threshold > SPAMLITE_THRESHOLD env > 0.5
          -g flag > SPAMLITE_TOE_GATE env > 0.2
          -d flag > SPAMLITE_DB env > ~/.spamlite/db.sqlite",
        env!("CARGO_PKG_VERSION")
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

    // SPAMLITE_THRESHOLD env is resolved in make_params (below params.toml
    // in priority), NOT here — promoting it into THRESHOLD would let it
    // silently defeat per-user params.toml thresholds.

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
        "train-dir" => cmd_train_dir(&args[1..]),
        "msgids" => cmd_msgids(&args[1..]),
        "stats" => cmd_stats(),
        "counts" => cmd_counts(),
        "cleanup" => cmd_cleanup(&args[1..]),
        "export" => cmd_export(),
        "import" => cmd_import(),
        "-V" | "--version" | "version" => println!("spamlite {}", env!("CARGO_PKG_VERSION")),
        "-h" | "--help" | "help" => usage(),
        other => {
            eprintln!("spamlite: unknown command '{other}'");
            usage();
            process::exit(1);
        }
    }
}
