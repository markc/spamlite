// Copyright 2026 Mark Constable <mc@netserva.org>
// SPDX-License-Identifier: MIT

use mail_parser::{Addr, HeaderName, HeaderValue, Host, MessageParser};

// Token length bounds are measured in BYTES (str::len), not chars — a
// deliberate choice kept for corpus compatibility: switching to chars would
// shift the token universe under every trained db. Practical effect: CJK
// words max out at ~13 chars and a 2-char CJK word (6 bytes) passes the
// minimum. Revisit only with a benchmark against the offline corpus.
const MIN_TOKEN_LEN: usize = 3;
const MAX_TOKEN_LEN: usize = 40;

/// Hard cap on tokens extracted from one message (pre-dedup). The 64 MiB
/// stdin cap in main.rs bounds memory, but a huge text body could still cost
/// millions of allocations plus thousands of chunked SQL lookups inside the
/// sieve hot path with dovecot waiting. Real mail produces well under 10k raw
/// tokens; the discriminating signal of any real message appears long before
/// this cap. spamprobe has the same guard (max terms per message).
const MAX_RAW_TOKENS: usize = 50_000;

/// Tokenizer configuration. Controls which headers are tokenized and the token
/// length bounds. `Default` preserves the historical behaviour; non-default
/// configs are used by the evaluation harness and can be promoted to defaults
/// once their win against the baseline is measured.
#[derive(Debug, Clone)]
pub struct TokenizerConfig {
    pub min_len: usize,
    pub max_len: usize,
    /// Expand header coverage: `h:to:*`, `h:cc:*`, and split received chain
    /// into `h:hrecv:*` (first hop) and `h:hrecvx:*` (all subsequent).
    pub expanded_headers: bool,
    /// Emit `x:tld:<effective-tld>` from sender address domains. The sending
    /// TLD is invariant across the full-domain rotation zero-day phishing uses,
    /// so it accumulates a Bayesian prior that a rotating domain token cannot.
    pub tld_feature: bool,
    /// Fold Unicode confusables/homoglyphs to an ASCII skeleton so obfuscated
    /// words (`accᴏunt`, `𝖢ustomer`) land on their trained tokens; also emit
    /// `x:confusable` / `x:mixedscript` flags. Defeats the fresh-token evasion.
    pub homoglyph_fold: bool,
    /// Tokenize the From display name (`h:fromname:*`) and emit
    /// `x:brandmiss:<brand>` when the display name impersonates a known brand
    /// whose domain does not match. Catches `AppIe`/`AIdi` display-name spoofs.
    pub brand_mismatch: bool,
    /// Emit `x:auth:{spf,dkim,dmarc}_<result>` / `x:spf:<result>` from
    /// Authentication-Results / Received-SPF when present. Inert when the
    /// delivery path does not stamp those headers (feasibility-gated per site).
    pub auth_tokens: bool,
}

impl Default for TokenizerConfig {
    fn default() -> Self {
        TokenizerConfig {
            min_len: MIN_TOKEN_LEN,
            max_len: MAX_TOKEN_LEN,
            expanded_headers: false,
            tld_feature: false,
            homoglyph_fold: false,
            brand_mismatch: false,
            auth_tokens: false,
        }
    }
}

impl TokenizerConfig {
    /// Build a config from `SPAMLITE_*` env vars, starting from `Default`. Lets
    /// the offline eval harness A/B individual anti-evasion features via the
    /// stock `good`/`spam`/`score` CLI without a rebuild or code change.
    /// Production sets none of these, so the default behaviour is unchanged.
    pub fn from_env() -> Self {
        let mut c = Self::default();
        let on = |k: &str| {
            std::env::var(k)
                .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
                .unwrap_or(false)
        };
        if on("SPAMLITE_EXPANDED_HEADERS") {
            c.expanded_headers = true;
        }
        if on("SPAMLITE_TLD") {
            c.tld_feature = true;
        }
        if on("SPAMLITE_FOLD") {
            c.homoglyph_fold = true;
        }
        if on("SPAMLITE_BRAND") {
            c.brand_mismatch = true;
        }
        if on("SPAMLITE_AUTH") {
            c.auth_tokens = true;
        }
        c
    }
}

/// Convert a mail-parser Host to a lowercase string
fn host_to_string(host: &Host<'_>) -> String {
    match host {
        Host::Name(name) => name.to_lowercase(),
        Host::IpAddr(ip) => ip.to_string(),
    }
}

/// Extract tokens from a raw email message (RFC 5322) using the default config.
pub fn tokenize(raw: &[u8]) -> Vec<String> {
    tokenize_with_config(raw, &TokenizerConfig::default())
}

/// Extract tokens using a config resolved from `SPAMLITE_*` env vars. The CLI
/// train/score/receive paths use this so anti-evasion features can be A/B'd in
/// the offline harness; with no env vars set it is identical to `tokenize`.
pub fn tokenize_env(raw: &[u8]) -> Vec<String> {
    tokenize_with_config(raw, &TokenizerConfig::from_env())
}

/// Extract tokens from a raw email message with explicit configuration.
pub fn tokenize_with_config(raw: &[u8], config: &TokenizerConfig) -> Vec<String> {
    let parser = MessageParser::default();
    let message = match parser.parse(raw) {
        Some(m) => m,
        None => return tokenize_fallback(raw, config),
    };

    let mut tokens = Vec::with_capacity(1024);
    let valid = |s: &str| s.len() >= config.min_len && s.len() <= config.max_len;

    // Subject header — individual tokens + bigrams
    if let Some(subject) = message.subject() {
        let words: Vec<String> = extract_words(subject).filter(|w| valid(w)).collect();

        for w in &words {
            push_word(&mut tokens, "h:subject:", w, config);
        }

        // Bigrams for subject
        for pair in words.windows(2) {
            tokens.push(format!("h:subject:{}_{}", pair[0], pair[1]));
        }
    }

    // From header
    if let Some(from) = message.from() {
        for addr in from.iter() {
            push_addr(&mut tokens, "h:from:", addr, &valid, config);
        }
    }

    // Reply-To / Sender — carry the real supplier identity when a bulk ESP
    // rewrites From into its own envelope domain. Decomposed to brand anchors
    // by push_addr, same as From. Default-on: additive per-sender signal.
    if let Some(reply_to) = message.reply_to() {
        for addr in reply_to.iter() {
            push_addr(&mut tokens, "h:replyto:", addr, &valid, config);
        }
    }
    if let Some(sender) = message.sender() {
        for addr in sender.iter() {
            push_addr(&mut tokens, "h:sender:", addr, &valid, config);
        }
    }

    // To / Cc headers (expanded coverage)
    if config.expanded_headers {
        if let Some(to) = message.to() {
            for addr in to.iter() {
                push_addr(&mut tokens, "h:to:", addr, &valid, config);
            }
        }
        if let Some(cc) = message.cc() {
            for addr in cc.iter() {
                push_addr(&mut tokens, "h:cc:", addr, &valid, config);
            }
        }
    }

    // Received headers — split first hop from subsequent when expanded
    if config.expanded_headers {
        let mut first = true;
        let root_headers = message.parts.first().map(|p| p.headers.as_slice()).unwrap_or(&[]);
        for header in root_headers {
            if header.name != HeaderName::Received {
                continue;
            }
            let HeaderValue::Received(received) = &header.value else { continue };
            let prefix = if first { "h:hrecv:" } else { "h:hrecvx:" };
            first = false;
            if let Some(from_host) = received.from() {
                let host = host_to_string(from_host);
                if valid(&host) {
                    tokens.push(format!("{prefix}{host}"));
                }
            }
            if let Some(by_host) = received.by() {
                let host = host_to_string(by_host);
                if valid(&host) {
                    tokens.push(format!("{prefix}{host}"));
                }
            }
        }
    } else if let Some(received) = message.received() {
        if let Some(from_host) = received.from() {
            let host = host_to_string(from_host);
            if valid(&host) {
                tokens.push(format!("h:received:{host}"));
            }
        }
        if let Some(by_host) = received.by() {
            let host = host_to_string(by_host);
            if valid(&host) {
                tokens.push(format!("h:received:{host}"));
            }
        }
    }

    // Authentication metadata — SPF/DKIM/DMARC outcomes are content-independent
    // and cannot be rotated by the attacker. Emit only when the header is
    // present; absence emits nothing (never a "missing auth" penalty). Inert on
    // delivery paths that don't stamp Authentication-Results (site feasibility).
    if config.auth_tokens {
        let root_headers = message
            .parts
            .first()
            .map(|p| p.headers.as_slice())
            .unwrap_or(&[]);
        for header in root_headers {
            let name = header.name.as_str();
            if name.eq_ignore_ascii_case("Authentication-Results")
                || name.eq_ignore_ascii_case("ARC-Authentication-Results")
            {
                if let Some(text) = header_text(&header.value) {
                    emit_auth_tokens(&mut tokens, &text);
                }
            } else if name.eq_ignore_ascii_case("Received-SPF") {
                if let Some(text) = header_text(&header.value) {
                    let res: String = text
                        .trim_start()
                        .chars()
                        .take_while(|c| c.is_ascii_alphabetic())
                        .flat_map(|c| c.to_lowercase())
                        .collect();
                    if !res.is_empty() {
                        tokens.push(format!("x:spf:{res}"));
                    }
                }
            }
        }
    }

    // Body parts. Bodies are the only unbounded token source (headers are
    // small), so the MAX_RAW_TOKENS cap is enforced here.
    for part in message.text_bodies() {
        if tokens.len() >= MAX_RAW_TOKENS {
            break;
        }
        let text = part.text_contents().unwrap_or_default();

        // URLs in plain-text bodies carry the same signal as HTML hrefs —
        // text-only spam was previously losing its `u:` tokens entirely.
        for url in extract_urls_from_text(text, config.max_len) {
            if valid(&url) {
                tokens.push(format!("u:{url}"));
            }
        }

        for w in extract_words(text) {
            if tokens.len() >= MAX_RAW_TOKENS {
                break;
            }
            if valid(&w) {
                push_word(&mut tokens, "b:", &w, config);
            }
        }
    }

    for part in message.html_bodies() {
        if tokens.len() >= MAX_RAW_TOKENS {
            break;
        }
        let html = part.text_contents().unwrap_or_default();

        // Extract URLs from HTML before stripping
        for url in extract_urls(html, config.max_len) {
            if valid(&url) {
                tokens.push(format!("u:{url}"));
            }
        }

        // Strip HTML and tokenize text
        let text = nanohtml2text::html2text(html);
        for w in extract_words(&text) {
            if tokens.len() >= MAX_RAW_TOKENS {
                break;
            }
            if valid(&w) {
                push_word(&mut tokens, "b:", &w, config);
            }
        }
    }

    // Deduplicate — we only care about presence, not frequency within a single message
    tokens.sort_unstable();
    tokens.dedup();
    tokens
}

/// Second-level labels that act as a public suffix in front of a 2-letter ccTLD
/// (e.g. `com.au`, `co.uk`, `com.qa`, `org.au`). Not a full public-suffix list —
/// just the common business SLDs this cluster's senders use. Used to find the
/// registrable domain so the bare brand label can be extracted.
const TWO_LEVEL_SLDS: &[&str] = &[
    "com", "net", "org", "edu", "gov", "co", "ac", "asn", "id", "or", "ne", "go",
    "gen", "mil", "biz", "info",
];

/// Decompose a DNS host into (registrable_domain, bare_brand_label).
/// `partners.intrepidtravel.com` → (`intrepidtravel.com`, `intrepidtravel`).
/// `survey.qatarairways.com.qa` → (`qatarairways.com.qa`, `qatarairways`).
/// Returns `None` for IP literals or hosts with fewer than two labels.
///
/// The bare brand label is the generalizing anchor: it is stable across every
/// rotating ESP subdomain/envelope a supplier sends through, so one ham retrain
/// of it flips all future mail from that sender — the spamprobe `addTokenParts`
/// behaviour (`TraditionalMailMessageParser.cc:115-143`) that spamlite lacked.
fn decompose_host(host: &str) -> Option<(String, String)> {
    if host.parse::<std::net::IpAddr>().is_ok() {
        return None;
    }
    let labels: Vec<&str> = host.split('.').filter(|l| !l.is_empty()).collect();
    let n = labels.len();
    if n < 2 {
        return None;
    }
    let two_level =
        n >= 3 && labels[n - 1].len() == 2 && TWO_LEVEL_SLDS.contains(&labels[n - 2]);
    let start = if two_level { n - 3 } else { n - 2 };
    let registrable = labels[start..].join(".");
    let brand = labels[start].to_string();
    Some((registrable, brand))
}

fn push_addr<F: Fn(&str) -> bool>(
    tokens: &mut Vec<String>,
    prefix: &str,
    addr: &Addr<'_>,
    valid: &F,
    config: &TokenizerConfig,
) {
    let Some(email) = addr.address.as_deref() else { return };
    let email_lower = email.to_lowercase();
    if valid(&email_lower) {
        tokens.push(format!("{prefix}{email_lower}"));
    }
    let mut domain_brand: Option<String> = None;
    if let Some(domain) = email_lower.split('@').nth(1) {
        if valid(domain) {
            tokens.push(format!("{prefix}{domain}"));
        }
        // Generalizing anchors: registrable domain + bare brand label. These
        // survive the supplier's rotating ESP subdomains, so per-sender ham
        // retraining actually generalizes. Brand label has a relaxed lower bound
        // (>=2) so short brands like "ncl" / "hp" aren't dropped.
        if let Some((registrable, brand)) = decompose_host(domain) {
            if registrable != domain && valid(&registrable) {
                tokens.push(format!("{prefix}{registrable}"));
            }
            if brand.len() >= 2 && brand.len() <= MAX_TOKEN_LEN {
                tokens.push(format!("{prefix}{brand}"));
            }
            domain_brand = Some(brand);
        }
        // Effective TLD — invariant across the attacker's full-domain rotation.
        if config.tld_feature {
            if let Some(tld) = effective_tld(domain) {
                tokens.push(format!("x:tld:{tld}"));
            }
        }
    }

    // Display-name tokens + brand-impersonation flag — From only. The display
    // name is where `AppIe`/`AIdi` brand spoofs live; it was previously discarded.
    if config.brand_mismatch && prefix == "h:from:" {
        if let Some(name) = addr.name.as_deref() {
            for w in extract_words(name) {
                if valid(&w) {
                    push_word(tokens, "h:fromname:", &w, config);
                }
            }
            if let Some(claimed) = claimed_brand(name) {
                let domain_matches = domain_brand
                    .as_deref()
                    .map(|b| brand_canonical(b).contains(&claimed))
                    .unwrap_or(false);
                if !domain_matches {
                    tokens.push(format!("x:brandmiss:{claimed}"));
                }
            }
        }
    }
}

/// Effective public-suffix of a host (`spammer.life` → `life`,
/// `flybuys.com.au` → `com.au`, `apple.com` → `com`). Uses the same two-level
/// SLD table as `decompose_host`. `None` for IPs / single-label hosts.
fn effective_tld(host: &str) -> Option<String> {
    if host.parse::<std::net::IpAddr>().is_ok() {
        return None;
    }
    let labels: Vec<&str> = host.split('.').filter(|l| !l.is_empty()).collect();
    let n = labels.len();
    if n < 2 {
        return None;
    }
    let two_level =
        n >= 3 && labels[n - 1].len() == 2 && TWO_LEVEL_SLDS.contains(&labels[n - 2]);
    if two_level {
        Some(format!("{}.{}", labels[n - 2], labels[n - 1]))
    } else {
        Some(labels[n - 1].to_string())
    }
}

/// Push a word token and, when `homoglyph_fold` is on and the word is not pure
/// ASCII, its confusable-folded ASCII skeleton (so `accᴏunt`/`𝖢ustomer` land on
/// the trained `account`/`customer`) plus the `x:confusable` / `x:mixedscript`
/// flags. The raw token is always kept — folding only ever ADDS tokens.
fn push_word(tokens: &mut Vec<String>, prefix: &str, word: &str, config: &TokenizerConfig) {
    tokens.push(format!("{prefix}{word}"));
    if !config.homoglyph_fold || word.is_ascii() {
        return;
    }
    if let Some(skel) = fold_skeleton(word) {
        if skel.len() >= config.min_len && skel.len() <= config.max_len {
            tokens.push(format!("{prefix}{skel}"));
        }
        tokens.push("x:confusable".to_string());
    }
    if is_mixed_script(word) {
        tokens.push("x:mixedscript".to_string());
    }
}

/// Fold a word's Unicode confusables to an ASCII skeleton. Returns `Some` only
/// when at least one character folded AND the result is pure ASCII (so accented
/// Latin like `café`/`Müller` and CJK fold to themselves → `None`, no flag).
fn fold_skeleton(word: &str) -> Option<String> {
    let mut changed = false;
    let mut out = String::with_capacity(word.len());
    for c in word.chars() {
        match map_confusable(c) {
            Some(t) => {
                out.push(t);
                changed = true;
            }
            None => out.push(c),
        }
    }
    if changed && out.is_ascii() {
        Some(out)
    } else {
        None
    }
}

/// True when a word mixes ASCII Latin letters with Cyrillic/Greek/Armenian —
/// the whole-script-swap-is-legit / mixed-script-is-hostile heuristic. A fully
/// non-Latin word (real Russian/Greek text) is NOT flagged.
fn is_mixed_script(word: &str) -> bool {
    let mut has_latin = false;
    let mut has_other = false;
    for c in word.chars() {
        if c.is_ascii_alphabetic() {
            has_latin = true;
        } else {
            let cp = c as u32;
            if (0x0400..=0x04FF).contains(&cp)   // Cyrillic
                || (0x0370..=0x03FF).contains(&cp) // Greek
                || (0x0530..=0x058F).contains(&cp)
            {
                // Armenian
                has_other = true;
            }
        }
    }
    has_latin && has_other
}

/// Map one Unicode confusable to its ASCII-lowercase base letter/digit, or
/// `None` if it is not a handled confusable.
fn map_confusable(c: char) -> Option<char> {
    let cp = c as u32;
    if (0x1D400..=0x1D7FF).contains(&cp) {
        return map_math_alnum(cp);
    }
    CONFUSABLE_TABLE
        .iter()
        .find(|&&(k, _)| k == c)
        .map(|&(_, v)| v)
}

/// Fold a Mathematical Alphanumeric Symbols code point (U+1D400–U+1D7FF) to its
/// ASCII base. The block is laid out as fixed-offset runs, so this is pure
/// arithmetic — assigned code points keep their natural offset even where a
/// reserved hole exists (the hole letters live in Letterlike Symbols and are
/// handled by CONFUSABLE_TABLE, not here). Upper- and lowercase both fold to
/// lowercase, matching `extract_words`' lowercasing.
fn map_math_alnum(cp: u32) -> Option<char> {
    // 13 alphabetic styles, each 52 code points: A–Z then a–z.
    const ALPHA_STARTS: [u32; 13] = [
        0x1D400, 0x1D434, 0x1D468, 0x1D49C, 0x1D4D0, 0x1D504, 0x1D538, 0x1D56C, 0x1D5A0, 0x1D5D4,
        0x1D608, 0x1D63C, 0x1D670,
    ];
    for &s in &ALPHA_STARTS {
        if cp >= s && cp <= s + 51 {
            let off = (cp - s) as u8;
            let base = if off < 26 { b'a' + off } else { b'a' + (off - 26) };
            return Some(base as char);
        }
    }
    // 5 digit styles, each 10 code points: 0–9.
    const DIGIT_STARTS: [u32; 5] = [0x1D7CE, 0x1D7D8, 0x1D7E2, 0x1D7EC, 0x1D7F6];
    for &s in &DIGIT_STARTS {
        if cp >= s && cp <= s + 9 {
            return Some((b'0' + (cp - s) as u8) as char);
        }
    }
    None
}

/// Curated confusable → ASCII-lowercase map: the Mathematical-Alphanumeric
/// reserved-hole letters that live in Letterlike Symbols, small-caps/phonetic
/// look-alikes, and the common Cyrillic/Greek Latin homoglyphs. Scoped to what
/// obfuscated phishing actually uses — deliberately NOT a full TR39 table.
#[rustfmt::skip]
const CONFUSABLE_TABLE: &[(char, char)] = &[
    // Letterlike Symbols (Math-Alphanumeric reserved holes appear here).
    ('ℎ','h'),('ℬ','b'),('ℰ','e'),('ℱ','f'),('ℋ','h'),('ℐ','i'),('ℒ','l'),('ℳ','m'),
    ('ℯ','e'),('ℊ','g'),('ℴ','o'),('ℭ','c'),('ℌ','h'),('ℑ','i'),('ℜ','r'),('ℨ','z'),
    ('ℂ','c'),('ℍ','h'),('ℕ','n'),('ℙ','p'),('ℚ','q'),('ℝ','r'),('ℤ','z'),
    // Small-caps / phonetic (U+1D00 block) — `accᴏunt` uses U+1D0F.
    ('ᴀ','a'),('ʙ','b'),('ᴄ','c'),('ᴅ','d'),('ᴇ','e'),('ꜰ','f'),('ɢ','g'),('ʜ','h'),
    ('ɪ','i'),('ᴊ','j'),('ᴋ','k'),('ʟ','l'),('ᴍ','m'),('ɴ','n'),('ᴏ','o'),('ᴘ','p'),
    ('ʀ','r'),('ᴛ','t'),('ᴜ','u'),('ᴠ','v'),('ᴡ','w'),('ʏ','y'),('ᴢ','z'),
    // Cyrillic look-alikes.
    ('а','a'),('е','e'),('о','o'),('р','p'),('с','c'),('х','x'),('у','y'),('ѕ','s'),
    ('і','i'),('ј','j'),('А','a'),('В','b'),('Е','e'),('К','k'),('М','m'),('Н','h'),
    ('О','o'),('Р','p'),('С','c'),('Т','t'),('Х','x'),('У','y'),
    // Greek look-alikes.
    ('ο','o'),('ρ','p'),('α','a'),('ν','v'),('Α','a'),('Β','b'),('Ε','e'),('Ζ','z'),
    ('Η','h'),('Ι','i'),('Κ','k'),('Μ','m'),('Ν','n'),('Ο','o'),('Ρ','p'),('Τ','t'),
    ('Υ','y'),('Χ','x'),
];

/// Known brands worth impersonating (AU-centric, matching this cluster's mail).
#[rustfmt::skip]
const BRANDS: &[&str] = &[
    "apple","paypal","aldi","coles","woolworths","netflix","amazon","microsoft",
    "google","anz","nab","commbank","westpac","auspost","linkt","telstra","optus",
    "mygov","medicare","ato","facebook","instagram","ebay","kmart","bunnings",
    "qantas","suncorp","bupa","unisuper","dhl","fedex","norton","mcafee","binance",
    "coinbase","outlook","office365",
];

/// Canonicalise a token for brand matching: lowercase, collapse the ASCII
/// letter/glyph look-alikes phishers use (i/l/1 → l, 0 → o, 5 → s, 3 → e), and
/// keep only alphanumerics. Scoped to brand detection ONLY — never applied to
/// the general token stream, where i/l/1 folding would be far too noisy.
fn brand_canonical(s: &str) -> String {
    s.chars()
        .flat_map(|c| c.to_lowercase())
        .filter_map(|c| match c {
            'i' | 'l' | '1' | '|' => Some('l'),
            '0' => Some('o'),
            '5' => Some('s'),
            '3' => Some('e'),
            c if c.is_ascii_alphanumeric() => Some(c),
            _ => None,
        })
        .collect()
}

/// If any whole word in a display name canonicalises to a known brand, return
/// that brand (its own canonical form). Whole-word (not substring) match keeps
/// `appleseed`-style legit names from tripping the brand-mismatch flag.
fn claimed_brand(name: &str) -> Option<String> {
    // Fold Unicode confusables first (e.g. `𝖠pple`), then split on non-letters.
    let folded: String = name
        .chars()
        .map(|c| map_confusable(c).unwrap_or(c))
        .collect();
    for word in folded.split(|c: char| !c.is_alphanumeric()) {
        if word.is_empty() {
            continue;
        }
        let canon = brand_canonical(word);
        for &b in BRANDS {
            if canon == brand_canonical(b) {
                return Some(brand_canonical(b));
            }
        }
    }
    None
}

/// Extract the flat text of an unstructured header value (Authentication-Results,
/// Received-SPF) for substring scanning.
fn header_text(v: &HeaderValue<'_>) -> Option<String> {
    match v {
        HeaderValue::Text(t) => Some(t.to_string()),
        HeaderValue::TextList(l) => Some(l.join(" ")),
        _ => None,
    }
}

/// Parse `method=result` pairs out of an Authentication-Results header and emit
/// `x:auth:<method>_<result>` tokens for spf/dkim/dmarc.
fn emit_auth_tokens(tokens: &mut Vec<String>, ar: &str) {
    let ar = ar.to_lowercase();
    for method in ["spf", "dkim", "dmarc"] {
        let needle = format!("{method}=");
        if let Some(idx) = ar.find(&needle) {
            let after = &ar[idx + needle.len()..];
            let val: String = after.chars().take_while(|c| c.is_ascii_alphabetic()).collect();
            if !val.is_empty() {
                tokens.push(format!("x:auth:{method}_{val}"));
            }
        }
    }
}

/// Fallback tokenizer for unparseable messages — treat as raw text
fn tokenize_fallback(raw: &[u8], config: &TokenizerConfig) -> Vec<String> {
    let text = String::from_utf8_lossy(raw);
    let mut tokens: Vec<String> = extract_words(&text)
        .filter(|w| w.len() >= config.min_len && w.len() <= config.max_len)
        .map(|w| format!("b:{w}"))
        .take(MAX_RAW_TOKENS)
        .collect();
    tokens.sort_unstable();
    tokens.dedup();
    tokens
}

/// Split text into lowercase words. Returns an iterator so body-tokenizing
/// loops don't materialise an intermediate Vec for the whole part.
fn extract_words(text: &str) -> impl Iterator<Item = String> + '_ {
    text.split(|c: char| !c.is_alphanumeric() && c != '.' && c != '-' && c != '_' && c != '@')
        .filter(|s| !s.is_empty())
        .map(|s| {
            // Trim leading/trailing punctuation
            s.trim_matches(|c: char| c == '.' || c == '-' || c == '_')
                .to_lowercase()
        })
        .filter(|s| !s.is_empty())
}

/// Extract URLs from HTML content (href and src attributes) in a single
/// left-to-right scan, accepting either quote style.
fn extract_urls(html: &str, max_len: usize) -> Vec<String> {
    let mut urls = Vec::new();
    let mut rest = html;
    loop {
        let (pos, attr_len) = match (rest.find("href="), rest.find("src=")) {
            (Some(h), Some(s)) if h < s => (h, 5),
            (Some(h), None) => (h, 5),
            (_, Some(s)) => (s, 4),
            (None, None) => break,
        };
        rest = &rest[pos + attr_len..];
        let quote = match rest.chars().next() {
            Some(q @ ('"' | '\'')) => q,
            _ => continue, // unquoted or truncated attribute — keep scanning
        };
        rest = &rest[1..];
        let Some(end) = rest.find(quote) else { continue };
        let url = &rest[..end];
        if url.starts_with("http://") || url.starts_with("https://") {
            // Normalize: lowercase, strip tracking params, keep domain+path
            let normalized = normalize_url(url, max_len);
            if !normalized.is_empty() {
                urls.push(normalized);
            }
        }
        rest = &rest[end..];
    }
    urls
}

/// Extract URLs from plain text — scan for http(s):// runs terminated by
/// whitespace or characters that can't appear in a sane URL. Same
/// normalization as the HTML path so text and HTML mail produce identical
/// `u:` tokens for the same link.
fn extract_urls_from_text(text: &str, max_len: usize) -> Vec<String> {
    let mut urls = Vec::new();
    let mut search = text;
    while let Some(pos) = search.find("http") {
        search = &search[pos..];
        let rest = if let Some(r) = search.strip_prefix("https://") {
            r
        } else if let Some(r) = search.strip_prefix("http://") {
            r
        } else {
            // "http" without "://" — skip past it and keep scanning
            search = &search[4..];
            continue;
        };
        let scheme_len = search.len() - rest.len();
        let end = rest
            .find(|c: char| {
                c.is_whitespace() || matches!(c, '"' | '\'' | '<' | '>' | ')' | ']' | '|')
            })
            .unwrap_or(rest.len());
        if end > 0 {
            let url = &search[..scheme_len + end];
            let normalized = normalize_url(url, max_len);
            if !normalized.is_empty() {
                urls.push(normalized);
            }
        }
        search = &rest[end..];
    }
    urls
}

/// Normalize a URL for tokenization — keep scheme+host+path, drop query
fn normalize_url(url: &str, max_len: usize) -> String {
    let url = url.to_lowercase();
    // Strip query string and fragment
    let cut = url.find(['?', '#']).unwrap_or(url.len());
    let url = &url[..cut];
    // Truncate to max token length, respecting char boundaries for multi-byte UTF-8
    if url.len() > max_len {
        let mut end = max_len;
        while end > 0 && !url.is_char_boundary(end) {
            end -= 1;
        }
        url[..end].to_string()
    } else {
        url.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_words() {
        let words: Vec<String> = extract_words("Hello World! This is a TEST-email_token.").collect();
        assert!(words.contains(&"hello".to_string()));
        assert!(words.contains(&"world".to_string()));
        assert!(words.contains(&"test-email_token".to_string()));
    }

    #[test]
    fn test_extract_urls() {
        let html = r#"<a href="https://example.com/page">click</a>"#;
        let urls = extract_urls(html, MAX_TOKEN_LEN);
        assert_eq!(urls, vec!["https://example.com/page"]);
    }

    #[test]
    fn test_extract_urls_mixed_quotes_document_order() {
        let html = r#"<img src='https://cdn.spam.biz/pix.gif'><a href="https://example.com/go">x</a> <a href=unquoted>y</a>"#;
        let urls = extract_urls(html, MAX_TOKEN_LEN);
        assert_eq!(
            urls,
            vec!["https://cdn.spam.biz/pix.gif", "https://example.com/go"]
        );
    }

    #[test]
    fn test_token_cap_bounds_pathological_body() {
        // A synthetic body with far more unique words than the cap must be
        // bounded (pre-dedup cap 50k, so post-dedup <= 50k + header tokens).
        let mut body = String::with_capacity(1 << 20);
        for i in 0..(MAX_RAW_TOKENS + 10_000) {
            body.push_str(&format!("word{i:06} "));
        }
        let email = format!("From: x@y.com\r\nSubject: s\r\n\r\n{body}");
        let tokens = tokenize(email.as_bytes());
        assert!(
            tokens.len() <= MAX_RAW_TOKENS + 100,
            "cap not enforced: {} tokens",
            tokens.len()
        );
    }

    #[test]
    fn test_tokenize_simple_email() {
        let email = b"From: sender@example.com\r\n\
                       Subject: Test Email\r\n\
                       Content-Type: text/plain\r\n\
                       \r\n\
                       Hello world, this is a test message.\r\n";
        let tokens = tokenize(email);
        assert!(!tokens.is_empty());
        // Should have subject tokens
        assert!(tokens.iter().any(|t| t.starts_with("h:subject:")));
        // Should have from tokens
        assert!(tokens.iter().any(|t| t.starts_with("h:from:")));
        // Should have body tokens
        assert!(tokens.iter().any(|t| t.starts_with("b:")));
    }

    #[test]
    fn test_subject_bigrams() {
        let email = b"Subject: make money fast\r\n\r\nbody\r\n";
        let tokens = tokenize(email);
        assert!(tokens.iter().any(|t| t == "h:subject:make_money"));
        assert!(tokens.iter().any(|t| t == "h:subject:money_fast"));
    }

    #[test]
    fn test_extract_urls_from_text() {
        let text = "Visit https://example.com/page?x=1 or http://spam.biz/buy now.\nNot a url: httpfoo";
        let urls = extract_urls_from_text(text, MAX_TOKEN_LEN);
        assert_eq!(urls, vec!["https://example.com/page", "http://spam.biz/buy"]);
    }

    #[test]
    fn test_extract_urls_from_text_multibyte_boundary() {
        // The exact production URL shape that panicked v0.2.0 (byte index 40
        // inside '圳'). Must truncate at a char boundary, never panic.
        let text = "click http://a.spread48.com/74987-2139538/深圳思齐软件有限公司.newsletter/forward.aspx now";
        let urls = extract_urls_from_text(text, MAX_TOKEN_LEN);
        assert_eq!(urls.len(), 1);
        assert!(urls[0].len() <= MAX_TOKEN_LEN);
        assert!(urls[0].starts_with("http://a.spread48.com/"));
    }

    #[test]
    fn test_text_body_urls_tokenized() {
        let email = b"From: x@y.com\r\nSubject: hi\r\nContent-Type: text/plain\r\n\r\nGo to https://example.com/offer today\r\n";
        let tokens = tokenize(email);
        assert!(
            tokens.iter().any(|t| t == "u:https://example.com/offer"),
            "expected u: token from plain-text body, got {tokens:?}"
        );
    }

    #[test]
    fn test_normalize_url() {
        assert_eq!(
            normalize_url("https://Example.COM/Path?track=1#frag", MAX_TOKEN_LEN),
            "https://example.com/path"
        );
    }

    #[test]
    fn test_decompose_host() {
        assert_eq!(
            decompose_host("partners.intrepidtravel.com"),
            Some(("intrepidtravel.com".into(), "intrepidtravel".into()))
        );
        assert_eq!(
            decompose_host("stay.orh.outrigger.com"),
            Some(("outrigger.com".into(), "outrigger".into()))
        );
        assert_eq!(
            decompose_host("survey.qatarairways.com.qa"),
            Some(("qatarairways.com.qa".into(), "qatarairways".into()))
        );
        assert_eq!(
            decompose_host("travellerschoice.com.au"),
            Some(("travellerschoice.com.au".into(), "travellerschoice".into()))
        );
        assert_eq!(
            decompose_host("cruising.org"),
            Some(("cruising.org".into(), "cruising".into()))
        );
        // IP literal and single-label → no decomposition
        assert_eq!(decompose_host("192.168.1.1"), None);
        assert_eq!(decompose_host("localhost"), None);
    }

    #[test]
    fn test_sender_brand_anchor_emitted() {
        // ESP-style rotating subdomain From: the durable brand anchor must appear
        // so one ham retrain generalizes across the supplier's sending domains.
        let email = b"From: Outrigger <stay@orh.outrigger.com>\r\nSubject: hi\r\n\r\nbody\r\n";
        let tokens = tokenize(email);
        assert!(tokens.iter().any(|t| t == "h:from:stay@orh.outrigger.com"));
        assert!(tokens.iter().any(|t| t == "h:from:orh.outrigger.com"));
        assert!(tokens.iter().any(|t| t == "h:from:outrigger.com"), "registrable anchor missing: {tokens:?}");
        assert!(tokens.iter().any(|t| t == "h:from:outrigger"), "brand anchor missing: {tokens:?}");
    }

    #[test]
    fn test_reply_to_anchor() {
        let email = b"From: ESP <bounce@mail123.sendgrid.net>\r\nReply-To: agent@tourradar.com\r\nSubject: x\r\n\r\nbody\r\n";
        let tokens = tokenize(email);
        assert!(tokens.iter().any(|t| t == "h:replyto:agent@tourradar.com"));
        assert!(tokens.iter().any(|t| t == "h:replyto:tourradar"), "reply-to brand anchor missing: {tokens:?}");
    }

    #[test]
    fn test_presence_dedup_repeated_words() {
        // Lock in presence (Bernoulli) counting: a word repeated many times in one
        // message yields exactly ONE token. Regressing to frequency counting would
        // inflate repeated bulk-ESP/template tokens and worsen the supplier FP.
        let email = b"From: x@y.com\r\nSubject: s\r\n\r\nunsubscribe unsubscribe unsubscribe UNSUBSCRIBE unsubscribe\r\n";
        let tokens = tokenize(email);
        let count = tokens.iter().filter(|t| *t == "b:unsubscribe").count();
        assert_eq!(count, 1, "repeated word must produce a single token: {tokens:?}");
    }

    // ---- anti-evasion features (all default-off; opt in per config) ----

    fn cfg(f: impl Fn(&mut TokenizerConfig)) -> TokenizerConfig {
        let mut c = TokenizerConfig::default();
        f(&mut c);
        c
    }

    #[test]
    fn test_features_off_by_default() {
        let c = TokenizerConfig::default();
        assert!(!c.tld_feature && !c.homoglyph_fold && !c.brand_mismatch && !c.auth_tokens);
        // A homoglyph/throwaway-TLD message must tokenize identically to before
        // when no feature flag is set — production behaviour is unchanged.
        let email = "From: WB <at@spammer.life>\r\nSubject: your accᴏunt\r\n\r\nciick now\r\n".as_bytes();
        let toks = tokenize(email);
        assert!(!toks.iter().any(|t| t.starts_with("x:")));
    }

    #[test]
    fn test_tld_feature() {
        let email = b"From: WB <at@spammer.life>\r\nSubject: hi\r\n\r\nbody\r\n";
        let toks = tokenize_with_config(email, &cfg(|c| c.tld_feature = true));
        assert!(toks.iter().any(|t| t == "x:tld:life"), "{toks:?}");
    }

    #[test]
    fn test_tld_two_level_stays_neutral_token() {
        let email = b"From: Flybuys <hello@flybuys.com.au>\r\nSubject: hi\r\n\r\nbody\r\n";
        let toks = tokenize_with_config(email, &cfg(|c| c.tld_feature = true));
        assert!(toks.iter().any(|t| t == "x:tld:com.au"), "{toks:?}");
    }

    #[test]
    fn test_effective_tld() {
        assert_eq!(effective_tld("spammer.life").as_deref(), Some("life"));
        assert_eq!(effective_tld("flybuys.com.au").as_deref(), Some("com.au"));
        assert_eq!(effective_tld("apple.com").as_deref(), Some("com"));
        assert_eq!(effective_tld("sub.survey.qatarairways.com.qa").as_deref(), Some("com.qa"));
        assert_eq!(effective_tld("192.168.0.1"), None);
        assert_eq!(effective_tld("localhost"), None);
    }

    #[test]
    fn test_homoglyph_fold_small_caps() {
        // `accᴏunt` (U+1D0F) must fold onto the trained `account`.
        let email = "From: x@y.com\r\nSubject: your accᴏunt\r\n\r\nreview your accᴏunt now\r\n".as_bytes();
        let toks = tokenize_with_config(email, &cfg(|c| c.homoglyph_fold = true));
        assert!(toks.iter().any(|t| t == "b:account"), "skeleton missing: {toks:?}");
        assert!(toks.iter().any(|t| t == "h:subject:account"), "{toks:?}");
        assert!(toks.iter().any(|t| t == "x:confusable"), "{toks:?}");
    }

    #[test]
    fn test_homoglyph_fold_math_alnum() {
        // `𝖢ustomer 𝖱ewards` (Math sans-serif U+1D5A2/U+1D5B1) → customer/rewards.
        let email = "From: x@y.com\r\nSubject: hi\r\n\r\n𝖢ustomer 𝖱ewards waiting\r\n".as_bytes();
        let toks = tokenize_with_config(email, &cfg(|c| c.homoglyph_fold = true));
        assert!(toks.iter().any(|t| t == "b:customer"), "{toks:?}");
        assert!(toks.iter().any(|t| t == "b:rewards"), "{toks:?}");
    }

    #[test]
    fn test_homoglyph_fold_letterlike_hole() {
        // Script capital H lives at U+210B (a reserved-hole letter), not in the
        // Math-Alphanumeric block — must still fold to `h`.
        assert_eq!(fold_skeleton("ℋello").as_deref(), Some("hello"));
    }

    #[test]
    fn test_fold_leaves_accented_latin_and_cjk_alone() {
        // Legit accented Latin / CJK must NOT fold and must NOT flag — this is
        // the false-positive guard for intl senders.
        assert_eq!(fold_skeleton("café"), None);
        assert_eq!(fold_skeleton("Müller"), None);
        assert_eq!(fold_skeleton("東京"), None);
        let email = "From: x@y.com\r\nSubject: réservation\r\n\r\nMüller café 東京\r\n".as_bytes();
        let toks = tokenize_with_config(email, &cfg(|c| c.homoglyph_fold = true));
        assert!(!toks.iter().any(|t| t == "x:confusable"), "{toks:?}");
    }

    #[test]
    fn test_mixed_script_flag() {
        // Cyrillic 'а' spliced into Latin "pаypal".
        let email = "From: x@y.com\r\nSubject: hi\r\n\r\nsecure pаypal login\r\n".as_bytes();
        let toks = tokenize_with_config(email, &cfg(|c| c.homoglyph_fold = true));
        assert!(toks.iter().any(|t| t == "x:mixedscript"), "{toks:?}");
        // ...and it folds onto the real word.
        assert!(toks.iter().any(|t| t == "b:paypal"), "{toks:?}");
    }

    #[test]
    fn test_brand_mismatch_flag() {
        // "AIdi" (ASCII cap-I for l) from a throwaway domain → brandmiss:aldi.
        let email = b"From: AIdi Administrator <amkfm@throwaway.info>\r\nSubject: hi\r\n\r\nbody\r\n";
        let toks = tokenize_with_config(email, &cfg(|c| c.brand_mismatch = true));
        assert!(toks.iter().any(|t| t == "x:brandmiss:aldl"), "{toks:?}");
        assert!(toks.iter().any(|t| t.starts_with("h:fromname:")), "{toks:?}");
    }

    #[test]
    fn test_brand_mismatch_not_fired_for_legit_brand_domain() {
        // Real Apple from apple.com must NOT flag (domain brand matches).
        let email = b"From: Apple <no-reply@apple.com>\r\nSubject: receipt\r\n\r\nbody\r\n";
        let toks = tokenize_with_config(email, &cfg(|c| c.brand_mismatch = true));
        assert!(!toks.iter().any(|t| t.starts_with("x:brandmiss:")), "{toks:?}");
    }

    #[test]
    fn test_auth_tokens_present() {
        let email = b"From: x@y.com\r\nAuthentication-Results: mx.example.com; spf=fail smtp.mailfrom=y.com; dkim=none; dmarc=fail\r\nSubject: hi\r\n\r\nbody\r\n";
        let toks = tokenize_with_config(email, &cfg(|c| c.auth_tokens = true));
        assert!(toks.iter().any(|t| t == "x:auth:spf_fail"), "{toks:?}");
        assert!(toks.iter().any(|t| t == "x:auth:dkim_none"), "{toks:?}");
        assert!(toks.iter().any(|t| t == "x:auth:dmarc_fail"), "{toks:?}");
    }

    #[test]
    fn test_auth_tokens_absent_emit_nothing() {
        // No Authentication-Results → no x:auth tokens (never a "missing" penalty).
        let email = b"From: x@y.com\r\nSubject: hi\r\n\r\nbody\r\n";
        let toks = tokenize_with_config(email, &cfg(|c| c.auth_tokens = true));
        assert!(!toks.iter().any(|t| t.starts_with("x:auth:")), "{toks:?}");
    }
}
