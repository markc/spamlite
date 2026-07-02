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
}

impl Default for TokenizerConfig {
    fn default() -> Self {
        TokenizerConfig {
            min_len: MIN_TOKEN_LEN,
            max_len: MAX_TOKEN_LEN,
            expanded_headers: false,
        }
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
            tokens.push(format!("h:subject:{w}"));
        }

        // Bigrams for subject
        for pair in words.windows(2) {
            tokens.push(format!("h:subject:{}_{}", pair[0], pair[1]));
        }
    }

    // From header
    if let Some(from) = message.from() {
        for addr in from.iter() {
            push_addr(&mut tokens, "h:from:", addr, &valid);
        }
    }

    // Reply-To / Sender — carry the real supplier identity when a bulk ESP
    // rewrites From into its own envelope domain. Decomposed to brand anchors
    // by push_addr, same as From. Default-on: additive per-sender signal.
    if let Some(reply_to) = message.reply_to() {
        for addr in reply_to.iter() {
            push_addr(&mut tokens, "h:replyto:", addr, &valid);
        }
    }
    if let Some(sender) = message.sender() {
        for addr in sender.iter() {
            push_addr(&mut tokens, "h:sender:", addr, &valid);
        }
    }

    // To / Cc headers (expanded coverage)
    if config.expanded_headers {
        if let Some(to) = message.to() {
            for addr in to.iter() {
                push_addr(&mut tokens, "h:to:", addr, &valid);
            }
        }
        if let Some(cc) = message.cc() {
            for addr in cc.iter() {
                push_addr(&mut tokens, "h:cc:", addr, &valid);
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
                tokens.push(format!("b:{w}"));
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
                tokens.push(format!("b:{w}"));
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
) {
    let Some(email) = addr.address.as_deref() else { return };
    let email_lower = email.to_lowercase();
    if valid(&email_lower) {
        tokens.push(format!("{prefix}{email_lower}"));
    }
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
}
