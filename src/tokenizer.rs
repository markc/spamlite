// Copyright 2026 Mark Constable <mc@netserva.org>
// SPDX-License-Identifier: MIT

use mail_parser::{Addr, HeaderName, HeaderValue, Host, MessageParser};

const MIN_TOKEN_LEN: usize = 3;
const MAX_TOKEN_LEN: usize = 40;

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
        let words: Vec<String> = extract_words(subject)
            .into_iter()
            .filter(|w| valid(w))
            .collect();

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
        for header in message.parts[0].headers.iter() {
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

    // Body parts
    for part in message.text_bodies() {
        let text = part.text_contents().unwrap_or_default();
        for w in extract_words(&text) {
            if valid(&w) {
                tokens.push(format!("b:{w}"));
            }
        }
    }

    for part in message.html_bodies() {
        let html = part.text_contents().unwrap_or_default();

        // Extract URLs from HTML before stripping
        for url in extract_urls(&html, config.max_len) {
            if valid(&url) {
                tokens.push(format!("u:{url}"));
            }
        }

        // Strip HTML and tokenize text
        let text = nanohtml2text::html2text(&html);
        for w in extract_words(&text) {
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
    }
}

/// Fallback tokenizer for unparseable messages — treat as raw text
fn tokenize_fallback(raw: &[u8], config: &TokenizerConfig) -> Vec<String> {
    let text = String::from_utf8_lossy(raw);
    let mut tokens: Vec<String> = extract_words(&text)
        .into_iter()
        .filter(|w| w.len() >= config.min_len && w.len() <= config.max_len)
        .map(|w| format!("b:{w}"))
        .collect();
    tokens.sort_unstable();
    tokens.dedup();
    tokens
}

/// Split text into lowercase words
fn extract_words(text: &str) -> Vec<String> {
    text.split(|c: char| !c.is_alphanumeric() && c != '.' && c != '-' && c != '_' && c != '@')
        .filter(|s| !s.is_empty())
        .map(|s| {
            // Trim leading/trailing punctuation
            s.trim_matches(|c: char| c == '.' || c == '-' || c == '_')
                .to_lowercase()
        })
        .filter(|s| !s.is_empty())
        .collect()
}

/// Extract URLs from HTML content (href and src attributes)
fn extract_urls(html: &str, max_len: usize) -> Vec<String> {
    let mut urls = Vec::new();
    // Simple regex-free URL extraction from href="..." and src="..."
    for attr in ["href=\"", "src=\"", "href='", "src='"] {
        let quote = if attr.ends_with('"') { '"' } else { '\'' };
        let mut search = html;
        while let Some(pos) = search.find(attr) {
            let start = pos + attr.len();
            search = &search[start..];
            if let Some(end) = search.find(quote) {
                let url = &search[..end];
                if url.starts_with("http://") || url.starts_with("https://") {
                    // Normalize: lowercase, strip tracking params, keep domain+path
                    let normalized = normalize_url(url, max_len);
                    if !normalized.is_empty() {
                        urls.push(normalized);
                    }
                }
                search = &search[end..];
            }
        }
    }
    urls
}

/// Normalize a URL for tokenization — keep scheme+host+path, drop query
fn normalize_url(url: &str, max_len: usize) -> String {
    let url = url.to_lowercase();
    // Strip query string and fragment
    let url = url.split('?').next().unwrap_or(&url);
    let url = url.split('#').next().unwrap_or(url);
    // Truncate to max token length
    if url.len() > max_len {
        url[..max_len].to_string()
    } else {
        url.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_words() {
        let words = extract_words("Hello World! This is a TEST-email_token.");
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
    fn test_normalize_url() {
        assert_eq!(
            normalize_url("https://Example.COM/Path?track=1#frag", MAX_TOKEN_LEN),
            "https://example.com/path"
        );
    }
}
