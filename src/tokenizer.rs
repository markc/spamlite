// Copyright 2026 Mark Constable <mc@netserva.org>
// SPDX-License-Identifier: MIT

use mail_parser::{Host, MessageParser};

const MIN_TOKEN_LEN: usize = 3;
const MAX_TOKEN_LEN: usize = 40;

/// Convert a mail-parser Host to a lowercase string
fn host_to_string(host: &Host<'_>) -> String {
    match host {
        Host::Name(name) => name.to_lowercase(),
        Host::IpAddr(ip) => ip.to_string(),
    }
}

/// Extract tokens from a raw email message (RFC 5322)
pub fn tokenize(raw: &[u8]) -> Vec<String> {
    let parser = MessageParser::default();
    let message = match parser.parse(raw) {
        Some(m) => m,
        None => return tokenize_fallback(raw),
    };

    let mut tokens = Vec::with_capacity(1024);

    // Subject header — individual tokens + bigrams
    if let Some(subject) = message.subject() {
        let words: Vec<String> = extract_words(subject)
            .into_iter()
            .filter(|w| is_valid_token(w))
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
            if let Some(email) = addr.address() {
                let email_lower = email.to_lowercase();
                tokens.push(format!("h:from:{email_lower}"));
                // Also tokenize domain
                if let Some(domain) = email_lower.split('@').nth(1) {
                    tokens.push(format!("h:from:{domain}"));
                }
            }
        }
    }

    // Received header (most recent) — extract hostnames/IPs
    if let Some(received) = message.received() {
        if let Some(from_host) = received.from() {
            let host = host_to_string(from_host);
            if is_valid_token(&host) {
                tokens.push(format!("h:received:{host}"));
            }
        }
        if let Some(by_host) = received.by() {
            let host = host_to_string(by_host);
            if is_valid_token(&host) {
                tokens.push(format!("h:received:{host}"));
            }
        }
    }

    // Body parts
    for part in message.text_bodies() {
        let text = part.text_contents().unwrap_or_default();
        for w in extract_words(&text) {
            if is_valid_token(&w) {
                tokens.push(format!("b:{w}"));
            }
        }
    }

    for part in message.html_bodies() {
        let html = part.text_contents().unwrap_or_default();

        // Extract URLs from HTML before stripping
        for url in extract_urls(&html) {
            if is_valid_token(&url) {
                tokens.push(format!("u:{url}"));
            }
        }

        // Strip HTML and tokenize text
        let text = nanohtml2text::html2text(&html);
        for w in extract_words(&text) {
            if is_valid_token(&w) {
                tokens.push(format!("b:{w}"));
            }
        }
    }

    // Deduplicate — we only care about presence, not frequency within a single message
    tokens.sort_unstable();
    tokens.dedup();
    tokens
}

/// Fallback tokenizer for unparseable messages — treat as raw text
fn tokenize_fallback(raw: &[u8]) -> Vec<String> {
    let text = String::from_utf8_lossy(raw);
    let mut tokens: Vec<String> = extract_words(&text)
        .into_iter()
        .filter(|w| is_valid_token(w))
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
fn extract_urls(html: &str) -> Vec<String> {
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
                    let normalized = normalize_url(url);
                    if is_valid_token(&normalized) {
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
fn normalize_url(url: &str) -> String {
    let url = url.to_lowercase();
    // Strip query string and fragment
    let url = url.split('?').next().unwrap_or(&url);
    let url = url.split('#').next().unwrap_or(url);
    // Truncate to max token length
    if url.len() > MAX_TOKEN_LEN {
        url[..MAX_TOKEN_LEN].to_string()
    } else {
        url.to_string()
    }
}

/// Check if a token is within valid length bounds
fn is_valid_token(s: &str) -> bool {
    let len = s.len();
    len >= MIN_TOKEN_LEN && len <= MAX_TOKEN_LEN
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
    fn test_is_valid_token() {
        assert!(!is_valid_token("ab"));
        assert!(is_valid_token("abc"));
        assert!(is_valid_token(&"a".repeat(40)));
        assert!(!is_valid_token(&"a".repeat(41)));
    }

    #[test]
    fn test_extract_urls() {
        let html = r#"<a href="https://example.com/page">click</a>"#;
        let urls = extract_urls(html);
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
            normalize_url("https://Example.COM/Path?track=1#frag"),
            "https://example.com/path"
        );
    }
}
