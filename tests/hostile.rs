// SPDX-FileCopyrightText: 2026 Mark Constable <mc@mixos.dev>
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Hostile-input regressions through the public tokenizer entry points. Each
//! input here once crashed, or was reported to crash, the delivery path. The
//! requirement is only that tokenizing returns: a panic is caught by the CLI's
//! fail-open guard and delivers the message as GOOD, and a stack overflow
//! aborts the process with no verdict at all.

use spamlite::tokenizer::{tokenize, tokenize_for_training, TokenizerConfig};

fn html_message(body: &str) -> Vec<u8> {
    format!(
        "From: sender@example.com\r\nTo: user@example.net\r\nSubject: hello there\r\n\
         MIME-Version: 1.0\r\nContent-Type: text/html; charset=utf-8\r\n\r\n{body}\r\n"
    )
    .into_bytes()
}

#[test]
fn unclosed_anchor_flood_does_not_overflow_the_stack() {
    let raw = html_message(&("<a>".repeat(200_000) + "visible payload words"));
    let tokens = tokenize(&raw);
    assert!(tokens.iter().any(|t| t == "b:payload"));
}

#[test]
fn repeated_empty_tags_finish_promptly() {
    let started = std::time::Instant::now();
    for body in [
        "<a></a>".repeat(150_000),
        "<style></style>".repeat(80_000),
        "<".repeat(1_000_000),
    ] {
        let _ = tokenize(&html_message(&body));
    }
    assert!(
        started.elapsed() < std::time::Duration::from_secs(30),
        "took {:?}",
        started.elapsed()
    );
}

/// mail-parser 0.11.5 was reported to panic in its `Received` parser on input
/// ending in the folding whitespace of a `Received:` line.
#[test]
fn received_header_ending_in_folding_whitespace_does_not_panic() {
    for raw in [
        &b"Received: x\r\n\t"[..],
        &b"Received: x\r\n "[..],
        &b"Received: from a by b\r\n\t"[..],
        &b"Subject: s\r\nReceived: from mail.example.com\r\n\t"[..],
        &b"Received:\r\n\t"[..],
        &b"Received: x\n\t"[..],
    ] {
        let _ = tokenize(raw);
        let _ = tokenize_for_training(raw, &TokenizerConfig::default());
    }
}

#[test]
fn degenerate_inputs_do_not_panic() {
    let inputs: Vec<Vec<u8>> = vec![
        Vec::new(),
        b"\r\n".to_vec(),
        b"\0\0\0".to_vec(),
        vec![0xff; 4096],
        b"Subject: \xff\xfe\xfd\r\n\r\n\xc3\x28".to_vec(),
        b"Content-Type: multipart/mixed; boundary=\"\"\r\n\r\n--\r\n--\r\n".to_vec(),
        b"Content-Type: multipart/mixed; boundary=b\r\n\r\n--b\r\n--b\r\n--b--".to_vec(),
        b"Content-Type: text/html\r\nContent-Transfer-Encoding: base64\r\n\r\n====".to_vec(),
        html_message("&#xFFFFFFFF; &#0; &; &#; &#x; <a href=\"&\">&</a>"),
    ];
    for raw in &inputs {
        let _ = tokenize(raw);
    }
}
