// SPDX-FileCopyrightText: 2026 Mark Constable <mc@mixos.dev>
// SPDX-License-Identifier: MIT OR Apache-2.0

//! HTML to text for the tokenizer, safe on hostile input.
//!
//! This is `nanohtml2text::html2text` with the same output on ordinary HTML,
//! restructured so that an attacker-controlled body can neither exhaust the
//! stack nor run in quadratic time. The upstream function:
//!
//! - recursed once per `<a>` whose content held another `<a>`, so a body of
//!   `<a>` repeated some tens of thousands of times overflowed the stack. A
//!   stack overflow aborts the process: it is not a panic, so the fail-open
//!   `catch_unwind` guards never ran and sieve received no verdict;
//! - lowercased a copy of the whole remaining document for every `<a>`,
//!   `<head>`, `<script>` and `<style>` tag;
//! - rescanned the whole remainder for `>` at every `<` once none was left.
//!
//! Here anchor nesting is capped at [`MAX_ANCHOR_DEPTH`], closing tags are
//! found by an in-place ASCII-case-insensitive search, an anchor nested inside
//! another never searches at all (its enclosing content is cut at the first
//! `</a>`, so none can be present), and a failed `>` search is remembered.
//! Entity decoding is still upstream's, reached through tag-free segments.

/// At most this many anchors are rendered inside one another. An anchor with
/// this many enclosing anchors already is treated as an ordinary tag: the tag
/// is dropped and its content kept, without the ` (href)` suffix. Nested anchors
/// are invalid HTML, so only malformed or hostile input reaches the cap.
const MAX_ANCHOR_DEPTH: usize = 8;

/// Convert an HTML string to plain text.
pub(crate) fn html_to_text(html: &str) -> String {
    // Collapse every whitespace run to one space, as upstream does first.
    let collapsed = html.split_whitespace().collect::<Vec<_>>().join(" ");
    render(&collapsed, 0)
}

/// Decode HTML entities in a tag-free, whitespace-collapsed segment using
/// upstream's decoder and entity table.
///
/// `html2text` on input without `<` is exactly whitespace collapse followed by
/// entity decoding. The collapse would trim a leading or trailing space that
/// the caller needs kept, so each such edge is shielded by a sentinel that is
/// neither whitespace nor entity syntax, and removed again afterwards.
fn decode_entities(seg: &str) -> String {
    if !seg.contains('&') {
        return seg.to_string();
    }
    const SENTINEL: char = '\u{1}';
    let lead = seg.starts_with(' ');
    let trail = seg.ends_with(' ');
    let mut buf = String::with_capacity(seg.len() + 2);
    if lead {
        buf.push(SENTINEL);
    }
    buf.push_str(seg);
    if trail {
        buf.push(SENTINEL);
    }
    let decoded = nanohtml2text::html2text(&buf);
    let mut out = decoded.as_str();
    if lead {
        out = out.strip_prefix(SENTINEL).unwrap_or(out);
    }
    if trail {
        out = out.strip_suffix(SENTINEL).unwrap_or(out);
    }
    out.to_string()
}

/// Byte offset of the first ASCII-case-insensitive match of `needle`, which
/// must be ASCII and start with `<` so every match lies on a char boundary.
fn find_ascii_ci(hay: &str, needle: &[u8]) -> Option<usize> {
    hay.as_bytes()
        .windows(needle.len())
        .position(|w| w.eq_ignore_ascii_case(needle))
}

/// Render whitespace-collapsed `html`. `depth` is the number of enclosing
/// anchors; at `depth > 0` the input is anchor content and holds no `</a>`.
fn render(html: &str, depth: usize) -> String {
    let mut out = String::new();
    let mut index = 0;
    // Set once a search for '>' fails: no later search in this input can succeed.
    let mut no_gt = false;
    while index < html.len() {
        let Some(pos) = html[index..].find('<') else {
            out.push_str(&decode_entities(&html[index..]));
            break;
        };
        if pos > 0 {
            out.push_str(&decode_entities(&html[index..index + pos]));
            index += pos;
        }
        index += 1; // skip the '<'
        let (text, advance) = if no_gt {
            ("<".to_string(), 0)
        } else {
            handle_tag(&html[index..], depth, &mut no_gt)
        };
        if !text.is_empty() {
            if out.ends_with("\r\n\r\n") || out.is_empty() {
                out.push_str(text.trim_start());
            } else {
                out.push_str(&text);
            }
        }
        index += advance;
    }
    out
}

/// Handle the tag starting just after a `<`. Returns the text it produces and
/// the number of bytes to skip.
fn handle_tag(s: &str, depth: usize, no_gt: &mut bool) -> (String, usize) {
    let Some((tag_content, rest)) = s.split_once('>') else {
        *no_gt = true;
        return ("<".to_string(), 0);
    };
    if tag_content.is_empty() {
        // "<>" is not a tag: the '<' is ordinary text.
        return ("<".to_string(), 0);
    }

    let (tag_name, attribs) = tag_content
        .split_once(char::is_whitespace)
        .unwrap_or((tag_content, ""));

    match tag_name.to_lowercase().as_str() {
        "a" => {
            if depth >= MAX_ANCHOR_DEPTH {
                return (String::new(), tag_content.len() + 1);
            }
            let href = attribs
                .split_ascii_whitespace()
                .find_map(|attr| {
                    let (key, value) = attr.split_once('=')?;
                    key.eq_ignore_ascii_case("href")
                        .then(|| value.trim_matches(['"', '\''].as_ref()))
                })
                .filter(|href| !href.starts_with("javascript:"))
                // A '<' inside an href cannot go through the tag-free decoder;
                // such a value is kept undecoded.
                .map(|href| {
                    if href.contains('<') {
                        href.to_string()
                    } else {
                        decode_entities(href)
                    }
                });

            let end_tag_start = if depth > 0 {
                rest.len()
            } else {
                find_ascii_ci(rest, b"</a>").unwrap_or(rest.len())
            };
            let closing_tag_len = if end_tag_start < rest.len() { 4 } else { 0 };
            let total_skip = tag_content.len() + 1 + end_tag_start + closing_tag_len;
            let content_text = render(rest[..end_tag_start].trim(), depth + 1);
            let link = match (href, content_text.is_empty()) {
                (Some(href_value), false) if content_text != href_value => {
                    format!("{content_text} ({href_value})")
                }
                (Some(href_value), _) => href_value,
                (_, false) => content_text,
                _ => String::new(),
            };
            (link, total_skip)
        }

        "br" | "br/" | "li" | "/ol" | "/ul" => ("\r\n".to_string(), tag_content.len() + 1),

        "p" | "h1" | "h2" | "h3" | "h4" | "h5" | "h6" | "/h1" | "/h2" | "/h3" | "/h4" | "/h5"
        | "/h6" => ("\r\n\r\n".to_string(), tag_content.len() + 1),

        // Dropped along with their content.
        name @ ("head" | "script" | "style") => {
            let closing_tag = format!("</{name}>");
            let end_tag_start = find_ascii_ci(rest, closing_tag.as_bytes()).unwrap_or(rest.len());
            let closing_tag_len = if end_tag_start < rest.len() {
                closing_tag.len()
            } else {
                0
            };
            (
                String::new(),
                tag_content.len() + 1 + end_tag_start + closing_tag_len,
            )
        }

        "!--" => {
            let end = s.find("-->").map_or(s.len(), |n| n + 3);
            (String::new(), end)
        }

        // Any other tag is dropped and its content kept.
        _ => (String::new(), tag_content.len() + 1),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Ordinary HTML must come out byte-identical to upstream, so swapping the
    /// stripper cannot move a score on legitimate mail.
    #[test]
    fn matches_upstream_on_ordinary_html() {
        let cases = [
            "",
            "blah",
            "<div></div>",
            "<div>simple text</div>",
            "click <a href=\"test\">here</a>",
            "click <a href=\"test\">test</a>",
            "click <a class=\"x\" href=\"test\">here</a>",
            "click <a href=\"ents/&apos;x&apos;\">here</a>",
            "click <a href=\"javascript:void(0)\">here</a>",
            "click <a href=\"test\"><span>here</span> or here</a>",
            "click <A HREF=\"http://example.com/2n4wXRs\">news</A> now",
            "<a rel=\"x\" href=\"/wiki/yet#English\" title=\"yet\">yet</a>, <a href=\"/b\">not yet</a>",
            "<a href='/x'> spaced </a> after",
            "<a>no href</a> tail",
            "<a href=\"/empty\"></a>tail",
            "open <a href=\"/never\">never closed and <b>bold</b>",
            "strong <strong>text</strong>",
            "some <div id=\"a\" class=\"b\">div</div>",
            "should  ignore   more spaces",
            "a\nb\nc",
            "should \nignore \r\nnew lines",
            "two<br>line<br/>breaks",
            "<p>two</p><p>paragraphs</p>",
            "<p>  lead</p>  <p> <a href=\"/x\"> y</a></p>",
            "First<h2>Second</h2>next section",
            "<h7>Not Header</h7>next section",
            "two&nbsp;&nbsp;spaces",
            "&copy; 2017 K3A",
            "&lt;printtag&gt;",
            "pay in &cent;, &pound;, &yen; or &euro;?",
            "Tom & Jerry is not an entity",
            "this &neither; as you see",
            "fish &amp; chips",
            "fish &amp <b>chips</b> &amp; <i>peas</i> &amp",
            " &amp; <b> &amp; </b> &amp; ",
            "list of items<ul><li>One</li><li>Two</li><li>Three</li></ul>",
            "&#8268; decimal and hex entities supported &#x204D;",
            "&#39;single quotes&#39; and &#52765;",
            "&#8203;zero&#8203;width",
            "<html><head><title>Good</title></head><body>x</body>",
            "<HTML><HEAD><TITLE>Good</TITLE></HEAD><BODY>x</BODY>",
            "we are not <script type=\"javascript\"></script>interested in scripts",
            "<style>p { color: red }</style>shown<STYLE>x</STYLE> too",
            "<style>never closed, all dropped",
            "a <!-- comment --> b <!--tight--> c",
            "a <!-- never closed",
            "<aa>hello</aa>",
            "<aa >hello</aa>",
            "<aa x=\"1\">hello</aa>",
            "&hellip",
            "1 < 2 and 3 > 2",
            "empty <> tag and a lone < at the end",
            "caf\u{e9} <b>na\u{ef}ve</b> \u{4e2d}\u{6587}<br>\u{a0}nbsp",
            "<table><tr><td>cell&nbsp;one</td><td><a href=\"https://example.com/a?b=1&amp;c=2\">Shop now</a></td></tr></table>",
        ];
        for case in cases {
            assert_eq!(
                html_to_text(case),
                nanohtml2text::html2text(case),
                "diverged from upstream on {case:?}"
            );
        }
    }

    /// The regression for the stack overflow: upstream recursed once per
    /// unclosed anchor and aborted the process on this input.
    #[test]
    fn deeply_nested_anchors_do_not_overflow_the_stack() {
        let html = "<a>".repeat(200_000) + "payload";
        assert_eq!(html_to_text(&html), "payload");

        let html = "<a href=\"http://example.com/x\">w ".repeat(100_000);
        let text = html_to_text(&html);
        assert!(text.contains("http://example.com/x"));
    }

    /// Inputs on which upstream was quadratic must finish promptly. Each is a
    /// megabyte or more; quadratic behaviour here takes minutes, not seconds.
    #[test]
    fn pathological_inputs_run_in_linear_time() {
        use std::time::{Duration, Instant};

        let inputs = [
            "<a></a>".repeat(200_000),
            "<a href=\"/x\">y</a> ".repeat(100_000),
            "<style></style>".repeat(100_000),
            "<script>x</script><head>y</head>".repeat(50_000),
            "<".repeat(1_500_000),
            "< b ".repeat(400_000),
            "<a>".repeat(100_000) + &"</a>".repeat(100_000),
            "<a><style>".repeat(100_000),
            "<!-- ".repeat(300_000),
        ];
        for input in &inputs {
            let started = Instant::now();
            let _ = html_to_text(input);
            assert!(
                started.elapsed() < Duration::from_secs(20),
                "took {:?} on {} bytes starting {:?}",
                started.elapsed(),
                input.len(),
                &input[..12]
            );
        }
    }

    #[test]
    fn anchors_past_the_depth_cap_keep_their_text() {
        let html = "<a href=\"/h\">t ".repeat(MAX_ANCHOR_DEPTH + 3);
        let text = html_to_text(&html);
        assert_eq!(text.matches('t').count(), MAX_ANCHOR_DEPTH + 3);
        assert_eq!(text.matches("/h").count(), MAX_ANCHOR_DEPTH);
    }
}
