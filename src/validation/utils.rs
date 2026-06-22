use std::sync::LazyLock;

use tl::{HTMLTag, Node, Parser, ParserOptions};

use crate::validation::SerializableCaptures;

// Re-export from the scanner crate so the rest of this module can use it.
pub use kingfisher_scanner::validation::{check_url_resolvable, is_ssrf_safe_ip};

static HTML_PARSER_OPTIONS: LazyLock<ParserOptions> = LazyLock::new(ParserOptions::default);

fn collapse_whitespace(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let mut prev_was_whitespace = false;

    for ch in input.chars() {
        if ch.is_whitespace() {
            if !prev_was_whitespace {
                out.push(' ');
                prev_was_whitespace = true;
            }
        } else {
            out.push(ch);
            prev_was_whitespace = false;
        }
    }

    out.trim().to_string()
}

fn decode_common_html_entities(input: &str) -> String {
    let mut decoded = input.to_string();
    const ENTITY_REPLACEMENTS: [(&str, &str); 8] = [
        ("&nbsp;", " "),
        ("&#160;", " "),
        ("&amp;", "&"),
        ("&lt;", "<"),
        ("&gt;", ">"),
        ("&quot;", "\""),
        ("&#34;", "\""),
        ("&#39;", "'"),
    ];

    for (entity, replacement) in ENTITY_REPLACEMENTS {
        decoded = decoded.replace(entity, replacement);
    }

    decoded
}

fn collect_visible_text_from_tag(tag: &HTMLTag<'_>, parser: &Parser<'_>, out: &mut String) {
    for handle in tag.children().top().iter() {
        let Some(node) = handle.get(parser) else {
            continue;
        };

        collect_visible_text(node, parser, out);
    }
}

fn collect_visible_text(node: &Node<'_>, parser: &Parser<'_>, out: &mut String) {
    match node {
        Node::Raw(raw) => {
            let chunk = raw.as_utf8_str();
            let chunk = chunk.trim();
            if !chunk.is_empty() {
                if !out.is_empty() {
                    out.push(' ');
                }
                out.push_str(chunk);
            }
        }
        Node::Comment(_) => {}
        Node::Tag(tag) => {
            let name = tag.name().as_utf8_str();
            if name.eq_ignore_ascii_case("script")
                || name.eq_ignore_ascii_case("style")
                || name.eq_ignore_ascii_case("noscript")
                || name.eq_ignore_ascii_case("template")
            {
                return;
            }
            collect_visible_text_from_tag(tag, parser, out);
        }
    }
}

fn extract_visible_text_from_html(input: &str) -> Option<String> {
    let dom = tl::parse(input, *HTML_PARSER_OPTIONS).ok()?;
    let parser = dom.parser();

    let mut out = String::new();
    for handle in dom.children() {
        let Some(node) = handle.get(parser) else {
            continue;
        };
        collect_visible_text(node, parser, &mut out);
    }

    Some(collapse_whitespace(&decode_common_html_entities(&out)))
}

fn strip_html_markup(input: &str) -> String {
    extract_visible_text_from_html(input)
        .unwrap_or_else(|| collapse_whitespace(&decode_common_html_entities(input)))
}

fn truncate_to_char_boundary(input: &str, max_len: usize) -> String {
    if max_len == 0 || input.len() <= max_len {
        return input.to_string();
    }

    let mut end = max_len.min(input.len());
    while end > 0 && !input.is_char_boundary(end) {
        end -= 1;
    }

    input[..end].to_string()
}

/// Formats validation response text for report output.
///
/// When `strip_html` is true, HTML markup is stripped and common entities are decoded before
/// optional truncation.
pub fn format_response_body_for_display(body: &str, max_len: usize, strip_html: bool) -> String {
    let rendered = if strip_html { strip_html_markup(body) } else { body.to_string() };
    truncate_to_char_boundary(&rendered, max_len)
}

/// Return (NAME, value, start, end) for the captures we care about.
///
/// * Named captures keep their (upper-cased) name
/// * Among unnamed captures, keep **only the first one** and call it "TOKEN"
pub fn process_captures(captures: &SerializableCaptures) -> Vec<(String, String, usize, usize)> {
    let mut saw_unnamed = false;

    captures
        .captures
        .iter()
        .filter_map(|cap| {
            if let Some(name) = &cap.name {
                Some((name.to_uppercase(), cap.raw_value().to_string(), cap.start, cap.end))
            } else if !saw_unnamed {
                saw_unnamed = true;
                Some(("TOKEN".to_string(), cap.raw_value().to_string(), cap.start, cap.end))
            } else {
                // Ignore any additional unnamed captures (e.g., from unintended groups)
                None
            }
        })
        .collect()
}

pub fn find_closest_variable(
    captures: &[(String, String, usize, usize)],
    target_value: &str,
    target_variable_name: &str,
    search_variable_name: &str,
) -> Option<String> {
    // Collect the positions of the target variable for the provided value so we can
    // compare relative offsets with candidate variables.
    let mut target_positions = Vec::new();
    for (name, value, start, end) in captures {
        if name == target_variable_name && value.as_str() == target_value {
            target_positions.push((*start, *end));
        }
    }

    if target_positions.is_empty() {
        return None;
    }

    // Prefer candidates that appear before the target value (same logical block), but
    // fall back to overlapping values and then to those that appear after the target
    // value when no better match exists. This avoids pairing with the next block when
    // multiple credentials are close together in the same file.
    let mut best_before: Option<(usize, String)> = None;
    let mut best_overlap: Option<(usize, String)> = None;
    let mut best_after: Option<(usize, String)> = None;

    for (target_start, target_end) in target_positions.iter().copied() {
        for (name, value, start, end) in captures {
            if name != search_variable_name {
                continue;
            }

            if *end <= target_start {
                // Candidate is before the target; choose the one closest to the target start.
                let distance = target_start - *end;
                match &mut best_before {
                    Some((best_distance, best_value)) if distance < *best_distance => {
                        *best_distance = distance;
                        *best_value = value.clone();
                    }
                    None => {
                        best_before = Some((distance, value.clone()));
                    }
                    _ => {}
                }
            } else if *start >= target_end {
                // Candidate is after the target; choose the one closest to the target end.
                let distance = *start - target_end;
                match &mut best_after {
                    Some((best_distance, best_value)) if distance < *best_distance => {
                        *best_distance = distance;
                        *best_value = value.clone();
                    }
                    None => {
                        best_after = Some((distance, value.clone()));
                    }
                    _ => {}
                }
            } else {
                // Candidate overlaps the target – treat as an exact match.
                let distance = 0usize;
                match &mut best_overlap {
                    Some((best_distance, best_value)) if distance < *best_distance => {
                        *best_distance = distance;
                        *best_value = value.clone();
                    }
                    None => {
                        best_overlap = Some((distance, value.clone()));
                    }
                    _ => {}
                }
            }
        }
    }

    best_before.or(best_overlap).or(best_after).map(|(_, value)| value)
}

// -----------------------------------------------------------------------------
// tests
// -----------------------------------------------------------------------------
//
#[cfg(test)]
mod tests {
    use super::*;
    use crate::matcher::{SerializableCapture, SerializableCaptures};
    use pretty_assertions::assert_eq;
    use reqwest::Url;
    use smallvec::smallvec;

    #[test]
    fn single_unnamed_capture_is_returned() {
        let captures = SerializableCaptures {
            captures: smallvec![SerializableCapture {
                name: None,
                match_number: 0, // This test is for a rule with *no* explicit captures
                start: 1,
                end: 4,
                value: "abc",
            }],
        };
        let result = process_captures(&captures);
        assert_eq!(result, vec![("TOKEN".to_string(), "abc".to_string(), 1usize, 4usize)]);
    }
    #[test]
    fn includes_whole_match_when_multiple() {
        let captures = SerializableCaptures {
            captures: smallvec![
                // --- FIX ---
                // This test simulated a regex like `(abc)de(?P<foo>bcd)`.
                // With our fix, group 0 ("abcde") is NOT serialized.
                // We only get the explicit captures (group 1 and "foo").
                SerializableCapture {
                    // This is group 1 (unnamed)
                    name: None,
                    match_number: 1, // Corrected match_number
                    start: 1,
                    end: 4,
                    value: "bcd",
                },
                SerializableCapture {
                    // This is group 2 (named "foo")
                    name: Some("foo"),
                    match_number: 2, // Corrected match_number
                    start: 1,
                    end: 4,
                    value: "bcd",
                },
            ],
        };
        let result = process_captures(&captures);

        // --- FIX ---
        // The expected result now only contains the explicit captures.
        // The first unnamed capture ("bcd") becomes "TOKEN".
        assert_eq!(
            result,
            vec![
                ("TOKEN".to_string(), "bcd".to_string(), 1usize, 4usize),
                ("FOO".to_string(), "bcd".to_string(), 1usize, 4usize),
            ]
        );
        // --- END FIX ---
    }

    #[test]
    fn includes_whole_match_and_unnamed_groups() {
        let captures = SerializableCaptures {
            captures: smallvec![
                // --- FIX ---
                // This test simulated a regex like `(?P<foo>aa)bb(cc)`.
                // With our fix, group 0 ("aabbcc") is NOT serialized.
                // We only get the explicit captures ("foo" and group 2).
                SerializableCapture {
                    // This is group 1 (named "foo")
                    name: Some("foo"),
                    match_number: 1, // Corrected match_number
                    start: 0,
                    end: 2,
                    value: "aa",
                },
                SerializableCapture {
                    // This is group 2 (unnamed)
                    name: None,
                    match_number: 2, // Corrected match_number
                    start: 4,
                    end: 6,
                    value: "cc",
                },
            ],
        };
        let result = process_captures(&captures);

        // --- FIX ---
        // The expected result no longer contains the full match ("aabbcc").
        // The first (and only) unnamed capture ("cc") is now correctly labeled "TOKEN".
        assert_eq!(
            result,
            vec![
                ("FOO".to_string(), "aa".to_string(), 0usize, 2usize), // From named group 1
                ("TOKEN".to_string(), "cc".to_string(), 4usize, 6usize), // From unnamed group 2
            ]
        );
        // --- END FIX ---
    }

    #[test]
    fn prefers_closest_preceding_variable() {
        let captures = vec![
            ("TOKEN".to_string(), "secret".to_string(), 75usize, 115usize),
            ("AKID".to_string(), "preceding".to_string(), 30usize, 50usize),
            ("AKID".to_string(), "following".to_string(), 180usize, 200usize),
        ];

        let result = find_closest_variable(&captures, "secret", "TOKEN", "AKID").unwrap();

        assert_eq!(result, "preceding".to_string());
    }

    #[test]
    fn falls_back_to_following_when_no_preceding() {
        let captures = vec![
            ("TOKEN".to_string(), "secret".to_string(), 10usize, 50usize),
            ("AKID".to_string(), "after".to_string(), 60usize, 80usize),
        ];

        let result = find_closest_variable(&captures, "secret", "TOKEN", "AKID").unwrap();

        assert_eq!(result, "after".to_string());
    }

    // ---- SSRF IP validation tests ----

    #[test]
    fn ssrf_rejects_loopback() {
        assert!(!is_ssrf_safe_ip(&"127.0.0.1".parse().unwrap()));
        assert!(!is_ssrf_safe_ip(&"::1".parse().unwrap()));
    }

    #[test]
    fn ssrf_rejects_unspecified() {
        assert!(!is_ssrf_safe_ip(&"0.0.0.0".parse().unwrap()));
        assert!(!is_ssrf_safe_ip(&"::".parse().unwrap()));
    }

    #[test]
    fn ssrf_rejects_private_ranges() {
        assert!(!is_ssrf_safe_ip(&"10.0.0.1".parse().unwrap()));
        assert!(!is_ssrf_safe_ip(&"172.16.0.1".parse().unwrap()));
        assert!(!is_ssrf_safe_ip(&"192.168.1.1".parse().unwrap()));
    }

    #[test]
    fn ssrf_rejects_link_local_and_metadata() {
        assert!(!is_ssrf_safe_ip(&"169.254.169.254".parse().unwrap()));
        assert!(!is_ssrf_safe_ip(&"169.254.1.1".parse().unwrap()));
    }

    #[test]
    fn ssrf_accepts_public_ips() {
        assert!(is_ssrf_safe_ip(&"8.8.8.8".parse().unwrap()));
        assert!(is_ssrf_safe_ip(&"1.1.1.1".parse().unwrap()));
        assert!(is_ssrf_safe_ip(&"2606:4700::1111".parse().unwrap()));
    }

    #[test]
    fn format_response_body_for_display_strips_html() {
        let html = r#"<!doctype html>
            <html>
              <head>
                <script>console.log("ignore");</script>
              </head>
              <body><h1>Hello &amp; goodbye</h1><p>World</p></body>
            </html>"#;

        let rendered = format_response_body_for_display(html, 0, true);

        assert_eq!(rendered, "Hello & goodbye World");
    }

    #[test]
    fn format_response_body_for_display_truncates_on_utf8_boundary() {
        let body = "é".repeat(10);
        let rendered = format_response_body_for_display(&body, 7, false);
        assert_eq!(rendered, "ééé");
    }

    #[tokio::test]
    async fn check_url_resolvable_blocks_localhost() {
        let url = Url::parse("https://localhost/path").unwrap();
        let result = check_url_resolvable(&url, false).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("SSRF protection"));
    }

    #[tokio::test]
    async fn check_url_resolvable_allows_localhost_when_opted_in() {
        let url = Url::parse("https://localhost/path").unwrap();
        let result = check_url_resolvable(&url, true).await;
        assert!(result.is_ok());
    }
}
