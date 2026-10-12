use std::collections::BTreeSet;

static TEMPLATE_BLOCK_RE: std::sync::LazyLock<regex::Regex> = std::sync::LazyLock::new(|| {
    regex::Regex::new(r"\{\{\s*([^}]*)\}\}").expect("template block regex should compile")
});

const LIQUID_LITERAL_NAMES: &[&str] = &["blank", "empty", "false", "nil", "null", "true"];

/// Inspect variable names in Liquid output expressions, including filter arguments.
/// Names are uppercased for Kingfisher input conventions. This is lexical
/// inspection, not a complete dependency analysis of Liquid control-flow tags.
pub fn extract_template_vars(text: &str) -> BTreeSet<String> {
    let mut vars = BTreeSet::new();

    for block_cap in TEMPLATE_BLOCK_RE.captures_iter(text) {
        let inner = block_cap.get(1).map(|m| m.as_str()).unwrap_or_default();
        for (segment_index, segment) in split_filter_segments(inner).into_iter().enumerate() {
            collect_segment_vars(segment, segment_index != 0, &mut vars);
        }
    }

    vars
}

fn split_filter_segments(inner: &str) -> Vec<&str> {
    let mut segments = Vec::new();
    let mut start = 0;
    let mut in_single = false;
    let mut in_double = false;
    let mut escaped = false;

    for (idx, ch) in inner.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }

        match ch {
            '\\' if in_single || in_double => escaped = true,
            '\'' if !in_double => in_single = !in_single,
            '"' if !in_single => in_double = !in_double,
            '|' if !in_single && !in_double => {
                segments.push(&inner[start..idx]);
                start = idx + ch.len_utf8();
            }
            _ => {}
        }
    }

    segments.push(&inner[start..]);
    segments
}

fn collect_segment_vars(segment: &str, skip_first_ident: bool, vars: &mut BTreeSet<String>) {
    let mut chars = segment.char_indices().peekable();
    let mut in_single = false;
    let mut in_double = false;
    let mut escaped = false;
    let mut skipped_filter_name = !skip_first_ident;

    while let Some((idx, ch)) = chars.next() {
        if escaped {
            escaped = false;
            continue;
        }

        match ch {
            '\\' if in_single || in_double => {
                escaped = true;
                continue;
            }
            '\'' if !in_double => {
                in_single = !in_single;
                continue;
            }
            '"' if !in_single => {
                in_double = !in_double;
                continue;
            }
            _ => {}
        }

        if in_single || in_double || !is_ident_start(ch) {
            continue;
        }

        let mut end = idx + ch.len_utf8();
        while let Some(&(next_idx, next_ch)) = chars.peek() {
            if !is_ident_continue(next_ch) {
                break;
            }
            chars.next();
            end = next_idx + next_ch.len_utf8();
        }

        let ident = &segment[idx..end];
        if !skipped_filter_name {
            skipped_filter_name = true;
            continue;
        }

        if LIQUID_LITERAL_NAMES.iter().any(|name| name.eq_ignore_ascii_case(ident)) {
            continue;
        }

        vars.insert(ident.to_ascii_uppercase());
    }
}

fn is_ident_start(ch: char) -> bool {
    ch.is_ascii_alphabetic() || ch == '_'
}

fn is_ident_continue(ch: char) -> bool {
    ch.is_ascii_alphanumeric() || ch == '_'
}

#[cfg(test)]
mod tests {
    use super::extract_template_vars;
    use std::collections::BTreeSet;

    #[test]
    fn ignores_filter_names_but_keeps_filter_argument_vars() {
        let vars = extract_template_vars(
            "{{ NEXT_PUBLIC_VERCEL_APP_CLIENT_ID | default: VERCEL_APP_CLIENT_ID | append: ':' | append: VERCEL_APP_CLIENT_SECRET | b64enc }}",
        );

        assert_eq!(
            vars,
            BTreeSet::from([
                "NEXT_PUBLIC_VERCEL_APP_CLIENT_ID".to_string(),
                "VERCEL_APP_CLIENT_ID".to_string(),
                "VERCEL_APP_CLIENT_SECRET".to_string(),
            ])
        );
    }

    #[test]
    fn ignores_literal_strings_and_new_filter_names() {
        let vars = extract_template_vars(
            r#"{{ "" | unix_timestamp_ms }} {{ "" | rfc1123_date }} {{ TOKEN | hmac_sha384_hex: SECRET }} {{ "https://example.com/oauth/callback" | url_encode }}"#,
        );

        assert_eq!(vars, BTreeSet::from(["SECRET".to_string(), "TOKEN".to_string()]));
    }

    #[test]
    fn ignores_liquid_literal_arguments() {
        let vars = extract_template_vars(r#"{{ TOKEN | default: blank | append: FALLBACK }}"#);

        assert_eq!(vars, BTreeSet::from(["FALLBACK".to_string(), "TOKEN".to_string()]));
    }
}
