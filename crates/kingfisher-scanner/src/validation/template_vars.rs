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
    // Preserve the public advisory extractor's historical escaping behavior.
    split_quoted_segments(inner, '|', true)
}

fn split_quoted_segments(inner: &str, separator: char, backslash_escapes: bool) -> Vec<&str> {
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
            '\\' if backslash_escapes && (in_single || in_double) => escaped = true,
            '\'' if !in_double => in_single = !in_single,
            '"' if !in_single => in_double = !in_double,
            ch if ch == separator && !in_single && !in_double => {
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

/// Proven external roots for offline crypto preparation, not a full Liquid interpreter.
/// Unlike the advisory extractor, retain Liquid's case-sensitive names and never
/// infer requirements from conditional/loop bodies, default chains, or unknown tags.
/// Possible assignments are retained even in those bodies: execution must decide
/// whether they provide a value. Unknown syntax defers all checks to execution.
pub(super) fn required_template_vars(text: &str) -> BTreeSet<String> {
    let mut required = BTreeSet::new();
    let mut locals = BTreeSet::new();
    let mut conditional_depth = 0_usize;
    let mut position = 0;

    while let Some((output, inner)) = next_template_block(text, &mut position) {
        if output {
            if conditional_depth == 0 {
                collect_required_expression(inner, &locals, &mut required);
            }
            continue;
        }
        let (tag, arguments) = inner.split_once(char::is_whitespace).unwrap_or((inner, ""));
        match tag {
            "assign" => {
                let Some((name, expression)) = arguments.split_once('=') else {
                    return BTreeSet::new();
                };
                let name = name.trim();
                if simple_variable_root(name) != Some(name) {
                    return BTreeSet::new();
                }
                if conditional_depth == 0 {
                    collect_required_expression(expression, &locals, &mut required);
                }
                locals.insert(name.to_string());
            }
            "capture" | "increment" | "decrement" => {
                let name = arguments.trim();
                if simple_variable_root(name) != Some(name) {
                    return BTreeSet::new();
                }
                // A capture is available on completion; marking it early is
                // conservative for self-references inside its own body.
                locals.insert(name.to_string());
            }
            "endcapture" => {}
            "if" | "unless" | "case" | "for" | "tablerow" | "ifchanged" => {
                conditional_depth += 1;
            }
            "endif" | "endunless" | "endcase" | "endfor" | "endtablerow" | "endifchanged" => {
                conditional_depth = conditional_depth.saturating_sub(1)
            }
            "else" | "elsif" | "when" => {}
            // Includes/partials, comments/raw blocks, interrupts, and custom
            // tags need fuller syntax/runtime knowledge. Never make their
            // uncertain lexical contents authoritative input requirements.
            _ => return BTreeSet::new(),
        }
    }
    required
}

/// Read output/tag delimiters outside quoted strings, including whitespace control.
/// The caller has already parsed the template successfully; no evaluation occurs.
fn next_template_block<'a>(text: &'a str, position: &mut usize) -> Option<(bool, &'a str)> {
    let remaining = &text[*position..];
    let (start, output) = match (remaining.find("{{"), remaining.find("{%")) {
        (Some(output), Some(tag)) if output < tag => (output, true),
        (_, Some(tag)) => (tag, false),
        (Some(output), None) => (output, true),
        (None, None) => return None,
    };
    let start = *position + start + 2;
    let ending = if output { "}}" } else { "%}" };
    let mut quote = None;
    // Liquid string literals do not interpret backslashes as quote escapes.
    for (offset, ch) in text[start..].char_indices() {
        if quote == Some(ch) {
            quote = None;
        } else if quote.is_none() && matches!(ch, '\'' | '"') {
            quote = Some(ch);
        } else if quote.is_none() && text[start + offset..].starts_with(ending) {
            *position = start + offset + ending.len();
            let inner = text[start..start + offset].trim();
            let inner = inner.strip_prefix('-').unwrap_or(inner);
            let inner = inner.strip_suffix('-').unwrap_or(inner);
            return Some((output, inner.trim()));
        }
    }
    None
}

fn collect_required_expression(
    expression: &str,
    locals: &BTreeSet<String>,
    required: &mut BTreeSet<String>,
) {
    let segments = split_quoted_segments(expression, '|', false);
    // Default/fallback behavior must not turn an optional input into a hard
    // requirement. Do not try to predict intermediate filter results offline.
    if segments
        .iter()
        .skip(1)
        .any(|segment| segment.split(':').next().is_some_and(|name| name.trim() == "default"))
    {
        return;
    }
    let mut collect = |value: &str| {
        if let Some(name) = simple_variable_root(value.trim())
            && !locals.contains(name)
        {
            required.insert(name.to_string());
        }
    };
    if let Some(input) = segments.first() {
        collect(input);
    }
    for filter in segments.iter().skip(1) {
        if let Some((name, arguments)) = filter.split_once(':') {
            // New crypto adapters eagerly evaluate their supplied arguments.
            // Do not infer requirements for arbitrary standard/custom filters,
            // whose arguments may be lazy or have fallback semantics.
            if !matches!(
                name.trim(),
                "ecdh"
                    | "ec_public_key"
                    | "ecdsa_sign"
                    | "ecdsa_verify"
                    | "aes_gcm_encrypt"
                    | "aes_gcm_decrypt"
                    | "hkdf_sha256"
                    | "pbkdf2_sha256"
                    | "ed25519_sign"
                    | "ed25519_verify"
                    | "random_bytes"
                    | "constant_time_eq"
                    | "hmac_sha512"
            ) {
                continue;
            }
            for argument in split_quoted_segments(arguments, ',', false) {
                collect(argument);
            }
        }
    }
}

/// Only simple roots/dotted paths are unambiguous here. Property names are not
/// external inputs; dynamic indexing/named arguments and literals are deferred.
fn simple_variable_root(expression: &str) -> Option<&str> {
    let mut path = expression.split('.');
    let root = path.next()?;
    let identifier = |name: &str| {
        name.chars().next().is_some_and(is_ident_start) && name.chars().all(is_ident_continue)
    };
    if !identifier(root) || LIQUID_LITERAL_NAMES.contains(&expression) {
        return None;
    }
    path.all(identifier).then_some(root)
}

fn is_ident_start(ch: char) -> bool {
    ch.is_ascii_alphabetic() || ch == '_'
}

fn is_ident_continue(ch: char) -> bool {
    ch.is_ascii_alphanumeric() || ch == '_'
}

#[cfg(test)]
mod tests {
    use super::{extract_template_vars, required_template_vars};
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

    #[test]
    fn required_vars_track_assign_and_capture_locals() {
        let vars = required_template_vars(
            "{%- assign nonce = '' | random_bytes: 12 -%}\n\
             {%- capture message -%}{{ CLIENT_ID }}:{{ nonce }}{%- endcapture -%}\n\
             {{ message | ecdsa_sign: TOKEN, 'P-256' }}",
        );
        assert_eq!(vars, BTreeSet::from(["CLIENT_ID".into(), "TOKEN".into()]));
    }

    #[test]
    fn required_vars_defer_conditional_and_loop_bodies() {
        let vars = required_template_vars(
            "{% if false %}{{ UNTAKEN | sha512 }}\
             {% elsif UNKNOWN_CONDITION %}{{ MAYBE }}{% else %}{{ OTHER }}{% endif %}\
             {% unless ENABLED %}{{ ALSO_OPTIONAL }}{% endunless %}\
             {% case CHOICE %}{% when 'x' %}{{ CASE_VALUE }}{% endcase %}\
             {% for item in ITEMS %}{{ item.secret | sha512 }}\
             {% for nested in item.values %}{{ nested }}{% endfor %}{% endfor %}\
             {{ TOKEN | sha512 }}",
        );
        assert_eq!(vars, BTreeSet::from(["TOKEN".into()]));
    }

    #[test]
    fn required_vars_do_not_leak_loop_bindings_but_keep_possible_assignments() {
        let vars = required_template_vars(
            "{% for item in ITEMS %}{% assign digest = item | sha512 %}{% endfor %}\
             {% if CONDITION %}{% capture maybe %}{{ OPTIONAL }}{% endcapture %}{% endif %}\
             {{ digest }}{{ maybe }}{{ item }}{{ EXTERNAL | sha512 }}",
        );
        assert_eq!(vars, BTreeSet::from(["EXTERNAL".into(), "item".into()]));
    }

    #[test]
    fn required_vars_keep_case_and_object_roots_and_defer_defaults() {
        let vars = required_template_vars(
            "{{ account.id | sha512 }}{{ lowercase | sha512 }}\
             {{ OPTIONAL | default: FALLBACK | sha512 }}\
             {{ TOKEN | ecdsa_sign: KEYS.private, 'P-256' }}\
             {{ TOKEN | custom_lazy: OPTIONAL_ARG }}\
             {{ dynamic[INDEX] | sha512 }}",
        );
        assert_eq!(
            vars,
            BTreeSet::from(["KEYS".into(), "TOKEN".into(), "account".into(), "lowercase".into()])
        );
    }

    #[test]
    fn required_vars_handle_multiline_whitespace_control_and_quoted_delimiters() {
        let vars = required_template_vars(
            "{%- assign message = '}}|not_a_filter,{{ fake }}' -%}\n\
             {{- TOKEN\n | ecdsa_sign:\n SECRET, 'P-256' -}}\n\
             {{ 'literal|sha512' | append: 'a,b' }}{{ message }}",
        );
        assert_eq!(vars, BTreeSet::from(["SECRET".into(), "TOKEN".into()]));
    }

    #[test]
    fn required_vars_use_liquid_literal_quotes_without_backslash_escapes() {
        for source in [
            r"{{ TOKEN | append: '\' | append: '| ecdsa_sign: MISSING }}' | sha512 }}",
            r#"{{ TOKEN | append: "\" | append: "| ecdsa_sign: MISSING }}" | sha512 }}"#,
        ] {
            assert_eq!(
                required_template_vars(source),
                BTreeSet::from(["TOKEN".into()]),
                "{source}"
            );
        }
    }

    #[test]
    fn required_vars_defer_unknown_or_opaque_tags_entirely() {
        for source in [
            "{% raw %}{{ NOT_AN_INPUT }}{% endraw %}{{ TOKEN | sha512 }}",
            "{% comment %}{{ NOT_AN_INPUT }}{% endcomment %}{{ TOKEN | sha512 }}",
            "{{ MAYBE }}{% render 'partial' %}{{ TOKEN | sha512 }}",
            "{% for item in ITEMS %}{% break %}{% endfor %}{{ MAYBE | sha512 }}",
        ] {
            assert!(required_template_vars(source).is_empty(), "{source}");
        }
    }
}
