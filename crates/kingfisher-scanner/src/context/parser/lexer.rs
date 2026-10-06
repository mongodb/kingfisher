use std::{borrow::Cow, sync::LazyLock};

use anyhow::Result;
use regex::Regex;

use super::Language;

macro_rules! quoted_literal_pattern {
    () => {
        r#"
            b?r\#*"(?s:.*?)"\#*
            |
            (?i:[rubf]{0,3})?"""(?s:.*?)"""
            |
            (?i:[rubf]{0,3})?'''(?s:.*?)'''
            |
            (?:\$@|@\$|@)"(?s:(?:[^"]|"")*)"
            |
            (?:\$|(?i:[rubf]{1,3}))?"(?:[^"\\]|\\.)*"
            |
            (?i:[rubf]{1,3})?'(?:[^'\\]|\\.)*'
            |
            '(?:[^'\\]|\\.)*'
            |
            `(?s:[^`]*)`
        "#
    };
}

static ASSIGNMENT_LITERAL_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(concat!(
        r#"(?x)
        (?P<key>[A-Za-z_@$][\w$@.:>-]*)
        \s*
        (?P<op>:=|=>|=|\+=)
        \s*
        (?P<value>
        "#,
        quoted_literal_pattern!(),
        r#"
            |
            [+-]?\d+(?:[_.xX[:xdigit:]]*)?
        )
    "#,
    ))
    .unwrap()
});

static ASSIGNMENT_ANY_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"(?x)
        (?P<key>[A-Za-z_@$][\w$@.:>-]*)
        \s*
        (?P<op>:=|=>|=|\+=)
        \s*
        (?P<rhs>.+)
    "#,
    )
    .unwrap()
});

static TYPED_ASSIGNMENT_LITERAL_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(concat!(
        r#"(?x)
        (?P<key>[A-Za-z_@$][\w$@.-]*)
        \s*:\s*[^=]+?
        =\s*
        (?P<value>
        "#,
        quoted_literal_pattern!(),
        r#"
            |
            [+-]?\d+(?:[_.xX[:xdigit:]]*)?
        )
    "#,
    ))
    .unwrap()
});

static PAIR_LITERAL_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(concat!(
        r#"(?x)
        (?:
            ^
            |
            [\{\[,]\s*
            |
            ,\s*
        )
        (?P<key>"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'|[A-Za-z_@$][\w$@.-]*)
        \s*:\s*
        (?P<value>
        "#,
        quoted_literal_pattern!(),
        r#"
            |
            [+-]?\d+(?:[_.xX[:xdigit:]]*)?
        )
    "#,
    ))
    .unwrap()
});

static TYPE_LITERAL_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(concat!(
        r#"(?x)
        (?P<key>[A-Za-z_@$][\w$@.-]*)
        \s*:\s*
        (?P<value>
        "#,
        quoted_literal_pattern!(),
        r#"
        )
    "#,
    ))
    .unwrap()
});

static CALL_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"(?x)
        (?:
            (?P<assign>[A-Za-z_@$][\w$@.:>-]*)\s*(?::=|=)\s*
        )?
        (?P<call>(?:new\s+)?[A-Za-z_@$][\w$@.:>-]*)
        \s*
        \((?P<args>[^)]*)\)
    "#,
    )
    .unwrap()
});

static BRACE_LIST_ASSIGN_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"(?x)
        (?P<key>[A-Za-z_@$][\w$@.:>-]*)
        \s*=\s*
        \{(?P<body>[^}]*)\}
    "#,
    )
    .unwrap()
});

pub(super) fn stream_context_candidates<F>(
    source: &[u8],
    language: &Language,
    sink: &mut F,
) -> Result<()>
where
    F: FnMut(&str) -> bool,
{
    let text = String::from_utf8_lossy(source);
    if text.is_empty() {
        return Ok(());
    }

    match language {
        Language::Bash => extract_bash(&text, sink),
        Language::Python => extract_python(&text, sink),
        Language::Ruby => extract_ruby(&text, sink),
        Language::Php => extract_php(&text, sink),
        Language::Yaml => extract_yaml(&text, sink),
        Language::Toml => extract_toml(&text, sink),
        Language::JavaScript => extract_javascript_like(&text, false, sink),
        Language::TypeScript => extract_javascript_like(&text, true, sink),
        Language::Rust => extract_rust(&text, sink),
        Language::C | Language::CSharp | Language::Cpp | Language::Go | Language::Java => {
            extract_c_style(&text, language, sink)
        }
        Language::Css | Language::Html => Ok(()),
    }
}

fn extract_bash<F>(text: &str, sink: &mut F) -> Result<()>
where
    F: FnMut(&str) -> bool,
{
    let cleaned = strip_comments(text, CommentStyle::shell());
    for line in cleaned.lines() {
        if emit_assignment_literals(line, false, sink).is_break() {
            return Ok(());
        }
    }
    Ok(())
}

fn extract_python<F>(text: &str, sink: &mut F) -> Result<()>
where
    F: FnMut(&str) -> bool,
{
    let cleaned = strip_comments(text, CommentStyle::python());
    for line in context_lines(&cleaned) {
        let line = line.as_ref();
        if emit_assignment_literals(line, false, sink).is_break() {
            return Ok(());
        }
        if emit_pairs(line, true, sink).is_break() {
            return Ok(());
        }
        if emit_calls(line, false, sink).is_break() {
            return Ok(());
        }
    }
    Ok(())
}

fn extract_ruby<F>(text: &str, sink: &mut F) -> Result<()>
where
    F: FnMut(&str) -> bool,
{
    let cleaned = strip_comments(text, CommentStyle::hash_only());
    for line in context_lines(&cleaned) {
        let line = line.as_ref();
        if emit_assignment_literals(line, false, sink).is_break() {
            return Ok(());
        }
        if emit_assignment_lists(line, false, sink).is_break() {
            return Ok(());
        }
        if emit_calls(line, false, sink).is_break() {
            return Ok(());
        }
    }
    Ok(())
}

fn extract_php<F>(text: &str, sink: &mut F) -> Result<()>
where
    F: FnMut(&str) -> bool,
{
    let cleaned = strip_comments(text, CommentStyle::php());
    for line in context_lines(&cleaned) {
        let line = line.as_ref();
        if emit_assignment_literals(line, false, sink).is_break() {
            return Ok(());
        }
        if emit_assignment_lists(line, false, sink).is_break() {
            return Ok(());
        }
        if emit_calls(line, false, sink).is_break() {
            return Ok(());
        }
    }
    Ok(())
}

fn extract_yaml<F>(text: &str, sink: &mut F) -> Result<()>
where
    F: FnMut(&str) -> bool,
{
    let cleaned = strip_comments(text, CommentStyle::hash_only());
    for line in cleaned.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('-') && !trimmed.contains(':') {
            continue;
        }
        if let Some((key, value)) = split_mapping_pair(trimmed) {
            let key = key.trim_start_matches('-').trim();
            if emit_value(key, value, true, true, sink).is_break() {
                return Ok(());
            }
        }
    }
    Ok(())
}

fn extract_toml<F>(text: &str, sink: &mut F) -> Result<()>
where
    F: FnMut(&str) -> bool,
{
    let cleaned = strip_comments(text, CommentStyle::hash_only());
    for line in cleaned.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('[') {
            continue;
        }
        if let Some((key, value)) = split_assignment(trimmed, '=')
            && emit_value(key, value, true, false, sink).is_break()
        {
            return Ok(());
        }
    }
    Ok(())
}

fn extract_javascript_like<F>(text: &str, include_type_literals: bool, sink: &mut F) -> Result<()>
where
    F: FnMut(&str) -> bool,
{
    let cleaned = strip_comments(text, CommentStyle::c_style().with_backticks());
    for line in context_lines(&cleaned) {
        let line = line.as_ref();
        if include_type_literals && emit_typed_assignment_literals(line, sink).is_break() {
            return Ok(());
        }
        if emit_assignment_literals(line, false, sink).is_break() {
            return Ok(());
        }
        if emit_pairs(line, false, sink).is_break() {
            return Ok(());
        }
        if include_type_literals && emit_type_literals(line, sink).is_break() {
            return Ok(());
        }
        if emit_assignment_lists(line, false, sink).is_break() {
            return Ok(());
        }
        if emit_calls(line, false, sink).is_break() {
            return Ok(());
        }
    }
    Ok(())
}

fn extract_rust<F>(text: &str, sink: &mut F) -> Result<()>
where
    F: FnMut(&str) -> bool,
{
    let cleaned = strip_comments(text, CommentStyle::c_style());
    for line in context_lines(&cleaned) {
        let line = line.as_ref();
        if emit_typed_assignment_literals(line, sink).is_break() {
            return Ok(());
        }
        if emit_assignment_literals(line, false, sink).is_break() {
            return Ok(());
        }
        if emit_calls(line, false, sink).is_break() {
            return Ok(());
        }
    }
    Ok(())
}

fn extract_c_style<F>(text: &str, language: &Language, sink: &mut F) -> Result<()>
where
    F: FnMut(&str) -> bool,
{
    let style = match language {
        Language::CSharp => CommentStyle::c_style().with_verbatim_strings(),
        Language::Go => CommentStyle::c_style().with_backticks(),
        _ => CommentStyle::c_style(),
    };
    let cleaned = strip_comments(text, style);
    for line in context_lines(&cleaned) {
        let line = line.as_ref();
        if emit_assignment_literals(line, false, sink).is_break() {
            return Ok(());
        }
        if emit_brace_list_assignments(line, sink).is_break() {
            return Ok(());
        }
        if matches!(language, Language::Cpp) && looks_like_cpp_ctor_initializer_line(line) {
            continue;
        }
        if emit_calls(line, false, sink).is_break() {
            return Ok(());
        }
    }
    Ok(())
}

#[derive(Clone, Copy)]
enum Flow {
    Continue,
    Break,
}

impl Flow {
    fn is_break(self) -> bool {
        matches!(self, Self::Break)
    }
}

fn context_lines(text: &str) -> impl Iterator<Item = Cow<'_, str>> {
    // Yield candidates lazily so a caller that early-exits (`is_break`) once
    // its sink is satisfied stops the scan immediately instead of paying for a
    // full pass over the file. Each source line is yielded in order, and a
    // stitched multi-line statement is yielded right after the line that
    // completes it (so in-source-order extraction survives early exit).
    let mut lines = text.lines();
    let mut current = String::new();
    let mut active = false;
    // A stitched statement produced while handling a source line is buffered
    // here and emitted on the next call, after that line.
    let mut pending: Option<Cow<'_, str>> = None;
    let mut flushed = false;

    std::iter::from_fn(move || {
        if let Some(stitched) = pending.take() {
            return Some(stitched);
        }

        if let Some(line) = lines.by_ref().next() {
            let trimmed = line.trim();
            if !trimmed.is_empty() {
                if active {
                    current.push(' ');
                    current.push_str(trimmed);
                    let structure = scan_structure(&current);
                    if multiline_context_complete(&current, structure) {
                        pending = Some(Cow::Owned(std::mem::take(&mut current)));
                        active = false;
                    }
                } else if starts_multiline_context(trimmed) {
                    current.push_str(trimmed);
                    let structure = scan_structure(&current);
                    if multiline_context_complete(&current, structure) {
                        current.clear();
                    } else {
                        active = true;
                    }
                }
            }
            return Some(Cow::Borrowed(line));
        }

        // Source exhausted: emit the trailing incomplete statement once, if it
        // still holds literal values worth surfacing.
        if !flushed {
            flushed = true;
            if active && !current.is_empty() && !extract_literal_values(&current, false).is_empty()
            {
                return Some(Cow::Owned(std::mem::take(&mut current)));
            }
        }
        None
    })
}

#[derive(Clone, Copy, Default)]
struct Structure {
    depth: i32,
    unclosed_literal: bool,
}

fn starts_multiline_context(line: &str) -> bool {
    if starts_with_block_keyword(line) {
        return false;
    }

    if !contains_assignment_operator(line) && !looks_like_multiline_call_start(line) {
        return false;
    }

    let structure = scan_structure(line);
    structure.unclosed_literal || structure.depth > 0 || statement_needs_more(line)
}

fn multiline_context_complete(statement: &str, structure: Structure) -> bool {
    !structure.unclosed_literal
        && structure.depth <= 0
        && !statement_needs_more(statement)
        && !extract_literal_values(statement, false).is_empty()
}

fn starts_with_block_keyword(line: &str) -> bool {
    const KEYWORDS: &[&str] = &[
        "catch", "class", "def", "else", "fn", "for", "function", "if", "impl", "match", "switch",
        "try", "while",
    ];

    KEYWORDS.iter().any(|keyword| {
        line.strip_prefix(keyword)
            .and_then(|rest| rest.chars().next())
            .is_some_and(|ch| ch.is_ascii_whitespace() || matches!(ch, '(' | '{' | '<'))
    })
}

fn contains_assignment_operator(line: &str) -> bool {
    let bytes = line.as_bytes();
    let mut idx = 0;
    while idx < bytes.len() {
        if let Some(span) = parse_any_literal_span(line, idx) {
            idx = span.end;
            continue;
        }

        if bytes[idx] == b'=' {
            let prev = idx.checked_sub(1).map(|pos| bytes[pos]);
            let next = bytes.get(idx + 1).copied();
            if next == Some(b'=') || matches!(prev, Some(b'!' | b'<' | b'>')) {
                idx += 1;
                continue;
            }
            return true;
        }
        idx += 1;
    }
    false
}

fn looks_like_multiline_call_start(line: &str) -> bool {
    let Some(paren_idx) = line.find('(') else {
        return false;
    };
    let call = line[..paren_idx].trim().trim_start_matches("new ").trim();
    if call.is_empty() || call.contains(char::is_whitespace) {
        return false;
    }
    call.chars().all(|ch| {
        ch.is_ascii_alphanumeric() || matches!(ch, '_' | '$' | '@' | '.' | ':' | '>' | '-')
    })
}

fn statement_needs_more(statement: &str) -> bool {
    let trimmed = statement.trim_end();
    trimmed.ends_with('\\')
        || trimmed.ends_with(',')
        || trimmed.ends_with('(')
        || trimmed.ends_with('[')
        || trimmed.ends_with('{')
        || trimmed.ends_with('=')
        || trimmed.ends_with(":=")
        || trimmed.ends_with("=>")
        || trimmed.ends_with("+=")
}

fn scan_structure(input: &str) -> Structure {
    let bytes = input.as_bytes();
    let mut structure = Structure::default();
    let mut idx = 0;

    while idx < bytes.len() {
        if let Some(span) = parse_any_literal_span(input, idx) {
            structure.unclosed_literal |= !span.closed;
            idx = span.end;
            continue;
        }

        match bytes[idx] {
            b'(' | b'[' | b'{' => structure.depth += 1,
            b')' | b']' | b'}' => structure.depth -= 1,
            _ => {}
        }
        idx += 1;
    }

    structure
}

fn emit_assignment_literals<F>(line: &str, keep_full_key: bool, sink: &mut F) -> Flow
where
    F: FnMut(&str) -> bool,
{
    for caps in ASSIGNMENT_LITERAL_RE.captures_iter(line) {
        let Some(key) = caps.name("key").map(|m| m.as_str()) else {
            continue;
        };
        let Some(value) = caps.name("value").map(|m| m.as_str()) else {
            continue;
        };
        if emit_value(key, value, keep_full_key, false, sink).is_break() {
            return Flow::Break;
        }
    }
    Flow::Continue
}

fn emit_typed_assignment_literals<F>(line: &str, sink: &mut F) -> Flow
where
    F: FnMut(&str) -> bool,
{
    for caps in TYPED_ASSIGNMENT_LITERAL_RE.captures_iter(line) {
        let Some(key) = caps.name("key").map(|m| m.as_str()) else {
            continue;
        };
        let Some(value) = caps.name("value").map(|m| m.as_str()) else {
            continue;
        };
        if emit_value(key, value, false, false, sink).is_break() {
            return Flow::Break;
        }
    }
    Flow::Continue
}

fn emit_assignment_lists<F>(line: &str, keep_full_key: bool, sink: &mut F) -> Flow
where
    F: FnMut(&str) -> bool,
{
    if let Some(caps) = ASSIGNMENT_ANY_RE.captures(line) {
        let Some(key) = caps.name("key").map(|m| m.as_str()) else {
            return Flow::Continue;
        };
        let Some(rhs) = caps.name("rhs").map(|m| m.as_str()) else {
            return Flow::Continue;
        };
        if rhs.contains(',') || rhs.contains('[') || rhs.contains('{') {
            for value in extract_literal_values(rhs, false) {
                if emit_value(key, &value, keep_full_key, false, sink).is_break() {
                    return Flow::Break;
                }
            }
        }
    }
    Flow::Continue
}

fn emit_brace_list_assignments<F>(line: &str, sink: &mut F) -> Flow
where
    F: FnMut(&str) -> bool,
{
    for caps in BRACE_LIST_ASSIGN_RE.captures_iter(line) {
        let Some(key) = caps.name("key").map(|m| m.as_str()) else {
            continue;
        };
        let Some(body) = caps.name("body").map(|m| m.as_str()) else {
            continue;
        };
        for value in extract_literal_values(body, false) {
            if emit_value(key, &value, false, false, sink).is_break() {
                return Flow::Break;
            }
        }
    }
    Flow::Continue
}

fn emit_pairs<F>(line: &str, keep_full_key: bool, sink: &mut F) -> Flow
where
    F: FnMut(&str) -> bool,
{
    for caps in PAIR_LITERAL_RE.captures_iter(line) {
        let Some(key) = caps.name("key").map(|m| m.as_str()) else {
            continue;
        };
        let Some(value) = caps.name("value").map(|m| m.as_str()) else {
            continue;
        };
        if emit_value(key, value, keep_full_key, false, sink).is_break() {
            return Flow::Break;
        }
    }
    Flow::Continue
}

fn emit_type_literals<F>(line: &str, sink: &mut F) -> Flow
where
    F: FnMut(&str) -> bool,
{
    for caps in TYPE_LITERAL_RE.captures_iter(line) {
        let Some(key) = caps.name("key").map(|m| m.as_str()) else {
            continue;
        };
        let Some(value) = caps.name("value").map(|m| m.as_str()) else {
            continue;
        };
        if emit_value(key, value, false, false, sink).is_break() {
            return Flow::Break;
        }
    }
    Flow::Continue
}

fn emit_calls<F>(line: &str, keep_full_assign_key: bool, sink: &mut F) -> Flow
where
    F: FnMut(&str) -> bool,
{
    for caps in CALL_RE.captures_iter(line) {
        let assign_key = caps.name("assign").map(|m| m.as_str());
        let Some(call) = caps.name("call").map(|m| m.as_str()) else {
            continue;
        };
        let Some(args) = caps.name("args").map(|m| m.as_str()) else {
            continue;
        };

        let values = extract_literal_values(args, false);
        if values.is_empty() {
            continue;
        }

        if let Some(key) = assign_key {
            for value in &values {
                if emit_value(key, value, keep_full_assign_key, false, sink).is_break() {
                    return Flow::Break;
                }
            }
        }

        let call_name = normalize_call_name(call);
        for value in &values {
            if emit_value(&call_name, value, true, false, sink).is_break() {
                return Flow::Break;
            }
        }

        if values.len() >= 2 {
            let first = values[0].trim_matches('"').trim_matches('\'');
            let second = &values[1];
            if looks_like_embedded_key(first)
                && emit_value(first, second, true, false, sink).is_break()
            {
                return Flow::Break;
            }
        }
    }
    Flow::Continue
}

fn emit_value<F>(
    key: &str,
    value: &str,
    keep_full_key: bool,
    allow_bare: bool,
    sink: &mut F,
) -> Flow
where
    F: FnMut(&str) -> bool,
{
    let key = normalize_key(key, keep_full_key);
    let value = normalize_value(value, allow_bare);
    if key.is_empty() || value.is_empty() {
        return Flow::Continue;
    }
    let candidate = format!("{key} = {value}");
    if sink(&candidate) { Flow::Continue } else { Flow::Break }
}

fn normalize_key(key: &str, keep_full_key: bool) -> String {
    let mut key = key.trim().trim_start_matches('$').trim_start_matches('@').to_string();
    if (key.starts_with('"') && key.ends_with('"'))
        || (key.starts_with('\'') && key.ends_with('\''))
    {
        key = key[1..key.len() - 1].to_string();
    }
    if keep_full_key {
        return key;
    }
    key.rsplit(['.', ':', '>'])
        .find(|segment| !segment.is_empty())
        .unwrap_or(&key)
        .trim_matches('-')
        .to_string()
}

fn normalize_value(value: &str, allow_bare: bool) -> String {
    let trimmed = value.trim().trim_end_matches([',', ';']);
    if trimmed.is_empty() {
        return String::new();
    }

    if let Some(stripped) = trim_wrapped_literal(trimmed) {
        return stripped;
    }

    if allow_bare || looks_like_number(trimmed) {
        return trimmed.trim_matches([')', ']', '}']).to_string();
    }

    String::new()
}

fn trim_wrapped_literal(value: &str) -> Option<String> {
    strip_rust_raw_literal(value)
        .or_else(|| strip_csharp_verbatim_literal(value))
        .or_else(|| strip_quoted_literal(value))
        .or_else(|| value.strip_prefix('`')?.strip_suffix('`').map(str::to_string))
}

fn strip_rust_raw_literal(value: &str) -> Option<String> {
    let span = parse_rust_raw_literal_span(value, 0)?;
    if !span.closed || span.end != value.len() {
        return None;
    }

    let bytes = value.as_bytes();
    let mut idx = 0;
    if matches!(bytes.get(idx), Some(b'b' | b'B')) {
        idx += 1;
    }
    idx += 1; // r/R
    let hash_start = idx;
    while matches!(bytes.get(idx), Some(b'#')) {
        idx += 1;
    }
    let hash_count = idx - hash_start;
    idx += 1; // opening quote

    Some(value[idx..value.len() - 1 - hash_count].to_string())
}

fn strip_csharp_verbatim_literal(value: &str) -> Option<String> {
    let span = parse_csharp_verbatim_literal_span(value, 0)?;
    if !span.closed || span.end != value.len() {
        return None;
    }

    let quote_idx = if value.starts_with("@\"") {
        1
    } else if value.starts_with("$@\"") || value.starts_with("@$\"") {
        2
    } else {
        return None;
    };

    Some(value[quote_idx + 1..value.len() - 1].replace("\"\"", "\""))
}

fn strip_quoted_literal(value: &str) -> Option<String> {
    let span = parse_quoted_literal_span(value, 0)?;
    if !span.closed || span.end != value.len() {
        return None;
    }

    let bytes = value.as_bytes();
    let mut quote_idx = 0;
    if matches!(bytes.get(quote_idx), Some(b'$')) {
        quote_idx += 1;
    } else {
        while quote_idx < bytes.len() && is_string_prefix_byte(bytes[quote_idx]) {
            quote_idx += 1;
        }
    }

    let quote = *bytes.get(quote_idx)?;
    if !matches!(quote, b'\'' | b'"') {
        return None;
    }
    let triple = quote_idx + 2 < bytes.len()
        && bytes[quote_idx + 1] == quote
        && bytes[quote_idx + 2] == quote;
    let content_start = quote_idx + if triple { 3 } else { 1 };
    let content_end = value.len() - if triple { 3 } else { 1 };
    Some(value[content_start..content_end].to_string())
}

fn normalize_call_name(call: &str) -> String {
    let call = call.trim().trim_start_matches("new ").trim();
    call.rsplit(['.', ':', '>'])
        .find(|segment| !segment.is_empty())
        .unwrap_or(call)
        .trim_matches('-')
        .to_string()
}

fn looks_like_embedded_key(value: &str) -> bool {
    let lower = value.trim().trim_end_matches('=').to_ascii_lowercase();
    !lower.is_empty()
        && lower.chars().all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '_' | '-' | '.'))
        && ["api", "auth", "credential", "key", "pass", "password", "secret", "token"]
            .iter()
            .any(|needle| lower.contains(needle))
}

fn looks_like_number(value: &str) -> bool {
    let value = value.trim().replace('_', "");
    let value = value.strip_prefix(['-', '+']).unwrap_or(&value);
    if value.is_empty() {
        return false;
    }
    if let Some(hex) = value.strip_prefix("0x").or_else(|| value.strip_prefix("0X")) {
        return !hex.is_empty() && hex.chars().all(|ch| ch.is_ascii_hexdigit());
    }

    let mut seen_digit = false;
    let mut seen_dot = false;
    for ch in value.chars() {
        if ch.is_ascii_digit() {
            seen_digit = true;
        } else if ch == '.' && !seen_dot {
            seen_dot = true;
        } else {
            return false;
        }
    }
    seen_digit
}

fn looks_like_cpp_ctor_initializer_line(line: &str) -> bool {
    let trimmed = line.trim_start();
    trimmed.contains(") :") || trimmed.starts_with(':') || trimmed.starts_with(',')
}

#[derive(Clone, Copy)]
struct LiteralSpan {
    end: usize,
    closed: bool,
}

fn parse_any_literal_span(input: &str, start: usize) -> Option<LiteralSpan> {
    parse_rust_raw_literal_span(input, start)
        .or_else(|| parse_csharp_verbatim_literal_span(input, start))
        .or_else(|| parse_quoted_literal_span(input, start))
        .or_else(|| parse_backtick_literal_span(input, start))
}

fn parse_rust_raw_literal_span(input: &str, start: usize) -> Option<LiteralSpan> {
    let bytes = input.as_bytes();
    let mut idx = start;

    if matches!(bytes.get(idx), Some(b'b' | b'B'))
        && matches!(bytes.get(idx + 1), Some(b'r' | b'R'))
    {
        idx += 1;
    }

    if !matches!(bytes.get(idx), Some(b'r' | b'R')) {
        return None;
    }
    idx += 1;

    let hash_start = idx;
    while matches!(bytes.get(idx), Some(b'#')) {
        idx += 1;
    }
    let hash_count = idx - hash_start;

    if !matches!(bytes.get(idx), Some(b'"')) {
        return None;
    }
    idx += 1;

    while idx < bytes.len() {
        if bytes[idx] == b'"'
            && idx + 1 + hash_count <= bytes.len()
            && bytes[idx + 1..idx + 1 + hash_count].iter().all(|ch| *ch == b'#')
        {
            return Some(LiteralSpan { end: idx + 1 + hash_count, closed: true });
        }
        idx += 1;
    }

    Some(LiteralSpan { end: bytes.len(), closed: false })
}

fn parse_csharp_verbatim_literal_span(input: &str, start: usize) -> Option<LiteralSpan> {
    let bytes = input.as_bytes();
    let quote_idx =
        if matches!(bytes.get(start), Some(b'@')) && matches!(bytes.get(start + 1), Some(b'"')) {
            start + 1
        } else if (matches!(bytes.get(start), Some(b'$'))
            && matches!(bytes.get(start + 1), Some(b'@'))
            && matches!(bytes.get(start + 2), Some(b'"')))
            || (matches!(bytes.get(start), Some(b'@'))
                && matches!(bytes.get(start + 1), Some(b'$'))
                && matches!(bytes.get(start + 2), Some(b'"')))
        {
            start + 2
        } else {
            return None;
        };

    let mut idx = quote_idx + 1;
    while idx < bytes.len() {
        if bytes[idx] == b'"' {
            if matches!(bytes.get(idx + 1), Some(b'"')) {
                idx += 2;
                continue;
            }
            return Some(LiteralSpan { end: idx + 1, closed: true });
        }
        idx += 1;
    }

    Some(LiteralSpan { end: bytes.len(), closed: false })
}

fn parse_quoted_literal_span(input: &str, start: usize) -> Option<LiteralSpan> {
    let bytes = input.as_bytes();
    let mut quote_idx = start;

    if matches!(bytes.get(quote_idx), Some(b'$')) {
        quote_idx += 1;
    } else if !matches!(bytes.get(quote_idx), Some(b'\'' | b'"')) {
        let prefix_start = quote_idx;
        while quote_idx < bytes.len()
            && quote_idx - prefix_start < 3
            && is_string_prefix_byte(bytes[quote_idx])
        {
            quote_idx += 1;
        }
        if quote_idx == prefix_start {
            return None;
        }
    }

    let &quote = bytes.get(quote_idx)?;
    if !matches!(quote, b'\'' | b'"') {
        return None;
    }

    let triple = quote_idx + 2 < bytes.len()
        && bytes[quote_idx + 1] == quote
        && bytes[quote_idx + 2] == quote;
    let mut idx = quote_idx + if triple { 3 } else { 1 };

    while idx < bytes.len() {
        if !triple && bytes[idx] == b'\\' {
            idx = (idx + 2).min(bytes.len());
            continue;
        }
        if triple {
            if idx + 2 < bytes.len()
                && bytes[idx] == quote
                && bytes[idx + 1] == quote
                && bytes[idx + 2] == quote
            {
                return Some(LiteralSpan { end: idx + 3, closed: true });
            }
        } else if bytes[idx] == quote {
            return Some(LiteralSpan { end: idx + 1, closed: true });
        }
        idx += 1;
    }

    Some(LiteralSpan { end: bytes.len(), closed: false })
}

fn parse_backtick_literal_span(input: &str, start: usize) -> Option<LiteralSpan> {
    let bytes = input.as_bytes();
    if !matches!(bytes.get(start), Some(b'`')) {
        return None;
    }

    let mut idx = start + 1;
    while idx < bytes.len() {
        if bytes[idx] == b'`' {
            return Some(LiteralSpan { end: idx + 1, closed: true });
        }
        idx += 1;
    }

    Some(LiteralSpan { end: bytes.len(), closed: false })
}

fn is_string_prefix_byte(ch: u8) -> bool {
    matches!(ch, b'b' | b'B' | b'f' | b'F' | b'r' | b'R' | b'u' | b'U')
}

fn extract_literal_values(input: &str, allow_bare: bool) -> Vec<String> {
    let bytes = input.as_bytes();
    let mut values = Vec::new();
    let mut idx = 0;

    while idx < bytes.len() {
        if let Some(span) = parse_any_literal_span(input, idx) {
            values.push(input[idx..span.end].to_string());
            idx = span.end;
            continue;
        }

        match bytes[idx] {
            b' ' | b'\t' | b'\r' | b'\n' | b',' => {
                idx += 1;
            }
            b'[' | b'(' | b'{' => {
                let (close, start) = match bytes[idx] {
                    b'[' => (b']', idx + 1),
                    b'(' => (b')', idx + 1),
                    _ => (b'}', idx + 1),
                };
                idx += 1;
                let mut depth = 1usize;
                let inner_start = start;
                while idx < bytes.len() && depth > 0 {
                    if let Some(span) = parse_any_literal_span(input, idx) {
                        idx = span.end;
                        continue;
                    }

                    match bytes[idx] {
                        ch if ch == bytes[start - 1] => {
                            depth += 1;
                            idx += 1;
                        }
                        ch if ch == close => {
                            depth -= 1;
                            if depth == 0 {
                                let inner = &input[inner_start..idx];
                                values.extend(extract_literal_values(inner, allow_bare));
                            }
                            idx += 1;
                        }
                        _ => idx += 1,
                    }
                }
            }
            ch if ch.is_ascii_digit() || ch == b'+' || ch == b'-' => {
                let start = idx;
                idx += 1;
                while idx < bytes.len()
                    && (bytes[idx].is_ascii_digit() || matches!(bytes[idx], b'.' | b'_' | b'x'))
                {
                    idx += 1;
                }
                values.push(input[start..idx].to_string());
            }
            ch if allow_bare
                && (ch.is_ascii_alphanumeric() || matches!(ch, b'_' | b'$' | b'@')) =>
            {
                let start = idx;
                idx += 1;
                while idx < bytes.len()
                    && !matches!(
                        bytes[idx],
                        b' ' | b'\t' | b'\r' | b'\n' | b',' | b')' | b']' | b'}'
                    )
                {
                    idx += 1;
                }
                values.push(input[start..idx].to_string());
            }
            _ => idx += 1,
        }
    }

    values
}

fn split_mapping_pair(line: &str) -> Option<(&str, &str)> {
    let mut in_single = false;
    let mut in_double = false;
    for (idx, ch) in line.char_indices() {
        match ch {
            '\'' if !in_double => in_single = !in_single,
            '"' if !in_single => in_double = !in_double,
            ':' if !in_single && !in_double => return Some((&line[..idx], &line[idx + 1..])),
            _ => {}
        }
    }
    None
}

fn split_assignment(line: &str, needle: char) -> Option<(&str, &str)> {
    let mut in_single = false;
    let mut in_double = false;
    for (idx, ch) in line.char_indices() {
        match ch {
            '\'' if !in_double => in_single = !in_single,
            '"' if !in_single => in_double = !in_double,
            ch if ch == needle && !in_single && !in_double => {
                return Some((&line[..idx], &line[idx + 1..]));
            }
            _ => {}
        }
    }
    None
}

#[derive(Clone, Copy)]
struct CommentStyle {
    line_comment_hash: bool,
    line_comment_slash: bool,
    block_comments: bool,
    backticks: bool,
    verbatim_strings: bool,
    triple_quotes: bool,
}

impl CommentStyle {
    const fn c_style() -> Self {
        Self {
            line_comment_hash: false,
            line_comment_slash: true,
            block_comments: true,
            backticks: false,
            verbatim_strings: false,
            triple_quotes: false,
        }
    }

    const fn shell() -> Self {
        Self {
            line_comment_hash: true,
            line_comment_slash: false,
            block_comments: false,
            backticks: false,
            verbatim_strings: false,
            triple_quotes: false,
        }
    }

    const fn hash_only() -> Self {
        Self {
            line_comment_hash: true,
            line_comment_slash: false,
            block_comments: false,
            backticks: false,
            verbatim_strings: false,
            triple_quotes: false,
        }
    }

    const fn php() -> Self {
        Self {
            line_comment_hash: true,
            line_comment_slash: true,
            block_comments: true,
            backticks: false,
            verbatim_strings: false,
            triple_quotes: false,
        }
    }

    const fn python() -> Self {
        Self {
            line_comment_hash: true,
            line_comment_slash: false,
            block_comments: false,
            backticks: false,
            verbatim_strings: false,
            triple_quotes: true,
        }
    }

    const fn with_backticks(mut self) -> Self {
        self.backticks = true;
        self
    }

    const fn with_verbatim_strings(mut self) -> Self {
        self.verbatim_strings = true;
        self
    }
}

// NOTE: We index `source` byte-by-byte and cast via `bytes[idx] as char`.
// This is correct for comment/string delimiter detection because all
// delimiters we care about (`'`, `"`, `/`, `*`, `#`, `` ` ``, `\n`, `@`)
// are single-byte ASCII.  Interior bytes of multi-byte UTF-8 sequences
// have their high bit set (0x80..0xFF) so they can never collide with
// those ASCII delimiters.  The cast produces a garbage char for non-ASCII
// bytes, but the output is only consumed by regex patterns that match
// ASCII identifiers and quoted strings, so this is harmless.
fn strip_comments(source: &str, style: CommentStyle) -> String {
    #[derive(Clone, Copy)]
    enum StringState {
        Single,
        Double,
        Backtick,
        Verbatim,
        TripleSingle,
        TripleDouble,
    }

    let bytes = source.as_bytes();
    let mut out = String::with_capacity(source.len());
    let mut idx = 0usize;
    let mut string_state: Option<StringState> = None;
    let mut in_block_comment = false;

    while idx < bytes.len() {
        if in_block_comment {
            if idx + 1 < bytes.len() && bytes[idx] == b'*' && bytes[idx + 1] == b'/' {
                in_block_comment = false;
                idx += 2;
            } else {
                if bytes[idx] == b'\n' {
                    out.push('\n');
                }
                idx += 1;
            }
            continue;
        }

        if let Some(state) = string_state {
            match state {
                StringState::Single => {
                    out.push(bytes[idx] as char);
                    if bytes[idx] == b'\\' && idx + 1 < bytes.len() {
                        out.push(bytes[idx + 1] as char);
                        idx += 2;
                        continue;
                    }
                    if bytes[idx] == b'\'' {
                        string_state = None;
                    }
                    idx += 1;
                }
                StringState::Double => {
                    out.push(bytes[idx] as char);
                    if bytes[idx] == b'\\' && idx + 1 < bytes.len() {
                        out.push(bytes[idx + 1] as char);
                        idx += 2;
                        continue;
                    }
                    if bytes[idx] == b'"' {
                        string_state = None;
                    }
                    idx += 1;
                }
                StringState::Backtick => {
                    out.push(bytes[idx] as char);
                    if bytes[idx] == b'`' {
                        string_state = None;
                    }
                    idx += 1;
                }
                StringState::Verbatim => {
                    out.push(bytes[idx] as char);
                    if bytes[idx] == b'"' {
                        if idx + 1 < bytes.len() && bytes[idx + 1] == b'"' {
                            out.push('"');
                            idx += 2;
                            continue;
                        }
                        string_state = None;
                    }
                    idx += 1;
                }
                StringState::TripleSingle => {
                    out.push(bytes[idx] as char);
                    if idx + 2 < bytes.len()
                        && bytes[idx] == b'\''
                        && bytes[idx + 1] == b'\''
                        && bytes[idx + 2] == b'\''
                    {
                        out.push('\'');
                        out.push('\'');
                        idx += 3;
                        string_state = None;
                        continue;
                    }
                    idx += 1;
                }
                StringState::TripleDouble => {
                    out.push(bytes[idx] as char);
                    if idx + 2 < bytes.len()
                        && bytes[idx] == b'"'
                        && bytes[idx + 1] == b'"'
                        && bytes[idx + 2] == b'"'
                    {
                        out.push('"');
                        out.push('"');
                        idx += 3;
                        string_state = None;
                        continue;
                    }
                    idx += 1;
                }
            }
            continue;
        }

        if style.block_comments
            && idx + 1 < bytes.len()
            && bytes[idx] == b'/'
            && bytes[idx + 1] == b'*'
        {
            in_block_comment = true;
            idx += 2;
            continue;
        }

        if style.line_comment_slash
            && idx + 1 < bytes.len()
            && bytes[idx] == b'/'
            && bytes[idx + 1] == b'/'
        {
            while idx < bytes.len() && bytes[idx] != b'\n' {
                idx += 1;
            }
            continue;
        }

        if style.line_comment_hash && bytes[idx] == b'#' {
            while idx < bytes.len() && bytes[idx] != b'\n' {
                idx += 1;
            }
            continue;
        }

        if style.verbatim_strings
            && idx + 1 < bytes.len()
            && bytes[idx] == b'@'
            && bytes[idx + 1] == b'"'
        {
            out.push('@');
            out.push('"');
            idx += 2;
            string_state = Some(StringState::Verbatim);
            continue;
        }

        if style.verbatim_strings
            && idx + 2 < bytes.len()
            && bytes[idx] == b'@'
            && bytes[idx + 1] == b'$'
            && bytes[idx + 2] == b'"'
        {
            out.push('@');
            out.push('$');
            out.push('"');
            idx += 3;
            string_state = Some(StringState::Verbatim);
            continue;
        }

        if style.triple_quotes && idx + 2 < bytes.len() {
            if bytes[idx] == b'\'' && bytes[idx + 1] == b'\'' && bytes[idx + 2] == b'\'' {
                out.push('\'');
                out.push('\'');
                out.push('\'');
                idx += 3;
                string_state = Some(StringState::TripleSingle);
                continue;
            }
            if bytes[idx] == b'"' && bytes[idx + 1] == b'"' && bytes[idx + 2] == b'"' {
                out.push('"');
                out.push('"');
                out.push('"');
                idx += 3;
                string_state = Some(StringState::TripleDouble);
                continue;
            }
        }

        match bytes[idx] {
            b'\'' => {
                out.push('\'');
                string_state = Some(StringState::Single);
                idx += 1;
            }
            b'"' => {
                out.push('"');
                string_state = Some(StringState::Double);
                idx += 1;
            }
            b'`' if style.backticks => {
                out.push('`');
                string_state = Some(StringState::Backtick);
                idx += 1;
            }
            _ => {
                out.push(bytes[idx] as char);
                idx += 1;
            }
        }
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── extract_literal_values ──────────────────────────────────────────

    #[test]
    fn extract_literals_double_quoted() {
        let vals = extract_literal_values(r#""hello", "world""#, false);
        assert_eq!(vals, vec![r#""hello""#, r#""world""#]);
    }

    #[test]
    fn extract_literals_single_quoted() {
        let vals = extract_literal_values("'abc', 'def'", false);
        assert_eq!(vals, vec!["'abc'", "'def'"]);
    }

    #[test]
    fn extract_literals_backtick() {
        let vals = extract_literal_values("`template ${var}`", false);
        assert_eq!(vals, vec!["`template ${var}`"]);
    }

    #[test]
    fn extract_literals_escaped_quotes() {
        let vals = extract_literal_values(r#""he said \"hi\"""#, false);
        assert_eq!(vals, vec![r#""he said \"hi\"""#]);
    }

    #[test]
    fn extract_literals_trailing_backslash_does_not_panic() {
        // Regression: a string literal ending in a lone backslash used to
        // push idx past bytes.len() and panic at `input[start..idx]`.
        // The unterminated literal should be returned as-is (without the
        // closing quote that doesn't exist) and contain the trailing
        // backslash.
        let single = extract_literal_values("'foo \\", false);
        assert_eq!(single, vec!["'foo \\"]);

        let double = extract_literal_values("\"foo \\", false);
        assert_eq!(double, vec!["\"foo \\"]);

        // The bracketed form should also recurse into the unterminated
        // string without panicking; the result may be empty if no inner
        // values were closed, but the call must return.
        let bracketed = extract_literal_values("['foo \\']", false);
        // Only assert non-panic; exact shape depends on bracket matching
        // around an unterminated string.
        let _ = bracketed;
    }

    #[test]
    fn extract_literals_numbers() {
        let vals = extract_literal_values("42, -3.14, +1", false);
        assert_eq!(vals, vec!["42", "-3.14", "+1"]);
    }

    #[test]
    fn extract_literals_nested_brackets() {
        let vals = extract_literal_values(r#"["a", ["b", "c"]]"#, false);
        assert_eq!(vals, vec![r#""a""#, r#""b""#, r#""c""#]);
    }

    #[test]
    fn extract_literals_nested_parens() {
        let vals = extract_literal_values(r#"("x", ("y"))"#, false);
        assert_eq!(vals, vec![r#""x""#, r#""y""#]);
    }

    #[test]
    fn extract_literals_nested_braces() {
        let vals = extract_literal_values(r#"{"key": "val"}"#, false);
        assert_eq!(vals, vec![r#""key""#, r#""val""#]);
    }

    #[test]
    fn extract_literals_mixed_nesting() {
        let vals = extract_literal_values(r#"[{"a": "b"}, ("c")]"#, false);
        assert_eq!(vals, vec![r#""a""#, r#""b""#, r#""c""#]);
    }

    #[test]
    fn extract_literals_empty_input() {
        let vals = extract_literal_values("", false);
        assert!(vals.is_empty());
    }

    #[test]
    fn extract_literals_only_whitespace() {
        let vals = extract_literal_values("   \t\n  ", false);
        assert!(vals.is_empty());
    }

    #[test]
    fn extract_literals_unclosed_string() {
        // Gracefully handles unclosed quote — takes everything to end
        let vals = extract_literal_values(r#""unclosed"#, false);
        assert_eq!(vals.len(), 1);
        assert!(vals[0].starts_with('"'));
    }

    #[test]
    fn extract_literals_mismatched_brackets_does_not_panic() {
        // Must not panic on mismatched brackets — result may be empty because
        // the unclosed bracket consumes to EOF and the inner recursion only
        // fires once the bracket is closed.
        let _ = extract_literal_values(r#"["a", "b""#, false);
    }

    #[test]
    fn extract_literals_verbatim_string() {
        let vals = extract_literal_values(r#"@"line1""line2""#, false);
        assert_eq!(vals.len(), 1);
        assert_eq!(vals[0], r#"@"line1""line2""#);
    }

    #[test]
    fn extract_literals_prefixed_and_raw_strings() {
        let vals = extract_literal_values(
            r##"r#"raw // ok"#, f"py", $@"a""b", $"cs", `go // raw`"##,
            false,
        );
        assert_eq!(
            vals,
            vec![r##"r#"raw // ok"#"##, r#"f"py""#, r#"$@"a""b""#, r#"$"cs""#, "`go // raw`"]
        );
    }

    #[test]
    fn extract_literals_bare_values_when_allowed() {
        let vals = extract_literal_values("foo, bar_baz", true);
        assert_eq!(vals, vec!["foo", "bar_baz"]);
    }

    #[test]
    fn extract_literals_bare_values_rejected_when_disallowed() {
        let vals = extract_literal_values("foo, bar", false);
        assert!(vals.is_empty());
    }

    // ── strip_comments ──────────────────────────────────────────────────

    #[test]
    fn strip_c_style_line_comment() {
        let result = strip_comments("x = 1; // comment\ny = 2;", CommentStyle::c_style());
        assert_eq!(result, "x = 1; \ny = 2;");
    }

    #[test]
    fn strip_c_style_block_comment() {
        let result = strip_comments("a /* block */ b", CommentStyle::c_style());
        assert_eq!(result, "a  b");
    }

    #[test]
    fn strip_c_style_block_comment_multiline() {
        let result = strip_comments("a /* line1\nline2 */ b", CommentStyle::c_style());
        assert_eq!(result, "a \n b");
    }

    #[test]
    fn strip_hash_comment() {
        let result = strip_comments("key = val # comment\nnext", CommentStyle::shell());
        assert_eq!(result, "key = val \nnext");
    }

    #[test]
    fn strip_preserves_hash_inside_string() {
        let result = strip_comments(r#"x = "has # inside""#, CommentStyle::shell());
        assert_eq!(result, r#"x = "has # inside""#);
    }

    #[test]
    fn strip_preserves_slash_inside_string() {
        let result = strip_comments(r#"x = "has // inside""#, CommentStyle::c_style());
        assert_eq!(result, r#"x = "has // inside""#);
    }

    #[test]
    fn strip_python_triple_double_quotes() {
        let result = strip_comments(
            "x = 1\n\"\"\"docstring # not a comment\"\"\"\ny = 2",
            CommentStyle::python(),
        );
        assert!(result.contains("docstring # not a comment"));
        assert!(result.contains("y = 2"));
    }

    #[test]
    fn strip_python_triple_single_quotes() {
        let result = strip_comments("'''multi\nline'''# real comment", CommentStyle::python());
        assert!(result.contains("multi\nline"));
        assert!(!result.contains("real comment"));
    }

    #[test]
    fn strip_csharp_verbatim_string() {
        let style = CommentStyle::c_style().with_verbatim_strings();
        let result = strip_comments(r#"x = @"path\to\file" // comment"#, style);
        assert!(result.contains(r#"@"path\to\file""#));
        assert!(!result.contains("comment"));
    }

    #[test]
    fn strip_csharp_interpolated_verbatim_string() {
        let style = CommentStyle::c_style().with_verbatim_strings();
        let result = strip_comments(r#"x = @$"path // still string" // comment"#, style);
        assert!(result.contains(r#"@$"path // still string""#));
        assert!(!result.ends_with("comment"));
    }

    #[test]
    fn strip_backtick_template_preserves_content() {
        let style = CommentStyle::c_style().with_backticks();
        let result = strip_comments("x = `template // not a comment`", style);
        assert_eq!(result, "x = `template // not a comment`");
    }

    #[test]
    fn strip_php_both_comment_styles() {
        let result = strip_comments("a # hash\nb // slash\nc", CommentStyle::php());
        assert_eq!(result, "a \nb \nc");
    }

    #[test]
    fn strip_escaped_quote_in_string() {
        let result =
            strip_comments(r#"x = "escaped \" quote" // comment"#, CommentStyle::c_style());
        assert!(result.contains(r#"escaped \" quote"#));
        assert!(!result.contains("comment"));
    }

    #[test]
    fn strip_no_comments_passthrough() {
        let input = "let x = 42;\nlet y = \"hello\";";
        let result = strip_comments(input, CommentStyle::c_style());
        assert_eq!(result, input);
    }

    // ── normalize_key / normalize_value ────────────────────────────────

    #[test]
    fn normalize_key_strips_prefix_symbols() {
        assert_eq!(normalize_key("$var", false), "var");
        assert_eq!(normalize_key("@ivar", false), "ivar");
    }

    #[test]
    fn normalize_key_extracts_last_segment() {
        assert_eq!(normalize_key("self.password", false), "password");
        assert_eq!(normalize_key("obj::field", false), "field");
    }

    #[test]
    fn normalize_key_keeps_full_when_requested() {
        assert_eq!(normalize_key("self.password", true), "self.password");
    }

    #[test]
    fn normalize_value_strips_quotes() {
        assert_eq!(normalize_value(r#""hello""#, false), "hello");
        assert_eq!(normalize_value("'world'", false), "world");
        assert_eq!(normalize_value("`tmpl`", false), "tmpl");
    }

    #[test]
    fn normalize_value_strips_prefixed_literals() {
        assert_eq!(normalize_value(r##"r#"raw value"#"##, false), "raw value");
        assert_eq!(normalize_value(r#"f"py {value}""#, false), "py {value}");
        assert_eq!(normalize_value(r#"$@"a""b""#, false), "a\"b");
    }

    #[test]
    fn normalize_value_rejects_bare_when_not_allowed() {
        assert_eq!(normalize_value("bareword", false), "");
    }

    #[test]
    fn normalize_value_rejects_lone_numeric_signs() {
        assert_eq!(normalize_value("+", false), "");
        assert_eq!(normalize_value("-", false), "");
    }

    #[test]
    fn normalize_value_accepts_bare_when_allowed() {
        assert_eq!(normalize_value("bareword", true), "bareword");
    }

    #[test]
    fn normalize_value_accepts_numbers() {
        assert_eq!(normalize_value("42", false), "42");
        assert_eq!(normalize_value("-3.14", false), "-3.14");
    }

    // ── language extraction regressions ─────────────────────────────────

    fn collect(source: &str, language: Language) -> Vec<String> {
        let mut texts = Vec::new();
        stream_context_candidates(source.as_bytes(), &language, &mut |text| {
            texts.push(text.to_string());
            true
        })
        .unwrap();
        texts
    }

    #[test]
    fn javascript_multiline_assignment_emits_variable_context() {
        let texts = collect(
            "const auth0_client_secret =\n  \"abcd1234abcd1234abcd1234abcd1234\";",
            Language::JavaScript,
        );
        assert!(
            texts
                .iter()
                .any(|text| text == "auth0_client_secret = abcd1234abcd1234abcd1234abcd1234"),
            "expected multiline assignment candidate, got {texts:?}"
        );
    }

    #[test]
    fn typescript_typed_assignment_uses_variable_name() {
        let texts = collect(r#"const apiToken: string = "secret123";"#, Language::TypeScript);
        assert!(texts.iter().any(|text| text == "apiToken = secret123"));
    }

    #[test]
    fn go_backtick_literal_preserves_comment_markers() {
        let texts = collect("apiKey := `secret // not comment`", Language::Go);
        assert!(texts.iter().any(|text| text == "apiKey = secret // not comment"));
    }

    #[test]
    fn embedded_call_key_must_look_secret_related() {
        let mut texts = Vec::new();
        assert!(matches!(
            emit_calls(r#"User::new("John", "Doe")"#, false, &mut |text| {
                texts.push(text.to_string());
                true
            }),
            Flow::Continue
        ));
        assert!(!texts.iter().any(|text| text == "John = Doe"), "got {texts:?}");

        texts.clear();
        assert!(matches!(
            emit_calls(r#"send("password=", "secret123")"#, false, &mut |text| {
                texts.push(text.to_string());
                true
            }),
            Flow::Continue
        ));
        assert!(texts.iter().any(|text| text == "password= = secret123"), "got {texts:?}");
    }
}
