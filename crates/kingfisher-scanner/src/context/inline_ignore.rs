use kingfisher_core::location::OffsetSpan;

/// Configuration for inline ignore directives.
#[derive(Clone, Debug, Default)]
pub struct InlineIgnoreConfig {
    tokens: Vec<Vec<u8>>,
}

impl InlineIgnoreConfig {
    /// Create a new configuration.
    ///
    /// * `additional_tokens` - inline ignore directives supplied by the user.
    pub fn new(additional_tokens: &[String]) -> Self {
        let mut tokens = vec![b"kingfisher:ignore".to_vec()];

        for token in additional_tokens {
            let trimmed = token.trim();
            if trimmed.is_empty() {
                continue;
            }

            let lowered = trimmed.to_ascii_lowercase().into_bytes();
            if tokens.iter().any(|existing| existing == &lowered) {
                continue;
            }

            tokens.push(lowered);
        }

        Self { tokens }
    }

    /// Return a configuration with inline ignores disabled.
    #[cfg(any(feature = "__cli-internals", test))]
    pub fn disabled() -> Self {
        Self { tokens: Vec::new() }
    }

    #[inline]
    fn has_tokens(&self) -> bool {
        !self.tokens.is_empty()
    }

    /// Returns `true` when the provided blob slice contains an inline ignore
    /// directive that should suppress a finding for the given span.
    #[cfg(any(feature = "__cli-internals", test))]
    pub fn should_ignore(&self, blob_bytes: &[u8], span: &OffsetSpan) -> bool {
        self.should_ignore_with_budget(blob_bytes, span, usize::MAX)
            .expect("unlimited directive search")
    }

    pub fn should_ignore_cached(
        &self,
        bytes: &[u8],
        span: &OffsetSpan,
        cache: &std::sync::OnceLock<InlineIgnoreIndex>,
    ) -> bool {
        if let Some(index) = cache.get() {
            return index.should_ignore(span);
        }
        if let Some(ignore) = self.should_ignore_with_budget(bytes, span, 4096) {
            return ignore;
        }
        cache.get_or_init(|| InlineIgnoreIndex::new(self, bytes)).should_ignore(span)
    }

    fn should_ignore_with_budget(
        &self,
        blob_bytes: &[u8],
        span: &OffsetSpan,
        mut budget: usize,
    ) -> Option<bool> {
        if !self.has_tokens() {
            return Some(false);
        }

        let (start_line_start, start_line_end) = line_bounds(blob_bytes, span.start);
        if start_line_end > start_line_start {
            let start_line = &blob_bytes[start_line_start..start_line_end];
            budget = budget.checked_sub(start_line.len().max(128))?;
            if line_has_directive(start_line, &self.tokens) {
                return Some(true);
            }
        }

        // Scan backwards to allow directives that appear before the start of a
        // multi-line string or value. This mirrors tools like Gitleaks where
        // the ignore directive is often placed immediately above the secret.
        let mut cursor = start_line_start;
        while cursor > 0 {
            let previous_index = cursor.saturating_sub(1);
            let (prev_start, prev_end) = line_bounds(blob_bytes, previous_index);
            if prev_end <= prev_start {
                break;
            }

            let prev_line = &blob_bytes[prev_start..prev_end];
            budget = budget.checked_sub(prev_line.len().max(128))?;
            if line_has_directive(prev_line, &self.tokens) {
                return Some(true);
            }

            if !should_skip_for_directive_search(prev_line) {
                break;
            }

            if prev_start == 0 {
                break;
            }

            cursor = prev_start;
        }

        let end_index = if span.end == 0 { 0 } else { span.end - 1 };
        let (closing_line_start, closing_line_end) =
            line_bounds(blob_bytes, end_index.min(blob_bytes.len()));
        if closing_line_end > closing_line_start
            && (closing_line_start != start_line_start || closing_line_end != start_line_end)
        {
            let closing_line = &blob_bytes[closing_line_start..closing_line_end];
            budget = budget.checked_sub(closing_line.len().max(128))?;
            if line_has_directive(closing_line, &self.tokens) {
                return Some(true);
            }
        }

        // Also consider lines after the match so that multi-line strings can be
        // ignored when the directive appears after the closing delimiter (a
        // common pattern in languages like Python).
        let mut cursor = closing_line_end;
        while cursor < blob_bytes.len() {
            if blob_bytes[cursor] == b'\n' {
                cursor += 1;
                continue;
            }

            let (_, next_end) = line_bounds(blob_bytes, cursor);
            if next_end <= cursor {
                break;
            }

            let next_line = &blob_bytes[cursor..next_end];
            budget = budget.checked_sub(next_line.len().max(128))?;
            if line_has_directive(next_line, &self.tokens) {
                return Some(true);
            }

            if !should_skip_for_directive_search(next_line) {
                break;
            }

            cursor = next_end;
        }

        Some(false)
    }
}

/// Per-input summaries of the existing backward/forward directive searches.
#[derive(Default, Clone)]
pub struct InlineIgnoreIndex {
    lines: Vec<IgnoreLine>,
    byte_len: usize,
}

#[derive(Clone)]
struct IgnoreLine {
    start: usize,
    directive: bool,
    before: bool,
    after: bool,
}

impl InlineIgnoreIndex {
    pub fn new(config: &InlineIgnoreConfig, bytes: &[u8]) -> Self {
        if !config.has_tokens() {
            return Self::default();
        }
        let mut lines = Vec::new();
        let mut lengths = Vec::new();
        let mut skippable = Vec::new();
        let mut start = 0;
        for line in bytes.split(|&byte| byte == b'\n') {
            let directive = line_has_directive(line, &config.tokens);
            let skip = should_skip_for_directive_search(line);
            let before = lines.last().is_some_and(|previous: &IgnoreLine| {
                // The original backward search stops at an empty physical line.
                *lengths.last().unwrap() > 0
                    && (previous.directive || (*skippable.last().unwrap() && previous.before))
            });
            lines.push(IgnoreLine { start, directive, before, after: false });
            lengths.push(line.len());
            skippable.push(skip);
            start += line.len() + 1;
        }
        for index in (0..lines.len().saturating_sub(1)).rev() {
            let next = &lines[index + 1];
            // Forward searches skip empty lines and continue across encoded bodies.
            lines[index].after =
                next.directive || ((lengths[index + 1] == 0 || skippable[index + 1]) && next.after);
        }
        Self { lines, byte_len: bytes.len() }
    }

    pub fn should_ignore(&self, span: &OffsetSpan) -> bool {
        if self.lines.is_empty() {
            return false;
        }
        let line = |offset: usize| {
            self.lines
                .partition_point(|line| line.start <= offset.min(self.byte_len))
                .saturating_sub(1)
        };
        let start = &self.lines[line(span.start)];
        let closing = &self.lines[line(span.end.saturating_sub(1))];
        start.directive || start.before || closing.directive || closing.after
    }
}

fn should_skip_for_directive_search(line: &[u8]) -> bool {
    let trimmed = trim_ascii_whitespace(line);
    if trimmed.is_empty() {
        return true;
    }

    if trimmed.iter().all(|&b| b == trimmed[0]) && matches!(trimmed[0], b'"' | b'\'' | b'`') {
        return true;
    }

    if ends_with_multiline_delimiter(trimmed) {
        return true;
    }

    if looks_like_pem_boundary(trimmed) {
        return true;
    }

    if looks_like_encoded_secret_body(trimmed) {
        return true;
    }

    false
}

fn ends_with_multiline_delimiter(trimmed: &[u8]) -> bool {
    if trimmed.len() < 3 {
        return false;
    }

    let last = *trimmed.last().unwrap();
    if !matches!(last, b'"' | b'\'' | b'`') {
        return false;
    }

    let count = trimmed.iter().rev().take_while(|&&ch| ch == last).count();

    count >= 3
}

fn looks_like_pem_boundary(trimmed: &[u8]) -> bool {
    trimmed.starts_with(b"-----BEGIN ") || trimmed.starts_with(b"-----END ")
}

fn looks_like_encoded_secret_body(trimmed: &[u8]) -> bool {
    const MIN_LEN: usize = 16;

    if trimmed.len() < MIN_LEN {
        return false;
    }

    let is_base64ish = trimmed.iter().all(|&b| {
        matches!(
            b,
            b'A'..=b'Z'
                | b'a'..=b'z'
                | b'0'..=b'9'
                | b'+'
                | b'/'
                | b'='
                | b'-'
                | b'_'
        )
    });
    if is_base64ish {
        return true;
    }

    let is_hexish = trimmed.iter().all(|&b| b.is_ascii_hexdigit());
    if is_hexish {
        return true;
    }

    let is_base32ish = trimmed.iter().all(|&b| matches!(b, b'A'..=b'Z' | b'2'..=b'7' | b'='));
    if is_base32ish {
        return true;
    }

    // Allow directives to be placed after payloads that mix a high percentage of
    // alpha-numeric characters commonly seen in encoded data (e.g. cryptographic
    // material that includes punctuation like ':' or '.') without risking
    // accidentally skipping regular source lines.
    let allowed = |b: u8| {
        matches!(
            b,
            b'A'..=b'Z'
                | b'a'..=b'z'
                | b'0'..=b'9'
                | b'+'
                | b'/'
                | b'='
                | b'-'
                | b'_'
                | b':'
                | b'.'
        )
    };

    let allowed_count = trimmed.iter().copied().filter(|&b| allowed(b)).count();
    allowed_count * 10 >= trimmed.len() * 9
}

fn trim_ascii_whitespace(line: &[u8]) -> &[u8] {
    let mut start = 0;
    while start < line.len() && line[start].is_ascii_whitespace() {
        start += 1;
    }

    let mut end = line.len();
    while end > start && line[end - 1].is_ascii_whitespace() {
        end -= 1;
    }

    &line[start..end]
}

fn line_bounds(bytes: &[u8], index: usize) -> (usize, usize) {
    if bytes.is_empty() {
        return (0, 0);
    }
    let mut start = index.min(bytes.len());
    while start > 0 && bytes[start - 1] != b'\n' {
        start -= 1;
    }
    let mut end = index.min(bytes.len());
    while end < bytes.len() && bytes[end] != b'\n' {
        end += 1;
    }
    (start, end)
}

fn line_has_directive(line: &[u8], tokens: &[Vec<u8>]) -> bool {
    if line.is_empty() {
        return false;
    }

    let mut lowercase = line.to_vec();
    lowercase.iter_mut().for_each(|b| *b = b.to_ascii_lowercase());

    tokens.iter().any(|token| memchr::memmem::find(&lowercase, token.as_slice()).is_some())
}

#[cfg(test)]
mod tests {
    use super::{
        InlineIgnoreConfig, line_bounds, line_has_directive, should_skip_for_directive_search,
        trim_ascii_whitespace,
    };
    use kingfisher_core::location::OffsetSpan;

    #[test]
    fn indexed_searches_match_original_directive_searches() {
        use super::InlineIgnoreIndex;
        let config = InlineIgnoreConfig::new(&["CUSTOM:IGNORE".into()]);
        for input in [
            "first\nkingfisher:ignore\n\"\"\"\naGVsbG93b3JsZGhlbGxvd29ybGRoZWxsb3dvcmxk\n\"\"\"\nlast",
            "first\nCUSTOM:IGNORE\n  \nYWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4\nlast\n",
            "kingfisher:ignore\n\nYWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4\nlast",
            "first\nYWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4\n\nKingfisher:Ignore\nlast",
            "first\r\nYWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4\r\ncustom:ignore\r\nlast",
            "",
            "\n\n",
            "kingfisher:ignore",
            "normal line\n",
        ] {
            let bytes = input.as_bytes();
            let index = InlineIgnoreIndex::new(&config, bytes);
            for start in 0..=bytes.len() {
                for end in start..=bytes.len() {
                    let span = OffsetSpan { start, end };
                    assert_eq!(
                        index.should_ignore(&span),
                        config.should_ignore(bytes, &span),
                        "input={input:?} span={span:?}"
                    );
                }
            }
        }
        assert!(
            !InlineIgnoreIndex::new(&InlineIgnoreConfig::disabled(), b"kingfisher:ignore")
                .should_ignore(&OffsetSpan { start: 0, end: 1 })
        );
    }

    #[test]
    fn sparse_directives_do_not_build_a_full_input_index() {
        let config = InlineIgnoreConfig::new(&[]);
        let cache = std::sync::OnceLock::new();
        let input = b"ordinary source line\nsecret_abcd1234\nordinary source line\n";
        assert!(!config.should_ignore_cached(input, &OffsetSpan { start: 22, end: 36 }, &cache));
        assert!(cache.get().is_none());
        let dense = "YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4\n".repeat(1000);
        assert!(!config.should_ignore_cached(
            dense.as_bytes(),
            &OffsetSpan { start: 0, end: 10 },
            &cache
        ));
        assert!(cache.get().is_some());
    }

    #[test]
    fn dense_encoded_lines_have_one_summary_per_line() {
        use super::InlineIgnoreIndex;
        let config = InlineIgnoreConfig::new(&[]);
        let input = "YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4\n".repeat(10_000);
        let index = InlineIgnoreIndex::new(&config, input.as_bytes());
        assert_eq!(index.lines.len(), 10_001);
        for start in (0..input.len()).step_by(33) {
            assert!(!index.should_ignore(&OffsetSpan { start, end: start + 1 }));
        }
    }

    #[test]
    fn bounds_cover_expected_ranges() {
        let data = b"one\ntwo\nthree";
        assert_eq!(line_bounds(data, 0), (0, 3));
        assert_eq!(line_bounds(data, 4), (4, 7));
        assert_eq!(line_bounds(data, data.len()), (8, 13));
    }

    #[test]
    fn detects_directives_in_lines() {
        let tokens = vec![b"kingfisher:ignore".to_vec()];
        assert!(line_has_directive(b"secret # kingfisher:ignore", &tokens));
        assert!(line_has_directive(b"kingfisher:ignore before value", &tokens));
        assert!(line_has_directive(b"value // Gitleaks:Allow", &[b"gitleaks:allow".to_vec()]));
        assert!(!line_has_directive(b"secret", &tokens));
    }

    #[test]
    fn respects_multiline_block_comment_prefix() {
        let tokens = vec![b"kingfisher:ignore".to_vec()];
        assert!(line_has_directive(b" * kingfisher:ignore", &tokens));
    }

    #[test]
    fn ignores_multi_line_string_with_trailing_comment() {
        let blob = b"let secret = \"\"\"\nline1\nline2\n\"\"\"\n# kingfisher:ignore\n";
        let matched = b"line1\nline2\n";
        let start = blob
            .windows(matched.len())
            .position(|window| window == matched)
            .expect("match bytes present");
        let span = OffsetSpan::from_range(start..start + matched.len());
        let config = InlineIgnoreConfig::new(&[]);
        assert!(config.should_ignore(blob, &span));
    }

    #[test]
    fn ignores_multiline_with_directive_on_closing_line() {
        let blob = b"api_key = \"\"\"\nline1\nline2\n\"\"\"  // kingfisher:ignore\n";
        let matched = b"line1\nline2\n";
        let start = blob
            .windows(matched.len())
            .position(|window| window == matched)
            .expect("match bytes present");
        let span = OffsetSpan::from_range(start..start + matched.len());
        let config = InlineIgnoreConfig::new(&[]);
        assert!(config.should_ignore(blob, &span));
    }

    #[test]
    fn ignores_pem_with_directive_before_block() {
        let blob = b"// kingfisher:ignore\napi_key = \"\"\"\n-----BEGIN RSA PRIVATE KEY-----\nMIICWwIBAAKBgQC7\n-----END RSA PRIVATE KEY-----\n\"\"\"\n";
        let matched = b"MIICWwIBAAKBgQC7\n";
        let start = blob
            .windows(matched.len())
            .position(|window| window == matched)
            .expect("match bytes present");
        let span = OffsetSpan::from_range(start..start + matched.len());
        let config = InlineIgnoreConfig::new(&[]);
        assert!(config.should_ignore(blob, &span));
    }

    #[test]
    fn ignores_multiline_hex_payload_with_directive() {
        let blob = b"# kingfisher:ignore\nsecret = \"\"\"\n00112233445566778899aabbccddeeff\nffeeddccbbaa99887766554433221100\n\"\"\"\n";
        let matched = b"00112233445566778899aabbccddeeff\nffeeddccbbaa99887766554433221100\n";
        let start = blob
            .windows(matched.len())
            .position(|window| window == matched)
            .expect("match bytes present");
        let span = OffsetSpan::from_range(start..start + matched.len());
        let config = InlineIgnoreConfig::new(&[]);
        assert!(config.should_ignore(blob, &span));
    }

    #[test]
    fn ignores_multiline_base32_payload_with_directive_after_block() {
        let blob =
            b"secret = \"\"\"\nMFRGGZDFMZTWQ2LK\nONSWG4TFOQ======\n\"\"\"\n// kingfisher:ignore\n";
        let matched = b"MFRGGZDFMZTWQ2LK\nONSWG4TFOQ======\n";
        let start = blob
            .windows(matched.len())
            .position(|window| window == matched)
            .expect("match bytes present");
        let span = OffsetSpan::from_range(start..start + matched.len());
        let config = InlineIgnoreConfig::new(&[]);
        assert!(config.should_ignore(blob, &span));
    }

    #[test]
    fn ignores_multiline_without_trailing_newline() {
        let blob = b"let secret = \"\"\"\nline1\nline2\n\"\"\"\n# kingfisher:ignore\n";
        let matched = b"line1\nline2";
        let start = blob
            .windows(matched.len())
            .position(|window| window == matched)
            .expect("match bytes present");
        let span = OffsetSpan::from_range(start..start + matched.len());
        let config = InlineIgnoreConfig::new(&[]);
        assert!(config.should_ignore(blob, &span));
    }

    #[test]
    fn ignores_multiline_with_directive_before_secret() {
        let blob = b"// kingfisher:ignore\nlet secret = \"\"\"\nline1\nline2\n\"\"\"\n";
        let matched = b"line1\nline2\n";
        let start = blob
            .windows(matched.len())
            .position(|window| window == matched)
            .expect("match bytes present");
        let span = OffsetSpan::from_range(start..start + matched.len());
        let config = InlineIgnoreConfig::new(&[]);
        assert!(config.should_ignore(blob, &span));
    }

    #[test]
    fn ignores_single_line_secret_with_directive_on_previous_line() {
        let blob = b"# safe-secret\n123456\n";
        let matched = b"123456";
        let start = blob
            .windows(matched.len())
            .position(|window| window == matched)
            .expect("match bytes present");
        let span = OffsetSpan::from_range(start..start + matched.len());
        let config = InlineIgnoreConfig::new(&["safe-secret".to_string()]);
        assert!(config.should_ignore(blob, &span));
    }

    #[test]
    fn trim_ascii_whitespace_returns_inner_slice() {
        assert_eq!(trim_ascii_whitespace(b"  abc  "), b"abc");
        assert!(trim_ascii_whitespace(b"   ").is_empty());
    }

    #[test]
    fn skips_lines_with_only_delimiters() {
        assert!(should_skip_for_directive_search(b"\"\"\""));
        assert!(should_skip_for_directive_search(b"   \"\"\"   "));
        assert!(should_skip_for_directive_search(b"let secret = \"\"\""));
        assert!(!should_skip_for_directive_search(b"value"));
        assert!(should_skip_for_directive_search(b"-----BEGIN RSA PRIVATE KEY-----"));
        assert!(should_skip_for_directive_search(b"MIICWwIBAAKBgQC7"));
        assert!(should_skip_for_directive_search(b"0011223344556677"));
        assert!(should_skip_for_directive_search(b"MFRGGZDFMZTWQ2LK"));
    }

    #[test]
    fn disabled_config_never_ignores() {
        let blob = b"let secret = 'value' # kingfisher:ignore";
        let matched = b"value";
        let start = blob
            .windows(matched.len())
            .position(|window| window == matched)
            .expect("match bytes present");
        let span = OffsetSpan::from_range(start..start + matched.len());
        let config = InlineIgnoreConfig::disabled();
        assert!(!config.should_ignore(blob, &span));
    }
}
