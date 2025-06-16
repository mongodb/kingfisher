use once_cell::sync::Lazy;
use regex::bytes::Regex;
use tracing::debug;
static SAFE_LIST_FILTER_REGEX: Lazy<Vec<Option<Regex>>> = Lazy::new(|| {
    vec![
        compile_regex(r"(?i)[:=][^:=]{0,64}EXAMPLEKEY"),
        compile_regex(r"(?i)\b(AKIA(?:.*?EXAMPLE|.*?FAKE|TEST|.*?SAMPLE))\b"),
        compile_regex(
            r"(?i)(password|pass|pwd|passwd|secret|cred|key|auth|authorization)[^=:?]{0,8}[=:?][^=:?]{0,8}\s(&&|\|\||\*{5,50})",
        ),
        compile_regex(
            r"(?i)(password|pass|pwd|passwd|secret|cred|key|auth|authorization)[^=:?]{0,8}[=:?][^=:?]{0,8}\b\w{4,12}\s{0,6}=\s{0,6}\D{0,3}\w{1,12}",
        ),
        compile_regex(
            r"(?i)(password|pass|pwd|passwd|secret|cred|key|auth|authorization)[^=:?]{0,8}[=:?][^=:?]{0,8}\$\w{4,30}",
        ),
        compile_regex(
            r"(?i)(password|pass|pwd|passwd|secret|cred|key|auth|authorization)[^=:?]{0,16}[=:?][^=:?]{0,8}\bopenssl\s{0,4}rand\b",
        ),
        compile_regex(
            r"(?i)(password|pass|pwd|passwd|secret|cred|key|auth|authorization)[^=:?]{0,8}[=:?][^=:?]{0,8}encrypted",
        ),
        compile_regex(
            r"(?i)(password|pass|pwd|passwd|secret|cred|key|auth|authorization)[^=:?]{0,8}[=:?][^=:?]{0,8}\b(?:false|true)\b",
        ),
        compile_regex(
            r"(?i)(password|pass|pwd|passwd|secret|cred|key|auth|authorization)[^=:?]{0,8}[=:?][^=:?]{0,8}\b(null|nil|none|password|pass|pwd|passwd|secret|cred|key|auth|authorization).{1,6}$",
        ),
        compile_regex(
            r"(?i)(password|pass|pwd|passwd|secret|cred|key|auth|authorization)[^=:?]{0,8}[=:?][^=:?]{0,8}hunter2",
        ),
        compile_regex(r"(?i)123456789|abcdefghij"),
        compile_regex(r"(?i)<secretmanager>"),
        compile_regex(r"(?i)[=:?][^=:?]{0,8}#/components/schemas/"),
        compile_regex(
            r"(?i)\b(mongodb(?:\+srv)?://(?:user|foo)[^:@]+:(?:pass|bar)[^@]+@[-\w.%+/:]{3,64}(?:/\w+)?)",
        ),
        compile_regex(r"(?i)\b(classpath://)"),
        compile_regex(r"(?i)(\b[^\s\t]{0,16}[=:][^$]*\$\{[a-z_-]{5,30}\})"),
        compile_regex(r"(?i)\b((?:https?:)?//[^:@]{3,50}:[^:@]{3,50}@[\w.]{0,16}(?:example|test))"),
        compile_regex(r"(?i)[:=][^:=]{0,32}\bSECRETMANAGER"),
    ]
});
fn compile_regex(pattern: &str) -> Option<Regex> {
    match Regex::new(pattern) {
        Ok(regex) => Some(regex),
        Err(e) => {
            debug!("Failed to compile regex '{}': {}", pattern, e);
            None
        }
    }
}
pub fn is_safe_match(input: &[u8]) -> bool {
    SAFE_LIST_FILTER_REGEX
        .iter()
        .filter_map(|regex_option| regex_option.as_ref())
        .any(|regex| regex.is_match(input))
}
