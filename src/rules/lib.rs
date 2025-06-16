//! This module re-exports the public API from submodules for use by external crates.
//! It also contains tests to verify behavior and demonstrate property-based testing.

pub mod rule;
mod rules;
pub use rule::Confidence;
mod util;
pub use rule::{
    DependsOnRule, HttpRequest, HttpValidation, ResponseMatcher, Rule, RuleSyntax, Validation,
};
pub use rules::Rules;

#[cfg(test)]
mod tests {
    use pretty_assertions::assert_eq;
    use proptest::prelude::*;

    // Property-based test that generates strings matching the secret key pattern.
    // This ensures that the regex for detecting keys generates valid secret strings.
    proptest! {
        #[test]
        fn test_regex_generation(s in r"((?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16})") {
            println!("{}", s);
        }
    }

    // A simple test that is expected to fail.
    #[test]
    #[should_panic(expected = "assertion failed")]
    fn test_failure() {
        assert_eq!(5, 42);
    }
}
