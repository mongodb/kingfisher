use std::cell::Cell;

use anyhow::Result;
use cssparser::{
    AtRuleParser, CowRcStr, DeclarationParser, ParseError, Parser, ParserState, RuleBodyItemParser,
    RuleBodyParser, StyleSheetParser, ToCss, Token, parse_important,
};

pub(super) fn stream_context_candidates<F>(source: &[u8], sink: &mut F) -> Result<()>
where
    F: FnMut(&str) -> bool,
{
    let css = String::from_utf8_lossy(source);
    if css.trim().is_empty() {
        return Ok(());
    }

    let mut parser = Parser::new(&css);
    let stopped = Cell::new(false);
    let mut collector = Collector { sink, stopped: &stopped };
    let mut stylesheet = StyleSheetParser::new(&mut parser, &mut collector);
    while !stopped.get() {
        if stylesheet.next().is_none() {
            break;
        }
    }
    Ok(())
}

struct Collector<'a, F> {
    sink: &'a mut F,
    stopped: &'a Cell<bool>,
}

impl<'a, F> Collector<'a, F>
where
    F: FnMut(&str) -> bool,
{
    fn emit(&mut self, name: &str, value: &str) {
        if self.stopped.get() {
            return;
        }
        let candidate = format!("{name} = {value}");
        self.stopped.set(!(self.sink)(&candidate));
    }
}

impl<'i, F> DeclarationParser<'i> for Collector<'_, F>
where
    F: FnMut(&str) -> bool,
{
    type Declaration = ();
    type Error = ();

    fn parse_value(
        &mut self,
        name: CowRcStr<'i>,
        input: &mut Parser<'i>,
        _declaration_start: &ParserState,
    ) -> Result<(), ParseError<()>> {
        let mut values = Vec::new();
        let mut important = false;
        loop {
            let start = input.state();
            let token = match input.next_including_whitespace().cloned() {
                Ok(token) => token,
                Err(_) => break,
            };

            if token == Token::Delim('!') {
                let after_bang = input.state();
                input.reset(&start);
                if parse_important(input).is_ok() && input.is_exhausted() {
                    important = true;
                    break;
                }
                // Keep the consumed '!' when it is not a trailing !important.
                input.reset(&after_bang);
            }

            collect_token_values(token, input, &mut values);
        }

        if values.is_empty() && !important {
            return Ok(());
        }

        if values.is_empty() && important {
            values.push("important".to_string());
        }

        for value in values {
            self.emit(&name, &value);
            if self.stopped.get() {
                break;
            }
        }
        Ok(())
    }
}

impl<'i, F> AtRuleParser<'i> for Collector<'_, F>
where
    F: FnMut(&str) -> bool,
{
    type Prelude = ();
    type AtRule = ();
    type Error = ();
}

impl<'i, F> cssparser::QualifiedRuleParser<'i> for Collector<'_, F>
where
    F: FnMut(&str) -> bool,
{
    type Prelude = ();
    type QualifiedRule = ();
    type Error = ();

    fn parse_prelude(&mut self, input: &mut Parser<'i>) -> Result<(), ParseError<()>> {
        while input.next_including_whitespace().is_ok() {}
        Ok(())
    }

    fn parse_block(
        &mut self,
        _prelude: (),
        _start: &ParserState,
        input: &mut Parser<'i>,
    ) -> Result<(), ParseError<()>> {
        let stopped = self.stopped;
        let mut rule_body = RuleBodyParser::new(input, self);
        while !stopped.get() {
            if rule_body.next().is_none() {
                break;
            }
        }
        Ok(())
    }
}

impl<F> RuleBodyItemParser<'_, (), ()> for Collector<'_, F>
where
    F: FnMut(&str) -> bool,
{
    fn parse_qualified(&self) -> bool {
        true
    }

    fn parse_declarations(&self) -> bool {
        true
    }
}

fn collect_token_values<'i>(token: Token<'i>, input: &mut Parser<'i>, values: &mut Vec<String>) {
    match token {
        Token::QuotedString(value) => values.push(value.to_string()),
        Token::UnquotedUrl(value) => values.push(value.to_string()),
        Token::Ident(value) => values.push(value.to_string()),
        Token::Hash(value) | Token::IDHash(value) => values.push(value.to_string()),
        Token::Number { .. }
        | Token::Percentage { .. }
        | Token::Dimension { .. }
        | Token::Function(_) => {
            values.push(token.to_css_string());
            if matches!(token, Token::Function(_)) {
                let _ = input.parse_nested_block(|nested| {
                    while let Ok(next) = nested.next_including_whitespace().cloned() {
                        collect_token_values(next, nested, values);
                    }
                    Ok::<(), ParseError<()>>(())
                });
            }
        }
        Token::ParenthesisBlock | Token::SquareBracketBlock | Token::CurlyBracketBlock => {
            let _ = input.parse_nested_block(|nested| {
                while let Ok(next) = nested.next_including_whitespace().cloned() {
                    collect_token_values(next, nested, values);
                }
                Ok::<(), ParseError<()>>(())
            });
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn candidates(source: &[u8]) -> Vec<String> {
        let mut candidates = Vec::new();
        stream_context_candidates(source, &mut |candidate| {
            candidates.push(candidate.to_owned());
            true
        })
        .unwrap();
        candidates
    }

    #[test]
    fn collects_all_value_token_kinds_and_nested_blocks_in_order() {
        let source = br#"
            :root {
                password: "secret";
                url: url(https://example.test/token);
                quoted-url: url("https://example.test/quoted");
                ident: token;
                hash: #abc123;
                unrestricted-hash: #123abc;
                numbers: 12 25% 4px;
                calls: outer("nested", inner(2));
                blocks: ("paren" ["square"] {"curly"});
                &:hover { password: "hover"; }
            }
            .next { last: "after"; }
        "#;
        assert_eq!(
            candidates(source),
            [
                "password = secret",
                "url = https://example.test/token",
                "quoted-url = url(",
                "quoted-url = https://example.test/quoted",
                "ident = token",
                "hash = abc123",
                "unrestricted-hash = 123abc",
                "numbers = 12",
                "numbers = 25%",
                "numbers = 4px",
                "calls = outer(",
                "calls = nested",
                "calls = inner(",
                "calls = 2",
                "blocks = paren",
                "blocks = square",
                "blocks = curly",
                "password = hover",
                "last = after",
            ]
        );
    }

    #[test]
    fn decodes_owned_escaped_strings_and_preserves_important_handling() {
        let source = br#"
            :root {
                --api\2d key: "sec\72 et";
                --id: to\6b en;
                --quoted-url: url("https://example.test/\74 oken");
                --hash: #\61 bc;
                --escaped-fn: f\6f o("v\61 lue");
                priority: "kept" ! IMPORTANT;
                only: !important;
            }
        "#;
        assert_eq!(
            candidates(source),
            [
                "--api-key = secret",
                "--id = token",
                "--quoted-url = url(",
                "--quoted-url = https://example.test/token",
                "--hash = abc",
                "--escaped-fn = foo(",
                "--escaped-fn = value",
                "priority = kept",
                "only = important",
            ]
        );
    }

    #[test]
    fn failed_or_nonterminal_important_probes_advance_and_preserve_value_order() {
        let source = br#"
            body {
                mismatch: !not-important;
                before: !important other;
                after: other !important;
                repeated: !important !important;
                mixed: !important !not-important !important;
                double: !!important;
                last: "after all probes";
            }
        "#;
        assert_eq!(
            candidates(source),
            [
                "mismatch = not-important",
                "before = important",
                "before = other",
                "after = other",
                "repeated = important",
                "mixed = important",
                "mixed = not-important",
                "double = important",
                "last = after all probes",
            ]
        );
    }

    #[test]
    fn sink_can_stop_within_values_nested_rules_and_stylesheet_rules() {
        let source = br#"
            :root {
                first: outer("nested", inner(2));
                &:hover { second: "hover"; }
                third: "after";
            }
            .next { last: "final"; }
        "#;
        let all = candidates(source);
        assert_eq!(all.len(), 7);
        for limit in 1..=all.len() {
            let mut emitted = Vec::new();
            stream_context_candidates(source, &mut |candidate| {
                emitted.push(candidate.to_owned());
                emitted.len() < limit
            })
            .unwrap();
            assert_eq!(emitted, all[..limit]);
        }
    }

    #[test]
    fn ignores_comments_and_at_rules_and_recovers_after_invalid_declarations() {
        let source = br#"
            @import url(https://example.test/ignored);
            @media screen { body { password: "ignored"; } }
            body {
                /* password: "ignored"; */
                password: "visible";
                broken;
                other: "after";
            }
        "#;
        assert_eq!(candidates(source), ["password = visible", "other = after"]);
        for empty in [b"".as_slice(), b" \r\n\t", b"/* comment only */"] {
            assert!(candidates(empty).is_empty());
        }
        assert_eq!(candidates(b"body { token: \"invalid \xff\"; }"), ["token = invalid \u{fffd}"]);
    }
}
