//! Small formatting helpers shared by CLI progress and reports.

use std::fmt;

/// Group an unsigned decimal count in threes with ASCII commas.
pub(crate) fn comma_grouped(count: u128) -> String {
    let digits = count.to_string();
    let mut grouped = String::with_capacity(digits.len() + (digits.len() - 1) / 3);
    for (index, digit) in digits.bytes().enumerate() {
        if index > 0 && (digits.len() - index).is_multiple_of(3) {
            grouped.push(',');
        }
        grouped.push(char::from(digit));
    }
    grouped
}

/// Prefix nonempty lines, retaining blank lines and trailing newlines verbatim.
pub(crate) fn prefixed<'a, W: fmt::Write>(
    writer: &'a mut W,
    prefix: &'static str,
) -> impl fmt::Write + 'a {
    Prefixed { writer, prefix, line_start: true }
}

struct Prefixed<'a, W> {
    writer: &'a mut W,
    prefix: &'static str,
    line_start: bool,
}

impl<W: fmt::Write> fmt::Write for Prefixed<'_, W> {
    fn write_str(&mut self, text: &str) -> fmt::Result {
        for line in text.split_inclusive('\n') {
            if self.line_start && !line.starts_with('\n') {
                self.writer.write_str(self.prefix)?;
                self.line_start = false;
            }
            self.writer.write_str(line)?;
            self.line_start = line.ends_with('\n');
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::fmt::Write as _;

    use super::*;

    #[test]
    fn count_grouping_preserves_boundaries_and_zeroes() {
        for (count, expected) in [
            (0, "0"),
            (9, "9"),
            (10, "10"),
            (99, "99"),
            (100, "100"),
            (999, "999"),
            (1_000, "1,000"),
            (1_001, "1,001"),
            (10_000, "10,000"),
            (100_000, "100,000"),
            (999_999, "999,999"),
            (1_000_000, "1,000,000"),
            (1_000_001, "1,000,001"),
            (u64::MAX as u128, "18,446,744,073,709,551,615"),
            (u128::MAX, "340,282,366,920,938,463,463,374,607,431,768,211,455"),
        ] {
            assert_eq!(comma_grouped(count), expected, "count: {count}");
        }
    }

    #[test]
    fn count_grouping_handles_every_decimal_width() {
        for exponent in 0..=38 {
            let count = 10_u128.pow(exponent);
            let expected = format!(
                "1{}{}",
                "0".repeat(exponent as usize % 3),
                ",000".repeat(exponent as usize / 3)
            );
            assert_eq!(comma_grouped(count), expected);
        }
        assert_eq!(comma_grouped(usize::MAX as u128).replace(',', ""), usize::MAX.to_string());
    }

    #[test]
    fn line_prefixing_preserves_empty_lines_and_line_endings() {
        for (input, expected) in [
            ("", ""),
            ("first", " |__first"),
            ("\n", "\n"),
            ("\n\n", "\n\n"),
            ("\nfirst\n\nsecond\n", "\n |__first\n\n |__second\n"),
            ("first\r\nsecond\r\n", " |__first\r\n |__second\r\n"),
            ("first\n \nsecond", " |__first\n |__ \n |__second"),
            ("é漢字\n🦀", " |__é漢字\n |__🦀"),
        ] {
            let mut output = String::new();
            write!(prefixed(&mut output, " |__"), "{input}").unwrap();
            assert_eq!(output, expected, "input: {input:?}");
        }
    }

    #[test]
    fn line_prefixing_keeps_state_across_format_fragments() {
        let mut output = String::new();
        {
            let mut writer = prefixed(&mut output, " |__");
            writer.write_str("").unwrap();
            writer.write_char('\n').unwrap();
            writer.write_str("Auth").unwrap();
            writer.write_str("or: ").unwrap();
            writer.write_str("").unwrap();
            writer.write_str("Alice\n").unwrap();
            writer.write_str("").unwrap();
            writer.write_str("\n").unwrap();
            writer.write_str("Bob").unwrap();
            writer.write_char('\n').unwrap();
            writer.write_char('🦀').unwrap();
        }
        assert_eq!(output, "\n |__Author: Alice\n\n |__Bob\n |__🦀");
    }

    #[test]
    fn line_prefixing_covers_multiple_interpolations_and_trailing_newlines() {
        let mut output = String::new();
        let author = "Alice\n\nBob";
        let email = "mail\n";
        writeln!(prefixed(&mut output, " |__"), "Author........: {author} <{email}>").unwrap();
        assert_eq!(output, " |__Author........: Alice\n\n |__Bob <mail\n |__>\n");

        let mut output = String::new();
        write!(prefixed(&mut output, ""), "a\n\nb\n").unwrap();
        assert_eq!(output, "a\n\nb\n");
    }

    #[test]
    fn line_prefixing_propagates_writer_errors() {
        struct FailAfter(usize);
        impl fmt::Write for FailAfter {
            fn write_str(&mut self, _: &str) -> fmt::Result {
                if self.0 == 0 {
                    Err(fmt::Error)
                } else {
                    self.0 -= 1;
                    Ok(())
                }
            }
        }

        // Fail while writing a prefix, line content, or a subsequent line.
        for writes in 0..4 {
            assert!(write!(prefixed(&mut FailAfter(writes), " |__"), "a\nb").is_err());
        }
    }
}
