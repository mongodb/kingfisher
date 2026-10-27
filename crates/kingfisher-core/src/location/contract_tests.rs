//! Characterization of span APIs and the existing lazy source-location mapping.

use super::*;

#[test]
fn offset_spans_preserve_empty_inverted_and_machine_boundary_values() {
    let bounds = [0, 1, 2, 17, usize::MAX - 1, usize::MAX];
    for start in bounds {
        assert_eq!(OffsetPoint::new(start), OffsetPoint(start));
        let encoded_point = serde_json::to_value(OffsetPoint::new(start)).unwrap();
        assert_eq!(encoded_point, serde_json::json!(start));
        assert_eq!(
            serde_json::from_value::<OffsetPoint>(encoded_point).unwrap(),
            OffsetPoint(start)
        );
        for end in bounds {
            let span = OffsetSpan::from_range(start..end);
            assert_eq!(span, OffsetSpan { start, end });
            assert_eq!(span, OffsetSpan::from_offsets(OffsetPoint(start), OffsetPoint(end)));
            let expected_len = end.max(start) - start;
            assert_eq!(span.len(), expected_len, "{start}..{end}");
            assert_eq!(span.is_empty(), expected_len == 0, "{start}..{end}");
            assert_eq!(span.to_string(), format!("{start}-{end}"));
            let encoded = serde_json::to_value(span).unwrap();
            assert_eq!(encoded, serde_json::json!({ "start": start, "end": end }));
            assert_eq!(serde_json::from_value::<OffsetSpan>(encoded).unwrap(), span);
        }
    }
}

#[test]
fn span_containment_preserves_boundary_and_inverted_interval_semantics() {
    let bounds = [0, 1, 2, usize::MAX - 1, usize::MAX];
    for outer_start in bounds {
        for outer_end in bounds {
            let outer = OffsetSpan { start: outer_start, end: outer_end };
            for inner_start in bounds {
                for inner_end in bounds {
                    let inner = OffsetSpan { start: inner_start, end: inner_end };
                    // This compares endpoints, including empty/inverted intervals;
                    // it does not require either range to contain actual bytes.
                    let expected = outer_start <= inner_start && inner_end <= outer_end;
                    assert_eq!(outer.fully_contains(&inner), expected, "{outer:?}, {inner:?}");
                }
            }
        }
    }
}

#[test]
fn source_positions_keep_byte_coordinates_and_display_contract() {
    let start = SourcePoint { line: 0, column: usize::MAX };
    let end = SourcePoint { line: usize::MAX, column: 0 };
    let span = SourceSpan { start, end };
    assert_eq!(start.to_string(), format!("0:{}", usize::MAX));
    assert_eq!(end.to_string(), format!("{}:0", usize::MAX));
    let expected = format!("0:{}-{}:0", usize::MAX, usize::MAX);
    assert_eq!(span.to_string(), expected);
    // These formats historically ignore flags on the enclosing source type.
    assert_eq!(format!("{start:>50.1}"), start.to_string());
    assert_eq!(format!("{span:>80.1}"), expected);
    let value = serde_json::to_value(&span).unwrap();
    assert_eq!(
        value,
        serde_json::json!({
            "start": { "line": 0, "column": usize::MAX },
            "end": { "line": usize::MAX, "column": 0 }
        })
    );
    assert_eq!(serde_json::from_value::<SourceSpan>(value).unwrap(), span);
}

#[test]
fn span_display_propagates_writer_failure_without_assuming_write_chunking() {
    struct Budget(usize);
    impl std::fmt::Write for Budget {
        fn write_str(&mut self, text: &str) -> std::fmt::Result {
            self.0 = self.0.checked_sub(text.len()).ok_or(std::fmt::Error)?;
            Ok(())
        }
    }
    let point = SourcePoint { line: 123, column: 45 };
    let source = SourceSpan { start: point, end: SourcePoint { line: 678, column: 90 } };
    let offset = OffsetSpan { start: 123, end: 456 };
    for value in [&point as &dyn std::fmt::Display, &source, &offset] {
        let needed = value.to_string().len();
        for remaining in 0..needed {
            assert!(std::fmt::write(&mut Budget(remaining), format_args!("{value}")).is_err());
        }
        assert!(std::fmt::write(&mut Budget(needed), format_args!("{value}")).is_ok());
    }
}

fn point_oracle(input: &[u8], offset: usize) -> SourcePoint {
    let prefix = &input[..offset.min(input.len())];
    let line = 1 + prefix.iter().filter(|&&byte| byte == b'\n').count();
    let column = match prefix.iter().rposition(|&byte| byte == b'\n') {
        Some(newline) => offset - newline - 1,
        None => offset,
    };
    SourcePoint { line, column }
}

#[test]
fn direct_location_points_follow_newline_byte_oracle_in_any_query_order() {
    let cases: &[&[u8]] = &[
        b"",
        b"abc",
        b"\n",
        b"\n\n",
        b"a\r\nb\rc\n",
        "é🙂\nβ\r\n".as_bytes(),
        b"\xff\n\0\r\x80\n",
    ];
    for &input in cases {
        let mapping = LocationMapping::new(input);
        for offset in (0..=input.len() + 2).rev() {
            assert_eq!(mapping.get_source_point(offset), point_oracle(input, offset));
        }
        for offset in 0..=input.len() + 2 {
            assert_eq!(mapping.get_source_point(offset), point_oracle(input, offset));
        }
        assert_eq!(mapping.get_source_point(usize::MAX), point_oracle(input, usize::MAX));
    }
}

#[test]
fn nonempty_source_spans_use_inclusive_end_byte_and_byte_columns() {
    let input = "é\r\n🙂\n\nlast".as_bytes();
    for start in 0..input.len() {
        for end in start + 1..=input.len() + 1 {
            let span = OffsetSpan { start, end };
            let expected =
                SourceSpan { start: point_oracle(input, start), end: point_oracle(input, end - 1) };
            let fresh = LocationMapping::new(input);
            assert_eq!(fresh.get_source_span(&span), expected);
            let cached = LocationMapping::new(input);
            cached.get_source_point(input.len());
            assert_eq!(cached.get_source_span(&span), expected);
        }
    }
}

#[test]
fn location_json_preserves_legacy_source_span_and_absent_value_behavior() {
    let offset_span = OffsetSpan { start: 3, end: 9 };
    let source = SourceSpan {
        start: SourcePoint { line: 2, column: 0 },
        end: SourcePoint { line: 3, column: 4 },
    };
    let location = Location::with_source_span(offset_span, Some(source.clone()));
    assert_eq!(location.resolved_source_span(), source);
    let encoded = serde_json::to_value(&location).unwrap();
    assert_eq!(
        encoded,
        serde_json::json!({
            "offset_span": { "start": 3, "end": 9 },
            "source_span": {
                "start": { "line": 2, "column": 0 },
                "end": { "line": 3, "column": 4 }
            }
        })
    );
    let decoded: Location = serde_json::from_value(encoded).unwrap();
    assert_eq!(decoded.offset_span, offset_span);
    assert_eq!(decoded.resolved_source_span(), source);
    let missing: Location = serde_json::from_value(serde_json::json!({
        "offset_span": { "start": 3, "end": 9 }
    }))
    .unwrap();
    assert!(missing.source_span().is_none());
    assert_eq!(
        serde_json::to_value(missing).unwrap()["source_span"],
        serde_json::json!({ "start": { "line": 0, "column": 0 }, "end": { "line": 0, "column": 0 } })
    );
    let null = serde_json::json!({
        "offset_span": { "start": 3, "end": 9 }, "source_span": null
    });
    assert_eq!(
        serde_json::from_value::<Location>(null).unwrap_err().to_string(),
        "invalid type: null, expected struct SourceSpan"
    );
}

#[test]
fn compact_source_spans_keep_zero_and_overflow_fallbacks() {
    let zero = CompactSourceSpan::zero().to_source_span();
    assert_eq!(zero.start, SourcePoint { line: 0, column: 0 });
    assert_eq!(zero.end, zero.start);
    let maximum = SourceSpan {
        start: SourcePoint { line: u32::MAX as usize, column: u32::MAX as usize },
        end: SourcePoint { line: 1, column: 2 },
    };
    assert_eq!(CompactSourceSpan::from_source_span(&maximum).to_source_span(), maximum);
    if let Ok(overflow) = usize::try_from(u64::from(u32::MAX) + 1) {
        let wide = SourceSpan {
            start: SourcePoint { line: overflow, column: 7 },
            end: SourcePoint { line: 8, column: overflow },
        };
        assert_eq!(
            CompactSourceSpan::from_source_span(&wide).to_source_span(),
            SourceSpan {
                start: SourcePoint { line: 0, column: 7 },
                end: SourcePoint { line: 8, column: 0 }
            }
        );
    }
}
