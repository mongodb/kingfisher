// Re-export from the canonical implementation in kingfisher-scanner.
pub(crate) use kingfisher_scanner::primitives::compute_match_key;

/// Keep CLI matching on the ordered containment tracker; the SDK's public
/// `record_match` helper accepts the legacy vector representation.
pub(crate) fn record_match(
    map: &mut rustc_hash::FxHashMap<usize, kingfisher_scanner::primitives::MatchSpans>,
    rule_id: usize,
    span: crate::location::OffsetSpan,
) -> bool {
    map.entry(rule_id).or_default().insert(span)
}
