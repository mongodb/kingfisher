use core::ops::Range;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// A point defined by a byte offset.
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, Copy, Clone)]
pub struct OffsetPoint(pub usize);

impl OffsetPoint {
    #[inline]
    pub fn new(idx: usize) -> Self {
        OffsetPoint(idx)
    }
}

/// A non‑empty span defined by two byte offsets (half‑open interval `[start, end)`).
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
pub struct OffsetSpan {
    pub start: usize,
    pub end: usize,
}

impl std::fmt::Display for OffsetSpan {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}-{}", self.start, self.end)
    }
}

impl OffsetSpan {
    #[inline]
    pub fn from_offsets(start: OffsetPoint, end: OffsetPoint) -> Self {
        OffsetSpan { start: start.0, end: end.0 }
    }

    #[inline]
    pub fn from_range(range: Range<usize>) -> Self {
        OffsetSpan { start: range.start, end: range.end }
    }

    /// Length in bytes.
    #[inline]
    #[must_use]
    pub fn len(&self) -> usize {
        self.end.saturating_sub(self.start)
    }

    /// True if empty or inverted.
    #[inline]
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.start >= self.end
    }

    /// True if `other` lies entirely within `self`.
    #[inline]
    #[must_use]
    pub fn fully_contains(&self, other: &Self) -> bool {
        self.start <= other.start && other.end <= self.end
    }
}

/// A point in the source file (line 1‑indexed, column 0‑indexed).
#[derive(Debug, PartialEq, Eq, Hash, Copy, Clone, Serialize, Deserialize, JsonSchema)]
pub struct SourcePoint {
    pub line: usize,
    pub column: usize,
}

impl std::fmt::Display for SourcePoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{}", self.line, self.column)
    }
}

/// A closed interval between two source points.
#[derive(Debug, PartialEq, Eq, Hash, Clone, Serialize, Deserialize, JsonSchema)]
pub struct SourceSpan {
    pub start: SourcePoint,
    pub end: SourcePoint,
}

impl std::fmt::Display for SourceSpan {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}-{}", self.start, self.end)
    }
}

/// Records newline byte‑offsets to map offsets -- (line, column).
pub struct LocationMapping {
    newline_offsets: Vec<usize>,
}

impl LocationMapping {
    /// Scan once for all `\n` positions.
    pub fn new(input: &[u8]) -> Self {
        let newline_offsets =
            input.iter().enumerate().filter_map(|(i, &b)| (b == b'\n').then_some(i)).collect();
        LocationMapping { newline_offsets }
    }

    /// Map a byte offset to a `SourcePoint`.
    pub fn get_source_point(&self, offset: usize) -> SourcePoint {
        let line = match self.newline_offsets.binary_search(&offset) {
            Ok(idx) => idx + 2, // exact newline -- next line
            Err(idx) => idx + 1,
        };
        let column = if let Some(&last) = self.newline_offsets.get(line.saturating_sub(2)) {
            offset.saturating_sub(last + 1)
        } else {
            offset
        };
        SourcePoint { line, column }
    }

    /// Map an `OffsetSpan` -- `SourceSpan` (closed interval).
    pub fn get_source_span(&self, span: &OffsetSpan) -> SourceSpan {
        let start = self.get_source_point(span.start);
        let end = self.get_source_point(span.end.saturating_sub(1));
        SourceSpan { start, end }
    }
}

/// Combined byte‑ and source‑span.
#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
pub struct Location {
    pub offset_span: OffsetSpan,
    pub source_span: SourceSpan,
}
