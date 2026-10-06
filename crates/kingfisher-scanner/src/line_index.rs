//! Reuse newline boundaries for filters on dense or minified input.
use bstr::ByteSlice;
pub struct LineIndex {
    newlines: Vec<usize>,
    byte_len: usize,
}

impl LineIndex {
    pub fn new(bytes: &[u8]) -> Self {
        Self { newlines: bytes.find_iter(b"\n").collect(), byte_len: bytes.len() }
    }

    /// Include complete lines touching the half-open full-match span. A newline
    /// at `start` belongs to the preceding line; one at `end` ends the last line.
    pub fn bounds(&self, start: usize, end: usize) -> (usize, usize) {
        let before = self.newlines.partition_point(|&offset| offset < start);
        let after = self.newlines.partition_point(|&offset| offset < end);
        (
            before.checked_sub(1).map_or(0, |i| self.newlines[i] + 1),
            self.newlines.get(after).copied().unwrap_or(self.byte_len),
        )
    }

    pub fn is_single_line(&self, start: usize, end: usize) -> bool {
        self.newlines.partition_point(|&offset| offset < start)
            == self.newlines.partition_point(|&offset| offset < end)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn indexed_bounds_preserve_multiline_and_newline_edges() {
        for bytes in [b"".as_slice(), b"one\r\ntwo\n\nthree\n", b"one long line"] {
            let index = LineIndex::new(bytes);
            for start in 0..=bytes.len() {
                for end in start..=bytes.len() {
                    let first = bytes[..start]
                        .iter()
                        .rposition(|&byte| byte == b'\n')
                        .map_or(0, |offset| offset + 1);
                    let last = bytes[end..]
                        .iter()
                        .position(|&byte| byte == b'\n')
                        .map_or(bytes.len(), |offset| end + offset);
                    assert_eq!(index.bounds(start, end), (first, last));
                }
            }
        }
    }
}
