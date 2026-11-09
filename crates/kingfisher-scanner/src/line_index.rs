//! Reuse newline boundaries without retaining every newline in large fragments.
use bstr::ByteSlice;

const BLOCK_SIZE: usize = 4096;

struct Boundary {
    line_start: usize,
    first_newline: usize,
}

enum Positions {
    Dense(Vec<usize>),
    Sparse(Vec<Boundary>),
}

pub struct LineIndex<'a> {
    bytes: &'a [u8],
    positions: Positions,
}

impl<'a> LineIndex<'a> {
    pub fn new(bytes: &'a [u8]) -> Self {
        let positions = if bytes.len() <= BLOCK_SIZE {
            // Bounded native confirmation windows are small; keep their cheap binary lookup.
            Positions::Dense(bytes.find_iter(b"\n").collect())
        } else {
            // Whole-fragment PREFILTER replay can touch millions of lines. Record both sides of
            // each byte block instead of eight bytes per newline. Queries scan at most one block,
            // even on minified inputs with extremely long lines or nonmonotonic match positions.
            let mut boundaries = Vec::with_capacity(bytes.len() / BLOCK_SIZE + 1);
            let mut newlines = bytes.find_iter(b"\n").peekable();
            let mut line_start = 0;
            for start in (0..=bytes.len()).step_by(BLOCK_SIZE) {
                while newlines.peek().is_some_and(|&offset| offset < start) {
                    line_start = newlines.next().unwrap() + 1;
                }
                boundaries.push(Boundary {
                    line_start,
                    first_newline: newlines.peek().copied().unwrap_or(bytes.len()),
                });
            }
            Positions::Sparse(boundaries)
        };
        Self { bytes, positions }
    }

    /// Include complete lines touching the half-open full-match span. A newline
    /// at `start` belongs to the preceding line; one at `end` ends the last line.
    /// Offsets beyond the input are treated as the end of the input.
    pub fn bounds(&self, start: usize, end: usize) -> (usize, usize) {
        let start = start.min(self.bytes.len());
        let end = end.min(self.bytes.len());
        match &self.positions {
            Positions::Dense(newlines) => {
                let before = newlines.partition_point(|&offset| offset < start);
                let after = newlines.partition_point(|&offset| offset < end);
                (
                    before.checked_sub(1).map_or(0, |i| newlines[i] + 1),
                    newlines.get(after).copied().unwrap_or(self.bytes.len()),
                )
            }
            Positions::Sparse(boundaries) => {
                let block = start / BLOCK_SIZE;
                let boundary = &boundaries[block];
                let line_start = if boundary.first_newline >= start {
                    boundary.line_start
                } else {
                    let block_start = block * BLOCK_SIZE;
                    self.bytes[block_start..start]
                        .rfind_byte(b'\n')
                        .map_or(boundary.line_start, |offset| block_start + offset + 1)
                };
                (line_start, self.next_newline(boundaries, end))
            }
        }
    }

    fn next_newline(&self, boundaries: &[Boundary], offset: usize) -> usize {
        let block = offset / BLOCK_SIZE;
        let boundary = &boundaries[block];
        if boundary.first_newline >= offset {
            return boundary.first_newline;
        }
        let block_end = ((block + 1) * BLOCK_SIZE).min(self.bytes.len());
        self.bytes[offset..block_end].find_byte(b'\n').map_or_else(
            || boundaries.get(block + 1).map_or(self.bytes.len(), |next| next.first_newline),
            |relative| offset + relative,
        )
    }

    pub fn is_single_line(&self, start: usize, end: usize) -> bool {
        let start = start.min(self.bytes.len());
        let end = end.min(self.bytes.len());
        match &self.positions {
            Positions::Dense(newlines) => {
                newlines.partition_point(|&offset| offset < start)
                    == newlines.partition_point(|&offset| offset < end)
            }
            Positions::Sparse(boundaries) => self.next_newline(boundaries, start) >= end,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assert_bounds(bytes: &[u8], positions: &[usize]) {
        let index = LineIndex::new(bytes);
        for &start in positions.iter().rev() {
            for &end in positions.iter().filter(|&&end| end >= start) {
                let first = bytes[..start]
                    .iter()
                    .rposition(|&byte| byte == b'\n')
                    .map_or(0, |offset| offset + 1);
                let last = bytes[end..]
                    .iter()
                    .position(|&byte| byte == b'\n')
                    .map_or(bytes.len(), |offset| end + offset);
                assert_eq!(index.bounds(start, end), (first, last), "{start}..{end}");
                assert_eq!(
                    index.is_single_line(start, end),
                    !bytes[start..end].contains(&b'\n'),
                    "{start}..{end}"
                );
            }
        }
    }

    #[test]
    fn out_of_range_offsets_are_clamped_for_dense_and_sparse_indexes() {
        for len in [0, 17, BLOCK_SIZE, BLOCK_SIZE * 3] {
            let bytes = vec![b'\n'; len];
            let index = LineIndex::new(&bytes);
            for start in [0, len, len.saturating_add(1), usize::MAX] {
                for end in [len, len.saturating_add(1), usize::MAX] {
                    assert_eq!(
                        index.bounds(start, end),
                        index.bounds(start.min(len), end.min(len))
                    );
                    assert_eq!(
                        index.is_single_line(start, end),
                        index.is_single_line(start.min(len), end.min(len))
                    );
                }
            }
        }
    }

    #[test]
    fn sparse_bounds_preserve_block_edges_long_lines_and_arbitrary_query_order() {
        for length in [BLOCK_SIZE + 1, BLOCK_SIZE * 3, BLOCK_SIZE * 4 + 3] {
            let mut positions = vec![0, 1, length - 1, length];
            for boundary in (BLOCK_SIZE..length).step_by(BLOCK_SIZE) {
                positions.extend([boundary - 1, boundary, boundary + 1]);
            }
            positions.sort_unstable();
            positions.dedup();
            for spacing in [1, 7, BLOCK_SIZE - 1, BLOCK_SIZE, BLOCK_SIZE + 1, length + 1] {
                let mut bytes = vec![0xff; length];
                for offset in (0..length).step_by(spacing) {
                    bytes[offset] = b'\n';
                }
                assert_bounds(&bytes, &positions);
            }
            let mut bytes = vec![b'a'; length];
            assert_bounds(&bytes, &positions);
            for &offset in &positions {
                if offset < length {
                    bytes[offset] = b'\n';
                }
            }
            assert_bounds(&bytes, &positions);
        }
    }

    #[test]
    fn dense_newline_fragments_use_bounded_sparse_storage() {
        let bytes = vec![b'\n'; 1024 * 1024];
        let index = LineIndex::new(&bytes);
        let Positions::Sparse(boundaries) = &index.positions else {
            panic!("large fragments must not retain one offset per newline");
        };
        assert_eq!(boundaries.len(), bytes.len() / BLOCK_SIZE + 1);
        assert!(boundaries.capacity() * std::mem::size_of::<Boundary>() < bytes.len() / 100);
        for offset in [0, 1, BLOCK_SIZE - 1, BLOCK_SIZE, bytes.len() - 1, bytes.len()] {
            assert_eq!(index.bounds(offset, offset), (offset, offset));
            assert!(index.is_single_line(offset, offset));
        }
    }

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
