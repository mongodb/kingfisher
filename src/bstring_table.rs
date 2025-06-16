use std::{
    collections::{hash_map::Entry, HashMap},
    ops::Range,
};

use bstr::{BStr, BString};

/// A symbolic range pointing into a `BStringTable` buffer.
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Symbol<T> {
    i: T,
    j: T,
}

/// Convert between `Symbol` and `Range<usize>`.
pub trait SymbolType: Copy + Eq + std::hash::Hash {
    fn to_range(self) -> Range<usize>;
    fn from_range(range: Range<usize>) -> Self;
}

impl SymbolType for Symbol<usize> {
    #[inline]
    fn to_range(self) -> Range<usize> {
        self.i..self.j
    }

    #[inline]
    fn from_range(range: Range<usize>) -> Self {
        Symbol { i: range.start, j: range.end }
    }
}

impl SymbolType for Symbol<u32> {
    #[inline]
    fn to_range(self) -> Range<usize> {
        (self.i as usize)..(self.j as usize)
    }

    #[inline]
    fn from_range(range: Range<usize>) -> Self {
        Symbol {
            i: range.start.try_into().expect("start fits in u32"),
            j: range.end.try_into().expect("end fits in u32"),
        }
    }
}

/// Interns `BString` values in one contiguous byte buffer.
#[derive(Default)]
pub struct BStringTable<S = Symbol<u32>> {
    storage: Vec<u8>,
    mapping: HashMap<BString, S>,
}

impl<S: SymbolType> BStringTable<S> {
    /// Default: ~32 KB symbols, ~1 MB bytes.
    #[inline]
    pub fn new() -> Self {
        Self::with_capacity(32 * 1024, 1024 * 1024)
    }

    /// Reserve space for `num_symbols` entries and `total_bytes` of storage.
    pub fn with_capacity(num_symbols: usize, total_bytes: usize) -> Self {
        BStringTable {
            storage: Vec::with_capacity(total_bytes),
            mapping: HashMap::with_capacity(num_symbols),
        }
    }

    /// Interns `s`, returning an existing or new symbol.
    #[inline]
    #[must_use]
    pub fn get_or_intern(&mut self, s: BString) -> S {
        match self.mapping.entry(s) {
            Entry::Occupied(e) => *e.get(),
            Entry::Vacant(e) => {
                let key = e.key();
                let start = self.storage.len();
                let end = start + key.len();
                self.storage.extend_from_slice(key.as_slice());
                *e.insert(S::from_range(start..end))
            }
        }
    }

    /// Look up the `BStr` slice for `symbol`.
    #[inline]
    #[must_use]
    pub fn resolve(&self, symbol: S) -> &BStr {
        let range = symbol.to_range();
        BStr::new(&self.storage[range])
    }
}

#[cfg(test)]
mod tests {
    use pretty_assertions::{assert_eq, assert_ne};

    use super::*;

    #[test]
    fn simple_roundtrip() {
        let mut table: BStringTable = BStringTable::new();
        let a = BStr::new("foo");
        let b = BStr::new("bar");

        let s1 = table.get_or_intern(a.into());
        let s1a = table.get_or_intern(a.into());
        assert_eq!(s1, s1a);

        let s2 = table.get_or_intern(b.into());
        assert_ne!(s1, s2);
        assert_eq!(a, table.resolve(s1));
        assert_eq!(b, table.resolve(s2));
    }
}
