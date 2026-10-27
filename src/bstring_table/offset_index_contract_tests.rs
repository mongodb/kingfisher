//! Baseline prerequisites for the offset-index interner; all must pass before replacement.

use std::collections::BTreeMap;
use std::panic::{AssertUnwindSafe, catch_unwind};

use super::*;

// No Default, and no implicit symbol resolution during interning is permitted.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
struct DeferredSymbol {
    start: usize,
    end: usize,
}

impl SymbolType for DeferredSymbol {
    fn from_range(range: Range<usize>) -> Self {
        Self { start: range.start, end: range.end }
    }

    fn to_range(self) -> Range<usize> {
        panic!("symbol resolution is deferred until requested by the caller")
    }
}

#[derive(Copy, Clone, Default, Debug, Eq, PartialEq, Hash)]
struct DefaultSymbol(usize, usize);

impl SymbolType for DefaultSymbol {
    fn from_range(range: Range<usize>) -> Self {
        Self(range.start, range.end)
    }

    fn to_range(self) -> Range<usize> {
        self.0..self.1
    }
}

#[test]
fn constructors_keep_default_capacity_and_nondefault_symbol_bounds() {
    let default = BStringTable::<DefaultSymbol>::default();
    assert_eq!(default.storage.capacity(), 0);
    assert_eq!(default.mapping.capacity(), 0);
    let reserved = BStringTable::<DeferredSymbol>::new();
    assert!(reserved.storage.capacity() >= 1024 * 1024);
    assert!(reserved.mapping.capacity() >= 32 * 1024);
    let mut small = BStringTable::<DeferredSymbol>::with_capacity(1, 1);
    assert_eq!(small.get_or_intern(BString::from("one")), DeferredSymbol { start: 0, end: 3 });
}

#[test]
fn interning_collisions_and_growth_do_not_resolve_custom_symbols() {
    let mut table = BStringTable::<DeferredSymbol>::with_forced_collisions(1, 1);
    let first = table.get_or_intern(BString::from("first"));
    assert_eq!(first, DeferredSymbol { start: 0, end: 5 });
    assert_eq!(table.get_or_intern(BString::from("first")), first);
    let mut end = 5;
    for index in 0..64 {
        let bytes = format!("key-{index}");
        let symbol = table.get_or_intern(BString::from(bytes.as_str()));
        assert_eq!(symbol, DeferredSymbol { start: end, end: end + bytes.len() });
        end += bytes.len();
        assert_eq!(table.get_or_intern(BString::from(bytes.as_str())), symbol);
    }
    assert_eq!(table.get_or_intern(BString::from("first")), first);
}

#[test]
fn forced_byte_hash_collisions_keep_full_keys_offsets_and_duplicates() {
    let mut table = BStringTable::<Symbol<usize>>::with_forced_collisions(1, 1);
    let mut keys = vec![
        b"shared/prefix/a".to_vec(),
        b"shared/prefix/b".to_vec(),
        Vec::new(),
        vec![0],
        vec![0xff, 0, b'/', b'\\'],
        b"Case".to_vec(),
        b"case".to_vec(),
    ];
    for index in 0..128_u32 {
        let mut key = b"shared/prefix/".to_vec();
        key.extend_from_slice(&index.to_le_bytes());
        keys.push(key);
    }
    let mut arena = Vec::new();
    let mut oracle = BTreeMap::<Vec<u8>, Range<usize>>::new();
    let mut symbols = Vec::new();
    for bytes in &keys {
        assert_eq!(table.selected_byte_hash(bytes), 0, "force complete 64-bit collisions");
        let expected = oracle.entry(bytes.clone()).or_insert_with(|| {
            let start = arena.len();
            arena.extend_from_slice(bytes);
            start..arena.len()
        });
        let symbol = table.get_or_intern(BString::from(bytes.clone()));
        assert_eq!(symbol.to_range(), *expected);
        assert_eq!(table.resolve(symbol), BStr::new(bytes));
        symbols.push(symbol);
    }
    for _ in 0..2 {
        for (bytes, symbol) in keys.iter().zip(&symbols).rev() {
            assert_eq!(table.selected_byte_hash(bytes), 0);
            assert_eq!(table.get_or_intern(BString::from(bytes.clone())), *symbol);
            assert_eq!(table.resolve(*symbol), BStr::new(bytes));
        }
    }
    assert_eq!(table.storage, arena);
    assert_eq!(table.mapping.len(), oracle.len());
}

#[test]
fn resolve_keeps_direct_subrange_and_invalid_range_behavior() {
    let mut table = BStringTable::<Symbol<usize>>::with_capacity(1, 1);
    let _ = table.get_or_intern(BString::from(vec![0xff, b'a', 0, b'z']));
    assert_eq!(table.resolve(Symbol::from_range(1..3)), BStr::new(&[b'a', 0]));
    assert_eq!(table.resolve(Symbol::from_range(4..4)), BStr::new(&[]));
    assert!(catch_unwind(AssertUnwindSafe(|| table.resolve(Symbol::from_range(3..1)))).is_err());
    assert!(catch_unwind(AssertUnwindSafe(|| table.resolve(Symbol::from_range(0..5)))).is_err());
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
struct RejectThree(Symbol<usize>);

impl SymbolType for RejectThree {
    fn from_range(range: Range<usize>) -> Self {
        assert_ne!(range.end - range.start, 3, "conversion rejects a three-byte insertion");
        Self(Symbol::from_range(range))
    }

    fn to_range(self) -> Range<usize> {
        self.0.to_range()
    }
}

#[test]
fn symbol_conversion_panic_leaves_appended_arena_but_no_index_entry() {
    let mut table = BStringTable::<RejectThree>::with_forced_collisions(1, 1);
    let first = table.get_or_intern(BString::from("ok"));
    let failed = catch_unwind(AssertUnwindSafe(|| table.get_or_intern(BString::from("bad"))));
    assert!(failed.is_err());
    assert_eq!(table.storage, b"okbad");
    assert_eq!(table.mapping.len(), 1);
    assert_eq!(table.get_or_intern(BString::from("ok")), first);
    assert_eq!(table.resolve(first), BStr::new("ok"));
    let later = table.get_or_intern(BString::from("later"));
    assert_eq!(later.to_range(), 5..10);
    assert_eq!(table.resolve(later), BStr::new("later"));
}
