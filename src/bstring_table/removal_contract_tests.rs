use super::*;

fn check_round_trip<S: SymbolType + std::fmt::Debug>(mut table: BStringTable<S>) {
    let inputs: Vec<Vec<u8>> = vec![
        vec![],
        b"a".to_vec(),
        b"ab".to_vec(),
        b"b".to_vec(),
        b"a\0b".to_vec(),
        vec![0xff, 0xfe, b'/', 0, b'\\'],
        "café/路径".as_bytes().to_vec(),
        b"Case".to_vec(),
        b"case".to_vec(),
        b"a/b".to_vec(),
        b"a\\b".to_vec(),
    ];
    let mut symbols = Vec::new();
    for bytes in &inputs {
        let symbol = table.get_or_intern(BString::from(bytes.clone()));
        assert_eq!(table.resolve(symbol), BStr::new(bytes));
        for previous in &symbols {
            assert_ne!(symbol, *previous, "distinct byte sequences must have distinct symbols");
        }
        symbols.push(symbol);
    }
    for (bytes, symbol) in inputs.iter().zip(&symbols).rev() {
        assert_eq!(table.get_or_intern(BString::from(bytes.clone())), *symbol);
        assert_eq!(table.resolve(*symbol), BStr::new(bytes));
    }
}

#[test]
fn byte_values_are_deduplicated_without_text_or_path_normalization() {
    check_round_trip(BStringTable::<Symbol<u32>>::new());
    check_round_trip(BStringTable::<Symbol<usize>>::new());
    check_round_trip(BStringTable::<ExternalSymbol>::default());
    check_round_trip(BStringTable::<Symbol<usize>>::with_capacity(0, 0));
}

#[test]
fn symbols_keep_their_byte_ranges_and_empty_insertion_position() {
    let mut table = BStringTable::<Symbol<u32>>::with_capacity(0, 0);
    let alpha = table.get_or_intern(BString::from("alpha"));
    let empty = table.get_or_intern(BString::from(""));
    let beta = table.get_or_intern(BString::from("β"));
    assert_eq!(alpha.to_range(), 0..5);
    assert_eq!(empty.to_range(), 5..5);
    assert_eq!(beta.to_range(), 5..7);
    assert_eq!(table.get_or_intern(BString::from("")), empty);
    assert_eq!(table.get_or_intern(BString::from("alpha")), alpha);
}

#[test]
fn symbols_survive_storage_growth_and_rehashing() {
    let mut table = BStringTable::<Symbol<u32>>::with_capacity(1, 1);
    let first_bytes = vec![0xff, 0, b'a'];
    let first = table.get_or_intern(BString::from(first_bytes.clone()));
    let mut inserted = Vec::new();
    for index in 0..4096u32 {
        let mut bytes = index.to_le_bytes().to_vec();
        bytes.extend_from_slice(b"/a-longer-path-component");
        let symbol = table.get_or_intern(BString::from(bytes.clone()));
        inserted.push((bytes, symbol));
    }
    assert_eq!(table.resolve(first), BStr::new(&first_bytes));
    assert_eq!(table.get_or_intern(BString::from(first_bytes)), first);
    for (bytes, symbol) in inserted {
        assert_eq!(table.resolve(symbol), BStr::new(&bytes));
        assert_eq!(table.get_or_intern(BString::from(bytes)), symbol);
    }
}

#[derive(Copy, Clone, Debug, Default, Eq, PartialEq, Hash)]
struct ExternalSymbol {
    start: usize,
    len: usize,
}

impl SymbolType for ExternalSymbol {
    fn to_range(self) -> Range<usize> {
        self.start..self.start + self.len
    }
    fn from_range(range: Range<usize>) -> Self {
        Self { start: range.start, len: range.end - range.start }
    }
}

#[test]
fn custom_symbol_implementations_work_without_layout_assumptions() {
    check_round_trip(BStringTable::<ExternalSymbol>::with_capacity(1, 1));
}

#[test]
fn symbols_convert_empty_nonzero_and_platform_sized_ranges() {
    for range in [0..0, 1..1, 17..49, u32::MAX as usize..u32::MAX as usize] {
        assert_eq!(Symbol::<u32>::from_range(range.clone()).to_range(), range);
    }
    for range in [0..0, 17..49, usize::MAX..usize::MAX] {
        assert_eq!(Symbol::<usize>::from_range(range.clone()).to_range(), range);
    }
}

#[cfg(target_pointer_width = "64")]
#[test]
fn compact_symbol_rejects_unrepresentable_offsets() {
    let too_large = u32::MAX as usize + 1;
    assert!(std::panic::catch_unwind(|| Symbol::<u32>::from_range(too_large..too_large)).is_err());
    assert!(std::panic::catch_unwind(|| Symbol::<u32>::from_range(0..too_large)).is_err());
}

#[test]
fn resolving_out_of_bounds_symbols_panics() {
    let mut table = BStringTable::<Symbol<u32>>::with_capacity(0, 0);
    let _ = table.get_or_intern(BString::from("abc"));
    assert!(std::panic::catch_unwind(|| table.resolve(Symbol::from_range(0..4))).is_err());
}
