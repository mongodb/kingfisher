//! Conservative, bounded-memory candidate starts for full-buffer byte-regex replay.
//!
//! A guard is a necessary literal after at most `MAX_LOOKBACK` prefix bytes on
//! every accepting path. It never proves a match: callers must anchor the ORIGINAL
//! regex at each candidate against the complete, unchanged haystack. Unsupported
//! frontiers return `None`, retaining the existing full-buffer search.

use std::sync::Arc;

use aho_corasick::{AhoCorasick, Input, MatchKind};
use anyhow::{Context, Result, bail, ensure};
use kingfisher_vectorscan::{BlockDatabase, Flag, Pattern, Scan};
use memchr::{memchr_iter, memchr2_iter};
use regex_syntax::hir::{Class, Hir, HirKind};

use crate::scanner_pool::ScannerPool;

const MIN_NEEDLE: usize = 3;
const MAX_NEEDLE: usize = 64;
const MAX_LOOKBACK: usize = 128;
const MAX_GUARDS: usize = 32;
const NATIVE_WINDOW: usize = 64 * 1024;
const MAX_NATIVE_HITS: usize = 65_536;
// MAX_GUARDS <= 32; each packed u32 is (window-relative start << 5) | guard ID.
const GUARD_BITS: u32 = 5;
const GUARD_MASK: u32 = (1 << GUARD_BITS) - 1;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct ByteSet([u64; 4]);

impl ByteSet {
    const ALL: Self = Self([u64::MAX; 4]);

    fn insert(&mut self, byte: u8) {
        self.0[usize::from(byte) / 64] |= 1_u64 << (byte % 64);
    }

    fn contains(self, byte: u8) -> bool {
        self.0[usize::from(byte) / 64] & (1_u64 << (byte % 64)) != 0
    }

    fn extend(&mut self, other: Self) {
        for (left, right) in self.0.iter_mut().zip(other.0) {
            *left |= right;
        }
    }

    fn search_kind(self) -> PrefixSearch {
        let mut bytes = [0; 2];
        let mut count = 0;
        for byte in 0..=u8::MAX {
            if self.contains(byte) {
                if count == bytes.len() {
                    return PrefixSearch::Many;
                }
                bytes[count] = byte;
                count += 1;
            }
        }
        match count {
            0 => PrefixSearch::Empty,
            1 => PrefixSearch::One(bytes[0]),
            2 => PrefixSearch::Two(bytes[0], bytes[1]),
            _ => unreachable!("at most two sparse prefix bytes"),
        }
    }
}

#[derive(Clone, Debug)]
struct Guard {
    needle: Vec<u8>,
    lookback: usize,
    // Possible first bytes when the prefix before this needle is nonempty.
    first: ByteSet,
}

#[derive(Clone, Copy, Debug)]
enum PrefixSearch {
    Empty,
    One(u8),
    Two(u8, u8),
    Many,
}

#[derive(Clone, Debug)]
struct PrefixClause {
    lookback: usize,
    first: ByteSet,
    search: PrefixSearch,
}

/// Shared, once-compiled prefix evidence for one merged literal. Preserve the
/// relation between first byte and distance: a long XML '<' prefix must not
/// widen a short word prefix merely because both reach the same keyword.
#[derive(Clone, Debug)]
struct CompiledGuard {
    needle: Vec<u8>,
    lookback: usize,
    prefixes: Vec<PrefixClause>,
}

impl CompiledGuard {
    fn new(guard: Guard) -> Self {
        let mut compiled = Self { needle: Vec::new(), lookback: 0, prefixes: Vec::new() };
        compiled.extend(&guard);
        compiled.needle = guard.needle;
        compiled
    }

    fn extend(&mut self, guard: &Guard) {
        self.lookback = self.lookback.max(guard.lookback);
        // The keyword itself is always enqueued, independent of prefix clauses.
        if guard.lookback == 0 {
            return;
        }
        if let Some(prefix) = self.prefixes.iter_mut().find(|p| p.lookback == guard.lookback) {
            prefix.first.extend(guard.first);
            prefix.search = prefix.first.search_kind();
        } else if let Some(prefix) = self.prefixes.iter_mut().find(|p| p.first == guard.first) {
            prefix.lookback = prefix.lookback.max(guard.lookback);
        } else {
            let search = guard.first.search_kind();
            if !matches!(search, PrefixSearch::Empty) {
                self.prefixes.push(PrefixClause {
                    lookback: guard.lookback,
                    first: guard.first,
                    search,
                });
            }
        }
    }
}

enum LiteralFinder {
    Native(Box<ScannerPool>),
    Aho(AhoCorasick),
}

impl LiteralFinder {
    fn new(guards: &[CompiledGuard]) -> Option<Self> {
        let patterns = guards
            .iter()
            .enumerate()
            .map(|(id, guard)| {
                Pattern::new(escaped_literal(&guard.needle), Flag::CASELESS, Some(id as u32))
            })
            .collect();
        // Literal compilation is optional. Keep the existing pure-Rust producer
        // if this platform/compiler cannot prepare the small native database.
        match BlockDatabase::new(patterns) {
            Ok(database) => Some(Self::Native(Box::new(ScannerPool::new(Arc::new(database))))),
            Err(_) => Self::aho(guards).map(Self::Aho),
        }
    }

    fn aho(guards: &[CompiledGuard]) -> Option<AhoCorasick> {
        AhoCorasick::builder()
            .match_kind(MatchKind::LeftmostFirst)
            .ascii_case_insensitive(true)
            .build(guards.iter().map(|guard| guard.needle.as_slice()))
            .ok()
    }
}

fn escaped_literal(bytes: &[u8]) -> Vec<u8> {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut pattern = Vec::with_capacity(bytes.len() * 4);
    for &byte in bytes {
        pattern.extend_from_slice(&[
            b'\\',
            b'x',
            HEX[usize::from(byte >> 4)],
            HEX[usize::from(byte & 15)],
        ]);
    }
    pattern
}

pub(crate) struct StartOracle {
    finder: LiteralFinder,
    guards: Vec<CompiledGuard>,
    max_lookback: usize,
    max_needle_len: usize,
}

impl StartOracle {
    /// Accept `original.as_str()` from RuleSyntax's byte-regex defaults, including
    /// any inline flags (not the source pattern before comment removal). Options
    /// from an arbitrary RegexBuilder cannot be reconstructed from the pattern.
    pub(crate) fn new(pattern: &str) -> Option<Self> {
        let hir = regex_syntax::ParserBuilder::new()
            .unicode(false)
            .utf8(false)
            .build()
            .parse(pattern)
            .ok()?;
        if hir.properties().minimum_len()? == 0 {
            return None;
        }
        Self::from_guards(frontier(&hir)?)
    }

    fn from_guards(mut guards: Vec<Guard>) -> Option<Self> {
        if guards.is_empty()
            || guards.len() > MAX_GUARDS
            || guards.iter().any(|guard| {
                !(MIN_NEEDLE..=MAX_NEEDLE).contains(&guard.needle.len())
                    || guard.lookback > MAX_LOOKBACK
            })
        {
            return None;
        }
        guards.sort_by(|a, b| a.needle.len().cmp(&b.needle.len()).then(a.needle.cmp(&b.needle)));
        let original_guard_count = guards.len();
        let mut merged: Vec<CompiledGuard> = Vec::new();
        for guard in guards {
            // LeftmostFirst reports only one same-start alternative. A shorter
            // prefix must therefore carry every longer guard's prefix evidence,
            // without widening unrelated first-byte/distance combinations.
            if let Some(cover) = merged.iter_mut().find(|old| guard.needle.starts_with(&old.needle))
            {
                cover.extend(&guard);
            } else {
                merged.push(CompiledGuard::new(guard));
            }
        }
        debug_assert!(
            merged.iter().map(|guard| guard.prefixes.len()).sum::<usize>() <= original_guard_count
        );
        let finder = LiteralFinder::new(&merged)?;
        let max_lookback = merged.iter().map(|guard| guard.lookback).max()?;
        let max_needle_len = merged.iter().map(|guard| guard.needle.len()).max()?;
        Some(Self { finder, guards: merged, max_lookback, max_needle_len })
    }

    pub(crate) fn candidates<'r, 'h>(&'r self, haystack: &'h [u8]) -> StartCandidates<'r, 'h> {
        StartCandidates {
            oracle: self,
            haystack,
            cursor: match &self.finder {
                LiteralFinder::Native(_) => HitCursor::Native(NativeCursor::default()),
                LiteralFinder::Aho(_) => HitCursor::Aho(0),
            },
            minimum: 0,
            hit: None,
            exhausted: false,
            failed: false,
            pending: PendingStarts::default(),
        }
    }

    #[cfg(test)]
    pub(crate) fn with_native_scanner_borrowed_for_test<R>(
        &self,
        callback: impl FnOnce() -> R,
    ) -> R {
        let LiteralFinder::Native(pool) = &self.finder else {
            panic!("expected native literal producer")
        };
        pool.try_with(|_| callback()).expect("borrow native scanner for fallback test")
    }
}

struct Prefix {
    maximum: usize,
    first: ByteSet,
    nullable: bool,
}

impl Prefix {
    fn empty() -> Self {
        Self { maximum: 0, first: ByteSet::default(), nullable: true }
    }

    fn append(&mut self, hir: &Hir) -> Option<()> {
        self.maximum = self.maximum.checked_add(hir.properties().maximum_len()?)?;
        if self.maximum > MAX_LOOKBACK {
            return None;
        }
        if self.nullable {
            self.first.extend(first_bytes(hir));
        }
        self.nullable &= hir.properties().minimum_len() == Some(0);
        Some(())
    }

    fn prepend(&self, mut guards: Vec<Guard>) -> Option<Vec<Guard>> {
        for guard in &mut guards {
            guard.lookback = guard.lookback.checked_add(self.maximum)?;
            if guard.lookback > MAX_LOOKBACK {
                return None;
            }
            let mut first = self.first;
            if self.nullable {
                first.extend(guard.first);
            }
            guard.first = first;
        }
        Some(guards)
    }
}

fn frontier(hir: &Hir) -> Option<Vec<Guard>> {
    if let Some(needle) = literalish(hir) {
        return (needle.len() >= MIN_NEEDLE)
            .then(|| vec![Guard { needle, lookback: 0, first: ByteSet::default() }]);
    }
    match hir.kind() {
        HirKind::Capture(capture) => frontier(&capture.sub),
        HirKind::Repetition(repetition) if repetition.min > 0 => frontier(&repetition.sub),
        HirKind::Alternation(branches) => {
            let mut guards = Vec::new();
            for branch in branches {
                guards.extend(frontier(branch)?);
                if guards.len() > MAX_GUARDS {
                    return None;
                }
            }
            Some(guards)
        }
        HirKind::Concat(parts) => {
            let mut prefix = Prefix::empty();
            let mut index = 0;
            while index < parts.len() {
                let mut needle = Vec::new();
                let mut end = index;
                while end < parts.len() {
                    let Some(bytes) = literalish(&parts[end]) else { break };
                    needle.extend(bytes.into_iter().take(MAX_NEEDLE - needle.len()));
                    end += 1;
                    if needle.len() == MAX_NEEDLE {
                        break;
                    }
                }
                if needle.len() >= MIN_NEEDLE {
                    return prefix.prepend(vec![Guard {
                        needle,
                        lookback: 0,
                        first: ByteSet::default(),
                    }]);
                }
                if end == index {
                    if let Some(guards) = frontier(&parts[index])
                        && let Some(guards) = prefix.prepend(guards)
                    {
                        return Some(guards);
                    }
                    end += 1;
                }
                // A child without a complete frontier may be skipped ONLY when
                // its maximum byte length keeps the later guard within budget.
                for part in &parts[index..end] {
                    prefix.append(part)?;
                }
                index = end;
            }
            None
        }
        _ => None,
    }
}

fn literalish(hir: &Hir) -> Option<Vec<u8>> {
    match hir.kind() {
        HirKind::Empty | HirKind::Look(_) => Some(Vec::new()),
        HirKind::Literal(literal) => {
            Some(literal.0.iter().take(MAX_NEEDLE).map(u8::to_ascii_lowercase).collect())
        }
        HirKind::Class(class) => {
            let byte = match class {
                Class::Bytes(class) => ascii_singleton(
                    class.iter().map(|r| (u32::from(r.start()), u32::from(r.end()))),
                ),
                Class::Unicode(class) => ascii_singleton(
                    class.iter().map(|r| (u32::from(r.start()), u32::from(r.end()))),
                ),
            }?;
            Some(vec![byte])
        }
        HirKind::Capture(capture) => literalish(&capture.sub),
        HirKind::Concat(parts) => {
            let mut bytes = Vec::new();
            for part in parts {
                bytes.extend(literalish(part)?.into_iter().take(MAX_NEEDLE - bytes.len()));
            }
            Some(bytes)
        }
        _ => None,
    }
}

fn ascii_singleton(ranges: impl Iterator<Item = (u32, u32)>) -> Option<u8> {
    let mut folded = None;
    for (start, end) in ranges {
        // In particular, Unicode K/Kelvin and S/long-S folding classes are NOT
        // one ASCII byte. They may instead be skipped as a finite-width prefix.
        if end > 0x7f {
            return None;
        }
        for byte in start..=end {
            let byte = (byte as u8).to_ascii_lowercase();
            if folded.is_some_and(|previous| previous != byte) {
                return None;
            }
            folded = Some(byte);
        }
    }
    folded
}

fn first_bytes(hir: &Hir) -> ByteSet {
    match hir.kind() {
        HirKind::Empty | HirKind::Look(_) => ByteSet::default(),
        HirKind::Literal(literal) => {
            let mut first = ByteSet::default();
            if let Some(&byte) = literal.0.first() {
                first.insert(byte.to_ascii_lowercase());
                first.insert(byte.to_ascii_uppercase());
            }
            first
        }
        HirKind::Class(_) => ByteSet::ALL,
        HirKind::Capture(capture) => first_bytes(&capture.sub),
        HirKind::Repetition(repetition) => first_bytes(&repetition.sub),
        HirKind::Concat(parts) | HirKind::Alternation(parts) => {
            let mut first = ByteSet::default();
            for part in parts {
                first.extend(first_bytes(part));
                if matches!(hir.kind(), HirKind::Concat(_))
                    && part.properties().minimum_len() != Some(0)
                {
                    break;
                }
            }
            first
        }
    }
}

/// Every live start lies within MAX_LOOKBACK bytes of the minimum. Keep the
/// exact set in three words relative to its minimum, rather than allocating a
/// BTreeSet node for every keyword. Bit zero is set whenever the set is nonempty.
#[derive(Clone, Copy, Debug, Default)]
struct PendingStarts {
    base: usize,
    bits: [u64; 3],
}

impl PendingStarts {
    fn is_empty(&self) -> bool {
        self.bits[0] | self.bits[1] | self.bits[2] == 0
    }

    fn len(&self) -> usize {
        self.bits.iter().map(|word| word.count_ones() as usize).sum()
    }

    fn first(&self) -> Option<usize> {
        (!self.is_empty()).then_some(self.base)
    }

    fn insert(&mut self, start: usize) -> Result<()> {
        if self.is_empty() {
            self.base = start;
            self.bits = [1, 0, 0];
        } else if start >= self.base {
            let offset = start - self.base;
            ensure!(offset <= MAX_LOOKBACK, "pending start frontier exceeded bounded span");
            self.bits[offset / 64] |= 1_u64 << (offset % 64);
        } else {
            let shift = self.base - start;
            let last = if self.bits[2] != 0 {
                128 + (63 - self.bits[2].leading_zeros()) as usize
            } else if self.bits[1] != 0 {
                64 + (63 - self.bits[1].leading_zeros()) as usize
            } else {
                (63 - self.bits[0].leading_zeros()) as usize
            };
            // Fail before changing anything if a future proof change violates
            // the span invariant. The caller must resume original full replay.
            ensure!(
                shift <= MAX_LOOKBACK && last <= MAX_LOOKBACK - shift,
                "pending start frontier exceeded bounded span"
            );
            self.shift_left(shift);
            self.base = start;
            self.bits[0] |= 1;
        }
        Ok(())
    }

    fn pop_first(&mut self) -> Option<usize> {
        let first = self.first()?;
        self.bits[0] &= !1;
        self.normalize();
        Some(first)
    }

    fn retain_from(&mut self, minimum: usize) {
        if self.is_empty() || minimum <= self.base {
            return;
        }
        let shift = minimum - self.base;
        if shift > MAX_LOOKBACK {
            self.bits = [0; 3];
            return;
        }
        self.shift_right(shift);
        self.base = minimum;
        self.normalize();
    }

    fn normalize(&mut self) {
        let shift = if self.bits[0] != 0 {
            self.bits[0].trailing_zeros() as usize
        } else if self.bits[1] != 0 {
            64 + self.bits[1].trailing_zeros() as usize
        } else if self.bits[2] != 0 {
            128 + self.bits[2].trailing_zeros() as usize
        } else {
            return;
        };
        if shift != 0 {
            self.shift_right(shift);
            // This is the position of an existing bit, hence cannot exceed
            // usize::MAX even for a frontier containing that exact position.
            self.base += shift;
        }
    }

    fn shift_left(&mut self, shift: usize) {
        let [a, b, c] = self.bits;
        self.bits = match shift {
            0 => [a, b, c],
            1..64 => [
                (a << shift),
                (b << shift) | (a >> (64 - shift)),
                (c << shift) | (b >> (64 - shift)),
            ],
            64 => [0, a, b],
            65..128 => [0, a << (shift - 64), (b << (shift - 64)) | (a >> (128 - shift))],
            128 => [0, 0, a],
            _ => unreachable!("bounded pending shift"),
        };
    }

    fn shift_right(&mut self, shift: usize) {
        let [a, b, c] = self.bits;
        self.bits = match shift {
            0 => [a, b, c],
            1..64 => {
                [(a >> shift) | (b << (64 - shift)), (b >> shift) | (c << (64 - shift)), c >> shift]
            }
            64 => [b, c, 0],
            65..128 => [(b >> (shift - 64)) | (c << (128 - shift)), c >> (shift - 64), 0],
            128 => [c, 0, 0],
            _ => unreachable!("bounded pending shift"),
        };
    }
}

#[derive(Clone, Copy, Debug)]
struct KeywordHit {
    start: usize,
    guard: usize,
}

enum HitStep {
    Hit(KeywordHit),
    // A bounded native window was consumed without exhausting the full input.
    // Recheck pending starts against the new lower bound before another scan.
    Progress,
    Exhausted,
}

#[derive(Default)]
struct NativeCursor {
    window_start: usize,
    next_window: usize,
    hits: Vec<u32>,
    at: usize,
    #[cfg(test)]
    hit_limit: Option<usize>,
}

impl NativeCursor {
    fn next_step(
        &mut self,
        pool: &ScannerPool,
        guards: &[CompiledGuard],
        haystack: &[u8],
        max_needle: usize,
    ) -> Result<HitStep> {
        if let Some(&packed) = self.hits.get(self.at) {
            self.at += 1;
            return Ok(HitStep::Hit(KeywordHit {
                start: self.window_start + (packed >> GUARD_BITS) as usize,
                guard: (packed & GUARD_MASK) as usize,
            }));
        }
        let base = self.next_window;
        if haystack.len() - base < MIN_NEEDLE {
            return Ok(HitStep::Exhausted);
        }
        let owned_end = base.saturating_add(NATIVE_WINDOW).min(haystack.len());
        let scan_end = owned_end.saturating_add(max_needle - 1).min(haystack.len());
        let owned_len = owned_end - base;
        let bytes = &haystack[base..scan_end];
        // The wrapper narrows length to u32. Only this <= 64KiB + 63B slice
        // reaches native code, regardless of the original haystack's size.
        debug_assert!(bytes.len() < NATIVE_WINDOW + MAX_NEEDLE);
        self.hits.clear();
        self.at = 0;
        let mut overflow = false;
        let mut invalid = false;
        let mut allocation_error = None;
        let hit_limit = {
            #[cfg(test)]
            {
                self.hit_limit.unwrap_or(MAX_NATIVE_HITS)
            }
            #[cfg(not(test))]
            {
                MAX_NATIVE_HITS
            }
        };
        let outcome = pool
            .try_with(|scanner| {
                scanner.scan(bytes, |id, _, end, _| {
                    let Some(guard) = guards.get(id as usize) else {
                        invalid = true;
                        return Scan::Terminate;
                    };
                    let Ok(end) = usize::try_from(end) else {
                        invalid = true;
                        return Scan::Terminate;
                    };
                    let Some(start) =
                        end.checked_sub(guard.needle.len()).filter(|_| end <= bytes.len())
                    else {
                        invalid = true;
                        return Scan::Terminate;
                    };
                    if start >= owned_len {
                        return Scan::Continue;
                    }
                    if self.hits.len() == hit_limit {
                        overflow = true;
                        return Scan::Terminate;
                    }
                    if self.hits.len() == self.hits.capacity() {
                        let additional =
                            self.hits.capacity().max(64).min(hit_limit - self.hits.len());
                        if let Err(error) = self.hits.try_reserve_exact(additional) {
                            allocation_error = Some(error);
                            return Scan::Terminate;
                        }
                    }
                    self.hits.push(((start as u32) << GUARD_BITS) | id);
                    Scan::Continue
                })
            })
            .context("borrow literal scanner")?
            .context("scan literal window")?;
        // The pool's scratch borrow is RELEASED before sorting, returning a
        // hit, or allowing the caller to run the original anchored regex.
        if let Some(error) = allocation_error {
            return Err(anyhow::Error::new(error).context("allocate bounded literal hits"));
        }
        ensure!(!overflow, "literal window exceeded bounded hit capacity");
        ensure!(!invalid, "native literal callback returned an invalid hit");
        ensure!(matches!(outcome, Scan::Continue), "native literal scan terminated early");
        self.hits.sort_unstable();
        self.hits.dedup();
        self.window_start = base;
        self.next_window = owned_end;
        Ok(HitStep::Progress)
    }

    fn seek_to(&mut self, minimum: usize) {
        while self
            .hits
            .get(self.at)
            .is_some_and(|packed| self.window_start + ((*packed >> GUARD_BITS) as usize) < minimum)
        {
            self.at += 1;
        }
        if self.next_window < minimum {
            self.next_window = minimum;
            self.at = self.hits.len();
        }
    }
}

enum HitCursor {
    Native(NativeCursor),
    Aho(usize),
}

impl HitCursor {
    fn lower_bound(&self) -> usize {
        match self {
            Self::Native(cursor) => {
                cursor.hits.get(cursor.at).map_or(cursor.next_window, |packed| {
                    cursor.window_start + (*packed >> GUARD_BITS) as usize
                })
            }
            Self::Aho(search_at) => *search_at,
        }
    }

    fn next_step(&mut self, oracle: &StartOracle, haystack: &[u8]) -> Result<HitStep> {
        match (self, &oracle.finder) {
            (Self::Native(cursor), LiteralFinder::Native(pool)) => {
                cursor.next_step(pool, &oracle.guards, haystack, oracle.max_needle_len)
            }
            (Self::Aho(search_at), LiteralFinder::Aho(finder)) => {
                let hit = finder.find(Input::new(haystack).span(*search_at..haystack.len()));
                Ok(match hit {
                    Some(hit) => {
                        // Restart by START, not end, to retain overlapping needles.
                        *search_at = hit.start() + 1;
                        HitStep::Hit(KeywordHit {
                            start: hit.start(),
                            guard: hit.pattern().as_usize(),
                        })
                    }
                    None => HitStep::Exhausted,
                })
            }
            _ => unreachable!("literal cursor and producer must agree"),
        }
    }

    fn seek_to(&mut self, minimum: usize) {
        match self {
            Self::Native(cursor) => cursor.seek_to(minimum),
            Self::Aho(search_at) => *search_at = (*search_at).max(minimum),
        }
    }
}

pub(crate) struct StartCandidates<'r, 'h> {
    oracle: &'r StartOracle,
    haystack: &'h [u8],
    cursor: HitCursor,
    minimum: usize,
    hit: Option<KeywordHit>,
    exhausted: bool,
    failed: bool,
    pending: PendingStarts,
}

impl StartCandidates<'_, '_> {
    /// Any error requires original full-buffer fallback. A failed iterator stays
    /// failed even after a seek; an incomplete native window must never be used.
    pub(crate) fn next_start(&mut self) -> Result<Option<usize>> {
        if self.failed {
            bail!("literal start oracle already failed");
        }
        let result = self.try_next_start();
        if result.is_err() {
            self.failed = true;
        }
        result
    }

    fn pop_pending(&mut self) -> Option<usize> {
        let start = self.pending.pop_first()?;
        self.minimum = start + 1;
        Some(start)
    }

    fn try_next_start(&mut self) -> Result<Option<usize>> {
        loop {
            if self.hit.is_none() && !self.exhausted {
                if self.pending.first().is_some_and(|start| {
                    self.cursor.lower_bound().saturating_sub(self.oracle.max_lookback) > start
                }) {
                    // Even the earliest possible future keyword cannot backstep
                    // to this start. Do not scan a distant keyword-free suffix
                    // just to establish lookahead. Subtraction avoids overflow
                    // in the equivalent future > start + max_lookback test.
                    return Ok(self.pop_pending());
                }
                match self.cursor.next_step(self.oracle, self.haystack)? {
                    HitStep::Hit(hit) => self.hit = Some(hit),
                    HitStep::Progress => continue,
                    HitStep::Exhausted => self.exhausted = true,
                }
            }
            if let Some(start) = self.pending.first()
                && self
                    .hit
                    .is_none_or(|hit| hit.start.saturating_sub(self.oracle.max_lookback) > start)
            {
                return Ok(self.pop_pending());
            }
            let Some(hit) = self.hit.take() else { return Ok(None) };
            if hit.start < self.minimum {
                continue;
            }
            let guard = &self.oracle.guards[hit.guard];
            self.pending.insert(hit.start)?;
            for prefix in &guard.prefixes {
                let base = hit.start.saturating_sub(prefix.lookback).max(self.minimum);
                let bytes = &self.haystack[base..hit.start];
                match prefix.search {
                    PrefixSearch::Empty => {}
                    PrefixSearch::One(byte) => {
                        for offset in memchr_iter(byte, bytes) {
                            self.pending.insert(base + offset)?;
                        }
                    }
                    PrefixSearch::Two(a, b) => {
                        for offset in memchr2_iter(a, b, bytes) {
                            self.pending.insert(base + offset)?;
                        }
                    }
                    PrefixSearch::Many => {
                        for (offset, &byte) in bytes.iter().enumerate() {
                            if prefix.first.contains(byte) {
                                self.pending.insert(base + offset)?;
                            }
                        }
                    }
                }
            }
            // Future hits are read ONE AT A TIME in global start order, including
            // across native windows. Never flush all of one window's candidates:
            // a next-window XML prefix can backstep before this pending minimum.
            // All pending starts lie in [hit.start-max_lookback, hit.start], so
            // the set holds at most max_lookback+1 positions (not O(input)).
            debug_assert!(self.pending.len() <= self.oracle.max_lookback + 1);
        }
    }

    /// Skip starts before a consuming ORIGINAL match's end. Already-read
    /// lookahead remains valid; forward seeks never invalidate known exhaustion.
    pub(crate) fn seek_to(&mut self, consuming_match_end: usize) {
        self.minimum = self.minimum.max(consuming_match_end.min(self.haystack.len()));
        self.pending.retain_from(self.minimum);
        if self.hit.is_some_and(|hit| hit.start < self.minimum) {
            self.hit = None;
        }
        self.cursor.seek_to(self.minimum);
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::*;
    use regex::bytes::{Regex, RegexBuilder};

    fn assert_pending_matches(pending: &PendingStarts, expected: &BTreeSet<usize>) {
        assert_eq!(pending.first(), expected.first().copied());
        assert_eq!(pending.len(), expected.len());
        assert_eq!(pending.is_empty(), expected.is_empty());
        assert!(pending.bits[2] <= 1, "the frontier spans at most 128 bytes");
        if !pending.is_empty() {
            assert_eq!(pending.bits[0] & 1, 1, "base is the exact live minimum");
        }
        let mut copy = *pending;
        let drained: Vec<_> = std::iter::from_fn(|| copy.pop_first()).collect();
        assert_eq!(drained, expected.iter().copied().collect::<Vec<_>>());
        assert!(copy.is_empty());
        assert!(copy.pop_first().is_none());
    }

    #[test]
    fn compact_pending_frontier_matches_btree_at_word_and_absolute_boundaries() {
        assert!(std::mem::size_of::<PendingStarts>() <= 32);
        for base in [0, 1, 63, 64, 127, 128, 191, 192, 193, usize::MAX - 129, usize::MAX - 128] {
            // Every shift, including exactly 64/128, in both insertion orders.
            for offset in 1..=MAX_LOOKBACK {
                for order in [[0, offset], [offset, 0]] {
                    let mut pending = PendingStarts::default();
                    let mut expected = BTreeSet::new();
                    for position in order {
                        pending.insert(base + position).unwrap();
                        expected.insert(base + position);
                        pending.insert(base + position).unwrap();
                        assert_pending_matches(&pending, &expected);
                    }
                    let mut retained = pending;
                    let minimum = base + offset / 2 + 1;
                    retained.retain_from(minimum);
                    let retained_expected = expected.split_off(&minimum);
                    assert_pending_matches(&retained, &retained_expected);
                }
            }
            // Full-width dense frontiers normalize a word at a time when popped,
            // and backstep across all three words when inserted in reverse.
            for reverse in [false, true] {
                let mut pending = PendingStarts::default();
                let mut expected = BTreeSet::new();
                for index in 0..=MAX_LOOKBACK {
                    let offset = if reverse { MAX_LOOKBACK - index } else { index };
                    pending.insert(base + offset).unwrap();
                    expected.insert(base + offset);
                    assert_pending_matches(&pending, &expected);
                }
                for offset in 0..=MAX_LOOKBACK {
                    let mut retained = pending;
                    retained.retain_from(base + offset);
                    let expected = expected.range(base + offset..).copied().collect();
                    assert_pending_matches(&retained, &expected);
                }
            }
        }
    }

    #[test]
    fn compact_pending_frontier_matches_btree_for_mixed_operations() {
        let mut state = 0x9abc_def0_1234_5678_u64;
        for base in [0, 63, 64, 127, 128, 191, 192, usize::MAX - MAX_LOOKBACK] {
            let mut pending = PendingStarts::default();
            let mut expected = BTreeSet::new();
            for _ in 0..2048 {
                state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
                let offset = ((state >> 32) % (MAX_LOOKBACK as u64 + 1)) as usize;
                let position = base + offset;
                match state % 5 {
                    0 => assert_eq!(pending.pop_first(), expected.pop_first()),
                    1 => {
                        pending.retain_from(position);
                        expected = expected.split_off(&position);
                    }
                    _ => {
                        pending.insert(position).unwrap();
                        expected.insert(position);
                    }
                }
                assert_pending_matches(&pending, &expected);
            }
        }
    }

    #[test]
    fn compact_pending_frontier_rejects_unbounded_spans_without_mutation() {
        let mut pending = PendingStarts::default();
        pending.insert(usize::MAX).unwrap();
        pending.insert(usize::MAX - MAX_LOOKBACK).unwrap();
        let expected = BTreeSet::from([usize::MAX - MAX_LOOKBACK, usize::MAX]);
        assert!(pending.insert(usize::MAX - MAX_LOOKBACK - 1).is_err());
        assert!(pending.insert(0).is_err());
        assert_pending_matches(&pending, &expected);
        pending.retain_from(usize::MAX);
        assert_eq!(pending.pop_first(), Some(usize::MAX));
        assert!(pending.pop_first().is_none());
        pending.insert(0).unwrap();
        assert!(pending.insert(MAX_LOOKBACK + 1).is_err());
        assert_pending_matches(&pending, &BTreeSet::from([0]));
        pending.retain_from(usize::MAX);
        assert_pending_matches(&pending, &BTreeSet::new());
    }

    fn original(pattern: &str) -> Regex {
        RegexBuilder::new(pattern).unicode(false).size_limit(16 * 1024 * 1024).build().unwrap()
    }

    fn prefix_bound(guard: &CompiledGuard, byte: u8) -> usize {
        guard
            .prefixes
            .iter()
            .filter(|p| p.first.contains(byte))
            .map(|p| p.lookback)
            .max()
            .unwrap_or(0)
    }

    fn starts(oracle: &StartOracle, haystack: &[u8]) -> Vec<usize> {
        let mut candidates = oracle.candidates(haystack);
        let mut found = Vec::new();
        while let Some(start) = candidates.next_start().unwrap() {
            assert!(candidates.pending.len() <= oracle.max_lookback + 1);
            found.push(start);
        }
        assert!(found.windows(2).all(|pair| pair[0] < pair[1]));
        found
    }

    fn aho_oracle(native: &StartOracle) -> StartOracle {
        assert!(
            matches!(&native.finder, LiteralFinder::Native(_)),
            "native literal compilation failed"
        );
        StartOracle {
            finder: LiteralFinder::Aho(LiteralFinder::aho(&native.guards).unwrap()),
            guards: native.guards.clone(),
            max_lookback: native.max_lookback,
            max_needle_len: native.max_needle_len,
        }
    }

    fn assert_covers(regex: &Regex, oracle: &StartOracle, haystack: &[u8]) -> Vec<usize> {
        let candidates = starts(oracle, haystack);
        // find_iter would omit overlapping accepted starts. Probe EVERY byte
        // offset against the original full haystack, retaining assertion context.
        for start in 0..=haystack.len() {
            if regex.find_at(haystack, start).is_some_and(|found| found.start() == start) {
                assert!(
                    candidates.binary_search(&start).is_ok(),
                    "missing {start}: pattern={:?} haystack={haystack:?} candidates={candidates:?}",
                    regex.as_str()
                );
            }
        }
        candidates
    }

    fn enumerate(
        alphabet: &[u8],
        remaining: usize,
        input: &mut Vec<u8>,
        check: &mut impl FnMut(&[u8]),
    ) {
        check(input);
        if remaining == 0 {
            return;
        }
        for &byte in alphabet {
            input.push(byte);
            enumerate(alphabet, remaining - 1, input, check);
            input.pop();
        }
    }

    #[test]
    fn every_accepted_start_is_present_over_small_ascii_and_binary_alphabets() {
        for (alphabet, depth, patterns) in [
            (
                b"aAbBcx".as_slice(),
                5,
                vec![
                    "abc",
                    "(?i)abc",
                    "a[bB]c",
                    "(?:abc|bca)",
                    "(?:abc|x.{0,2}bca)",
                    "x?abc",
                    "x?(a{1,2}bca)",
                    "(?:a|)abc",
                    "(?:ab|x)bca",
                    "(abc)+?",
                    r"\babc\b",
                    r"\Aabc|bca\z",
                ],
            ),
            (
                &[0, 0x80, 0xff][..],
                6,
                vec![
                    r"\x00\xFF\x80",
                    r"[\x00\x80]{0,2}\xFF\x00\x80",
                    r"(?s:.{0,2})\xFF\x00\x80",
                    r"(?:\xFF\x00\x80|\x00\xFF\x80)",
                ],
            ),
        ] {
            let compiled: Vec<_> = patterns
                .iter()
                .map(|pattern| {
                    let native = StartOracle::new(pattern).unwrap();
                    let aho = aho_oracle(&native);
                    (original(pattern), native, aho)
                })
                .collect();
            enumerate(alphabet, depth, &mut Vec::new(), &mut |haystack| {
                for (regex, native, aho) in &compiled {
                    assert_eq!(assert_covers(regex, native, haystack), starts(aho, haystack));
                }
            });
        }
    }

    #[test]
    fn binary_noise_unicode_prefixes_and_assertions_keep_all_original_starts() {
        let patterns = [
            "(?ui)kabc",
            "(?ui)ssabc",
            "(?u:é{0,2})abc",
            r"(?u:\w{0,2})abc",
            "éabc",
            r"(?u:\b)abc",
            r"(?m)^abc$",
            r"(?mR)^abc$",
            r"\Aabc\z",
            r"\Babc|\babc",
            "x(abc)",
            "x?(y{1,2}abc)",
            "x(y{1,2}abc)",
            "(?:abc|x.{0,2}bcd)",
            "(?:x|yz){0,2}abc",
        ];
        let fixtures: &[&[u8]] = &[
            b"abc",
            b"ABC",
            b"xabc",
            b"xyyabc",
            b"xabcde",
            b"\nabc\r\nabc\n",
            "Kabc ſſabc ééabc αβabc".as_bytes(),
            b"\xFFabc\x80abc\x00",
        ];
        let mut seed = 0xd572_08ab_c4f1_963e_u64;
        for pattern in patterns {
            let regex = original(pattern);
            let oracle = StartOracle::new(pattern).unwrap();
            let aho = aho_oracle(&oracle);
            for fixture in fixtures {
                assert_eq!(assert_covers(&regex, &oracle, fixture), starts(&aho, fixture));
                for length in 0..32 {
                    let mut bytes = Vec::new();
                    for _ in 0..length {
                        seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
                        bytes.push((seed >> 32) as u8);
                    }
                    bytes.extend_from_slice(fixture);
                    bytes.extend_from_slice(b"\x00abc\xFF");
                    assert_eq!(assert_covers(&regex, &oracle, &bytes), starts(&aho, &bytes));
                }
            }
        }
    }

    #[test]
    fn unicode_fold_classes_are_not_ascii_singletons() {
        for pattern in ["(?ui)kbc", "(?ui)sbc", "(?ui)Kbc", "(?ui)ſbc"] {
            assert!(StartOracle::new(pattern).is_none(), "{pattern}");
        }
        for (pattern, lookback, haystack) in [("(?ui)kabc", 3, "Kabc"), ("(?ui)sabc", 2, "ſabc")]
        {
            let oracle = StartOracle::new(pattern).unwrap();
            assert_eq!(oracle.guards[0].needle, b"abc");
            assert_eq!(oracle.guards[0].lookback, lookback);
            assert_covers(&original(pattern), &oracle, haystack.as_bytes());
        }
        assert_eq!(StartOracle::new("(?i)kbc").unwrap().guards[0].needle, b"kbc");
    }

    #[test]
    fn overlapping_hits_and_future_hits_cannot_hide_an_earlier_start() {
        let oracle = StartOracle::new("abab").unwrap();
        assert_eq!(starts(&oracle, b"ababab"), vec![0, 2]);
        let oracle = StartOracle::new("(?:abc|x.{0,2}bcd)").unwrap();
        // abc is found first at1; bcd at2 must contribute original start0
        // before either literal's own position is emitted.
        assert_eq!(starts(&oracle, b"xabcde"), vec![0, 1, 2]);
    }

    #[test]
    fn prefix_and_duplicate_needles_merge_all_prefix_evidence() {
        let mut x = ByteSet::default();
        x.insert(b'x');
        let mut y = ByteSet::default();
        y.insert(b'y');
        let oracle = StartOracle::from_guards(vec![
            Guard { needle: b"abc".to_vec(), lookback: 0, first: ByteSet::default() },
            Guard { needle: b"abcd".to_vec(), lookback: 3, first: x },
            Guard { needle: b"abc".to_vec(), lookback: 2, first: y },
        ])
        .unwrap();
        assert_eq!(oracle.guards.len(), 1);
        assert_eq!(oracle.guards[0].lookback, 3);
        assert_eq!(prefix_bound(&oracle.guards[0], b'x'), 3);
        assert_eq!(prefix_bound(&oracle.guards[0], b'y'), 2);
        assert_eq!(starts(&oracle, b"xabcdyabc"), vec![0, 1, 5, 6]);
        // Longer-needle evidence is inherited, but its distance must not widen
        // the unrelated first byte from a duplicate shorter guard.
        assert_eq!(starts(&oracle, b"x..abc"), vec![0, 3]);
        assert_eq!(starts(&oracle, b"y..abc"), vec![3]);
    }

    #[test]
    fn sparse_prefix_clauses_preserve_distance_correlations_and_native_seams() {
        let mut seam = vec![b'!'; 2 * NATIVE_WINDOW + 80];
        let xml = NATIVE_WINDOW - 20;
        let keyword = NATIVE_WINDOW + 10;
        seam[xml] = b'<';
        seam[xml + 1..keyword].fill(b'A');
        seam[NATIVE_WINDOW - 6..NATIVE_WINDOW - 1].copy_from_slice(b"token");
        seam[keyword..keyword + 9].copy_from_slice(b"token=123");
        let dense = b"t.t.token t.t.token ttoken=123 <ABtoken=123".to_vec();
        for (pattern, short_t_prefix) in [
            (r"(?:token|<[A-Za-z]{0,64}token)=[0-9]+", false),
            (r"(?:t{0,1}token|<[A-Za-z]{0,64}token)=[0-9]+", true),
        ] {
            let native = StartOracle::new(pattern).unwrap();
            let aho = aho_oracle(&native);
            assert_eq!(native.guards.len(), 1);
            assert_eq!(prefix_bound(&native.guards[0], b'<'), 65);
            assert_eq!(prefix_bound(&native.guards[0], b't'), if short_t_prefix { 1 } else { 0 });
            assert!(
                native.guards[0]
                    .prefixes
                    .iter()
                    .any(|p| matches!(p.search, PrefixSearch::One(b'<')))
            );
            if short_t_prefix {
                assert!(
                    native.guards[0]
                        .prefixes
                        .iter()
                        .any(|p| matches!(p.search, PrefixSearch::Two(_, _)))
                );
            }
            for bytes in [&dense, &seam] {
                let mut expected = BTreeSet::new();
                for (hit, _) in bytes.windows(5).enumerate().filter(|(_, word)| *word == b"token") {
                    expected.insert(hit);
                    if short_t_prefix && hit > 0 && bytes[hit - 1].eq_ignore_ascii_case(&b't') {
                        expected.insert(hit - 1);
                    }
                    for (start, &byte) in
                        bytes.iter().enumerate().take(hit).skip(hit.saturating_sub(65))
                    {
                        if byte == b'<' {
                            expected.insert(start);
                        }
                    }
                }
                let expected: Vec<_> = expected.into_iter().collect();
                assert_eq!(starts(&native, bytes), expected);
                assert_eq!(starts(&aho, bytes), expected);
                for found in original(pattern).find_iter(bytes) {
                    assert!(expected.binary_search(&found.start()).is_ok());
                }
            }
            // These isolated 't' bytes are several bytes before a keyword;
            // merging the XML bound into their first-byte set would add them.
            assert!(!starts(&native, &dense).contains(&0));
            assert!(!starts(&native, &dense).contains(&2));
        }
    }

    #[test]
    fn bundled_generic_prefix_clause_shapes_are_bounded_and_use_sparse_xml_search() {
        let mut rules =
            crate::defaults::get_builtin_rules(Some(crate::rule::Confidence::Low)).unwrap();
        let generic = rules.rules.remove("betterleaks.generic-api-key").unwrap();
        let original = generic.as_regex().unwrap();
        let oracle = StartOracle::new(original.as_str()).unwrap();
        let clause_count: usize = oracle.guards.iter().map(|g| g.prefixes.len()).sum();
        assert!(clause_count <= MAX_GUARDS);
        assert!(
            oracle
                .guards
                .iter()
                .flat_map(|g| &g.prefixes)
                .any(|p| { p.lookback >= 65 && matches!(p.search, PrefixSearch::One(b'<')) })
        );
        for guard in &oracle.guards {
            let shape: Vec<_> = guard.prefixes.iter().map(|p| (p.lookback, p.search)).collect();
            eprintln!(
                "generic guard {:?}: lookback={}, clauses={shape:?}",
                String::from_utf8_lossy(&guard.needle),
                guard.lookback
            );
        }
    }

    #[test]
    fn nullable_prefixes_union_first_bytes_but_nonnullable_prefixes_dominate() {
        let nullable = StartOracle::new("x?(y{1,2}abc)").unwrap();
        assert_eq!(nullable.guards[0].lookback, 3);
        for byte in b"xXyY" {
            assert_eq!(prefix_bound(&nullable.guards[0], *byte), 3);
        }
        let nonnullable = StartOracle::new("x(y{1,2}abc)").unwrap();
        assert_eq!(nonnullable.guards[0].lookback, 3);
        assert_eq!(prefix_bound(&nonnullable.guards[0], b'x'), 3);
        assert_eq!(prefix_bound(&nonnullable.guards[0], b'y'), 0);
        assert_eq!(
            starts(&StartOracle::new("x{1,2}abc").unwrap(), b"pXxabc abc"),
            vec![1, 2, 3, 7]
        );
    }

    #[test]
    fn unsupported_empty_unbounded_and_oversized_frontiers_fall_back() {
        for pattern in [
            "",
            "abc?",
            "(?:abc|)",
            "(?:abc|xy)",
            ".*abc",
            "a*abc",
            "(?:abc)*def",
            "(?:abc|x.*)",
            ".{129}abc",
            "x.{128}abc",
            "ab",
            "(",
        ] {
            assert!(StartOracle::new(pattern).is_none(), "{pattern}");
        }
        let guards = (0..=MAX_GUARDS)
            .map(|byte| Guard {
                needle: vec![byte as u8, b'a', b'b'],
                lookback: 0,
                first: ByteSet::default(),
            })
            .collect();
        assert!(StartOracle::from_guards(guards).is_none());
        assert!(StartOracle::from_guards(Vec::new()).is_none());
        for pattern in ["(?:abc)+", "(?:abc)?def", "(?:abc|)def", ".{128}abc"] {
            assert!(StartOracle::new(pattern).is_some(), "{pattern}");
        }
        for literal in ["a".repeat(100), "€".repeat(40)] {
            let oracle = StartOracle::new(&literal).unwrap();
            assert_eq!(oracle.guards[0].needle.len(), MAX_NEEDLE);
            assert_covers(&original(&literal), &oracle, literal.as_bytes());
        }
    }

    #[test]
    fn seeking_after_consuming_matches_preserves_original_find_iter() {
        let haystacks: &[&[u8]] = &[
            b"abcabcabc",
            b"xabcde abcdef abc",
            b"xxxxabc abc abcdefdef abc",
            b"aaaabaaaabcaaaabc",
            b"\nabc\r\nabc\n",
            "KabcKabc ſabc".as_bytes(),
        ];
        for pattern in [
            "abc",
            "abc|x.{0,2}bcd",
            "x{0,3}abc",
            "abc.*def|abc",
            "abc.+?abc",
            "aaaa|aaa",
            "(?m)^abc$",
            "(?ui)kabc",
        ] {
            let regex = original(pattern);
            let oracle = StartOracle::new(pattern).unwrap();
            for haystack in haystacks {
                let expected: Vec<_> = regex.find_iter(haystack).map(|m| m.range()).collect();
                let mut candidates = oracle.candidates(haystack);
                let mut found = Vec::new();
                while let Some(start) = candidates.next_start().unwrap() {
                    if let Some(m) = regex.find_at(haystack, start)
                        && m.start() == start
                    {
                        found.push(m.range());
                        candidates.seek_to(m.end());
                    }
                }
                assert_eq!(found, expected, "pattern={pattern} haystack={haystack:?}");
            }
        }
    }

    #[test]
    fn known_future_lower_bounds_do_not_scan_distant_keyword_free_tails() {
        let native = StartOracle::new("abc").unwrap();
        let aho = aho_oracle(&native);
        let mut bytes = vec![b'!'; 3 * NATIVE_WINDOW];
        bytes[..3].copy_from_slice(b"abc");
        for oracle in [&native, &aho] {
            let mut candidates = oracle.candidates(&bytes);
            assert_eq!(candidates.next_start().unwrap(), Some(0));
            assert!(!candidates.exhausted, "yield before searching the distant tail");
            match &candidates.cursor {
                HitCursor::Native(cursor) => assert_eq!(cursor.next_window, NATIVE_WINDOW),
                HitCursor::Aho(search_at) => assert_eq!(*search_at, 1),
            }
            candidates.seek_to(bytes.len());
            assert!(candidates.next_start().unwrap().is_none());
            assert!(candidates.exhausted);
        }
    }

    #[test]
    fn empty_native_lookahead_window_rechecks_its_future_lower_bound() {
        let native = StartOracle::new("x{0,128}abc").unwrap();
        let aho = aho_oracle(&native);
        let mut bytes = vec![b'!'; 3 * NATIVE_WINDOW];
        let keyword = NATIVE_WINDOW - 3;
        bytes[keyword - MAX_LOOKBACK] = b'x';
        bytes[keyword..keyword + 3].copy_from_slice(b"abc");
        let mut candidates = native.candidates(&bytes);
        assert_eq!(candidates.next_start().unwrap(), Some(keyword - MAX_LOOKBACK));
        let HitCursor::Native(cursor) = &candidates.cursor else {
            panic!("expected native cursor")
        };
        assert_eq!(cursor.next_window, NATIVE_WINDOW);
        assert_eq!(candidates.next_start().unwrap(), Some(keyword));
        let HitCursor::Native(cursor) = &candidates.cursor else {
            panic!("expected native cursor")
        };
        assert_eq!(cursor.next_window, 2 * NATIVE_WINDOW, "do not scan the third window");
        assert!(!candidates.exhausted);
        assert!(candidates.next_start().unwrap().is_none());
        assert_eq!(starts(&native, &bytes), starts(&aho, &bytes));
    }

    #[test]
    fn violated_pending_span_proof_returns_a_latched_error() {
        let oracle = StartOracle::new("abc").unwrap();
        let mut candidates = oracle.candidates(b"abc");
        // Only a test can violate the stream's invariant in this way. An
        // unexpected future proof expansion must fail closed, never drop bits.
        candidates.pending.insert(usize::MAX).unwrap();
        assert!(candidates.next_start().is_err());
        assert!(candidates.failed);
        candidates.seek_to(3);
        assert!(candidates.next_start().is_err());
    }

    #[test]
    fn forward_seeks_keep_pending_lookahead_and_exhaustion_valid() {
        let oracle = StartOracle::new("x{0,3}abc|abc.*def").unwrap();
        let bytes = b"xxabc abcdef xxxxabc abc";
        let all = starts(&oracle, bytes);
        for seek in 0..=bytes.len() + 1 {
            let mut candidates = oracle.candidates(bytes);
            let first = candidates.next_start().unwrap().unwrap();
            candidates.seek_to(seek);
            let remaining: Vec<_> =
                std::iter::from_fn(|| candidates.next_start().unwrap()).collect();
            let expected: Vec<_> =
                all.iter().copied().filter(|&s| s > first && s >= seek).collect();
            assert_eq!(remaining, expected, "seek={seek}");
            assert!(candidates.exhausted);
            candidates.seek_to(bytes.len());
            assert!(candidates.exhausted, "a forward seek must not rescan an exhausted suffix");
            assert!(candidates.next_start().unwrap().is_none());
        }
    }

    #[test]
    fn native_hits_sort_by_start_not_native_end_order() {
        let oracle = StartOracle::new("abcxyzdefghi|xyz").unwrap();
        let aho = aho_oracle(&oracle);
        assert_eq!(starts(&oracle, b"abcxyzdefghi"), vec![0, 3]);
        assert_eq!(starts(&oracle, b"abcxyzdefghi"), starts(&aho, b"abcxyzdefghi"));
    }

    #[test]
    fn next_window_keyword_can_backstep_before_previous_window_candidate() {
        let pattern = "abc|<.{0,40}key";
        let oracle = StartOracle::new(pattern).unwrap();
        let aho = aho_oracle(&oracle);
        let mut bytes = vec![b'_'; NATIVE_WINDOW + 100];
        bytes[NATIVE_WINDOW - 15] = b'<';
        bytes[NATIVE_WINDOW - 2..NATIVE_WINDOW + 1].copy_from_slice(b"abc");
        bytes[NATIVE_WINDOW + 20..NATIVE_WINDOW + 23].copy_from_slice(b"key");
        // abc belongs to the first owned region; key belongs to the next. Its
        // bounded XML-like prefix starts BEFORE abc, so a window-local flush
        // would emit starts in the wrong order and could miss the first match.
        let expected = vec![NATIVE_WINDOW - 15, NATIVE_WINDOW - 2, NATIVE_WINDOW + 20];
        assert_eq!(starts(&oracle, &bytes), expected);
        assert_eq!(starts(&oracle, &bytes), starts(&aho, &bytes));
        assert_eq!(original(pattern).find(&bytes).unwrap().start(), NATIVE_WINDOW - 15);
    }

    #[test]
    fn native_right_overlap_covers_long_needles_at_both_window_seams() {
        let literal: String = (0..MAX_NEEDLE).map(|i| char::from(b'a' + (i % 26) as u8)).collect();
        let oracle = StartOracle::new(&literal).unwrap();
        let aho = aho_oracle(&oracle);
        for start in [
            NATIVE_WINDOW - MAX_NEEDLE + 1,
            NATIVE_WINDOW - 32,
            NATIVE_WINDOW - 1,
            NATIVE_WINDOW,
            NATIVE_WINDOW + 1,
            2 * NATIVE_WINDOW - MAX_NEEDLE + 1,
            2 * NATIVE_WINDOW - 1,
        ] {
            let mut bytes = vec![b'_'; 2 * NATIVE_WINDOW + MAX_NEEDLE];
            bytes[start..start + literal.len()].copy_from_slice(literal.as_bytes());
            assert_eq!(starts(&oracle, &bytes), vec![start], "start={start}");
            assert_eq!(starts(&oracle, &bytes), starts(&aho, &bytes));
            assert_eq!(original(&literal).find(&bytes).unwrap().start(), start);
        }
        // Confirmation may extend far past the scanned right-overlap: the
        // oracle's 64B prefix is not a replacement for the full original regex.
        let literal = format!("literal-start-{}", "a".repeat(100));
        let oracle = StartOracle::new(&literal).unwrap();
        let start = NATIVE_WINDOW - 20;
        let mut bytes = vec![b'_'; start + literal.len()];
        bytes[start..].copy_from_slice(literal.as_bytes());
        assert_eq!(starts(&oracle, &bytes), vec![start]);
        assert_eq!(original(&literal).find(&bytes).unwrap().range(), start..bytes.len());
    }

    #[test]
    fn native_literals_escape_regex_syntax_and_preserve_binary_and_unicode_flags() {
        assert_eq!(escaped_literal(b".*[\0\xFF"), b"\\x2e\\x2a\\x5b\\x00\\xff");
        for (pattern, bytes) in [
            (r"\x00\xFF\x80\.\*\[\]\\abc", b"_\0\xFF\x80.*[]\\abc_".as_slice()),
            (r"(?i)\xFF\x80abc", b"\0\xFF\x80ABC\xFF\x80abc\0".as_slice()),
            ("(?ui)éabc", "_ÉABC_éabc_".as_bytes()),
            ("éabc", "_éabc_Éabc_".as_bytes()),
        ] {
            let oracle = StartOracle::new(pattern).unwrap();
            let aho = aho_oracle(&oracle);
            assert_eq!(assert_covers(&original(pattern), &oracle, bytes), starts(&aho, bytes));
        }
    }

    #[test]
    fn native_seeks_skip_owned_regions_and_preserve_lookahead() {
        let oracle = StartOracle::new("x{0,3}abc").unwrap();
        let aho = aho_oracle(&oracle);
        let mut bytes = vec![b'_'; 3 * NATIVE_WINDOW + 100];
        for start in [10, NATIVE_WINDOW - 2, NATIVE_WINDOW + 20, 3 * NATIVE_WINDOW + 10] {
            bytes[start..start + 6].copy_from_slice(b"xxxabc");
        }
        let all = starts(&aho, &bytes);
        for seek in [
            0,
            13,
            NATIVE_WINDOW - 3,
            NATIVE_WINDOW,
            2 * NATIVE_WINDOW,
            bytes.len(),
            bytes.len() + 1,
        ] {
            let mut candidates = oracle.candidates(&bytes);
            let first = candidates.next_start().unwrap().unwrap();
            candidates.seek_to(seek);
            candidates.seek_to(0); // backward seeks cannot resurrect earlier starts
            let remaining: Vec<_> =
                std::iter::from_fn(|| candidates.next_start().unwrap()).collect();
            let expected: Vec<_> =
                all.iter().copied().filter(|&s| s > first && s >= seek).collect();
            assert_eq!(remaining, expected, "seek={seek}");
            assert!(candidates.exhausted);
            candidates.seek_to(bytes.len());
            assert!(candidates.exhausted);
            assert!(candidates.next_start().unwrap().is_none());
        }
    }

    #[test]
    fn native_scratch_errors_before_and_after_a_prefix_are_latched() {
        let oracle = StartOracle::new("abc").unwrap();
        oracle.with_native_scanner_borrowed_for_test(|| {
            let mut candidates = oracle.candidates(b"abc");
            assert!(candidates.next_start().is_err());
            candidates.seek_to(3);
            assert!(candidates.next_start().is_err());
        });
        // A new iterator works once the test's scratch borrow is released.
        assert_eq!(starts(&oracle, b"abc"), vec![0]);
        let mut bytes = vec![b'_'; 3 * NATIVE_WINDOW];
        for start in [0, NATIVE_WINDOW + 10, 2 * NATIVE_WINDOW + 10] {
            bytes[start..start + 3].copy_from_slice(b"abc");
        }
        let mut candidates = oracle.candidates(&bytes);
        assert_eq!(candidates.next_start().unwrap(), Some(0));
        oracle.with_native_scanner_borrowed_for_test(|| {
            // First-window output already happened without scanning ahead. The
            // next window now needs scratch, whose reentry must fail.
            assert!(candidates.next_start().is_err());
        });
        assert!(candidates.next_start().is_err());
        assert!(candidates.failed);
    }

    #[test]
    fn native_dense_window_hit_bound_and_overflow_failure() {
        let oracle = StartOracle::new("aaa").unwrap();
        let bytes = vec![b'a'; NATIVE_WINDOW + 2];
        let mut candidates = oracle.candidates(&bytes);
        assert_eq!(candidates.next_start().unwrap(), Some(0));
        let HitCursor::Native(cursor) = &candidates.cursor else {
            panic!("expected native cursor")
        };
        assert_eq!(cursor.hits.len(), MAX_NATIVE_HITS);
        assert!(cursor.hits.capacity() <= MAX_NATIVE_HITS);
        candidates.seek_to(bytes.len());
        assert!(candidates.next_start().unwrap().is_none());

        // With prefix-merged guards there is normally at most one hit per
        // owned start. Lower the test-only cap to exercise the fail-closed path.
        let mut candidates = oracle.candidates(&bytes);
        let HitCursor::Native(cursor) = &mut candidates.cursor else {
            panic!("expected native cursor")
        };
        cursor.hit_limit = Some(8);
        let error = candidates.next_start().unwrap_err();
        assert!(error.to_string().contains("bounded hit capacity"));
        let HitCursor::Native(cursor) = &candidates.cursor else { unreachable!() };
        assert_eq!(cursor.hits.len(), 8);
        assert!(cursor.hits.capacity() <= 8);
        assert!(candidates.pending.is_empty());
        candidates.seek_to(bytes.len());
        assert!(candidates.next_start().is_err());
    }

    #[test]
    fn dense_candidates_keep_only_a_bounded_pending_frontier() {
        let oracle = StartOracle::new(".{0,128}aaa").unwrap();
        let bytes = vec![b'a'; 5000];
        let mut candidates = oracle.candidates(&bytes);
        let mut count = 0;
        while candidates.next_start().unwrap().is_some() {
            count += 1;
            assert!(candidates.pending.len() <= MAX_LOOKBACK + 1);
        }
        assert_eq!(count, bytes.len() - 2);
    }
}
