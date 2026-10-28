
use std::cell::Cell;
use std::collections::{BTreeMap, BTreeSet};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Barrier};
use std::thread;

use super::{BlobId, BlobIdMap};

fn identifier(first: u8, sequence: u64) -> BlobId {
    let mut bytes = [0; 20];
    bytes[0] = first;
    bytes[1..9].copy_from_slice(&sequence.to_le_bytes());
    bytes[9..17].copy_from_slice(&sequence.rotate_left(17).to_be_bytes());
    bytes[19] = first.wrapping_add(sequence as u8);
    BlobId::from_hex(&hex::encode(bytes)).expect("fixture has exactly 20 bytes")
}

#[test]
fn new_and_default_are_empty_and_missing_reads_do_not_insert() {
    for map in [BlobIdMap::<bool>::new(), BlobIdMap::default()] {
        assert_eq!(map.len(), 0);
        assert!(map.is_empty());
        for first in 0..=u8::MAX {
            let key = identifier(first, 0);
            assert!(!map.contains_key(&key));
            assert_eq!(map.get(&key), None);
        }
        assert_eq!(map.len(), 0);
        map.clear();
        assert!(map.is_empty());
    }
}

#[test]
fn insert_replaces_and_returns_the_previous_value_including_false() {
    let map = BlobIdMap::new();
    let key = identifier(255, 17);
    assert_eq!(map.insert(key, false), None);
    assert!(map.contains_key(&key));
    assert_eq!(map.get(&key), Some(false));
    assert_eq!(map.insert(key, true), Some(false));
    assert_eq!(map.insert(key, false), Some(true));
    assert_eq!(map.get(&key), Some(false));
    assert_eq!(map.len(), 1);
}

#[test]
fn every_first_byte_retains_independent_keys_and_clear_removes_all() {
    let map = BlobIdMap::new();
    for first in 0..=u8::MAX {
        for sequence in 0..4 {
            assert_eq!(map.insert(identifier(first, sequence), (first, sequence)), None);
        }
    }
    assert_eq!(map.len(), 256 * 4);
    for first in 0..=u8::MAX {
        for sequence in 0..4 {
            assert_eq!(map.get(&identifier(first, sequence)), Some((first, sequence)));
        }
    }
    map.clear();
    assert_eq!(map.len(), 0);
    assert!(map.is_empty());
    for first in 0..=u8::MAX {
        assert!(!map.contains_key(&identifier(first, 0)));
        assert_eq!(map.get(&identifier(first, 0)), None);
    }
    // A cleared map remains usable, including the two boundary first bytes.
    for first in [0, 255] {
        let key = identifier(first, u64::MAX);
        assert_eq!(map.insert(key, (first, u64::MAX)), None);
        assert_eq!(map.get(&key), Some((first, u64::MAX)));
    }
    assert_eq!(map.len(), 2);
}

#[test]
fn all_twenty_digest_bytes_participate_in_key_identity() {
    let map = BlobIdMap::new();
    let zero = BlobId::default();
    assert_eq!(map.insert(zero, 0), None);
    for index in 0..20 {
        let mut bytes = [0; 20];
        bytes[index] = 1;
        let key = BlobId::from_hex(&hex::encode(bytes)).unwrap();
        assert_eq!(map.insert(key, index + 1), None);
        assert_eq!(map.get(&key), Some(index + 1));
    }
    let all_ones = BlobId::from_hex(&"ff".repeat(20)).unwrap();
    assert_eq!(map.insert(all_ones, 21), None);
    assert_eq!(map.get(&zero), Some(0));
    assert_eq!(map.len(), 22);
}

#[test]
fn same_prefix_growth_does_not_lose_or_evict_entries() {
    let map = BlobIdMap::new();
    for sequence in 0..4096 {
        assert_eq!(map.insert(identifier(37, sequence), sequence), None);
    }
    assert_eq!(map.len(), 4096);
    for sequence in 0..4096 {
        assert_eq!(map.get(&identifier(37, sequence)), Some(sequence));
    }
}

#[test]
fn deterministic_operations_match_an_independent_ordered_map() {
    let map = BlobIdMap::new();
    let mut expected = BTreeMap::new();
    let keys: Vec<_> = (0..257).map(|n| identifier((n % 256) as u8, n / 3)).collect();
    let mut state = 0x97b2_f18a_315c_064du64;
    for step in 0..8000 {
        state = state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        let key = keys[(state as usize) % keys.len()];
        match (state >> 32) % 29 {
            0 => {
                map.clear();
                expected.clear();
            }
            1..=19 => assert_eq!(map.insert(key, step), expected.insert(key, step)),
            _ => {
                assert_eq!(map.get(&key), expected.get(&key).copied());
                assert_eq!(map.contains_key(&key), expected.contains_key(&key));
            }
        }
        assert_eq!(map.len(), expected.len());
        assert_eq!(map.is_empty(), expected.is_empty());
    }
    for key in keys {
        assert_eq!(map.get(&key), expected.get(&key).copied());
    }
}

#[test]
fn zero_sized_values_and_borrowed_values_are_supported() {
    let units = BlobIdMap::new();
    let key = identifier(7, 0);
    assert_eq!(units.insert(key, ()), None);
    assert_eq!(units.insert(key, ()), Some(()));
    assert_eq!(units.get(&key), Some(()));
    let owned = String::from("borrowed value");
    let borrowed = BlobIdMap::new();
    assert_eq!(borrowed.insert(key, owned.as_str()), None);
    assert_eq!(borrowed.get(&key), Some(owned.as_str()));
}

struct DropProbe {
    value: usize,
    dropped: Arc<AtomicUsize>,
}

impl Drop for DropProbe {
    fn drop(&mut self) {
        self.dropped.fetch_add(1, Ordering::SeqCst);
    }
}

#[test]
fn non_copy_values_are_returned_owned_and_dropped_exactly_once() {
    let dropped = Arc::new(AtomicUsize::new(0));
    let key = identifier(4, 99);
    let map = BlobIdMap::new();
    assert!(map.insert(key, DropProbe { value: 1, dropped: dropped.clone() }).is_none());
    let old = map
        .insert(key, DropProbe { value: 2, dropped: dropped.clone() })
        .expect("the old value is returned to the caller");
    assert_eq!(old.value, 1);
    assert_eq!(dropped.load(Ordering::SeqCst), 0);
    assert!(map.contains_key(&key));
    drop(old);
    assert_eq!(dropped.load(Ordering::SeqCst), 1);
    map.clear();
    assert_eq!(dropped.load(Ordering::SeqCst), 2);
    map.clear();
    assert_eq!(dropped.load(Ordering::SeqCst), 2);
    assert!(map.insert(key, DropProbe { value: 3, dropped: dropped.clone() }).is_none());
    drop(map);
    assert_eq!(dropped.load(Ordering::SeqCst), 3);
}

#[test]
fn dropping_a_populated_map_releases_values_across_all_first_bytes() {
    let dropped = Arc::new(AtomicUsize::new(0));
    {
        let map = BlobIdMap::new();
        for first in 0..=u8::MAX {
            drop(
                map.insert(identifier(first, 0), DropProbe { value: 0, dropped: dropped.clone() }),
            );
        }
        assert_eq!(dropped.load(Ordering::SeqCst), 0);
    }
    assert_eq!(dropped.load(Ordering::SeqCst), 256);
}

#[test]
fn map_supports_send_values_that_are_not_sync() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<BlobIdMap<Cell<usize>>>();
    let map = BlobIdMap::new();
    let key = identifier(0, 1);
    assert!(map.insert(key, Cell::new(7)).is_none());
    assert_eq!(map.insert(key, Cell::new(9)).unwrap().get(), 7);
    assert!(map.contains_key(&key));
}

#[test]
fn concurrent_unique_inserts_with_the_same_first_byte_all_survive() {
    const WORKERS: usize = 8;
    const PER_WORKER: usize = 256;
    let map = BlobIdMap::new();
    let start = Barrier::new(WORKERS);
    thread::scope(|scope| {
        for worker in 0..WORKERS {
            let map = &map;
            let start = &start;
            scope.spawn(move || {
                start.wait();
                for index in 0..PER_WORKER {
                    let sequence = (worker * PER_WORKER + index) as u64;
                    assert_eq!(map.insert(identifier(0, sequence), sequence), None);
                }
            });
        }
    });
    assert_eq!(map.len(), WORKERS * PER_WORKER);
    for sequence in 0..(WORKERS * PER_WORKER) as u64 {
        assert_eq!(map.get(&identifier(0, sequence)), Some(sequence));
    }
}

#[test]
fn concurrent_inserts_across_all_first_bytes_are_visible_after_join() {
    const WORKERS: usize = 8;
    let map = BlobIdMap::new();
    let start = Barrier::new(WORKERS);
    thread::scope(|scope| {
        for worker in 0..WORKERS {
            let map = &map;
            let start = &start;
            scope.spawn(move || {
                start.wait();
                for first in 0..=u8::MAX {
                    let key = identifier(first, worker as u64);
                    assert_eq!(map.insert(key, worker), None);
                    assert!(map.contains_key(&key));
                    assert_eq!(map.get(&key), Some(worker));
                }
            });
        }
    });
    assert_eq!(map.len(), 256 * WORKERS);
    for worker in 0..WORKERS {
        for first in 0..=u8::MAX {
            assert_eq!(map.get(&identifier(first, worker as u64)), Some(worker));
        }
    }
}

#[test]
fn simultaneous_replacements_return_each_previous_value_exactly_once() {
    const WORKERS: usize = 8;
    const PER_WORKER: usize = 128;
    let map = BlobIdMap::new();
    let key = identifier(255, 1);
    let start = Barrier::new(WORKERS);
    let mut returned = Vec::new();
    thread::scope(|scope| {
        let mut workers = Vec::new();
        for worker in 0..WORKERS {
            let map = &map;
            let start = &start;
            workers.push(scope.spawn(move || {
                start.wait();
                (0..PER_WORKER)
                    .map(|index| map.insert(key, worker * PER_WORKER + index))
                    .collect::<Vec<_>>()
            }));
        }
        for worker in workers {
            returned.extend(worker.join().expect("map worker must finish"));
        }
    });
    assert_eq!(returned.iter().filter(|old| old.is_none()).count(), 1);
    let mut values: Vec<_> = returned.into_iter().flatten().collect();
    values.push(map.get(&key).expect("the last inserted value remains"));
    values.sort_unstable();
    assert_eq!(values, (0..WORKERS * PER_WORKER).collect::<Vec<_>>());
    assert_eq!(map.len(), 1);
}

#[test]
fn concurrent_non_copy_replacement_transfers_all_ownership_to_callers_or_map() {
    const WORKERS: usize = 6;
    const PER_WORKER: usize = 128;
    let map = BlobIdMap::new();
    let dropped = Arc::new(AtomicUsize::new(0));
    let key = identifier(3, 7);
    let start = Barrier::new(WORKERS);
    let mut old_values = Vec::new();
    thread::scope(|scope| {
        let mut workers = Vec::new();
        for worker in 0..WORKERS {
            let map = &map;
            let start = &start;
            let dropped = &dropped;
            workers.push(scope.spawn(move || {
                start.wait();
                let mut old = Vec::new();
                for index in 0..PER_WORKER {
                    if let Some(value) = map.insert(
                        key,
                        DropProbe { value: worker * PER_WORKER + index, dropped: dropped.clone() },
                    ) {
                        old.push(value);
                    }
                }
                old
            }));
        }
        for worker in workers {
            old_values.extend(worker.join().expect("map worker must finish"));
        }
    });
    assert_eq!(dropped.load(Ordering::SeqCst), 0);
    assert_eq!(old_values.len(), WORKERS * PER_WORKER - 1);
    assert_eq!(
        old_values.iter().map(|value| value.value).collect::<BTreeSet<_>>().len(),
        old_values.len()
    );
    map.clear();
    assert_eq!(dropped.load(Ordering::SeqCst), 1);
    drop(old_values);
    assert_eq!(dropped.load(Ordering::SeqCst), WORKERS * PER_WORKER);
}

#[test]
fn concurrent_clears_and_writes_release_every_value_exactly_once() {
    const WORKERS: usize = 6;
    const PER_WORKER: usize = 256;
    let map = BlobIdMap::new();
    let dropped = Arc::new(AtomicUsize::new(0));
    let start = Barrier::new(WORKERS + 1);
    thread::scope(|scope| {
        for worker in 0..WORKERS {
            let map = &map;
            let dropped = &dropped;
            let start = &start;
            scope.spawn(move || {
                start.wait();
                for index in 0..PER_WORKER {
                    let key = identifier(index as u8, worker as u64);
                    drop(map.insert(key, DropProbe { value: index, dropped: dropped.clone() }));
                    let _ = map.contains_key(&key);
                }
            });
        }
        start.wait();
        for _ in 0..64 {
            map.clear();
        }
    });
    // clear/len/is_empty are sequential observations of the shards rather than
    // atomic whole-map operations; assert the final state only after writers join.
    map.clear();
    assert_eq!(map.len(), 0);
    assert!(map.is_empty());
    assert_eq!(dropped.load(Ordering::SeqCst), WORKERS * PER_WORKER);
    assert!(
        map.insert(identifier(255, 99), DropProbe { value: 99, dropped: dropped.clone() })
            .is_none()
    );
    drop(map);
    assert_eq!(dropped.load(Ordering::SeqCst), WORKERS * PER_WORKER + 1);
}

struct PanicOnDrop {
    panic_once: Arc<AtomicBool>,
    dropped: Arc<AtomicUsize>,
}

impl Drop for PanicOnDrop {
    fn drop(&mut self) {
        self.dropped.fetch_add(1, Ordering::SeqCst);
        assert!(!self.panic_once.swap(false, Ordering::SeqCst), "intentional fixture panic");
    }
}

#[test]
fn value_drop_panic_does_not_poison_the_map_lock() {
    let map = BlobIdMap::new();
    let panic_once = Arc::new(AtomicBool::new(true));
    let dropped = Arc::new(AtomicUsize::new(0));
    let key = identifier(0, 99);
    drop(map.insert(key, PanicOnDrop { panic_once: panic_once.clone(), dropped: dropped.clone() }));
    assert!(catch_unwind(AssertUnwindSafe(|| map.clear())).is_err());
    assert_eq!(dropped.load(Ordering::SeqCst), 1);
    assert_eq!(map.len(), 0);
    assert!(!map.contains_key(&key));
    assert!(map.insert(key, PanicOnDrop { panic_once, dropped: dropped.clone() }).is_none());
    map.clear();
    assert_eq!(dropped.load(Ordering::SeqCst), 2);
}
