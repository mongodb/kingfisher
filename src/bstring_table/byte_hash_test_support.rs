//! Private test-only control over the real interner's byte-key hash builder.

use std::collections::hash_map::RandomState;
use std::hash::{BuildHasher, Hasher};

#[derive(Default)]
pub(super) struct ByteHashState {
    random: RandomState,
    collide: bool,
}

impl ByteHashState {
    pub(super) fn colliding() -> Self {
        Self { random: RandomState::new(), collide: true }
    }
}

pub(super) struct ByteHasher {
    inner: <RandomState as BuildHasher>::Hasher,
    collide: bool,
}

impl BuildHasher for ByteHashState {
    type Hasher = ByteHasher;

    fn build_hasher(&self) -> Self::Hasher {
        ByteHasher { inner: self.random.build_hasher(), collide: self.collide }
    }
}

impl Hasher for ByteHasher {
    fn finish(&self) -> u64 {
        if self.collide { 0 } else { self.inner.finish() }
    }

    fn write(&mut self, bytes: &[u8]) {
        self.inner.write(bytes);
    }

    fn write_usize(&mut self, value: usize) {
        self.inner.write_usize(value);
    }
}
