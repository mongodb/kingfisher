//! Compatibility façade for the shared native scanner implementation.

use std::sync::Arc;

use anyhow::Result;
use kingfisher_vectorscan::{BlockDatabase, BlockScanner};

/// A pool of Vectorscan block scanners for efficient multi-threaded scanning.
///
/// Each thread gets its own scanner instance to avoid contention.
///
pub struct ScannerPool {
    inner: kingfisher_rules::scanner_pool::ScannerPool,
}

impl ScannerPool {
    /// Creates a new scanner pool from a compiled Vectorscan database.
    pub fn new(db: Arc<BlockDatabase>) -> Self {
        Self { inner: kingfisher_rules::scanner_pool::ScannerPool::new(db) }
    }

    /// Executes a callback with a thread-local scanner.
    ///
    /// # Panics
    ///
    /// Panics on allocation failure or reentrant access. Prefer [`Self::try_with`].
    pub fn with<F, R>(&self, f: F) -> R
    where
        F: for<'db> FnOnce(&mut BlockScanner<'db>) -> R,
    {
        self.inner.with(f)
    }

    /// Executes a callback with a scanner, returning allocation or reentrancy errors.
    ///
    /// A callback must not recursively borrow this pool on the same thread.
    /// Separate threads use separate scratch space. A panic releases the borrow.
    ///
    /// # Errors
    ///
    /// Returns an error if native scratch allocation fails or a callback reenters
    /// this pool on the same thread. A fallible callback produces a nested `Result`.
    ///
    /// The callback cannot return a scanner borrowing the pool's database:
    ///
    /// ```compile_fail
    /// # fn example(pool: &kingfisher_scanner::ScannerPool) {
    /// let escaped = pool.try_with(|scanner| scanner.clone());
    /// # }
    /// ```
    pub fn try_with<F, R>(&self, f: F) -> Result<R>
    where
        F: for<'db> FnOnce(&mut BlockScanner<'db>) -> R,
    {
        self.inner.try_with(f)
    }
}
