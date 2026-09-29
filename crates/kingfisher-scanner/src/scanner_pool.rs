//! Thread-local scanner pool for efficient multi-threaded scanning.

use std::cell::RefCell;
use std::sync::Arc;

use anyhow::{Context, Result};
use kingfisher_vectorscan::{BlockDatabase, BlockScanner};
use thread_local::ThreadLocal;

/// A pool of Vectorscan block scanners for efficient multi-threaded scanning.
///
/// Each thread gets its own scanner instance to avoid contention.
///
/// # Field Order
///
/// The field order is significant: `scanners` must be declared before `db`
/// because Rust drops fields in declaration order. The scanners hold references
/// to the database (via lifetime transmute), so they must be dropped first.
pub struct ScannerPool {
    // IMPORTANT: scanners must be dropped before db - do not reorder these fields
    scanners: ThreadLocal<RefCell<Option<BlockScanner<'static>>>>,
    db: Arc<BlockDatabase>,
}

// Safety: Each thread only accesses its own scanner instance
unsafe impl Send for ScannerPool {}
unsafe impl Sync for ScannerPool {}

impl ScannerPool {
    /// Creates a new scanner pool from a compiled Vectorscan database.
    pub fn new(db: Arc<BlockDatabase>) -> Self {
        Self { db, scanners: ThreadLocal::new() }
    }

    /// Executes a function with a thread-local scanner.
    ///
    /// This ensures each thread has its own scanner instance, avoiding
    /// the need for locking during scanning operations.
    ///
    /// # Panics
    /// Panics on allocation failure or reentrant access. Prefer [`Self::try_with`].
    pub fn with<F, R>(&self, f: F) -> R
    where
        F: FnOnce(&mut BlockScanner<'_>) -> R,
    {
        self.try_with(f).expect("unable to borrow or initialize scanner")
    }

    /// Executes a callback with a scanner, returning allocation or reentrancy errors.
    ///
    /// A callback must not recursively borrow the same pool on the same thread.
    /// Separate threads use separate scratch space. A panic releases the borrow.
    pub fn try_with<F, R>(&self, f: F) -> Result<R>
    where
        F: FnOnce(&mut BlockScanner<'_>) -> R,
    {
        let cell = self.scanners.get_or(|| RefCell::new(None));
        let mut scanner_opt = cell.try_borrow_mut().context("scanner pool is already borrowed")?;

        // SAFETY: The pool owns the database; scanners are dropped before it.
        // RefCell prevents overlapping mutable borrows, including reentrant callbacks.
        if scanner_opt.is_none() {
            let db_ref: &'static BlockDatabase =
                unsafe { std::mem::transmute::<&BlockDatabase, &'static BlockDatabase>(&self.db) };
            *scanner_opt = Some(BlockScanner::new(db_ref)?);
        }

        Ok(f(scanner_opt.as_mut().unwrap()))
    }
}
