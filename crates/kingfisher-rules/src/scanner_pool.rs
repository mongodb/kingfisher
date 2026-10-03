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
        F: for<'db> FnOnce(&mut BlockScanner<'db>) -> R,
    {
        self.try_with(f).expect("unable to borrow or initialize scanner")
    }

    /// Executes a callback with a scanner, returning allocation or reentrancy errors.
    ///
    /// A callback must not recursively borrow the same pool on the same thread.
    /// Separate threads use separate scratch space. A panic releases the borrow.
    ///
    /// # Errors
    ///
    /// Returns an error if native scratch allocation fails or a callback reenters
    /// this pool on the same thread. Errors returned by the callback remain its
    /// return value, so a fallible callback produces a nested `Result`.
    ///
    /// The callback cannot return a scanner borrowing the pool's database:
    ///
    /// ```compile_fail
    /// # fn example(pool: &kingfisher_rules::scanner_pool::ScannerPool) {
    /// let escaped = pool.try_with(|scanner| scanner.clone());
    /// # }
    /// ```
    pub fn try_with<F, R>(&self, f: F) -> Result<R>
    where
        F: for<'db> FnOnce(&mut BlockScanner<'db>) -> R,
    {
        let cell = self.scanners.get_or(|| RefCell::new(None));
        let mut scanner_opt = cell.try_borrow_mut().context("scanner pool is already borrowed")?;

        // SAFETY: The pool owns the database; scanners are dropped before it.
        // Arc keeps the database at a stable address even when the pool moves.
        // RefCell prevents overlapping mutable borrows, including reentrant callbacks.
        // The higher-ranked callback cannot expose the extended lifetime to callers.
        if scanner_opt.is_none() {
            let db_ref: &'static BlockDatabase =
                unsafe { std::mem::transmute::<&BlockDatabase, &'static BlockDatabase>(&self.db) };
            *scanner_opt = Some(BlockScanner::new(db_ref)?);
        }

        Ok(f(scanner_opt.as_mut().unwrap()))
    }
}

#[cfg(test)]
mod tests {
    use std::panic::{AssertUnwindSafe, catch_unwind};

    use kingfisher_vectorscan::{Flag, Pattern, Scan};

    use super::*;

    fn database() -> Arc<BlockDatabase> {
        Arc::new(
            BlockDatabase::new(vec![Pattern::new(b"secret".to_vec(), Flag::default(), Some(0))])
                .unwrap(),
        )
    }

    #[test]
    fn pool_retains_database_until_all_thread_scratch_is_dropped() {
        let database = database();
        let weak = Arc::downgrade(&database);
        let pool = ScannerPool::new(database);
        std::thread::scope(|scope| {
            for _ in 0..4 {
                let pool = &pool;
                scope.spawn(move || {
                    let mut matches = 0;
                    pool.try_with(|scanner| {
                        scanner.scan(b"a secret", |_, _, _, _| {
                            matches += 1;
                            Scan::Continue
                        })
                    })
                    .unwrap()
                    .unwrap();
                    assert_eq!(matches, 1);
                });
            }
        });
        assert!(weak.upgrade().is_some());
        drop(pool);
        assert!(weak.upgrade().is_none());
    }

    #[test]
    fn panicking_callback_releases_the_scanner_borrow() {
        let pool = ScannerPool::new(database());
        assert!(
            catch_unwind(AssertUnwindSafe(|| {
                let _ = pool.try_with(|_| panic!("callback failed"));
            }))
            .is_err()
        );
        pool.try_with(|_| ()).unwrap();
    }
}
