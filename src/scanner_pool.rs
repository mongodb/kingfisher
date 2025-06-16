use std::{cell::RefCell, sync::Arc};

use thread_local::ThreadLocal; // external crate ✔
use vectorscan_rs::{BlockDatabase, BlockScanner};

pub struct ScannerPool {
    vsdb: Arc<BlockDatabase>, // keep DB alive
    pool: ThreadLocal<RefCell<BlockScanner<'static>>>,
}

impl ScannerPool {
    pub fn new(vsdb: Arc<BlockDatabase>) -> Self {
        // Initially empty; each Rayon worker builds its own scanner on first use
        Self { vsdb, pool: ThreadLocal::new() }
    }

    #[inline]
    pub fn with<F, R>(&self, f: F) -> R
    where
        F: FnOnce(&mut BlockScanner<'_>) -> R,
    {
        // get_or creates exactly one scratch arena for *this* thread
        let cell = self.pool.get_or(|| {
            RefCell::new(
                BlockScanner::new(unsafe { &*(self.vsdb.as_ref() as *const _) })
                    .expect("Vectorscan scratch alloc"),
            )
        });
        f(&mut *cell.borrow_mut())
    }
}
