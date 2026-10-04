//! Shared thread-local Vectorscan scanners.
//!
//! This compatibility module preserves the application import path. Prefer
//! [`ScannerPool::try_with`] to propagate allocation and reentrancy errors.

pub use kingfisher_scanner::ScannerPool;
