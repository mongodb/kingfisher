//! Offline content extraction. Bytecode is parsed, never executed.
pub mod pyc;
pub mod sqlite;

/// A strict content transform could not finish within its output/work budget.
/// Callers must propagate this error instead of falling back to raw content.
#[derive(Debug, thiserror::Error)]
pub enum ExtractionLimitExceeded {
    /// The generated content would exceed the aggregate byte budget.
    #[error("extracted content exceeds max_bytes budget")]
    Bytes,
    /// The shared SQLite row-work limit was reached.
    #[error("SQLite extraction exceeds row limit")]
    Rows,
    /// A bytecode nesting/collection/number limit was reached before parsing completed.
    #[error("bytecode extraction exceeds work limit")]
    BytecodeWork,
}
