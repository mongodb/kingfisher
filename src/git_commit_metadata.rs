//! Git commit metadata types.
//!
//! This module re-exports from [`kingfisher_core::git_commit_metadata`] and
//! owns the process-wide pool for Git identity strings gathered during scans.

use std::sync::{Arc, LazyLock};

use dashmap::DashSet;

pub use kingfisher_core::git_commit_metadata::CommitMetadata;

/// Interns a Git committer name or email address for the lifetime of the process.
pub(crate) fn intern_git_identity(value: &str) -> Arc<str> {
    static IDENTITIES: LazyLock<DashSet<Arc<str>>> = LazyLock::new(|| DashSet::with_capacity(512));

    if let Some(existing) = IDENTITIES.get(value) {
        return Arc::clone(existing.key());
    }

    let interned: Arc<str> = value.into();
    if IDENTITIES.insert(Arc::clone(&interned)) {
        return interned;
    }

    // Another enumerator inserted the same identity between the lookup and insert.
    Arc::clone(IDENTITIES.get(value).expect("inserted Git identity must exist").key())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn git_identities_are_interned() {
        let first = intern_git_identity("committer@example.com");
        let second = intern_git_identity("committer@example.com");

        assert!(Arc::ptr_eq(&first, &second));
    }
}
