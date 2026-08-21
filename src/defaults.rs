//! Betterleaks-derived default rule loading.
//!
//! This module re-exports the builtin rule loader from [`kingfisher_rules::defaults`].

pub use kingfisher_rules::defaults::{get_betterleaks_rules, get_builtin_rules};
