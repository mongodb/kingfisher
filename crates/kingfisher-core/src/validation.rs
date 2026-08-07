//! Validation outcomes shared by scanning, reporting, and integrations.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// The semantic outcome of credential validation.
///
/// This is intentionally separate from transport-specific status codes. A
/// network failure, an intentionally skipped check, and an authoritative
/// credential rejection are different outcomes even when all three have a
/// false legacy `validation_success` value.
#[derive(
    Debug,
    Default,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Serialize,
    Deserialize,
    JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum ValidationOutcome {
    /// A live or cryptographic validator proved the credential is usable.
    VerifiedActive,
    /// The rule author marked the credential as valid without live validation.
    Assumed,
    /// Network-free cryptographic validation parsed the material and derived public evidence.
    LocallyDerived,
    /// Network-free cryptographic validation rejected malformed key material.
    InvalidMaterial,
    /// A live validator authoritatively rejected the credential.
    VerifiedInactive,
    /// Validation was attempted but infrastructure or the remote service was unavailable.
    Unavailable,
    /// Validation was intentionally skipped, for example because a dependency was missing.
    Skipped,
    /// No validation result was produced, either because the rule has no validator
    /// or because configured validation was not run.
    #[default]
    NotAttempted,
}

impl ValidationOutcome {
    /// Whether this outcome is a verified-active credential.
    pub const fn is_verified_active(self) -> bool {
        matches!(self, Self::VerifiedActive)
    }

    /// Whether this outcome should pass the actionable validation filter.
    pub const fn is_actionable(self) -> bool {
        matches!(self, Self::VerifiedActive | Self::Assumed | Self::LocallyDerived)
    }

    /// Stable human-readable label used by reports.
    pub const fn display_name(self) -> &'static str {
        match self {
            Self::VerifiedActive => "Active Credential",
            Self::Assumed => "Assumed Valid (Not Live-Validated)",
            Self::LocallyDerived => "Locally Derived",
            Self::InvalidMaterial => "Invalid Cryptographic Material",
            Self::VerifiedInactive => "Inactive Credential",
            Self::Unavailable => "Inconclusive Validation",
            Self::Skipped => "Validation Skipped",
            Self::NotAttempted => "Not Attempted",
        }
    }

    /// Classify legacy validation fields during the compatibility migration.
    ///
    /// Status values are HTTP-compatible because existing scanner state uses
    /// them for both real responses and internal sentinels.
    pub const fn from_legacy(assumed: bool, success: bool, status: u16) -> Self {
        if assumed {
            return Self::Assumed;
        }
        if success {
            return Self::VerifiedActive;
        }
        if matches!(status, 408 | 429 | 500..=599) {
            return Self::Unavailable;
        }
        match status {
            0 | 100 => Self::NotAttempted,
            428 => Self::Skipped,
            _ => Self::VerifiedInactive,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn actionable_outcomes_are_explicit() {
        assert!(ValidationOutcome::VerifiedActive.is_actionable());
        assert!(ValidationOutcome::Assumed.is_actionable());
        assert!(ValidationOutcome::LocallyDerived.is_actionable());
        assert!(!ValidationOutcome::InvalidMaterial.is_actionable());
        assert!(!ValidationOutcome::VerifiedInactive.is_actionable());
        assert!(!ValidationOutcome::Unavailable.is_actionable());
        assert!(!ValidationOutcome::Skipped.is_actionable());
        assert!(!ValidationOutcome::NotAttempted.is_actionable());
    }

    #[test]
    fn legacy_classification_distinguishes_failure_modes() {
        assert_eq!(
            ValidationOutcome::from_legacy(false, true, 200),
            ValidationOutcome::VerifiedActive
        );
        assert_eq!(ValidationOutcome::from_legacy(true, false, 100), ValidationOutcome::Assumed);
        assert_eq!(
            ValidationOutcome::from_legacy(false, false, 401),
            ValidationOutcome::VerifiedInactive
        );
        assert_eq!(
            ValidationOutcome::from_legacy(false, false, 502),
            ValidationOutcome::Unavailable
        );
        assert_eq!(
            ValidationOutcome::from_legacy(false, false, 100),
            ValidationOutcome::NotAttempted
        );
    }

    #[test]
    fn outcome_serialization_is_stable_snake_case() {
        assert_eq!(
            serde_json::to_string(&ValidationOutcome::LocallyDerived).unwrap(),
            "\"locally_derived\""
        );
        assert_eq!(
            serde_json::to_string(&ValidationOutcome::InvalidMaterial).unwrap(),
            "\"invalid_material\""
        );
        assert_eq!(
            serde_json::to_string(&ValidationOutcome::NotAttempted).unwrap(),
            "\"not_attempted\""
        );
    }

    #[test]
    fn unavailable_outcome_has_inconclusive_display_name() {
        assert_eq!(ValidationOutcome::Unavailable.display_name(), "Inconclusive Validation");
    }

    #[test]
    fn assumed_outcome_has_high_confidence_display_name() {
        assert_eq!(ValidationOutcome::Assumed.display_name(), "Assumed Valid (Not Live-Validated)");
    }

    #[test]
    fn active_outcome_preserves_compatible_display_name() {
        assert_eq!(ValidationOutcome::VerifiedActive.display_name(), "Active Credential");
    }
}
