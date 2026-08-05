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
    /// A live or cryptographic validator authoritatively rejected the credential.
    VerifiedInactive,
    /// The secret material is structurally valid, but its live use is unknown.
    StructurallyValid,
    /// Validation was attempted but infrastructure or the remote service was unavailable.
    Unavailable,
    /// Validation was intentionally skipped, for example because a dependency was missing.
    Skipped,
    /// The rule has no validation strategy.
    #[default]
    NotConfigured,
    /// The rule has validation, but it was not run.
    NotAttempted,
    /// Rule authors explicitly marked this high-signal finding for manual review.
    Assumed,
}

impl ValidationOutcome {
    /// Whether this outcome is a verified-active credential.
    pub const fn is_verified_active(self) -> bool {
        matches!(self, Self::VerifiedActive)
    }

    /// Whether this outcome should pass the actionable validation filter.
    pub const fn is_actionable(self) -> bool {
        matches!(
            self,
            Self::VerifiedActive
                | Self::StructurallyValid
                | Self::Unavailable
                | Self::NotAttempted
                | Self::Assumed
        )
    }

    /// Stable human-readable label used by reports.
    pub const fn display_name(self) -> &'static str {
        match self {
            Self::VerifiedActive => "Active Credential",
            Self::VerifiedInactive => "Inactive Credential",
            Self::StructurallyValid => "Structurally Valid Secret",
            Self::Unavailable => "Validation Unavailable",
            Self::Skipped => "Validation Skipped",
            Self::NotConfigured => "Validation Not Configured",
            Self::NotAttempted => "Not Attempted",
            Self::Assumed => "Manual Review Required",
        }
    }

    /// Classify legacy validation fields during the compatibility migration.
    ///
    /// Status values are HTTP-compatible because existing scanner state uses
    /// them for both real responses and internal sentinels.
    pub const fn from_legacy(
        validation_configured: bool,
        assumed: bool,
        success: bool,
        status: u16,
    ) -> Self {
        if assumed {
            return Self::Assumed;
        }
        if success {
            return Self::VerifiedActive;
        }
        if matches!(status, 408 | 429 | 500..=599) {
            return Self::Unavailable;
        }
        if !validation_configured {
            return Self::NotConfigured;
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
        assert!(ValidationOutcome::StructurallyValid.is_actionable());
        assert!(ValidationOutcome::Unavailable.is_actionable());
        assert!(ValidationOutcome::NotAttempted.is_actionable());
        assert!(ValidationOutcome::Assumed.is_actionable());
        assert!(!ValidationOutcome::VerifiedInactive.is_actionable());
        assert!(!ValidationOutcome::Skipped.is_actionable());
        assert!(!ValidationOutcome::NotConfigured.is_actionable());
    }

    #[test]
    fn legacy_classification_distinguishes_failure_modes() {
        assert_eq!(
            ValidationOutcome::from_legacy(true, false, true, 200),
            ValidationOutcome::VerifiedActive
        );
        assert_eq!(
            ValidationOutcome::from_legacy(true, false, false, 401),
            ValidationOutcome::VerifiedInactive
        );
        assert_eq!(
            ValidationOutcome::from_legacy(true, false, false, 502),
            ValidationOutcome::Unavailable
        );
        assert_eq!(
            ValidationOutcome::from_legacy(false, false, false, 100),
            ValidationOutcome::NotConfigured
        );
        assert_eq!(
            ValidationOutcome::from_legacy(true, true, false, 100),
            ValidationOutcome::Assumed
        );
    }

    #[test]
    fn outcome_serialization_is_stable_snake_case() {
        assert_eq!(
            serde_json::to_string(&ValidationOutcome::StructurallyValid).unwrap(),
            "\"structurally_valid\""
        );
    }
}
