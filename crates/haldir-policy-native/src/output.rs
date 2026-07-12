//! Policy decision output.

use haldir_contracts::receipt::DecisionReasonCodeV1;

/// The policy outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyOutcome {
    /// Allow, with the computed effective output validity (ms).
    Allow {
        /// Effective output validity in milliseconds.
        effective_validity_ms: u32,
    },
    /// Deny.
    Deny,
}

/// A deterministic policy decision with stable, bounded reason codes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyDecision {
    /// The outcome.
    pub outcome: PolicyOutcome,
    /// Reason codes (deny reasons first, bounded to 32).
    pub reasons: Vec<DecisionReasonCodeV1>,
}

impl PolicyDecision {
    /// Whether the decision is an allow.
    #[must_use]
    pub fn is_allow(&self) -> bool {
        matches!(self.outcome, PolicyOutcome::Allow { .. })
    }

    /// The effective validity if allowed.
    #[must_use]
    pub fn effective_validity_ms(&self) -> Option<u32> {
        match self.outcome {
            PolicyOutcome::Allow {
                effective_validity_ms,
            } => Some(effective_validity_ms),
            PolicyOutcome::Deny => None,
        }
    }

    /// Whether a specific reason code is present.
    #[must_use]
    pub fn has_reason(&self, code: DecisionReasonCodeV1) -> bool {
        self.reasons.contains(&code)
    }
}
