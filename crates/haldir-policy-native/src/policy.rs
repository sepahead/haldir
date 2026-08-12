//! Compiled native policy parameters (all integer / fixed-point, no floats).

use haldir_contracts::action::ActionClassV1;
use haldir_contracts::cbor::CborWriter;
use haldir_contracts::digest::{DigestDomain, DigestV1};
use haldir_contracts::scalar::{AsciiId, BoundedAscii};

const MAX_PHASE_RULES: usize = 64;
const MAX_ACTIONS_PER_PHASE: usize = 8;
const MAX_PLANT_MODE_RULES: usize = 64;
const MAX_ACTIONS_PER_PLANT_MODE: usize = 8;

/// Immutable schema identifier embedded in native-policy digest preimages.
///
/// Version 1 fixes the executable fields, their CBOR layout, phase ordering,
/// and action-class tags. A change to any of those semantics requires a new
/// schema and encoder; version 1 must remain available for existing identities.
pub const NATIVE_POLICY_DIGEST_SCHEMA_V1: u64 = 1;

/// Schema identifier for policies that execute the locally admitted motion envelope.
///
/// Version 2 appends the exact local-NED frame, acceleration, slew,
/// continuous-motion, Hold-dwell, and plant-mode/action semantics in
/// [`LocallyAdmittedMotionEnvelopeV2`]. The schema-v1 encoder and its identities
/// remain unchanged and cannot encode that envelope.
pub const NATIVE_POLICY_DIGEST_SCHEMA_V2: u64 = 2;

/// A semantic failure in a native policy snapshot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum NativePolicyError {
    /// A velocity bound is not strictly positive.
    NonPositiveVelocityBound,
    /// The validity parameters cannot produce even one minimally useful output.
    IncoherentValidity,
    /// The nominal update interval is zero.
    ZeroNominalUpdate,
    /// A v2 acceleration, slew, or continuous-motion maximum is zero.
    NonPositiveMotionBound,
    /// The expanded evaluator was given a legacy v1 snapshot with no v2 envelope.
    MotionEnvelopeV2Required,
    /// A snapshot containing v2 semantics was passed to the legacy v1 encoder.
    MotionEnvelopeNotRepresentableInV1,
    /// A tracking or uncertainty distance is negative.
    NegativeSafetyDistance,
    /// A geofence axis is inverted or has no point inside its safety margin.
    UnusableGeofence,
    /// The duty window is zero or its active allowance exceeds the window.
    IncoherentDutyLimit,
    /// The number of phase rules exceeds the fixed policy bound.
    TooManyPhaseRules,
    /// A phase name is not a canonical bounded identifier.
    InvalidPhase,
    /// More than one rule names the same phase.
    DuplicatePhase,
    /// A phase contains too many allowed action classes.
    TooManyPhaseActions,
    /// A phase repeats an allowed action class.
    DuplicatePhaseAction,
    /// An action class is not defined by native-policy digest schemas v1/v2.
    UnsupportedActionClass,
    /// The number of plant-mode rules exceeds the fixed policy bound.
    TooManyPlantModeRules,
    /// More than one rule names the same plant mode.
    DuplicatePlantMode,
    /// A plant mode contains too many allowed action classes.
    TooManyPlantModeActions,
    /// A plant mode repeats an allowed action class.
    DuplicatePlantModeAction,
}

impl NativePolicyError {
    /// Stable machine-readable failure class.
    #[must_use]
    pub const fn reason_code(self) -> &'static str {
        match self {
            Self::NonPositiveVelocityBound => "NATIVE_POLICY_NON_POSITIVE_VELOCITY_BOUND",
            Self::IncoherentValidity => "NATIVE_POLICY_INCOHERENT_VALIDITY",
            Self::ZeroNominalUpdate => "NATIVE_POLICY_ZERO_NOMINAL_UPDATE",
            Self::NonPositiveMotionBound => "NATIVE_POLICY_NON_POSITIVE_MOTION_BOUND",
            Self::MotionEnvelopeV2Required => "NATIVE_POLICY_MOTION_ENVELOPE_V2_REQUIRED",
            Self::MotionEnvelopeNotRepresentableInV1 => {
                "NATIVE_POLICY_MOTION_ENVELOPE_NOT_REPRESENTABLE_IN_V1"
            }
            Self::NegativeSafetyDistance => "NATIVE_POLICY_NEGATIVE_SAFETY_DISTANCE",
            Self::UnusableGeofence => "NATIVE_POLICY_UNUSABLE_GEOFENCE",
            Self::IncoherentDutyLimit => "NATIVE_POLICY_INCOHERENT_DUTY_LIMIT",
            Self::TooManyPhaseRules => "NATIVE_POLICY_TOO_MANY_PHASE_RULES",
            Self::InvalidPhase => "NATIVE_POLICY_INVALID_PHASE",
            Self::DuplicatePhase => "NATIVE_POLICY_DUPLICATE_PHASE",
            Self::TooManyPhaseActions => "NATIVE_POLICY_TOO_MANY_PHASE_ACTIONS",
            Self::DuplicatePhaseAction => "NATIVE_POLICY_DUPLICATE_PHASE_ACTION",
            Self::UnsupportedActionClass => "NATIVE_POLICY_UNSUPPORTED_ACTION_CLASS",
            Self::TooManyPlantModeRules => "NATIVE_POLICY_TOO_MANY_PLANT_MODE_RULES",
            Self::DuplicatePlantMode => "NATIVE_POLICY_DUPLICATE_PLANT_MODE",
            Self::TooManyPlantModeActions => "NATIVE_POLICY_TOO_MANY_PLANT_MODE_ACTIONS",
            Self::DuplicatePlantModeAction => "NATIVE_POLICY_DUPLICATE_PLANT_MODE_ACTION",
        }
    }
}

impl std::fmt::Display for NativePolicyError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.reason_code())
    }
}

impl std::error::Error for NativePolicyError {}

/// A rectangular allowed geofence region in the local frame, millimetres.
/// A point on or outside the (uncertainty/margin-shrunk) boundary denies.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GeofenceBoxV1 {
    /// Inclusive lower bounds per axis (mm).
    pub min_mm: [i64; 3],
    /// Inclusive upper bounds per axis (mm).
    pub max_mm: [i64; 3],
}

/// A mission-phase rule: which action classes are permitted in a phase.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PhaseRuleV1 {
    /// The Gate-owned mission phase name.
    pub phase: String,
    /// Action classes permitted in this phase.
    pub allowed: Vec<ActionClassV1>,
}

/// Which Gate actions may be emitted while trusted state reports one plant mode.
///
/// An unlisted mode permits no action. Keeping this mapping action-specific lets
/// a profile authorize `Hold` in a degraded mode without also authorizing motion.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlantModeRuleV2 {
    /// Exact canonical plant-mode identifier reported in trusted state.
    pub plant_mode: AsciiId<64>,
    /// Action classes permitted while the plant is in this mode.
    pub allowed: Vec<ActionClassV1>,
}

/// Locally admitted executable motion-policy envelope introduced by digest schema v2.
///
/// This is one locally configured executable envelope, not a claim that Gate has
/// obtained authenticated policy-package provenance or a matching independent
/// live plant-capability attestation. The evaluator intersects its
/// maxima with the signed mission lease (`min`) and intersects minimum dwell with
/// `max`, so neither authority can make the effective envelope looser.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocallyAdmittedMotionEnvelopeV2 {
    /// Exact trusted-state/NCP frame identifier in which local-NED values are interpreted.
    pub local_ned_frame_id: BoundedAscii<128>,
    /// Maximum measured-state-to-command acceleration norm (mm/s²).
    pub max_linear_accel_mm_s2: u32,
    /// Maximum command-to-command slew norm (mm/s²).
    pub max_linear_slew_mm_s2: u32,
    /// Maximum wall-clock burst duration without a published Hold (ms).
    pub max_continuous_motion_ms: u32,
    /// Minimum continuously covered published-Hold dwell before a new burst (ms).
    pub minimum_hold_between_bursts_ms: u32,
    /// Exact plant-mode/action permissions. Unlisted modes deny every action.
    pub plant_mode_rules: Vec<PlantModeRuleV2>,
}

impl LocallyAdmittedMotionEnvelopeV2 {
    /// Whether the exact trusted plant mode permits `class`.
    ///
    /// Unknown modes deny by construction.
    #[must_use]
    pub(crate) fn plant_mode_permits(
        &self,
        plant_mode: &AsciiId<64>,
        class: ActionClassV1,
    ) -> bool {
        self.plant_mode_rules
            .iter()
            .find(|rule| &rule.plant_mode == plant_mode)
            .is_some_and(|rule| rule.allowed.contains(&class))
    }
}

/// Immutable compiled native-policy parameters for one deployment profile.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativePolicySnapshot {
    /// Maximum absolute value of any single velocity component (mm/s).
    pub max_component_mm_s: i32,
    /// Maximum speed (vector norm) (mm/s).
    pub max_speed_mm_s: i32,
    /// Policy cap on output validity (ms).
    pub max_output_validity_ms: u32,
    /// Minimum useful output validity; below this, DENY (ms).
    pub min_useful_validity_ms: u32,
    /// Publication safety margin subtracted from effective validity (ms).
    pub publication_safety_margin_ms: u32,
    /// Maximum source age at decision (ms).
    pub source_freshness_cap_ms: u32,
    /// Maximum state age at decision (ms).
    pub state_freshness_cap_ms: u32,
    /// Hard NCP-protocol validity cap (ms).
    pub ncp_validity_cap_ms: u32,
    /// Plant-profile validity cap (ms).
    pub plant_validity_cap_ms: u32,
    /// Nominal control-update period used to scale measured acceleration and cap slew (ms).
    pub nominal_update_ms: u32,
    /// Configured bounded tracking-error margin added to the geofence projection (mm).
    pub tracking_error_mm: i64,
    /// Position-uncertainty margin added to the geofence projection (mm).
    pub uncertainty_margin_mm: i64,
    /// Maximum tolerated position uncertainty; above this, DENY (mm).
    pub max_position_uncertainty_mm: i64,
    /// Allowed geofence region.
    pub geofence: GeofenceBoxV1,
    /// Duty accounting window (ms).
    pub duty_window_ms: u32,
    /// Maximum aggregate non-hold command validity within the window (ms).
    pub max_active_ms_in_window: u32,
    /// Executable motion semantics added by native-policy digest schema v2.
    ///
    /// `None` represents a legacy schema-v1 snapshot for identity/migration only.
    /// The expanded evaluator and integrated Gate reject it rather than silently
    /// assigning new motion semantics to an old policy identity.
    pub motion_envelope_v2: Option<LocallyAdmittedMotionEnvelopeV2>,
    /// Mission-phase rules.
    pub phase_rules: Vec<PhaseRuleV1>,
}

/// An owned schema-v2 native policy whose semantics and canonical identity were validated.
///
/// Construction computes the canonical digest once. Integrated callers can retain
/// this type and use the validated evaluator path without repeating whole-policy
/// validation or digest construction on every decision.
#[derive(Debug, Clone, PartialEq, Eq)]
#[must_use = "retain the validated policy for authorization decisions"]
pub struct ValidatedNativePolicy {
    snapshot: NativePolicySnapshot,
    canonical_digest: DigestV1,
}

impl ValidatedNativePolicy {
    /// Validate `snapshot` and cache its canonical identity.
    ///
    /// # Errors
    /// Returns a [`NativePolicyError`] when the snapshot is not safe to evaluate.
    pub fn new(snapshot: NativePolicySnapshot) -> Result<Self, NativePolicyError> {
        snapshot.validate_for_evaluation()?;
        let canonical_digest = snapshot.canonical_digest_v2()?;
        Ok(Self {
            snapshot,
            canonical_digest,
        })
    }

    /// The validated executable policy parameters.
    #[must_use]
    pub const fn snapshot(&self) -> &NativePolicySnapshot {
        &self.snapshot
    }

    /// The canonical identity computed during validation.
    #[must_use]
    pub const fn canonical_digest(&self) -> DigestV1 {
        self.canonical_digest
    }
}

impl NativePolicySnapshot {
    /// Validate every cross-field invariant used by the native evaluator.
    ///
    /// This validation is intentionally independent of Gate construction:
    /// callers of the public pure evaluator receive the same fail-closed
    /// semantics as the integrated Gate.
    ///
    /// # Errors
    /// Returns a [`NativePolicyError`] for an unsafe, ambiguous, unbounded, or
    /// internally unusable snapshot.
    pub fn validate(&self) -> Result<(), NativePolicyError> {
        if self.max_component_mm_s <= 0 || self.max_speed_mm_s <= 0 {
            return Err(NativePolicyError::NonPositiveVelocityBound);
        }

        let usable_validity_cap = [
            self.max_output_validity_ms,
            self.source_freshness_cap_ms,
            self.state_freshness_cap_ms,
            self.ncp_validity_cap_ms,
            self.plant_validity_cap_ms,
        ]
        .into_iter()
        .min()
        .unwrap_or(0);
        if self.min_useful_validity_ms == 0
            || usable_validity_cap
                .checked_sub(self.publication_safety_margin_ms)
                .is_none_or(|remaining| remaining < self.min_useful_validity_ms)
        {
            return Err(NativePolicyError::IncoherentValidity);
        }
        if self.nominal_update_ms == 0 {
            return Err(NativePolicyError::ZeroNominalUpdate);
        }
        if let Some(motion) = self.motion_envelope_v2.as_ref() {
            if motion.max_linear_accel_mm_s2 == 0
                || motion.max_linear_slew_mm_s2 == 0
                || motion.max_continuous_motion_ms == 0
            {
                return Err(NativePolicyError::NonPositiveMotionBound);
            }
            if motion.plant_mode_rules.len() > MAX_PLANT_MODE_RULES {
                return Err(NativePolicyError::TooManyPlantModeRules);
            }
            for (rule_index, rule) in motion.plant_mode_rules.iter().enumerate() {
                if motion
                    .plant_mode_rules
                    .iter()
                    .take(rule_index)
                    .any(|prior| prior.plant_mode == rule.plant_mode)
                {
                    return Err(NativePolicyError::DuplicatePlantMode);
                }
                if rule.allowed.len() > MAX_ACTIONS_PER_PLANT_MODE {
                    return Err(NativePolicyError::TooManyPlantModeActions);
                }
                for (action_index, action) in rule.allowed.iter().enumerate() {
                    native_policy_action_tag_v1(*action)?;
                    if rule
                        .allowed
                        .iter()
                        .take(action_index)
                        .any(|prior| prior == action)
                    {
                        return Err(NativePolicyError::DuplicatePlantModeAction);
                    }
                }
            }
        }
        if self.tracking_error_mm < 0
            || self.uncertainty_margin_mm < 0
            || self.max_position_uncertainty_mm < 0
        {
            return Err(NativePolicyError::NegativeSafetyDistance);
        }

        let safety_margin =
            i128::from(self.tracking_error_mm) + i128::from(self.uncertainty_margin_mm);
        for (&min, &max) in self.geofence.min_mm.iter().zip(self.geofence.max_mm.iter()) {
            let width = i128::from(max) - i128::from(min);
            // Boundary contact denies. For integer positions, a usable axis
            // therefore needs at least one whole millimetre strictly between
            // both safety-margin boundaries.
            if width <= safety_margin.saturating_mul(2).saturating_add(1) {
                return Err(NativePolicyError::UnusableGeofence);
            }
        }

        if self.duty_window_ms == 0 || self.max_active_ms_in_window > self.duty_window_ms {
            return Err(NativePolicyError::IncoherentDutyLimit);
        }
        if self.phase_rules.len() > MAX_PHASE_RULES {
            return Err(NativePolicyError::TooManyPhaseRules);
        }

        for (rule_index, rule) in self.phase_rules.iter().enumerate() {
            if AsciiId::<64>::validate_str(&rule.phase).is_err() {
                return Err(NativePolicyError::InvalidPhase);
            }
            if self
                .phase_rules
                .iter()
                .take(rule_index)
                .any(|prior| prior.phase == rule.phase)
            {
                return Err(NativePolicyError::DuplicatePhase);
            }
            if rule.allowed.len() > MAX_ACTIONS_PER_PHASE {
                return Err(NativePolicyError::TooManyPhaseActions);
            }
            for (action_index, action) in rule.allowed.iter().enumerate() {
                native_policy_action_tag_v1(*action)?;
                if rule
                    .allowed
                    .iter()
                    .take(action_index)
                    .any(|prior| prior == action)
                {
                    return Err(NativePolicyError::DuplicatePhaseAction);
                }
            }
        }
        Ok(())
    }

    /// Validate that the snapshot carries every semantic required by the expanded
    /// evaluator.
    ///
    /// A legacy schema-v1 snapshot remains representable and digestible, but it
    /// cannot authorize an action because doing so would silently assign motion
    /// semantics that its identity never committed to.
    ///
    /// # Errors
    /// Returns [`NativePolicyError::MotionEnvelopeV2Required`] for a v1 snapshot,
    /// or another [`NativePolicyError`] for malformed fields.
    pub fn validate_for_evaluation(&self) -> Result<(), NativePolicyError> {
        self.validate()?;
        if self.motion_envelope_v2.is_none() {
            return Err(NativePolicyError::MotionEnvelopeV2Required);
        }
        Ok(())
    }

    /// Canonical digest of the complete executable policy semantics.
    ///
    /// Phase rules and their action sets are sorted before encoding because
    /// their evaluation semantics are order-independent after duplicate
    /// validation.
    ///
    /// # Errors
    /// Returns a [`NativePolicyError`] instead of assigning an identity to an
    /// invalid policy.
    pub fn canonical_digest(&self) -> Result<DigestV1, NativePolicyError> {
        if self.motion_envelope_v2.is_some() {
            self.canonical_digest_v2()
        } else {
            self.canonical_digest_v1()
        }
    }

    /// Canonical schema-v1 digest of the complete executable policy semantics.
    ///
    /// This method and its golden vector are retained when later schemas are
    /// introduced; a new schema must use a separate encoder rather than alter
    /// the version-1 preimage.
    ///
    /// # Errors
    /// Returns a [`NativePolicyError`] instead of assigning an identity to an
    /// invalid or schema-incompatible policy.
    pub fn canonical_digest_v1(&self) -> Result<DigestV1, NativePolicyError> {
        Ok(DigestV1::compute(
            DigestDomain::PolicySnapshot,
            &self.canonical_preimage_v1()?,
        ))
    }

    /// Canonical schema-v2 digest of the complete executable policy semantics.
    ///
    /// # Errors
    /// Returns a [`NativePolicyError`] instead of assigning a v2 identity to a
    /// legacy or invalid snapshot.
    pub fn canonical_digest_v2(&self) -> Result<DigestV1, NativePolicyError> {
        Ok(DigestV1::compute(
            DigestDomain::PolicySnapshot,
            &self.canonical_preimage_v2()?,
        ))
    }

    fn canonical_preimage_v1(&self) -> Result<Vec<u8>, NativePolicyError> {
        if self.motion_envelope_v2.is_some() {
            return Err(NativePolicyError::MotionEnvelopeNotRepresentableInV1);
        }
        self.validate()?;

        let mut rules: Vec<&PhaseRuleV1> = self.phase_rules.iter().collect();
        rules.sort_by(|a, b| a.phase.cmp(&b.phase));

        let mut writer = CborWriter::new();
        writer.array_header(18);
        writer.uint(NATIVE_POLICY_DIGEST_SCHEMA_V1);
        writer.int(i64::from(self.max_component_mm_s));
        writer.int(i64::from(self.max_speed_mm_s));
        writer.uint(u64::from(self.max_output_validity_ms));
        writer.uint(u64::from(self.min_useful_validity_ms));
        writer.uint(u64::from(self.publication_safety_margin_ms));
        writer.uint(u64::from(self.source_freshness_cap_ms));
        writer.uint(u64::from(self.state_freshness_cap_ms));
        writer.uint(u64::from(self.ncp_validity_cap_ms));
        writer.uint(u64::from(self.plant_validity_cap_ms));
        writer.uint(u64::from(self.nominal_update_ms));
        writer.int(self.tracking_error_mm);
        writer.int(self.uncertainty_margin_mm);
        writer.int(self.max_position_uncertainty_mm);
        writer.array_header(2);
        writer.array_header(3);
        for value in self.geofence.min_mm {
            writer.int(value);
        }
        writer.array_header(3);
        for value in self.geofence.max_mm {
            writer.int(value);
        }
        writer.uint(u64::from(self.duty_window_ms));
        writer.uint(u64::from(self.max_active_ms_in_window));
        let rule_count =
            u64::try_from(rules.len()).map_err(|_| NativePolicyError::TooManyPhaseRules)?;
        writer.array_header(rule_count);
        for rule in rules {
            let mut action_tags = rule
                .allowed
                .iter()
                .copied()
                .map(native_policy_action_tag_v1)
                .collect::<Result<Vec<_>, NativePolicyError>>()?;
            action_tags.sort_unstable();
            writer.array_header(2);
            writer.text(&rule.phase);
            let action_count = u64::try_from(action_tags.len())
                .map_err(|_| NativePolicyError::TooManyPhaseActions)?;
            writer.array_header(action_count);
            for tag in action_tags {
                writer.uint(tag);
            }
        }

        Ok(writer.into_bytes())
    }

    fn canonical_preimage_v2(&self) -> Result<Vec<u8>, NativePolicyError> {
        self.validate_for_evaluation()?;
        let motion = self
            .motion_envelope_v2
            .as_ref()
            .ok_or(NativePolicyError::MotionEnvelopeV2Required)?;

        let mut rules: Vec<&PhaseRuleV1> = self.phase_rules.iter().collect();
        rules.sort_by(|a, b| a.phase.cmp(&b.phase));
        let mut plant_mode_rules: Vec<&PlantModeRuleV2> = motion.plant_mode_rules.iter().collect();
        plant_mode_rules.sort_by(|a, b| a.plant_mode.cmp(&b.plant_mode));

        let mut writer = CborWriter::new();
        writer.array_header(19);
        writer.uint(NATIVE_POLICY_DIGEST_SCHEMA_V2);
        writer.int(i64::from(self.max_component_mm_s));
        writer.int(i64::from(self.max_speed_mm_s));
        writer.uint(u64::from(self.max_output_validity_ms));
        writer.uint(u64::from(self.min_useful_validity_ms));
        writer.uint(u64::from(self.publication_safety_margin_ms));
        writer.uint(u64::from(self.source_freshness_cap_ms));
        writer.uint(u64::from(self.state_freshness_cap_ms));
        writer.uint(u64::from(self.ncp_validity_cap_ms));
        writer.uint(u64::from(self.plant_validity_cap_ms));
        writer.uint(u64::from(self.nominal_update_ms));
        writer.int(self.tracking_error_mm);
        writer.int(self.uncertainty_margin_mm);
        writer.int(self.max_position_uncertainty_mm);
        writer.array_header(2);
        writer.array_header(3);
        for value in self.geofence.min_mm {
            writer.int(value);
        }
        writer.array_header(3);
        for value in self.geofence.max_mm {
            writer.int(value);
        }
        writer.uint(u64::from(self.duty_window_ms));
        writer.uint(u64::from(self.max_active_ms_in_window));
        writer.array_header(6);
        writer.text(motion.local_ned_frame_id.as_str());
        writer.uint(u64::from(motion.max_linear_accel_mm_s2));
        writer.uint(u64::from(motion.max_linear_slew_mm_s2));
        writer.uint(u64::from(motion.max_continuous_motion_ms));
        writer.uint(u64::from(motion.minimum_hold_between_bursts_ms));
        let plant_mode_rule_count = u64::try_from(plant_mode_rules.len())
            .map_err(|_| NativePolicyError::TooManyPlantModeRules)?;
        writer.array_header(plant_mode_rule_count);
        for rule in plant_mode_rules {
            let mut action_tags = rule
                .allowed
                .iter()
                .copied()
                .map(native_policy_action_tag_v1)
                .collect::<Result<Vec<_>, NativePolicyError>>()?;
            action_tags.sort_unstable();
            writer.array_header(2);
            writer.text(rule.plant_mode.as_str());
            let action_count = u64::try_from(action_tags.len())
                .map_err(|_| NativePolicyError::TooManyPlantModeActions)?;
            writer.array_header(action_count);
            for tag in action_tags {
                writer.uint(tag);
            }
        }
        let rule_count =
            u64::try_from(rules.len()).map_err(|_| NativePolicyError::TooManyPhaseRules)?;
        writer.array_header(rule_count);
        for rule in rules {
            let mut action_tags = rule
                .allowed
                .iter()
                .copied()
                .map(native_policy_action_tag_v1)
                .collect::<Result<Vec<_>, NativePolicyError>>()?;
            action_tags.sort_unstable();
            writer.array_header(2);
            writer.text(&rule.phase);
            let action_count = u64::try_from(action_tags.len())
                .map_err(|_| NativePolicyError::TooManyPhaseActions)?;
            writer.array_header(action_count);
            for tag in action_tags {
                writer.uint(tag);
            }
        }

        Ok(writer.into_bytes())
    }

    /// The v2 locally admitted motion envelope, when this is a v2 snapshot.
    #[must_use]
    pub const fn motion_envelope_v2(&self) -> Option<&LocallyAdmittedMotionEnvelopeV2> {
        self.motion_envelope_v2.as_ref()
    }

    /// Whether `class` is permitted in `phase`. An unknown phase denies (no rule).
    #[must_use]
    pub(crate) fn phase_permits(&self, phase: &str, class: ActionClassV1) -> bool {
        self.phase_rules
            .iter()
            .find(|r| r.phase == phase)
            .is_some_and(|r| r.allowed.contains(&class))
    }
}

const fn native_policy_action_tag_v1(action: ActionClassV1) -> Result<u64, NativePolicyError> {
    match action {
        ActionClassV1::Hold => Ok(1),
        ActionClassV1::VelocityLocalNed => Ok(2),
        _ => Err(NativePolicyError::UnsupportedActionClass),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::fmt::Write;
    use haldir_contracts::cbor::CanonicalValue;

    fn snapshot() -> NativePolicySnapshot {
        NativePolicySnapshot {
            max_component_mm_s: 3_000,
            max_speed_mm_s: 4_000,
            max_output_validity_ms: 500,
            min_useful_validity_ms: 50,
            publication_safety_margin_ms: 20,
            source_freshness_cap_ms: 200,
            state_freshness_cap_ms: 200,
            ncp_validity_cap_ms: 1_000,
            plant_validity_cap_ms: 1_000,
            nominal_update_ms: 20,
            tracking_error_mm: 50,
            uncertainty_margin_mm: 50,
            max_position_uncertainty_mm: 500,
            geofence: GeofenceBoxV1 {
                min_mm: [-100_000; 3],
                max_mm: [100_000; 3],
            },
            duty_window_ms: 10_000,
            max_active_ms_in_window: 6_000,
            motion_envelope_v2: Some(LocallyAdmittedMotionEnvelopeV2 {
                local_ned_frame_id: BoundedAscii::new("map").unwrap(),
                max_linear_accel_mm_s2: 1_000_000,
                max_linear_slew_mm_s2: 100_000,
                max_continuous_motion_ms: 60_000,
                minimum_hold_between_bursts_ms: 0,
                plant_mode_rules: vec![PlantModeRuleV2 {
                    plant_mode: AsciiId::new("NOMINAL").unwrap(),
                    allowed: vec![ActionClassV1::Hold, ActionClassV1::VelocityLocalNed],
                }],
            }),
            phase_rules: vec![
                PhaseRuleV1 {
                    phase: "INSPECTION".to_owned(),
                    allowed: vec![ActionClassV1::Hold, ActionClassV1::VelocityLocalNed],
                },
                PhaseRuleV1 {
                    phase: "RETURN".to_owned(),
                    allowed: vec![ActionClassV1::Hold],
                },
            ],
        }
    }

    fn changed(mutator: impl FnOnce(&mut NativePolicySnapshot)) -> DigestV1 {
        let mut policy = snapshot();
        mutator(&mut policy);
        policy.canonical_digest().unwrap()
    }

    fn lowercase_hex(bytes: &[u8]) -> String {
        let mut encoded = String::with_capacity(bytes.len().saturating_mul(2));
        for byte in bytes {
            write!(&mut encoded, "{byte:02x}").unwrap();
        }
        encoded
    }

    #[test]
    fn schema_v1_policy_preimage_and_digest_remain_the_original_golden_vector() {
        let mut policy = snapshot();
        policy.motion_envelope_v2 = None;
        let preimage = policy.canonical_preimage_v1().unwrap();
        let digest = policy.canonical_digest_v1().unwrap();
        let preimage_hex = lowercase_hex(&preimage);
        let digest_hex = lowercase_hex(&digest.value);

        assert_eq!(NATIVE_POLICY_DIGEST_SCHEMA_V1, 1);
        assert_eq!(policy.canonical_digest().unwrap(), digest);
        assert_eq!(
            (preimage_hex.as_str(), digest_hex.as_str()),
            (
                "9201190bb8190fa01901f418321418c818c81903e81903e814183218321901f482833a0001869f3a0001869f3a0001869f831a000186a01a000186a01a000186a019271019177082826a494e5350454354494f4e820102826652455455524e8101",
                "7bb0aea494dbc4bdfad621dd5ee911ce6dde1213c8be8cd1e16932c2ced4d9bd",
            )
        );
    }

    #[test]
    fn schema_v2_policy_preimage_and_digest_match_golden_vector() {
        let policy = snapshot();
        let preimage = policy.canonical_preimage_v2().unwrap();
        let digest = policy.canonical_digest_v2().unwrap();

        assert_eq!(NATIVE_POLICY_DIGEST_SCHEMA_V2, 2);
        assert_eq!(policy.canonical_digest().unwrap(), digest);
        assert_eq!(
            (
                lowercase_hex(&preimage).as_str(),
                lowercase_hex(&digest.value).as_str(),
            ),
            (
                "9302190bb8190fa01901f418321418c818c81903e81903e814183218321901f482833a0001869f3a0001869f3a0001869f831a000186a01a000186a01a000186a019271019177086636d61701a000f42401a000186a019ea60008182674e4f4d494e414c82010282826a494e5350454354494f4e820102826652455455524e8101",
                "3944fdda8360fe2bd6d53abe700698fd2e24192baf9cbeaf70212e98dda447a1",
            )
        );
    }

    #[test]
    fn policy_errors_have_stable_reason_codes_and_standard_error_display() {
        for (error, reason) in [
            (
                NativePolicyError::NonPositiveVelocityBound,
                "NATIVE_POLICY_NON_POSITIVE_VELOCITY_BOUND",
            ),
            (
                NativePolicyError::IncoherentValidity,
                "NATIVE_POLICY_INCOHERENT_VALIDITY",
            ),
            (
                NativePolicyError::ZeroNominalUpdate,
                "NATIVE_POLICY_ZERO_NOMINAL_UPDATE",
            ),
            (
                NativePolicyError::NonPositiveMotionBound,
                "NATIVE_POLICY_NON_POSITIVE_MOTION_BOUND",
            ),
            (
                NativePolicyError::MotionEnvelopeV2Required,
                "NATIVE_POLICY_MOTION_ENVELOPE_V2_REQUIRED",
            ),
            (
                NativePolicyError::MotionEnvelopeNotRepresentableInV1,
                "NATIVE_POLICY_MOTION_ENVELOPE_NOT_REPRESENTABLE_IN_V1",
            ),
            (
                NativePolicyError::NegativeSafetyDistance,
                "NATIVE_POLICY_NEGATIVE_SAFETY_DISTANCE",
            ),
            (
                NativePolicyError::UnusableGeofence,
                "NATIVE_POLICY_UNUSABLE_GEOFENCE",
            ),
            (
                NativePolicyError::IncoherentDutyLimit,
                "NATIVE_POLICY_INCOHERENT_DUTY_LIMIT",
            ),
            (
                NativePolicyError::TooManyPhaseRules,
                "NATIVE_POLICY_TOO_MANY_PHASE_RULES",
            ),
            (
                NativePolicyError::InvalidPhase,
                "NATIVE_POLICY_INVALID_PHASE",
            ),
            (
                NativePolicyError::DuplicatePhase,
                "NATIVE_POLICY_DUPLICATE_PHASE",
            ),
            (
                NativePolicyError::TooManyPhaseActions,
                "NATIVE_POLICY_TOO_MANY_PHASE_ACTIONS",
            ),
            (
                NativePolicyError::DuplicatePhaseAction,
                "NATIVE_POLICY_DUPLICATE_PHASE_ACTION",
            ),
            (
                NativePolicyError::UnsupportedActionClass,
                "NATIVE_POLICY_UNSUPPORTED_ACTION_CLASS",
            ),
            (
                NativePolicyError::TooManyPlantModeRules,
                "NATIVE_POLICY_TOO_MANY_PLANT_MODE_RULES",
            ),
            (
                NativePolicyError::DuplicatePlantMode,
                "NATIVE_POLICY_DUPLICATE_PLANT_MODE",
            ),
            (
                NativePolicyError::TooManyPlantModeActions,
                "NATIVE_POLICY_TOO_MANY_PLANT_MODE_ACTIONS",
            ),
            (
                NativePolicyError::DuplicatePlantModeAction,
                "NATIVE_POLICY_DUPLICATE_PLANT_MODE_ACTION",
            ),
        ] {
            let standard_error: &dyn std::error::Error = &error;
            assert_eq!(error.reason_code(), reason);
            assert_eq!(standard_error.to_string(), reason);
        }
    }

    #[test]
    fn schema_v1_action_tags_match_the_canonical_action_contract() {
        for action in [ActionClassV1::Hold, ActionClassV1::VelocityLocalNed] {
            let mut contract = CborWriter::new();
            action.encode(&mut contract);
            let mut policy_schema = CborWriter::new();
            policy_schema.uint(native_policy_action_tag_v1(action).unwrap());

            assert_eq!(policy_schema.into_bytes(), contract.into_bytes());
        }
    }

    #[test]
    fn validated_policy_retains_the_exact_snapshot_and_cached_identity() {
        let snapshot = snapshot();
        let digest = snapshot.canonical_digest().unwrap();
        let validated = ValidatedNativePolicy::new(snapshot.clone()).unwrap();

        assert_eq!(
            (validated.snapshot(), validated.canonical_digest()),
            (&snapshot, digest)
        );
    }

    #[test]
    fn canonical_digest_covers_every_executable_field() {
        let original = snapshot().canonical_digest().unwrap();

        assert_ne!(original, changed(|p| p.max_component_mm_s += 1));
        assert_ne!(original, changed(|p| p.max_speed_mm_s += 1));
        assert_ne!(original, changed(|p| p.max_output_validity_ms += 1));
        assert_ne!(original, changed(|p| p.min_useful_validity_ms += 1));
        assert_ne!(original, changed(|p| p.publication_safety_margin_ms += 1));
        assert_ne!(original, changed(|p| p.source_freshness_cap_ms += 1));
        assert_ne!(original, changed(|p| p.state_freshness_cap_ms += 1));
        assert_ne!(original, changed(|p| p.ncp_validity_cap_ms += 1));
        assert_ne!(original, changed(|p| p.plant_validity_cap_ms += 1));
        assert_ne!(original, changed(|p| p.nominal_update_ms += 1));
        assert_ne!(original, changed(|p| p.tracking_error_mm += 1));
        assert_ne!(original, changed(|p| p.uncertainty_margin_mm += 1));
        assert_ne!(original, changed(|p| p.max_position_uncertainty_mm += 1));
        assert_ne!(original, changed(|p| p.geofence.min_mm[0] -= 1));
        assert_ne!(original, changed(|p| p.geofence.max_mm[2] += 1));
        assert_ne!(original, changed(|p| p.duty_window_ms += 1));
        assert_ne!(original, changed(|p| p.max_active_ms_in_window += 1));
        assert_ne!(
            original,
            changed(|p| {
                p.motion_envelope_v2.as_mut().unwrap().local_ned_frame_id =
                    BoundedAscii::new("local_ned").unwrap();
            })
        );
        assert_ne!(
            original,
            changed(|p| {
                p.motion_envelope_v2
                    .as_mut()
                    .unwrap()
                    .max_linear_accel_mm_s2 += 1;
            })
        );
        assert_ne!(
            original,
            changed(|p| {
                p.motion_envelope_v2.as_mut().unwrap().max_linear_slew_mm_s2 += 1;
            })
        );
        assert_ne!(
            original,
            changed(|p| {
                p.motion_envelope_v2
                    .as_mut()
                    .unwrap()
                    .max_continuous_motion_ms += 1;
            })
        );
        assert_ne!(
            original,
            changed(|p| {
                p.motion_envelope_v2
                    .as_mut()
                    .unwrap()
                    .minimum_hold_between_bursts_ms += 1;
            })
        );
        assert_ne!(
            original,
            changed(|p| {
                p.motion_envelope_v2.as_mut().unwrap().plant_mode_rules[0].plant_mode =
                    AsciiId::new("AUTONOMOUS").unwrap();
            })
        );
        assert_ne!(
            original,
            changed(|p| {
                p.motion_envelope_v2.as_mut().unwrap().plant_mode_rules[0].allowed =
                    vec![ActionClassV1::Hold];
            })
        );
        assert_ne!(
            original,
            changed(|p| p.phase_rules[0].phase = "SURVEY".to_owned())
        );
        assert_ne!(
            original,
            changed(|p| {
                p.phase_rules[0].allowed = vec![ActionClassV1::VelocityLocalNed];
            })
        );
    }

    #[test]
    fn digest_canonicalizes_semantically_unordered_sets() {
        let original = snapshot().canonical_digest().unwrap();
        let mut reordered = snapshot();
        reordered.phase_rules.reverse();
        reordered.phase_rules[1].allowed.reverse();
        assert_eq!(reordered.canonical_digest().unwrap(), original);

        reordered
            .motion_envelope_v2
            .as_mut()
            .unwrap()
            .plant_mode_rules
            .push(PlantModeRuleV2 {
                plant_mode: AsciiId::new("DEGRADED").unwrap(),
                allowed: vec![ActionClassV1::Hold],
            });
        let with_second_mode = reordered.canonical_digest().unwrap();
        let motion = reordered.motion_envelope_v2.as_mut().unwrap();
        motion.plant_mode_rules.reverse();
        motion.plant_mode_rules[1].allowed.reverse();

        assert_ne!(with_second_mode, original);
        assert_eq!(reordered.canonical_digest().unwrap(), with_second_mode);
    }

    #[test]
    fn validation_rejects_unsafe_and_ambiguous_shapes() {
        let mut policy = snapshot();
        policy.max_component_mm_s = 0;
        assert_eq!(
            policy.validate(),
            Err(NativePolicyError::NonPositiveVelocityBound)
        );

        let mut policy = snapshot();
        policy.max_output_validity_ms = 69;
        assert_eq!(
            policy.validate(),
            Err(NativePolicyError::IncoherentValidity)
        );

        let mut policy = snapshot();
        policy.nominal_update_ms = 0;
        assert_eq!(policy.validate(), Err(NativePolicyError::ZeroNominalUpdate));

        for clear_bound in [
            |motion: &mut LocallyAdmittedMotionEnvelopeV2| motion.max_linear_accel_mm_s2 = 0,
            |motion: &mut LocallyAdmittedMotionEnvelopeV2| motion.max_linear_slew_mm_s2 = 0,
            |motion: &mut LocallyAdmittedMotionEnvelopeV2| motion.max_continuous_motion_ms = 0,
        ] {
            let mut policy = snapshot();
            clear_bound(policy.motion_envelope_v2.as_mut().unwrap());
            assert_eq!(
                policy.validate(),
                Err(NativePolicyError::NonPositiveMotionBound)
            );
        }

        let mut policy = snapshot();
        policy.motion_envelope_v2.as_mut().unwrap().plant_mode_rules = (0..=MAX_PLANT_MODE_RULES)
            .map(|index| PlantModeRuleV2 {
                plant_mode: AsciiId::new(&format!("MODE_{index}")).unwrap(),
                allowed: Vec::new(),
            })
            .collect();
        assert_eq!(
            policy.validate(),
            Err(NativePolicyError::TooManyPlantModeRules)
        );

        let mut policy = snapshot();
        let duplicate = policy.motion_envelope_v2.as_ref().unwrap().plant_mode_rules[0].clone();
        policy
            .motion_envelope_v2
            .as_mut()
            .unwrap()
            .plant_mode_rules
            .push(duplicate);
        assert_eq!(
            policy.validate(),
            Err(NativePolicyError::DuplicatePlantMode)
        );

        let mut policy = snapshot();
        policy.motion_envelope_v2.as_mut().unwrap().plant_mode_rules[0].allowed =
            vec![ActionClassV1::Hold; MAX_ACTIONS_PER_PLANT_MODE + 1];
        assert_eq!(
            policy.validate(),
            Err(NativePolicyError::TooManyPlantModeActions)
        );

        let mut policy = snapshot();
        policy.motion_envelope_v2.as_mut().unwrap().plant_mode_rules[0].allowed =
            vec![ActionClassV1::Hold, ActionClassV1::Hold];
        assert_eq!(
            policy.validate(),
            Err(NativePolicyError::DuplicatePlantModeAction)
        );

        let mut policy = snapshot();
        policy.uncertainty_margin_mm = -1;
        assert_eq!(
            policy.validate(),
            Err(NativePolicyError::NegativeSafetyDistance)
        );

        let mut policy = snapshot();
        policy.geofence.max_mm[0] = policy.geofence.min_mm[0] + 201;
        assert_eq!(policy.validate(), Err(NativePolicyError::UnusableGeofence));

        let mut policy = snapshot();
        policy.max_active_ms_in_window = policy.duty_window_ms + 1;
        assert_eq!(
            policy.validate(),
            Err(NativePolicyError::IncoherentDutyLimit)
        );

        let mut policy = snapshot();
        policy.phase_rules = (0..=MAX_PHASE_RULES)
            .map(|index| PhaseRuleV1 {
                phase: format!("P{index}"),
                allowed: Vec::new(),
            })
            .collect();
        assert_eq!(policy.validate(), Err(NativePolicyError::TooManyPhaseRules));

        let mut policy = snapshot();
        policy.phase_rules[0].phase = "NOT A PHASE".to_owned();
        assert_eq!(policy.validate(), Err(NativePolicyError::InvalidPhase));

        let mut policy = snapshot();
        policy.phase_rules[1].phase = policy.phase_rules[0].phase.clone();
        assert_eq!(policy.validate(), Err(NativePolicyError::DuplicatePhase));

        let mut policy = snapshot();
        policy.phase_rules[0].allowed = vec![ActionClassV1::Hold; MAX_ACTIONS_PER_PHASE + 1];
        assert_eq!(
            policy.validate(),
            Err(NativePolicyError::TooManyPhaseActions)
        );

        let mut policy = snapshot();
        policy.phase_rules[0].allowed = vec![
            ActionClassV1::VelocityLocalNed,
            ActionClassV1::VelocityLocalNed,
        ];
        assert_eq!(
            policy.validate(),
            Err(NativePolicyError::DuplicatePhaseAction)
        );
    }

    #[test]
    fn legacy_v1_identity_never_silently_acquires_v2_evaluation_semantics() {
        let mut legacy = snapshot();
        legacy.motion_envelope_v2 = None;

        assert!(legacy.canonical_digest_v1().is_ok());
        assert_eq!(legacy.canonical_digest(), legacy.canonical_digest_v1());
        assert_eq!(
            legacy.validate_for_evaluation(),
            Err(NativePolicyError::MotionEnvelopeV2Required)
        );
        assert_eq!(
            ValidatedNativePolicy::new(legacy).unwrap_err(),
            NativePolicyError::MotionEnvelopeV2Required
        );

        let v2 = snapshot();
        assert_eq!(
            v2.canonical_digest_v1(),
            Err(NativePolicyError::MotionEnvelopeNotRepresentableInV1)
        );
    }
}
