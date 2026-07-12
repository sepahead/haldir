//! Compiled native policy parameters (all integer / fixed-point, no floats).

use haldir_contracts::action::ActionClassV1;

/// A rectangular allowed geofence region in the local frame, millimetres.
/// A point on or outside the (uncertainty/margin-shrunk) boundary denies.
#[derive(Debug, Clone)]
pub struct GeofenceBoxV1 {
    /// Inclusive lower bounds per axis (mm).
    pub min_mm: [i64; 3],
    /// Inclusive upper bounds per axis (mm).
    pub max_mm: [i64; 3],
}

/// A mission-phase rule: which action classes are permitted in a phase.
#[derive(Debug, Clone)]
pub struct PhaseRuleV1 {
    /// The Gate-owned mission phase name.
    pub phase: String,
    /// Action classes permitted in this phase.
    pub allowed: Vec<ActionClassV1>,
}

/// Immutable compiled native-policy parameters for one deployment profile.
#[derive(Debug, Clone)]
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
    /// Nominal control-update period used to scale the slew bound (ms).
    pub nominal_update_ms: u32,
    /// Conservative bounded tracking error added to the reachable set (mm).
    pub tracking_error_mm: i64,
    /// Position-uncertainty margin added to the reachable set (mm).
    pub uncertainty_margin_mm: i64,
    /// Maximum tolerated position uncertainty; above this, DENY (mm).
    pub max_position_uncertainty_mm: i64,
    /// Allowed geofence region.
    pub geofence: GeofenceBoxV1,
    /// Duty accounting window (ms).
    pub duty_window_ms: u32,
    /// Maximum aggregate non-hold command validity within the window (ms).
    pub max_active_ms_in_window: u32,
    /// Mission-phase rules.
    pub phase_rules: Vec<PhaseRuleV1>,
}

impl NativePolicySnapshot {
    /// Whether `class` is permitted in `phase`. An unknown phase denies (no rule).
    #[must_use]
    pub fn phase_permits(&self, phase: &str, class: ActionClassV1) -> bool {
        self.phase_rules
            .iter()
            .find(|r| r.phase == phase)
            .is_some_and(|r| r.allowed.contains(&class))
    }
}
