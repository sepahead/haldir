//! `DecisionReceiptV1` and its stable reason/outcome/stage vocabularies.
//!
//! A Gate-signed receipt records only the stage Gate itself observed
//! (punch-list H2); post-publish stages such as `CREBAIN_ACCEPTED` or
//! `ADAPTER_APPLIED` are asserted by other producers, never inside the Gate
//! receipt.

use crate::digest::DigestV1;
use crate::ids::{
    ControllerId, DecisionId, GateBootId, GateId, MissionId, MissionLeaseId, VehicleId,
};
use crate::scalar::BoundedVec;
use crate::session::{
    HaldirIntentPositionV1, NcpSessionIdentityV1, NcpSourceRefV1, NcpStreamPositionV1,
};

tagged_enum! {
    /// The top-level decision outcome.
    pub enum DecisionOutcomeV1 {
        Allow = 1 => "ALLOW",
        Deny = 2 => "DENY",
        Error = 3 => "ERROR",
    }
}

tagged_enum! {
    /// Stable machine reason codes for a decision. Allow codes are positive
    /// outcomes; `Deny*` are refusals; `Error*` are internal faults.
    pub enum DecisionReasonCodeV1 {
        AllowPublished = 1 => "ALLOW_PUBLISHED",
        AllowNotPublishedOverload = 2 => "ALLOW_NOT_PUBLISHED_OVERLOAD",
        DenyOversize = 10 => "DENY_OVERSIZE",
        DenyOverload = 11 => "DENY_OVERLOAD",
        DenyMalformed = 12 => "DENY_MALFORMED",
        DenyWrongActualKey = 13 => "DENY_WRONG_ACTUAL_KEY",
        DenySignatureInvalid = 14 => "DENY_SIGNATURE_INVALID",
        DenyNonCanonical = 15 => "DENY_NONCANONICAL",
        DenyWrongRole = 16 => "DENY_WRONG_ROLE",
        DenyKeyRevoked = 17 => "DENY_KEY_REVOKED",
        DenyGateBootMismatch = 18 => "DENY_GATE_BOOT_MISMATCH",
        DenySessionStale = 19 => "DENY_SESSION_STALE",
        DenyScopeMismatch = 20 => "DENY_SCOPE_MISMATCH",
        DenyLeaseAbsent = 21 => "DENY_LEASE_ABSENT",
        DenyLeaseExpired = 22 => "DENY_LEASE_EXPIRED",
        DenyLeaseRevoked = 23 => "DENY_LEASE_REVOKED",
        DenyAdmissionRevoked = 24 => "DENY_ADMISSION_REVOKED",
        DenyAdmissionMismatch = 25 => "DENY_ADMISSION_MISMATCH",
        DenyBackendMismatch = 26 => "DENY_BACKEND_MISMATCH",
        DenyIntentReplay = 27 => "DENY_INTENT_REPLAY",
        DenyRetiredEpoch = 28 => "DENY_RETIRED_EPOCH",
        DenySourceUnknown = 29 => "DENY_SOURCE_UNKNOWN",
        DenySourceStale = 30 => "DENY_SOURCE_STALE",
        DenyStateUnavailable = 31 => "DENY_STATE_UNAVAILABLE",
        DenyStateStale = 32 => "DENY_STATE_STALE",
        DenyActionShape = 33 => "DENY_ACTION_SHAPE",
        DenyCommandRange = 34 => "DENY_COMMAND_RANGE",
        DenyNormBound = 35 => "DENY_NORM_BOUND",
        DenySlew = 36 => "DENY_SLEW",
        DenyDutyLimit = 37 => "DENY_DUTY_LIMIT",
        DenyPhaseRule = 38 => "DENY_PHASE_RULE",
        DenyGeofence = 39 => "DENY_GEOFENCE",
        DenyUncertainty = 40 => "DENY_UNCERTAINTY",
        DenyValidityTooShort = 41 => "DENY_VALIDITY_TOO_SHORT",
        DenyPolicyDiagnostic = 42 => "DENY_POLICY_DIAGNOSTIC",
        DenyNoPublicationAuthority = 43 => "DENY_NO_PUBLICATION_AUTHORITY",
        DenyArithmeticOverflow = 44 => "DENY_ARITHMETIC_OVERFLOW",
        ErrorInternalFault = 90 => "ERROR_INTERNAL_FAULT",
    }
}

impl DecisionReasonCodeV1 {
    /// Whether this reason is a hard deny that must take precedence over permits
    /// and be retained first when the bounded reason vector overflows (H6/P4).
    #[must_use]
    pub const fn is_hard_deny(self) -> bool {
        !matches!(self, Self::AllowPublished | Self::AllowNotPublishedOverload)
    }
}

tagged_enum! {
    /// Evidence-stage marker. Appended (append-only) keyed by `decision_id`.
    /// `UnknownAfterPublish` is used when a crash prevents determining later stages
    /// (spec F4 / punch-list H2).
    pub enum PublishStageV1 {
        DecidedDeny = 1 => "DECIDED_DENY",
        DecidedAllow = 2 => "DECIDED_ALLOW",
        OutputPrepared = 3 => "OUTPUT_PREPARED",
        PublishCalled = 4 => "PUBLISH_CALLED",
        PublishReturnedOk = 5 => "PUBLISH_RETURNED_OK",
        PublishReturnedError = 6 => "PUBLISH_RETURNED_ERROR",
        CrebainReceived = 7 => "CREBAIN_RECEIVED",
        CrebainAccepted = 8 => "CREBAIN_ACCEPTED",
        CrebainRejected = 9 => "CREBAIN_REJECTED",
        AdapterApplied = 10 => "ADAPTER_APPLIED",
        AdapterFailed = 11 => "ADAPTER_FAILED",
        PlantObserved = 12 => "PLANT_OBSERVED",
        Expired = 13 => "EXPIRED",
        UnknownAfterPublish = 14 => "UNKNOWN_AFTER_PUBLISH",
    }
}

tagged_enum! {
    /// The relation between the requested fixed-point action and the emitted frame.
    /// Never `IDENTITY` where a decimal-to-binary conversion occurs (spec P6/H17).
    pub enum TransformationRelationV1 {
        Identity = 1 => "IDENTITY",
        FixedPointToNcpFloatV1 = 2 => "FIXED_POINT_TO_NCP_FLOAT_V1",
    }
}

canonical_struct! {
    /// A signed decision receipt (spec §DecisionReceiptV1). Optional fields are
    /// absent (not null) when a decision short-circuits early.
    pub struct DecisionReceiptV1 kind "haldir.decision_receipt" {
        req 2 decision_id: DecisionId,
        req 3 gate_id: GateId,
        req 4 gate_boot_id: GateBootId,
        req 5 vehicle_id: VehicleId,
        opt 6 mission_id: MissionId,
        req 7 ncp_session: NcpSessionIdentityV1,
        req 8 received_key_digest: DigestV1,
        req 9 raw_envelope_digest: DigestV1,
        opt 10 payload_digest: DigestV1,
        opt 11 semantic_intent_digest: DigestV1,
        opt 12 controller_id: ControllerId,
        opt 13 controller_intent_position: HaldirIntentPositionV1,
        opt 14 mission_lease_id: MissionLeaseId,
        opt 15 admission_digest: DigestV1,
        opt 16 source: NcpSourceRefV1,
        opt 17 state_snapshot_digest: DigestV1,
        req 18 policy_snapshot_digest: DigestV1,
        req 19 decision: DecisionOutcomeV1,
        req 20 reason_codes: BoundedVec<DecisionReasonCodeV1, 32>,
        opt 21 effective_validity_ms: u32,
        opt 22 gate_output_stream: NcpStreamPositionV1,
        opt 23 output_frame_digest: DigestV1,
        opt 24 transformation_relation: TransformationRelationV1,
        req 25 received_mono_ns: u64,
        req 26 decided_mono_ns: u64,
        req 27 publish_stage: PublishStageV1,
    }
}

impl crate::cbor::Validate for DecisionReceiptV1 {}
