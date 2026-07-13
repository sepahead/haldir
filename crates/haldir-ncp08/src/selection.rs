//! Closed selection between Haldir's modeled and exact pinned NCP adapters.
//!
//! Gate stores this type rather than an open adapter trait object. That keeps
//! adapter selection explicit without introducing an arbitrary frame-construction
//! injection seam into the authorization runtime.

use crate::{
    AclOnlyAdapter, ExactNcpCommandFrame, GateCommandBuildInputV1, NcpAdapterError,
    NcpCommandAdapter, NcpCompatibilityRecordV1,
};

#[cfg(feature = "real-ncp")]
use crate::RealNcp08Adapter;

/// Observable wire profile selected for one Gate runtime.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NcpCommandWireProfile {
    /// Dependency-light deterministic semantic bytes used by the P0 model.
    ModeledP0,
    /// Upstream-validated compact NCP v0.8.0 JSON.
    ExactNcpV0_8Json,
}

#[derive(Debug, Clone)]
enum SelectedAdapterInner {
    Modeled(AclOnlyAdapter),
    #[cfg(feature = "real-ncp")]
    Exact(RealNcp08Adapter),
}

/// One closed, pinned command-adapter selection.
///
/// The exact constructor exists only when the `real-ncp` feature compiles the
/// immutable upstream adapter. There is no constructor accepting caller-defined
/// adapter implementations.
#[derive(Debug, Clone)]
pub struct SelectedNcpCommandAdapter {
    inner: SelectedAdapterInner,
}

impl SelectedNcpCommandAdapter {
    /// Select deterministic modeled P0 bytes.
    #[must_use]
    pub fn modeled_p0() -> Self {
        Self {
            inner: SelectedAdapterInner::Modeled(AclOnlyAdapter::new()),
        }
    }

    /// Select upstream-validated exact NCP v0.8.0 JSON.
    #[cfg(feature = "real-ncp")]
    #[must_use]
    pub fn exact_ncp_v0_8_json() -> Self {
        Self {
            inner: SelectedAdapterInner::Exact(RealNcp08Adapter::new()),
        }
    }

    /// Report the selected wire profile without exposing the inner adapter.
    #[must_use]
    pub const fn wire_profile(&self) -> NcpCommandWireProfile {
        match self.inner {
            SelectedAdapterInner::Modeled(_) => NcpCommandWireProfile::ModeledP0,
            #[cfg(feature = "real-ncp")]
            SelectedAdapterInner::Exact(_) => NcpCommandWireProfile::ExactNcpV0_8Json,
        }
    }
}

impl NcpCommandAdapter for SelectedNcpCommandAdapter {
    fn compatibility(&self) -> &NcpCompatibilityRecordV1 {
        match &self.inner {
            SelectedAdapterInner::Modeled(adapter) => adapter.compatibility(),
            #[cfg(feature = "real-ncp")]
            SelectedAdapterInner::Exact(adapter) => adapter.compatibility(),
        }
    }

    fn build_command(
        &self,
        input: &GateCommandBuildInputV1,
    ) -> Result<ExactNcpCommandFrame, NcpAdapterError> {
        match &self.inner {
            SelectedAdapterInner::Modeled(adapter) => adapter.build_command(input),
            #[cfg(feature = "real-ncp")]
            SelectedAdapterInner::Exact(adapter) => adapter.build_command(input),
        }
    }

    fn validate_exact_command(
        &self,
        frame: &ExactNcpCommandFrame,
        expected: &GateCommandBuildInputV1,
    ) -> Result<(), NcpAdapterError> {
        match &self.inner {
            SelectedAdapterInner::Modeled(adapter) => {
                adapter.validate_exact_command(frame, expected)
            }
            #[cfg(feature = "real-ncp")]
            SelectedAdapterInner::Exact(adapter) => adapter.validate_exact_command(frame, expected),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::num::{NonZeroU32, NonZeroU64};
    use haldir_contracts::action::RequestedActionV1;
    use haldir_contracts::ids::{DecisionId, GateOutputEpoch, OutputSeq, SourceSeq};
    use haldir_contracts::scalar::{AsciiId, BoundedAscii, CanonicalUuidV4String};
    use haldir_contracts::session::{NcpSessionIdentityV1, NcpSourceRefV1, NcpStreamPositionV1};

    fn input() -> GateCommandBuildInputV1 {
        GateCommandBuildInputV1 {
            decision_id: DecisionId::new([1; 16]),
            session: NcpSessionIdentityV1 {
                session_id: AsciiId::new("sess-1").unwrap(),
                generation: CanonicalUuidV4String::from_random_bytes([1; 16]),
            },
            stream: NcpStreamPositionV1 {
                epoch: GateOutputEpoch::new(CanonicalUuidV4String::from_random_bytes([2; 16])),
                seq: OutputSeq::new(NonZeroU64::new(1).unwrap()),
            },
            source: NcpSourceRefV1 {
                source_key: BoundedAscii::new("veh/uav-1/state/pose").unwrap(),
                stream_epoch: CanonicalUuidV4String::from_random_bytes([3; 16]),
                stream_seq: SourceSeq::new(NonZeroU64::new(7).unwrap()),
            },
            frame_id: BoundedAscii::new("map").unwrap(),
            source_t_ns: 1_000_000_000,
            gate_t_ns: 2_000_000_000,
            action: RequestedActionV1::Hold {
                requested_validity_ms: NonZeroU32::new(200).unwrap(),
            },
            effective_validity_ms: 200,
        }
    }

    #[test]
    fn modeled_constructor_selects_and_delegates_to_the_modeled_profile() {
        let adapter = SelectedNcpCommandAdapter::modeled_p0();
        assert_eq!(adapter.wire_profile(), NcpCommandWireProfile::ModeledP0);
        let input = input();
        let frame = adapter.build_command(&input).unwrap();
        adapter.validate_exact_command(&frame, &input).unwrap();
        assert!(!frame.bytes().starts_with(b"{"));
    }

    #[cfg(feature = "real-ncp")]
    #[test]
    fn exact_constructor_selects_and_delegates_to_upstream_json() {
        let adapter = SelectedNcpCommandAdapter::exact_ncp_v0_8_json();
        let modeled = SelectedNcpCommandAdapter::modeled_p0();
        assert_eq!(
            adapter.wire_profile(),
            NcpCommandWireProfile::ExactNcpV0_8Json
        );
        assert_eq!(adapter.compatibility(), modeled.compatibility());
        let input = input();
        let frame = adapter.build_command(&input).unwrap();
        adapter.validate_exact_command(&frame, &input).unwrap();
        let decoded = ncp_core::decode_validated::<ncp_core::CommandFrame>(frame.bytes()).unwrap();
        assert_eq!(decoded.kind, "command_frame");
        assert_eq!(decoded.session_id, "sess-1");
    }

    #[cfg(feature = "real-ncp")]
    #[test]
    fn selected_profiles_reject_each_others_bytes() {
        let input = input();
        let modeled = SelectedNcpCommandAdapter::modeled_p0();
        let exact = SelectedNcpCommandAdapter::exact_ncp_v0_8_json();
        let modeled_frame = modeled.build_command(&input).unwrap();
        let exact_frame = exact.build_command(&input).unwrap();

        assert_eq!(
            modeled.validate_exact_command(&exact_frame, &input),
            Err(NcpAdapterError::ValidatorMismatch)
        );
        assert_eq!(
            exact.validate_exact_command(&modeled_frame, &input),
            Err(NcpAdapterError::ValidatorMismatch)
        );
    }
}
