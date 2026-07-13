//! Off-by-default typed Zenoh transport over a strict mTLS client configuration.
//!
//! These integration primitives make no claim that a router ACL, certificate
//! identity, or end-to-end delivery campaign has been exercised successfully.

use std::fmt;
use std::path::Path;
use std::str::FromStr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use haldir_ncp08::ExactNcpCommandFrame;
use serde_json::Value;
use tokio::sync::mpsc;
use zenoh::bytes::Encoding;
use zenoh::config::EndPoint;
use zenoh::qos::{CongestionControl, Priority};
use zenoh::sample::{Locality, SampleKind};
use zenoh::{Config, Session};

use crate::HaldirKeys;

/// A secure-client, ingress, or publication failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecureZenohError {
    /// The explicit Zenoh configuration file could not be loaded.
    ConfigLoad,
    /// Client mode is not exact or is absent.
    ClientModeRequired,
    /// Connect endpoints are absent, malformed, or not exclusively `tls/`.
    TlsConnectRequired,
    /// A client listen endpoint was configured.
    ListenerForbidden,
    /// Multicast or gossip discovery was enabled.
    DiscoveryForbidden,
    /// Admin-space, plugin loading, or shared-memory surfaces were enabled.
    AuxiliarySurfaceForbidden,
    /// Connect timeout/exit behavior was absent or outside the bounded profile.
    ConnectPolicyRequired,
    /// CA, client certificate, or private-key path is absent.
    ClientIdentityRequired,
    /// TLS client-certificate authentication was not explicitly enabled.
    MutualTlsRequired,
    /// TLS hostname verification was not enabled.
    HostnameVerificationRequired,
    /// Certificate-expiration link closure was not enabled.
    ExpirationClosureRequired,
    /// The bounded ingress limits are zero or outside the hard profile ceiling.
    InvalidIngressLimits,
    /// Zenoh's pre-callback receive/defragmentation bounds are absent or excessive.
    InvalidTransportLimits,
    /// Exact intent-route construction failed.
    IntentRoute,
    /// The strict Zenoh session could not be opened.
    SessionOpen,
    /// Zenoh returned an error while explicitly closing the session.
    SessionClose,
    /// The exact intent subscriber could not be declared.
    Subscribe,
    /// The local Zenoh publication call returned an error.
    Publish,
    /// The prepared bytes are not an upstream-validated NCP v0.8 JSON command.
    InvalidCommandFrame,
    /// The frame's embedded session differs from the publisher's bound route.
    CommandSessionMismatch,
}

impl fmt::Display for SecureZenohError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::ConfigLoad => "failed to load the explicit Zenoh configuration",
            Self::ClientModeRequired => "Zenoh client mode is required",
            Self::TlsConnectRequired => "one or more explicit TLS connect endpoints are required",
            Self::ListenerForbidden => "Zenoh client listen endpoints are forbidden",
            Self::DiscoveryForbidden => "Zenoh multicast and gossip discovery must be disabled",
            Self::AuxiliarySurfaceForbidden => {
                "Zenoh admin-space, plugins, and shared memory must be disabled"
            }
            Self::ConnectPolicyRequired => {
                "a bounded connect timeout with exit-on-failure is required"
            }
            Self::ClientIdentityRequired => {
                "TLS CA, client certificate, and private key are required"
            }
            Self::MutualTlsRequired => "TLS client-certificate authentication is required",
            Self::HostnameVerificationRequired => "TLS hostname verification is required",
            Self::ExpirationClosureRequired => "TLS expiration link closure is required",
            Self::InvalidIngressLimits => "invalid bounded intent-ingress limits",
            Self::InvalidTransportLimits => "invalid Zenoh receive/defragmentation limits",
            Self::IntentRoute => "invalid exact intent route",
            Self::SessionOpen => "failed to open the Zenoh session",
            Self::SessionClose => "failed to close the Zenoh session",
            Self::Subscribe => "failed to declare the exact intent subscriber",
            Self::Publish => "the local Zenoh final-command publication returned an error",
            Self::InvalidCommandFrame => {
                "the final command is not validated upstream NCP v0.8 JSON"
            }
            Self::CommandSessionMismatch => {
                "the final command session differs from the bound command route"
            }
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for SecureZenohError {}

/// A parsed client configuration that passed Haldir's fail-closed mTLS checks.
///
/// Validation does not prove the router's ACL policy or identify a sample's
/// publisher. Those properties require the separate live certificate×route
/// delivery campaign and the signed application envelope.
///
/// Zenoh 1.9 always seeds its client trust store with public WebPKI roots and
/// then extends it with `root_ca_certificate`; it offers no exclusive-custom-CA
/// switch. This type therefore proves that an explicit CA is configured and
/// hostname verification is on, not that server trust is limited to that CA.
/// The reference profile uses a reserved `.invalid` router name to reduce public
/// issuance risk. Exclusive router trust requires a patched/upgraded Zenoh or an
/// API that accepts a pinned Rustls verifier.
pub struct SecureClientConfig {
    inner: Config,
}

impl fmt::Debug for SecureClientConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Never render certificate or private-key configuration into diagnostics.
        formatter
            .debug_struct("SecureClientConfig")
            .finish_non_exhaustive()
    }
}

impl SecureClientConfig {
    /// Load and validate one explicit JSON/JSON5 client configuration file.
    ///
    /// There is deliberately no environment-variable fallback and no open
    /// default: a missing or malformed path fails closed.
    ///
    /// # Errors
    /// Returns a classified configuration error for any missing strict-client
    /// invariant or file load/parse failure.
    pub fn from_file(path: impl AsRef<Path>) -> Result<Self, SecureZenohError> {
        let config = Config::from_file(path).map_err(|_| SecureZenohError::ConfigLoad)?;
        validate_secure_client_config(&config)?;
        Ok(Self { inner: config })
    }
}

/// An open strict-client Zenoh session with no public raw session escape hatch.
pub struct SecureZenohSession {
    session: Arc<Session>,
}

impl SecureZenohSession {
    /// Open a previously validated explicit client configuration.
    ///
    /// # Errors
    /// Returns [`SecureZenohError::SessionOpen`] if Zenoh cannot establish the
    /// configured session. This does not by itself prove ACL delivery.
    pub async fn open(config: SecureClientConfig) -> Result<Self, SecureZenohError> {
        let session = zenoh::open(config.inner)
            .await
            .map_err(|_| SecureZenohError::SessionOpen)?;
        Ok(Self {
            session: Arc::new(session),
        })
    }

    /// Load, validate, and open one explicit strict client config.
    ///
    /// # Errors
    /// Returns on file/config validation or Zenoh session-open failure.
    pub async fn open_file(path: impl AsRef<Path>) -> Result<Self, SecureZenohError> {
        Self::open(SecureClientConfig::from_file(path)?).await
    }

    /// Close this client's Zenoh session.
    ///
    /// # Errors
    /// This closes the shared Zenoh session even when typed handles still exist;
    /// later operations through those handles fail at Zenoh. Returns
    /// [`SecureZenohError::SessionClose`] on a Zenoh close error.
    pub async fn close(self) -> Result<(), SecureZenohError> {
        self.session
            .close()
            .await
            .map_err(|_| SecureZenohError::SessionClose)
    }
}

/// Hard maximum for one signed intent envelope before verification.
pub const HARD_MAX_INTENT_BYTES: usize = 16 * 1024;
/// Hard maximum number of copied intent envelopes waiting for Gate.
pub const HARD_MAX_INTENT_QUEUE: usize = 1024;
/// Maximum admitted Zenoh message defragmentation size before the callback.
pub const HARD_MAX_ZENOH_MESSAGE_BYTES: usize = 32 * 1024;
/// Maximum per-link receive buffer admitted before the callback.
pub const HARD_MAX_ZENOH_RX_BUFFER_BYTES: usize = 65_535;

/// Bounded pre-verification ingress limits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IngressLimits {
    max_intent_bytes: usize,
    queue_capacity: usize,
}

impl IngressLimits {
    /// Construct nonzero limits within the hard transport profile ceilings.
    ///
    /// # Errors
    /// Returns [`SecureZenohError::InvalidIngressLimits`] for zero or excessive
    /// byte/count bounds.
    pub const fn new(
        max_intent_bytes: usize,
        queue_capacity: usize,
    ) -> Result<Self, SecureZenohError> {
        if max_intent_bytes == 0
            || max_intent_bytes > HARD_MAX_INTENT_BYTES
            || queue_capacity == 0
            || queue_capacity > HARD_MAX_INTENT_QUEUE
        {
            return Err(SecureZenohError::InvalidIngressLimits);
        }
        Ok(Self {
            max_intent_bytes,
            queue_capacity,
        })
    }

    /// Maximum copied envelope bytes.
    #[must_use]
    pub const fn max_intent_bytes(self) -> usize {
        self.max_intent_bytes
    }

    /// Fixed Gate handoff queue capacity.
    #[must_use]
    pub const fn queue_capacity(self) -> usize {
        self.queue_capacity
    }
}

/// One bounded raw intent sample handed to Gate.
///
/// `actual_key` is observed sample metadata. No publisher-CN field exists because
/// Zenoh's stable sample API does not expose the mTLS certificate principal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IntentIngressEvent {
    /// Exact key expression observed on the received sample.
    pub actual_key: String,
    /// Raw signed envelope bytes, copied only after the size check.
    pub bytes: Vec<u8>,
}

#[derive(Debug, Default)]
struct CounterInner {
    accepted: AtomicU64,
    oversize_dropped: AtomicU64,
    queue_full_dropped: AtomicU64,
    non_put_dropped: AtomicU64,
    receiver_closed_dropped: AtomicU64,
}

/// Shared bounded-label ingress counters.
#[derive(Debug, Clone, Default)]
pub struct IngressCounters(Arc<CounterInner>);

impl IngressCounters {
    /// Read a consistent-enough operational snapshot of monotonic counters.
    #[must_use]
    pub fn snapshot(&self) -> IngressCountersSnapshot {
        IngressCountersSnapshot {
            accepted: self.0.accepted.load(Ordering::Relaxed),
            oversize_dropped: self.0.oversize_dropped.load(Ordering::Relaxed),
            queue_full_dropped: self.0.queue_full_dropped.load(Ordering::Relaxed),
            non_put_dropped: self.0.non_put_dropped.load(Ordering::Relaxed),
            receiver_closed_dropped: self.0.receiver_closed_dropped.load(Ordering::Relaxed),
        }
    }
}

/// Snapshot of intent-ingress outcomes. No untrusted route or identity labels are retained.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IngressCountersSnapshot {
    /// Samples accepted into the bounded Gate queue.
    pub accepted: u64,
    /// Samples rejected before payload copying because their raw payload was too large.
    pub oversize_dropped: u64,
    /// Samples rejected because the bounded Gate queue had no capacity.
    pub queue_full_dropped: u64,
    /// Delete/non-PUT samples ignored by the intent ingress.
    pub non_put_dropped: u64,
    /// Samples rejected after the Gate receiver was dropped.
    pub receiver_closed_dropped: u64,
}

/// One exact-route subscription and its bounded Gate handoff queue.
pub struct IntentIngress {
    receiver: mpsc::Receiver<IntentIngressEvent>,
    counters: IngressCounters,
    _subscriber: zenoh::pubsub::Subscriber<()>,
}

impl IntentIngress {
    /// Declare one exact controller intent subscription.
    ///
    /// The callback performs only kind/size checks, one bounded copy, and
    /// `try_send`; it never blocks a Zenoh receive task or performs signature work.
    ///
    /// # Errors
    /// Returns for invalid route input or subscriber declaration failure.
    pub async fn declare(
        session: &SecureZenohSession,
        keys: &HaldirKeys,
        controller_id: &str,
        limits: IngressLimits,
    ) -> Result<Self, SecureZenohError> {
        let intent_key = keys
            .intent(controller_id)
            .map_err(|_| SecureZenohError::IntentRoute)?;
        let (sender, receiver) = mpsc::channel(limits.queue_capacity);
        let counters = IngressCounters::default();
        let callback_counters = counters.clone();
        let subscriber = session
            .session
            .declare_subscriber(intent_key)
            // Router ACLs do not mediate same-session loopback delivery. Gate
            // intents must therefore originate on a remote transport session.
            .allowed_origin(Locality::Remote)
            .callback(move |sample| {
                if sample.kind() != SampleKind::Put {
                    bump(&callback_counters.0.non_put_dropped);
                    return;
                }
                if !precheck_payload_size(
                    &callback_counters,
                    sample.payload().len(),
                    limits.max_intent_bytes,
                ) {
                    return;
                }
                let Some(permit) = reserve_ingress(&sender, &callback_counters) else {
                    return;
                };
                let actual_key = sample.key_expr().as_str();
                let bytes = sample.payload().to_bytes();
                permit.send(IntentIngressEvent {
                    actual_key: actual_key.to_owned(),
                    bytes: bytes.to_vec(),
                });
                bump(&callback_counters.0.accepted);
            })
            .await
            .map_err(|_| SecureZenohError::Subscribe)?;
        Ok(Self {
            receiver,
            counters,
            _subscriber: subscriber,
        })
    }

    /// Wait for the next bounded raw intent event.
    pub async fn recv(&mut self) -> Option<IntentIngressEvent> {
        self.receiver.recv().await
    }

    /// Attempt to receive without waiting.
    ///
    /// # Errors
    /// Returns Tokio's empty/disconnected classification when no event is available.
    pub fn try_recv(&mut self) -> Result<IntentIngressEvent, mpsc::error::TryRecvError> {
        self.receiver.try_recv()
    }

    /// Shared operational counters for this ingress.
    #[must_use]
    pub fn counters(&self) -> IngressCounters {
        self.counters.clone()
    }
}

/// Typed publisher permanently bound to one standard NCP base command route.
pub struct FinalCommandPublisher {
    session: Arc<Session>,
    final_command_key: String,
    session_id: String,
}

impl FinalCommandPublisher {
    /// Bind a publisher to the exact base command route built by pinned NCP.
    #[must_use]
    pub fn new(session: &SecureZenohSession, keys: &HaldirKeys) -> Self {
        Self {
            session: session.session.clone(),
            final_command_key: keys.final_command().to_owned(),
            session_id: keys.session_id().to_owned(),
        }
    }

    /// Submit the immutable exact NCP bytes on the sole bound command route.
    ///
    /// A successful return means only that the local Zenoh call returned `Ok`;
    /// it does not prove router delivery, Crebain receipt, acceptance, or application.
    /// No retry is performed here, so callers can preserve exact bytes/sequence and
    /// classify ambiguous outcomes explicitly.
    ///
    /// # Errors
    /// Rejects modeled/non-JSON bytes or a frame bound to another session before
    /// touching Zenoh. Returns [`SecureZenohError::Publish`] when the local Zenoh
    /// call itself returns an error.
    pub async fn publish(&self, frame: &ExactNcpCommandFrame) -> Result<(), SecureZenohError> {
        let bytes = validated_upstream_json_bytes(frame, &self.session_id)?;
        self.session
            .put(&self.final_command_key, bytes.to_vec())
            .encoding(Encoding::APPLICATION_JSON)
            // Final commands must not report local success after a congestion drop.
            .congestion_control(CongestionControl::Block)
            .priority(Priority::RealTime)
            .express(true)
            // Never satisfy a session-local subscriber without crossing the
            // router enforcement point exercised by the deployment profile.
            .allowed_destination(Locality::Remote)
            .await
            .map_err(|_| SecureZenohError::Publish)
    }

    /// Exact standard NCP base command route owned by this publisher.
    #[must_use]
    pub fn route(&self) -> &str {
        &self.final_command_key
    }
}

fn validate_secure_client_config(config: &Config) -> Result<(), SecureZenohError> {
    if config_value(config, "mode")?.as_str() != Some("client") {
        return Err(SecureZenohError::ClientModeRequired);
    }
    let endpoints = exact_string_array(config, "connect/endpoints")?;
    if endpoints.len() != 1 || endpoints.iter().any(|endpoint| !is_tls_endpoint(endpoint)) {
        return Err(SecureZenohError::TlsConnectRequired);
    }
    let connect_timeout_ms = config_value(config, "connect/timeout_ms")?
        .as_i64()
        .ok_or(SecureZenohError::ConnectPolicyRequired)?;
    if !(1..=30_000).contains(&connect_timeout_ms)
        || config_value(config, "connect/exit_on_failure")?.as_bool() != Some(true)
    {
        return Err(SecureZenohError::ConnectPolicyRequired);
    }
    if !exact_string_array(config, "listen/endpoints")?.is_empty() {
        return Err(SecureZenohError::ListenerForbidden);
    }
    for path in ["scouting/multicast/enabled", "scouting/gossip/enabled"] {
        if config_value(config, path)?.as_bool() != Some(false) {
            return Err(SecureZenohError::DiscoveryForbidden);
        }
    }
    if config_value(config, "adminspace/enabled")?.as_bool() != Some(false)
        || config_value(config, "plugins_loading/enabled")?.as_bool() != Some(false)
        || config_value(config, "plugins")?
            .as_object()
            .is_none_or(|plugins| !plugins.is_empty())
        || config_value(config, "transport/shared_memory/enabled")?.as_bool() != Some(false)
    {
        return Err(SecureZenohError::AuxiliarySurfaceForbidden);
    }
    for path in [
        "transport/link/tls/root_ca_certificate",
        "transport/link/tls/connect_certificate",
        "transport/link/tls/connect_private_key",
    ] {
        let value = config_value(config, path)?;
        if value.as_str().is_none_or(|value| value.trim().is_empty()) {
            return Err(SecureZenohError::ClientIdentityRequired);
        }
    }
    if config_value(config, "transport/link/tls/enable_mtls")?.as_bool() != Some(true) {
        return Err(SecureZenohError::MutualTlsRequired);
    }
    if config_value(config, "transport/link/tls/verify_name_on_connect")?.as_bool() != Some(true) {
        return Err(SecureZenohError::HostnameVerificationRequired);
    }
    if config_value(config, "transport/link/tls/close_link_on_expiration")?.as_bool() != Some(true)
    {
        return Err(SecureZenohError::ExpirationClosureRequired);
    }
    let max_message_size = exact_usize(config, "transport/link/rx/max_message_size")?;
    let rx_buffer_size = exact_usize(config, "transport/link/rx/buffer_size")?;
    let block_wait_us = config_value(
        config,
        "transport/link/tx/queue/congestion_control/block/wait_before_close",
    )?
    .as_i64()
    .ok_or(SecureZenohError::InvalidTransportLimits)?;
    if max_message_size != HARD_MAX_ZENOH_MESSAGE_BYTES
        || rx_buffer_size != HARD_MAX_ZENOH_RX_BUFFER_BYTES
        || block_wait_us != 50_000
    {
        return Err(SecureZenohError::InvalidTransportLimits);
    }
    Ok(())
}

fn is_tls_endpoint(endpoint: &str) -> bool {
    endpoint.trim() == endpoint
        && EndPoint::from_str(endpoint).is_ok_and(|parsed| {
            parsed.protocol().as_str() == "tls"
                && parsed.metadata().as_str().is_empty()
                && parsed.config().as_str().is_empty()
        })
}

fn validated_upstream_json_bytes<'a>(
    frame: &'a ExactNcpCommandFrame,
    expected_session_id: &str,
) -> Result<&'a [u8], SecureZenohError> {
    if frame.session_id() != expected_session_id {
        return Err(SecureZenohError::CommandSessionMismatch);
    }
    let decoded = ncp_core::decode_validated::<ncp_core::CommandFrame>(frame.bytes())
        .map_err(|_| SecureZenohError::InvalidCommandFrame)?;
    if decoded.session_id != expected_session_id {
        return Err(SecureZenohError::CommandSessionMismatch);
    }
    Ok(frame.bytes())
}

fn config_value(config: &Config, path: &str) -> Result<Value, SecureZenohError> {
    let json = config
        .get_json(path)
        .map_err(|_| SecureZenohError::ConfigLoad)?;
    serde_json::from_str(&json).map_err(|_| SecureZenohError::ConfigLoad)
}

fn exact_string_array(config: &Config, path: &str) -> Result<Vec<String>, SecureZenohError> {
    let values = config_value(config, path)?;
    let array = values.as_array().ok_or_else(|| {
        if path == "listen/endpoints" {
            SecureZenohError::ListenerForbidden
        } else {
            SecureZenohError::TlsConnectRequired
        }
    })?;
    array
        .iter()
        .map(|value| {
            value.as_str().map(str::to_owned).ok_or_else(|| {
                if path == "listen/endpoints" {
                    SecureZenohError::ListenerForbidden
                } else {
                    SecureZenohError::TlsConnectRequired
                }
            })
        })
        .collect()
}

fn exact_usize(config: &Config, path: &str) -> Result<usize, SecureZenohError> {
    let value = config_value(config, path)?;
    let raw = value
        .as_u64()
        .ok_or(SecureZenohError::InvalidTransportLimits)?;
    usize::try_from(raw).map_err(|_| SecureZenohError::InvalidTransportLimits)
}

#[cfg(test)]
fn enqueue_bounded(
    sender: &mpsc::Sender<IntentIngressEvent>,
    counters: &IngressCounters,
    actual_key: &str,
    bytes: &[u8],
) {
    let Some(permit) = reserve_ingress(sender, counters) else {
        return;
    };
    let event = IntentIngressEvent {
        actual_key: actual_key.to_owned(),
        bytes: bytes.to_vec(),
    };
    permit.send(event);
    bump(&counters.0.accepted);
}

fn reserve_ingress<'a>(
    sender: &'a mpsc::Sender<IntentIngressEvent>,
    counters: &IngressCounters,
) -> Option<mpsc::Permit<'a, IntentIngressEvent>> {
    match sender.try_reserve() {
        Ok(permit) => Some(permit),
        Err(mpsc::error::TrySendError::Full(())) => {
            bump(&counters.0.queue_full_dropped);
            None
        }
        Err(mpsc::error::TrySendError::Closed(())) => {
            bump(&counters.0.receiver_closed_dropped);
            None
        }
    }
}

fn precheck_payload_size(
    counters: &IngressCounters,
    raw_payload_len: usize,
    max_intent_bytes: usize,
) -> bool {
    if raw_payload_len > max_intent_bytes {
        bump(&counters.0.oversize_dropped);
        false
    } else {
        true
    }
}

fn bump(counter: &AtomicU64) {
    let _ = counter.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
        Some(value.saturating_add(1))
    });
}

#[cfg(test)]
mod tests {
    use core::num::{NonZeroU32, NonZeroU64};
    use std::fs;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    use haldir_contracts::action::RequestedActionV1;
    use haldir_contracts::ids::{DecisionId, GateOutputEpoch, OutputSeq, SourceSeq};
    use haldir_contracts::scalar::{AsciiId, BoundedAscii, CanonicalUuidV4String};
    use haldir_contracts::session::{NcpSessionIdentityV1, NcpSourceRefV1, NcpStreamPositionV1};
    use haldir_ncp08::{
        AclOnlyAdapter, GateCommandBuildInputV1, NcpCommandAdapter, RealNcp08Adapter,
    };

    use super::*;

    static TEST_SEQUENCE: AtomicU64 = AtomicU64::new(0);

    struct TestFile(PathBuf);

    impl TestFile {
        fn new(contents: &str) -> Self {
            let sequence = TEST_SEQUENCE.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "haldir-zenoh-config-test-{}-{sequence}.json5",
                std::process::id()
            ));
            fs::write(&path, contents).unwrap();
            Self(path)
        }
    }

    impl Drop for TestFile {
        fn drop(&mut self) {
            let _ = fs::remove_file(&self.0);
        }
    }

    const VALID_CONFIG: &str = r#"
    {
      mode: "client",
      adminspace: { enabled: false },
      plugins: {},
      plugins_loading: { enabled: false },
      connect: {
        endpoints: ["tls/router.example:7447"],
        exit_on_failure: true,
        timeout_ms: 10000,
      },
      listen: { endpoints: [] },
      scouting: {
        multicast: { enabled: false },
        gossip: { enabled: false },
      },
      transport: { shared_memory: { enabled: false }, link: { tls: {
        root_ca_certificate: "ca.pem",
        connect_certificate: "gate.pem",
        connect_private_key: "gate-key.pem",
        enable_mtls: true,
        verify_name_on_connect: true,
        close_link_on_expiration: true,
      }, rx: {
        buffer_size: 65535,
        max_message_size: 32768,
      }, tx: { queue: { congestion_control: { block: {
        wait_before_close: 50000,
      } } } } } },
    }
    "#;

    fn config_with(replacement: (&str, &str)) -> TestFile {
        TestFile::new(&VALID_CONFIG.replace(replacement.0, replacement.1))
    }

    fn command_input() -> GateCommandBuildInputV1 {
        GateCommandBuildInputV1 {
            decision_id: DecisionId::new([1; 16]),
            session: NcpSessionIdentityV1 {
                session_id: AsciiId::new("sess-1").unwrap(),
                generation: CanonicalUuidV4String::from_random_bytes([1; 16]),
            },
            stream: NcpStreamPositionV1 {
                epoch: GateOutputEpoch::new(CanonicalUuidV4String::from_random_bytes([5; 16])),
                seq: OutputSeq::new(NonZeroU64::new(1).unwrap()),
            },
            source: NcpSourceRefV1 {
                source_key: BoundedAscii::new("veh/uav-1/state/pose").unwrap(),
                stream_epoch: CanonicalUuidV4String::from_random_bytes([2; 16]),
                stream_seq: SourceSeq::new(NonZeroU64::new(7).unwrap()),
            },
            frame_id: BoundedAscii::new("map").unwrap(),
            source_t_ns: 111,
            gate_t_ns: 222,
            action: RequestedActionV1::Hold {
                requested_validity_ms: NonZeroU32::new(300).unwrap(),
            },
            effective_validity_ms: 300,
        }
    }

    #[test]
    fn strict_config_accepts_only_explicit_mtls_client_shape() {
        let valid = TestFile::new(VALID_CONFIG);
        assert!(SecureClientConfig::from_file(&valid.0).is_ok());

        let cases = [
            (
                config_with(("mode: \"client\"", "mode: \"peer\"")),
                SecureZenohError::ClientModeRequired,
            ),
            (
                config_with(("tls/router.example:7447", "tcp/router.example:7447")),
                SecureZenohError::TlsConnectRequired,
            ),
            (
                config_with((
                    "tls/router.example:7447",
                    "tls/router.example:7447#verify_name_on_connect=false",
                )),
                SecureZenohError::TlsConnectRequired,
            ),
            (
                config_with(("endpoints: [\"tls/router.example:7447\"]", "endpoints: []")),
                SecureZenohError::TlsConnectRequired,
            ),
            (
                config_with((
                    "endpoints: [\"tls/router.example:7447\"]",
                    "endpoints: [\"tls/router.example:7447\", \"tls/backup.example:7447\"]",
                )),
                SecureZenohError::TlsConnectRequired,
            ),
            (
                config_with(("timeout_ms: 10000", "timeout_ms: -1")),
                SecureZenohError::ConnectPolicyRequired,
            ),
            (
                config_with(("exit_on_failure: true", "exit_on_failure: false")),
                SecureZenohError::ConnectPolicyRequired,
            ),
            (
                config_with((
                    "listen: { endpoints: [] }",
                    "listen: { endpoints: [\"tls/0.0.0.0:1\"] }",
                )),
                SecureZenohError::ListenerForbidden,
            ),
            (
                config_with((
                    "multicast: { enabled: false }",
                    "multicast: { enabled: true }",
                )),
                SecureZenohError::DiscoveryForbidden,
            ),
            (
                config_with(("gossip: { enabled: false }", "gossip: { enabled: true }")),
                SecureZenohError::DiscoveryForbidden,
            ),
            (
                config_with(("plugins: {}", "plugins: { rogue: {} }")),
                SecureZenohError::AuxiliarySurfaceForbidden,
            ),
            (
                config_with((
                    "shared_memory: { enabled: false }",
                    "shared_memory: { enabled: true }",
                )),
                SecureZenohError::AuxiliarySurfaceForbidden,
            ),
            (
                config_with((
                    "root_ca_certificate: \"ca.pem\"",
                    "root_ca_certificate: \"\"",
                )),
                SecureZenohError::ClientIdentityRequired,
            ),
            (
                config_with((
                    "connect_certificate: \"gate.pem\"",
                    "connect_certificate: \"\"",
                )),
                SecureZenohError::ClientIdentityRequired,
            ),
            (
                config_with((
                    "connect_private_key: \"gate-key.pem\"",
                    "connect_private_key: \"\"",
                )),
                SecureZenohError::ClientIdentityRequired,
            ),
            (
                config_with(("enable_mtls: true", "enable_mtls: false")),
                SecureZenohError::MutualTlsRequired,
            ),
            (
                config_with((
                    "verify_name_on_connect: true",
                    "verify_name_on_connect: false",
                )),
                SecureZenohError::HostnameVerificationRequired,
            ),
            (
                config_with((
                    "close_link_on_expiration: true",
                    "close_link_on_expiration: false",
                )),
                SecureZenohError::ExpirationClosureRequired,
            ),
            (
                config_with(("max_message_size: 32768", "max_message_size: 1073741824")),
                SecureZenohError::InvalidTransportLimits,
            ),
            (
                config_with(("buffer_size: 65535", "buffer_size: 1048576")),
                SecureZenohError::InvalidTransportLimits,
            ),
            (
                config_with(("wait_before_close: 50000", "wait_before_close: 5000000")),
                SecureZenohError::InvalidTransportLimits,
            ),
        ];
        for (file, expected) in cases {
            assert_eq!(
                SecureClientConfig::from_file(&file.0).unwrap_err(),
                expected
            );
        }
    }

    #[test]
    fn missing_config_never_falls_back_to_a_default_session() {
        assert_eq!(
            SecureClientConfig::from_file("/haldir/does/not/exist").unwrap_err(),
            SecureZenohError::ConfigLoad
        );
    }

    #[test]
    fn publisher_precheck_rejects_modeled_wire_and_accepts_upstream_json() {
        let input = command_input();
        let modeled = AclOnlyAdapter::new().build_command(&input).unwrap();
        assert_eq!(
            validated_upstream_json_bytes(&modeled, "sess-1").unwrap_err(),
            SecureZenohError::InvalidCommandFrame
        );

        let exact = RealNcp08Adapter::new().build_command(&input).unwrap();
        assert_eq!(
            validated_upstream_json_bytes(&exact, "sess-2").unwrap_err(),
            SecureZenohError::CommandSessionMismatch
        );
        assert_eq!(
            validated_upstream_json_bytes(&exact, "sess-1").unwrap(),
            exact.bytes()
        );
    }

    #[test]
    fn queue_is_bounded_and_retains_actual_key_and_raw_bytes() {
        let (sender, mut receiver) = mpsc::channel(1);
        let counters = IngressCounters::default();
        enqueue_bounded(&sender, &counters, "realm/intent/a", b"first");
        enqueue_bounded(&sender, &counters, "realm/intent/a", b"second");

        assert_eq!(
            receiver.try_recv().unwrap(),
            IntentIngressEvent {
                actual_key: "realm/intent/a".to_owned(),
                bytes: b"first".to_vec(),
            }
        );
        assert_eq!(
            counters.snapshot(),
            IngressCountersSnapshot {
                accepted: 1,
                oversize_dropped: 0,
                queue_full_dropped: 1,
                non_put_dropped: 0,
                receiver_closed_dropped: 0,
            }
        );
    }

    #[test]
    fn closed_gate_queue_is_counted_without_blocking() {
        let (sender, receiver) = mpsc::channel(1);
        let counters = IngressCounters::default();
        drop(receiver);

        enqueue_bounded(&sender, &counters, "realm/intent/a", b"intent");

        assert_eq!(counters.snapshot().receiver_closed_dropped, 1);
        assert_eq!(counters.snapshot().accepted, 0);
    }

    #[test]
    fn raw_size_is_rejected_before_queue_copy() {
        let counters = IngressCounters::default();

        assert!(!precheck_payload_size(&counters, 5, 4));
        assert!(precheck_payload_size(&counters, 4, 4));
        assert_eq!(counters.snapshot().oversize_dropped, 1);
    }

    #[test]
    fn zero_or_excessive_ingress_limits_are_rejected() {
        assert_eq!(
            IngressLimits::new(0, 1),
            Err(SecureZenohError::InvalidIngressLimits)
        );
        assert_eq!(
            IngressLimits::new(HARD_MAX_INTENT_BYTES, HARD_MAX_INTENT_QUEUE + 1),
            Err(SecureZenohError::InvalidIngressLimits)
        );
        assert!(IngressLimits::new(HARD_MAX_INTENT_BYTES, 1).is_ok());
    }

    #[test]
    fn public_transport_types_remain_send() {
        fn assert_send<T: Send>() {}
        assert_send::<SecureClientConfig>();
        assert_send::<SecureZenohSession>();
        assert_send::<IntentIngress>();
        assert_send::<FinalCommandPublisher>();
    }
}
