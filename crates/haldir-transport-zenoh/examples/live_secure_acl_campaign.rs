//! Receiver-observed live ACL campaign for the fixed secure-reference profile.
//!
//! This example is intentionally not part of the ordinary test suite. A
//! harness must provision the rendered client configurations and ephemeral
//! certificates, start the pinned router, and set:
//!
//! - `HALDIR_LIVE_ACL_CONFIG_DIR` to the bundle root containing `clients/` and
//!   `no-certificate.json`;
//! - `HALDIR_LIVE_ACL_RESULT_PATH` to a new result file.

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fs::OpenOptions;
use std::io::{self, Write};
use std::num::{NonZeroU32, NonZeroU64};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use haldir_contracts::action::RequestedActionV1;
use haldir_contracts::ids::{DecisionId, GateOutputEpoch, OutputSeq, SourceSeq};
use haldir_contracts::scalar::{AsciiId, BoundedAscii, CanonicalUuidV4String};
use haldir_contracts::session::{NcpSessionIdentityV1, NcpSourceRefV1, NcpStreamPositionV1};
use haldir_ncp08::{
    ExactNcpCommandFrame, GateCommandBuildInputV1, NcpCommandAdapter, RealNcp08Adapter,
};
use haldir_transport_zenoh::{
    FinalCommandPublisher, HaldirKeys, IngressCountersSnapshot, IngressLimits, IntentIngress,
    IntentIngressEvent, SecureClientConfig, SecureZenohSession,
};
use serde_json::{Value, json};
use tokio::sync::mpsc;
use tokio::time::{Instant, timeout};
use zenoh::bytes::Encoding;
use zenoh::qos::{CongestionControl, Priority};
use zenoh::sample::{Locality, Sample};
use zenoh::{Config, Session};

type CampaignError = Box<dyn Error + Send + Sync>;
type CampaignResult<T> = Result<T, CampaignError>;

const REALM: &str = "haldir-ncp";
const SESSION_ID: &str = "uav-1";
const CALLBACK_CAPACITY: usize = 64;
const POSITIVE_TIMEOUT: Duration = Duration::from_secs(5);
const DECLARATION_SETTLE: Duration = Duration::from_secs(1);
const QUARANTINE: Duration = Duration::from_secs(2);

const FINAL_POSITIVE_PRE: &str = "final-positive-pre";
const FINAL_POSITIVE_POST: &str = "final-positive-post";
const INTENT_A_POSITIVE_PRE: &str = "intent-a-positive-pre";
const INTENT_A_POSITIVE_POST: &str = "intent-a-positive-post";
const INTENT_B_POSITIVE_PRE: &str = "intent-b-positive-pre";
const INTENT_B_POSITIVE_POST: &str = "intent-b-positive-post";
const INTENT_A_DENIED_CONTROLLER_B: &str = "intent-a-denied-controller-b";
const INTENT_B_DENIED_CONTROLLER_A: &str = "intent-b-denied-controller-a";
const CONTROLLER_A_FINAL_SUBSCRIBE_DENIED: &str = "controller-a-final-subscribe-denied";

const FINAL_CASES: &[(u64, &str)] = &[
    (1, FINAL_POSITIVE_PRE),
    (2, "final-denied-admission-authority"),
    (3, "final-denied-controller-a"),
    (4, "final-denied-controller-b"),
    (5, "final-denied-lifecycle"),
    (6, "final-denied-mission-authority"),
    (7, "final-denied-observer"),
    (8, "final-denied-robot-crebain"),
    (9, FINAL_POSITIVE_POST),
];

#[derive(Debug)]
struct Observation {
    receiver: String,
    route: String,
    case_id: String,
}

impl Observation {
    fn to_json(&self) -> Value {
        json!({
            "receiver": self.receiver,
            "route": self.route,
            "case_id": self.case_id,
        })
    }
}

struct OpenSessions {
    gate_final: SecureZenohSession,
    gate_intent: SecureZenohSession,
    admission: Session,
    controller_a: Session,
    controller_b: Session,
    lifecycle: Session,
    mission_authority: Session,
    observer_attacker: Session,
    robot_attacker: Session,
    robot_receiver: Session,
    observer_receiver: Session,
    controller_a_receiver: Session,
}

impl OpenSessions {
    fn records(&self) -> Vec<Value> {
        vec![
            session_record("gate-final-sender", self.gate_final.zid()),
            session_record("gate-intent-receiver", self.gate_intent.zid()),
            session_record(
                "admission-authority-attacker",
                self.admission.zid().to_string(),
            ),
            session_record("controller-a-attacker", self.controller_a.zid().to_string()),
            session_record("controller-b-attacker", self.controller_b.zid().to_string()),
            session_record("lifecycle-attacker", self.lifecycle.zid().to_string()),
            session_record(
                "mission-authority-attacker",
                self.mission_authority.zid().to_string(),
            ),
            session_record(
                "observer-attacker",
                self.observer_attacker.zid().to_string(),
            ),
            session_record(
                "robot-crebain-attacker",
                self.robot_attacker.zid().to_string(),
            ),
            session_record(
                "robot-crebain-final-receiver",
                self.robot_receiver.zid().to_string(),
            ),
            session_record(
                "observer-final-receiver",
                self.observer_receiver.zid().to_string(),
            ),
            session_record(
                "controller-a-final-receiver",
                self.controller_a_receiver.zid().to_string(),
            ),
        ]
    }

    async fn close(self) -> CampaignResult<()> {
        self.controller_a_receiver.close().await?;
        self.observer_receiver.close().await?;
        self.robot_receiver.close().await?;
        self.robot_attacker.close().await?;
        self.observer_attacker.close().await?;
        self.mission_authority.close().await?;
        self.lifecycle.close().await?;
        self.controller_b.close().await?;
        self.controller_a.close().await?;
        self.admission.close().await?;
        self.gate_intent.close().await?;
        self.gate_final.close().await?;
        Ok(())
    }
}

struct CampaignOutput {
    sessions: Vec<Value>,
    attempts: Vec<Value>,
    observations: Vec<Observation>,
    denied_case_ids: Vec<&'static str>,
    no_certificate_rejected: bool,
    callback_overflow: bool,
}

fn campaign_error(message: impl Into<String>) -> CampaignError {
    Box::new(io::Error::other(message.into()))
}

fn required_env_path(name: &str) -> CampaignResult<PathBuf> {
    let value = std::env::var_os(name).ok_or_else(|| {
        campaign_error(format!("required environment variable is absent: {name}"))
    })?;
    if value.is_empty() {
        return Err(campaign_error(format!(
            "required environment variable is empty: {name}"
        )));
    }
    Ok(PathBuf::from(value))
}

fn client_path(config_dir: &Path, principal: &str) -> PathBuf {
    config_dir.join("clients").join(format!("{principal}.json"))
}

async fn open_raw(config_dir: &Path, principal: &str) -> CampaignResult<Session> {
    let path = client_path(config_dir, principal);
    // Attack traffic uses the raw Zenoh API intentionally, but every role
    // config must still pass the same fail-closed checks as production.
    let _strict = SecureClientConfig::from_file(&path)?;
    let config = Config::from_file(&path)?;
    zenoh::open(config).await
}

async fn open_sessions(config_dir: &Path) -> CampaignResult<OpenSessions> {
    Ok(OpenSessions {
        gate_final: SecureZenohSession::open_file(client_path(config_dir, "gate")).await?,
        gate_intent: SecureZenohSession::open_file(client_path(config_dir, "gate")).await?,
        admission: open_raw(config_dir, "admission-authority").await?,
        controller_a: open_raw(config_dir, "controller-a").await?,
        controller_b: open_raw(config_dir, "controller-b").await?,
        lifecycle: open_raw(config_dir, "lifecycle").await?,
        mission_authority: open_raw(config_dir, "mission-authority").await?,
        observer_attacker: open_raw(config_dir, "observer").await?,
        robot_attacker: open_raw(config_dir, "robot-crebain").await?,
        robot_receiver: open_raw(config_dir, "robot-crebain").await?,
        observer_receiver: open_raw(config_dir, "observer").await?,
        controller_a_receiver: open_raw(config_dir, "controller-a").await?,
    })
}

fn session_record(label: &str, zid: String) -> Value {
    json!({"label": label, "zid": zid})
}

fn assert_unique_sessions(records: &[Value]) -> CampaignResult<()> {
    if records.len() != 12 {
        return Err(campaign_error("campaign must open exactly twelve sessions"));
    }
    let zids = records
        .iter()
        .filter_map(|record| record.get("zid").and_then(Value::as_str))
        .collect::<BTreeSet<_>>();
    if zids.len() != records.len() {
        return Err(campaign_error(
            "campaign session ZIDs are not globally unique",
        ));
    }
    Ok(())
}

fn frame_case_id(sequence: u64) -> Option<&'static str> {
    FINAL_CASES
        .iter()
        .find_map(|(candidate, case_id)| (*candidate == sequence).then_some(*case_id))
}

fn callback(
    receiver: &'static str,
    sender: mpsc::Sender<Observation>,
    overflow: Arc<AtomicBool>,
) -> impl Fn(Sample) + Send + Sync + 'static {
    move |sample| {
        let bytes = sample.payload().to_bytes();
        let case_id = ncp_core::decode_validated::<ncp_core::CommandFrame>(bytes.as_ref())
            .ok()
            .and_then(|frame| u64::try_from(frame.stream.seq).ok())
            .and_then(frame_case_id)
            .unwrap_or("invalid-final-command-payload")
            .to_owned();
        let observation = Observation {
            receiver: receiver.to_owned(),
            route: sample.key_expr().as_str().to_owned(),
            case_id,
        };
        if sender.try_send(observation).is_err() {
            overflow.store(true, Ordering::Relaxed);
        }
    }
}

fn build_input(sequence: u64) -> CampaignResult<GateCommandBuildInputV1> {
    let output_sequence = NonZeroU64::new(sequence)
        .ok_or_else(|| campaign_error("final command sequence must be nonzero"))?;
    let validity =
        NonZeroU32::new(200).ok_or_else(|| campaign_error("command validity must be nonzero"))?;
    Ok(GateCommandBuildInputV1 {
        decision_id: DecisionId::new([u8::try_from(sequence).unwrap_or(u8::MAX); 16]),
        session: NcpSessionIdentityV1 {
            session_id: AsciiId::new(SESSION_ID)?,
            generation: CanonicalUuidV4String::parse("293279f3-d459-4bfd-aeeb-604799e96925")?,
        },
        stream: NcpStreamPositionV1 {
            epoch: GateOutputEpoch::new(CanonicalUuidV4String::parse(
                "3ef6f0ad-8ee6-4c6a-9e3f-86dc9ce849a1",
            )?),
            seq: OutputSeq::new(output_sequence),
        },
        source: NcpSourceRefV1 {
            source_key: BoundedAscii::new("haldir-ncp/session/uav-1/sensor/pose")?,
            stream_epoch: CanonicalUuidV4String::parse("7d61c9ba-4e1d-4aab-8ae6-08e05206aa67")?,
            stream_seq: SourceSeq::new(
                NonZeroU64::new(sequence)
                    .ok_or_else(|| campaign_error("source sequence must be nonzero"))?,
            ),
        },
        frame_id: BoundedAscii::new("map")?,
        source_t_ns: sequence.saturating_mul(1_000_000),
        gate_t_ns: sequence.saturating_mul(1_000_000).saturating_add(1),
        action: RequestedActionV1::Hold {
            requested_validity_ms: validity,
        },
        effective_validity_ms: validity.get(),
    })
}

fn build_frames() -> CampaignResult<BTreeMap<&'static str, ExactNcpCommandFrame>> {
    let adapter = RealNcp08Adapter::new();
    FINAL_CASES
        .iter()
        .map(|(sequence, case_id)| {
            let input = build_input(*sequence)?;
            let frame = adapter
                .build_command(&input)
                .map_err(|error| campaign_error(error.as_str()))?;
            adapter
                .validate_exact_command(&frame, &input)
                .map_err(|error| campaign_error(error.as_str()))?;
            Ok((*case_id, frame))
        })
        .collect()
}

fn attempt(
    case_id: &str,
    sender: &str,
    route: &str,
    expected_receivers: &[&str],
    local_put_ok: Option<bool>,
) -> Value {
    json!({
        "case_id": case_id,
        "sender": sender,
        "route": route,
        "expected_receivers": expected_receivers,
        "local_put_ok": local_put_ok,
        "operation": "put",
    })
}

async fn raw_put(session: &Session, route: &str, payload: Vec<u8>) -> bool {
    session
        .put(route, payload)
        .encoding(Encoding::APPLICATION_JSON)
        .congestion_control(CongestionControl::Block)
        .priority(Priority::RealTime)
        .express(true)
        .allowed_destination(Locality::Remote)
        .await
        .is_ok()
}

async fn intent_put(session: &Session, route: &str, case_id: &str) -> bool {
    session
        .put(route, case_id.as_bytes().to_vec())
        .congestion_control(CongestionControl::Block)
        .allowed_destination(Locality::Remote)
        .await
        .is_ok()
}

async fn wait_for_final(
    receiver: &mut mpsc::Receiver<Observation>,
    observations: &mut Vec<Observation>,
    case_id: &str,
) -> CampaignResult<()> {
    let expected = BTreeSet::from(["observer", "robot-crebain"]);
    let deadline = Instant::now() + POSITIVE_TIMEOUT;
    loop {
        let seen = observations
            .iter()
            .filter(|observation| observation.case_id == case_id)
            .map(|observation| observation.receiver.as_str())
            .collect::<BTreeSet<_>>();
        if seen == expected {
            return Ok(());
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(campaign_error(format!(
                "timed out waiting for allowed receivers of {case_id}"
            )));
        }
        let next = timeout(remaining, receiver.recv())
            .await
            .map_err(|_| campaign_error(format!("timed out waiting for {case_id}")))?
            .ok_or_else(|| campaign_error("final callback channel closed"))?;
        observations.push(next);
    }
}

async fn receive_intent(
    ingress: &mut IntentIngress,
    receiver_route: &str,
    expected_case_id: &str,
    observations: &mut Vec<Observation>,
) -> CampaignResult<()> {
    let event = timeout(POSITIVE_TIMEOUT, ingress.recv())
        .await
        .map_err(|_| campaign_error(format!("timed out waiting for {expected_case_id}")))?
        .ok_or_else(|| campaign_error("intent ingress closed"))?;
    let case_id = String::from_utf8(event.bytes)?;
    if event.actual_key != receiver_route || case_id != expected_case_id {
        return Err(campaign_error(format!(
            "unexpected intent delivery: key={} case_id={case_id}",
            event.actual_key
        )));
    }
    observations.push(Observation {
        receiver: "gate".to_owned(),
        route: event.actual_key,
        case_id,
    });
    Ok(())
}

async fn drain_quiesced_final(
    receiver: &mut mpsc::Receiver<Observation>,
    observations: &mut Vec<Observation>,
) -> CampaignResult<()> {
    timeout(POSITIVE_TIMEOUT, async {
        while let Some(observation) = receiver.recv().await {
            observations.push(observation);
        }
    })
    .await
    .map_err(|_| campaign_error("final callback channel did not quiesce"))?;
    Ok(())
}

fn drain_intent_events(
    events: Vec<IntentIngressEvent>,
    route: &str,
    observations: &mut Vec<Observation>,
) {
    for event in events {
        let case_id =
            String::from_utf8(event.bytes).unwrap_or_else(|_| "invalid-intent-payload".to_owned());
        observations.push(Observation {
            receiver: "gate".to_owned(),
            route: if event.actual_key.is_empty() {
                route.to_owned()
            } else {
                event.actual_key
            },
            case_id,
        });
    }
}

fn assert_intent_ingress_counters(
    label: &str,
    counters: IngressCountersSnapshot,
) -> CampaignResult<()> {
    if counters.accepted != 2
        || counters.unexpected_key_dropped != 0
        || counters.oversize_dropped != 0
        || counters.queue_full_dropped != 0
        || counters.non_put_dropped != 0
        || counters.receiver_closed_dropped != 0
    {
        return Err(campaign_error(format!(
            "unexpected {label} intent ingress counters: {counters:?}"
        )));
    }
    Ok(())
}

fn assert_exact_observations(
    observations: &[Observation],
    final_route: &str,
    intent_a: &str,
    intent_b: &str,
) -> CampaignResult<()> {
    let expected = BTreeSet::from([
        ("robot-crebain", final_route, FINAL_POSITIVE_PRE),
        ("observer", final_route, FINAL_POSITIVE_PRE),
        ("robot-crebain", final_route, FINAL_POSITIVE_POST),
        ("observer", final_route, FINAL_POSITIVE_POST),
        ("gate", intent_a, INTENT_A_POSITIVE_PRE),
        ("gate", intent_a, INTENT_A_POSITIVE_POST),
        ("gate", intent_b, INTENT_B_POSITIVE_PRE),
        ("gate", intent_b, INTENT_B_POSITIVE_POST),
    ]);
    let actual = observations
        .iter()
        .map(|observation| {
            (
                observation.receiver.as_str(),
                observation.route.as_str(),
                observation.case_id.as_str(),
            )
        })
        .collect::<BTreeSet<_>>();
    if observations.len() != expected.len() || actual != expected {
        return Err(campaign_error(format!(
            "receiver observations differ: expected={expected:?} actual={actual:?}"
        )));
    }
    Ok(())
}

async fn no_certificate_is_rejected(config_dir: &Path) -> CampaignResult<bool> {
    let config = Config::from_file(config_dir.join("no-certificate.json"))?;
    match zenoh::open(config).await {
        Ok(session) => {
            session.close().await?;
            Ok(false)
        }
        Err(_) => Ok(true),
    }
}

async fn run_campaign(config_dir: &Path) -> CampaignResult<CampaignOutput> {
    let sessions = open_sessions(config_dir).await?;
    let session_records = sessions.records();
    assert_unique_sessions(&session_records)?;

    let keys = HaldirKeys::try_new(REALM, SESSION_ID)?;
    let final_route = keys.final_command().to_owned();
    let intent_a = keys.intent("controller-a")?;
    let intent_b = keys.intent("controller-b")?;
    let frames = build_frames()?;
    let publisher = FinalCommandPublisher::new(&sessions.gate_final, &keys);
    if publisher.route() != final_route {
        return Err(campaign_error(
            "typed publisher route differs from pinned NCP route",
        ));
    }

    let overflow = Arc::new(AtomicBool::new(false));
    let (callback_sender, mut callback_receiver) = mpsc::channel(CALLBACK_CAPACITY);
    let robot_subscriber = sessions
        .robot_receiver
        .declare_subscriber(final_route.clone())
        .allowed_origin(Locality::Remote)
        .callback(callback(
            "robot-crebain",
            callback_sender.clone(),
            overflow.clone(),
        ))
        .await?;
    let observer_subscriber = sessions
        .observer_receiver
        .declare_subscriber(final_route.clone())
        .allowed_origin(Locality::Remote)
        .callback(callback(
            "observer",
            callback_sender.clone(),
            overflow.clone(),
        ))
        .await?;
    let controller_subscriber = sessions
        .controller_a_receiver
        .declare_subscriber(final_route.clone())
        .allowed_origin(Locality::Remote)
        .callback(callback("controller-a", callback_sender, overflow.clone()))
        .await?;
    let limits = IngressLimits::new(16 * 1024, 16)?;
    let mut ingress_a =
        IntentIngress::declare(&sessions.gate_intent, &keys, "controller-a", limits).await?;
    let mut ingress_b =
        IntentIngress::declare(&sessions.gate_intent, &keys, "controller-b", limits).await?;
    tokio::time::sleep(DECLARATION_SETTLE).await;

    let no_certificate_rejected = no_certificate_is_rejected(config_dir).await?;
    if !no_certificate_rejected {
        return Err(campaign_error(
            "router admitted the deliberately certificate-less client",
        ));
    }

    let mut attempts = vec![json!({
        "case_id": CONTROLLER_A_FINAL_SUBSCRIBE_DENIED,
        "sender": "controller-a",
        "route": final_route,
        "expected_receivers": [],
        "local_put_ok": null,
        "local_declare_ok": true,
        "operation": "subscribe",
    })];
    let mut observations = Vec::new();

    let pre = frames
        .get(FINAL_POSITIVE_PRE)
        .ok_or_else(|| campaign_error("missing pre-positive frame"))?;
    publisher.publish(pre).await?;
    attempts.push(attempt(
        FINAL_POSITIVE_PRE,
        "gate",
        &final_route,
        &["observer", "robot-crebain"],
        Some(true),
    ));
    wait_for_final(
        &mut callback_receiver,
        &mut observations,
        FINAL_POSITIVE_PRE,
    )
    .await?;

    let final_denials = [
        (
            "final-denied-admission-authority",
            "admission-authority",
            &sessions.admission,
        ),
        (
            "final-denied-controller-a",
            "controller-a",
            &sessions.controller_a,
        ),
        (
            "final-denied-controller-b",
            "controller-b",
            &sessions.controller_b,
        ),
        ("final-denied-lifecycle", "lifecycle", &sessions.lifecycle),
        (
            "final-denied-mission-authority",
            "mission-authority",
            &sessions.mission_authority,
        ),
        (
            "final-denied-observer",
            "observer",
            &sessions.observer_attacker,
        ),
        (
            "final-denied-robot-crebain",
            "robot-crebain",
            &sessions.robot_attacker,
        ),
    ];
    for (case_id, principal, session) in final_denials {
        let frame = frames
            .get(case_id)
            .ok_or_else(|| campaign_error(format!("missing denial frame: {case_id}")))?;
        let local_put_ok = raw_put(session, &final_route, frame.bytes().to_vec()).await;
        attempts.push(attempt(
            case_id,
            principal,
            &final_route,
            &[],
            Some(local_put_ok),
        ));
        if !local_put_ok {
            return Err(campaign_error(format!(
                "local Zenoh PUT failed before ACL observation: {case_id}"
            )));
        }
    }

    let post = frames
        .get(FINAL_POSITIVE_POST)
        .ok_or_else(|| campaign_error("missing post-positive frame"))?;
    publisher.publish(post).await?;
    attempts.push(attempt(
        FINAL_POSITIVE_POST,
        "gate",
        &final_route,
        &["observer", "robot-crebain"],
        Some(true),
    ));
    wait_for_final(
        &mut callback_receiver,
        &mut observations,
        FINAL_POSITIVE_POST,
    )
    .await?;

    let intent_a_pre_ok =
        intent_put(&sessions.controller_a, &intent_a, INTENT_A_POSITIVE_PRE).await;
    attempts.push(attempt(
        INTENT_A_POSITIVE_PRE,
        "controller-a",
        &intent_a,
        &["gate"],
        Some(intent_a_pre_ok),
    ));
    if !intent_a_pre_ok {
        return Err(campaign_error("controller A positive intent PUT failed"));
    }
    receive_intent(
        &mut ingress_a,
        &intent_a,
        INTENT_A_POSITIVE_PRE,
        &mut observations,
    )
    .await?;

    let intent_a_cross_ok = intent_put(
        &sessions.controller_b,
        &intent_a,
        INTENT_A_DENIED_CONTROLLER_B,
    )
    .await;
    attempts.push(attempt(
        INTENT_A_DENIED_CONTROLLER_B,
        "controller-b",
        &intent_a,
        &[],
        Some(intent_a_cross_ok),
    ));
    if !intent_a_cross_ok {
        return Err(campaign_error(
            "controller B cross-route PUT failed locally",
        ));
    }

    let intent_a_post_ok =
        intent_put(&sessions.controller_a, &intent_a, INTENT_A_POSITIVE_POST).await;
    attempts.push(attempt(
        INTENT_A_POSITIVE_POST,
        "controller-a",
        &intent_a,
        &["gate"],
        Some(intent_a_post_ok),
    ));
    if !intent_a_post_ok {
        return Err(campaign_error(
            "controller A post-positive intent PUT failed",
        ));
    }
    receive_intent(
        &mut ingress_a,
        &intent_a,
        INTENT_A_POSITIVE_POST,
        &mut observations,
    )
    .await?;

    let intent_b_pre_ok =
        intent_put(&sessions.controller_b, &intent_b, INTENT_B_POSITIVE_PRE).await;
    attempts.push(attempt(
        INTENT_B_POSITIVE_PRE,
        "controller-b",
        &intent_b,
        &["gate"],
        Some(intent_b_pre_ok),
    ));
    if !intent_b_pre_ok {
        return Err(campaign_error("controller B positive intent PUT failed"));
    }
    receive_intent(
        &mut ingress_b,
        &intent_b,
        INTENT_B_POSITIVE_PRE,
        &mut observations,
    )
    .await?;

    let intent_b_cross_ok = intent_put(
        &sessions.controller_a,
        &intent_b,
        INTENT_B_DENIED_CONTROLLER_A,
    )
    .await;
    attempts.push(attempt(
        INTENT_B_DENIED_CONTROLLER_A,
        "controller-a",
        &intent_b,
        &[],
        Some(intent_b_cross_ok),
    ));
    if !intent_b_cross_ok {
        return Err(campaign_error(
            "controller A cross-route PUT failed locally",
        ));
    }

    let intent_b_post_ok =
        intent_put(&sessions.controller_b, &intent_b, INTENT_B_POSITIVE_POST).await;
    attempts.push(attempt(
        INTENT_B_POSITIVE_POST,
        "controller-b",
        &intent_b,
        &["gate"],
        Some(intent_b_post_ok),
    ));
    if !intent_b_post_ok {
        return Err(campaign_error(
            "controller B post-positive intent PUT failed",
        ));
    }
    receive_intent(
        &mut ingress_b,
        &intent_b,
        INTENT_B_POSITIVE_POST,
        &mut observations,
    )
    .await?;

    tokio::time::sleep(QUARANTINE).await;
    robot_subscriber.undeclare().await?;
    observer_subscriber.undeclare().await?;
    controller_subscriber.undeclare().await?;
    let (remaining_a, counters_a) = ingress_a.undeclare_and_drain().await?;
    let (remaining_b, counters_b) = ingress_b.undeclare_and_drain().await?;
    drain_quiesced_final(&mut callback_receiver, &mut observations).await?;
    drain_intent_events(remaining_a, &intent_a, &mut observations);
    drain_intent_events(remaining_b, &intent_b, &mut observations);
    assert_intent_ingress_counters("controller-a", counters_a)?;
    assert_intent_ingress_counters("controller-b", counters_b)?;
    let callback_overflow = overflow.load(Ordering::Relaxed);
    if callback_overflow {
        return Err(campaign_error("bounded callback channel overflowed"));
    }
    assert_exact_observations(&observations, &final_route, &intent_a, &intent_b)?;

    let denied_case_ids = vec![
        "final-denied-admission-authority",
        "final-denied-controller-a",
        "final-denied-controller-b",
        "final-denied-lifecycle",
        "final-denied-mission-authority",
        "final-denied-observer",
        "final-denied-robot-crebain",
        INTENT_A_DENIED_CONTROLLER_B,
        INTENT_B_DENIED_CONTROLLER_A,
        CONTROLLER_A_FINAL_SUBSCRIBE_DENIED,
    ];

    drop(publisher);
    sessions.close().await?;

    Ok(CampaignOutput {
        sessions: session_records,
        attempts,
        observations,
        denied_case_ids,
        no_certificate_rejected,
        callback_overflow,
    })
}

fn write_result(path: &Path, run_id: &str, output: CampaignOutput) -> CampaignResult<()> {
    let document = json!({
        "schema_version": 1,
        "status": "pass",
        "run_id": run_id,
        "quarantine_ms": QUARANTINE.as_millis(),
        "no_certificate_rejected": output.no_certificate_rejected,
        "callback_overflow": output.callback_overflow,
        "sessions": output.sessions,
        "attempts": output.attempts,
        "observations": output
            .observations
            .iter()
            .map(Observation::to_json)
            .collect::<Vec<_>>(),
        "denied_case_ids": output.denied_case_ids,
    });
    let bytes = serde_json::to_vec_pretty(&document)?;
    let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
    file.write_all(&bytes)?;
    file.write_all(b"\n")?;
    file.sync_all()?;
    Ok(())
}

#[tokio::main(flavor = "multi_thread", worker_threads = 2)]
async fn main() -> CampaignResult<()> {
    let config_dir = required_env_path("HALDIR_LIVE_ACL_CONFIG_DIR")?;
    let result_path = required_env_path("HALDIR_LIVE_ACL_RESULT_PATH")?;
    let run = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let run_id = format!("haldir-live-acl-{run}");
    let output = run_campaign(&config_dir).await?;
    write_result(&result_path, &run_id, output)?;
    println!(
        "CAMPAIGN_PASS run_id={run_id} result={}",
        result_path.display()
    );
    Ok(())
}
