//! Fallible exact route builders for one NCP session.

use std::fmt;

use ncp_core::Keys;

/// Maximum complete route length accepted by Haldir signed routing fields.
const MAX_ROUTE_BYTES: usize = 256;
/// Maximum signed Haldir realm length (one exact route segment).
const MAX_REALM_BYTES: usize = 64;
/// Maximum NCP session-id length, matching Haldir's signed session contract.
const MAX_SESSION_BYTES: usize = 64;
/// Maximum controller or named-state route segment.
const MAX_ENTITY_BYTES: usize = 64;

/// Failure to construct one exact, bounded route.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HaldirKeyError {
    /// Realm is empty, too long, or contains an unsafe NCP key segment.
    InvalidRealm,
    /// Session id is empty, too long, or contains key-expression syntax.
    InvalidSession,
    /// Controller or named state segment is empty, too long, or unsafe.
    InvalidEntity,
    /// The resulting exact route exceeds Haldir's signed routing bound.
    RouteTooLong,
    /// The pinned NCP builder rejected the requested standard route.
    NcpRoute,
}

impl fmt::Display for HaldirKeyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::InvalidRealm => "invalid NCP realm",
            Self::InvalidSession => "invalid NCP session id",
            Self::InvalidEntity => "invalid route entity",
            Self::RouteTooLong => "complete route exceeds the signed routing bound",
            Self::NcpRoute => "pinned NCP rejected the route",
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for HaldirKeyError {}

/// Exact Haldir and NCP routes scoped to one validated realm/session pair.
///
/// Standard NCP routes are always obtained from the pinned [`ncp_core::Keys`]
/// implementation. Haldir extension routes share the already-validated NCP
/// realm and session prefix and contain no wildcard-bearing caller input.
#[derive(Debug, Clone)]
pub struct HaldirKeys {
    ncp: Keys,
    session_id: String,
    session_prefix: String,
    final_command: String,
    decision: String,
    challenge: String,
    application: String,
}

impl HaldirKeys {
    /// Construct a bounded exact route set from deployment input.
    ///
    /// # Errors
    /// Rejects unsafe/overlength realm or session values and any standard NCP
    /// command route that the exact pinned builder refuses.
    pub fn try_new(realm: &str, session_id: &str) -> Result<Self, HaldirKeyError> {
        // Haldir's signed realm field is `AsciiId<64>`, so a multi-segment NCP
        // prefix cannot be bound to the lease/intent scope even though NCP's
        // generic builder accepts one. Keep the transport route representable by
        // the signed contract instead of creating an uncheckable deployment.
        if !valid_haldir_id(realm, MAX_REALM_BYTES) {
            return Err(HaldirKeyError::InvalidRealm);
        }
        let ncp = Keys::try_new(realm).map_err(|_| HaldirKeyError::InvalidRealm)?;
        validate_entity(session_id, MAX_SESSION_BYTES)
            .map_err(|_| HaldirKeyError::InvalidSession)?;
        let final_command = ncp
            .try_command(session_id)
            .map_err(|_| HaldirKeyError::NcpRoute)?;
        check_route(&final_command)?;
        let suffix = "/command";
        let session_prefix = final_command
            .strip_suffix(suffix)
            .ok_or(HaldirKeyError::NcpRoute)?
            .to_owned();
        let decision = extension_route(&session_prefix, "decision")?;
        let challenge = extension_route(&session_prefix, "challenge")?;
        let application = extension_route(&session_prefix, "application")?;
        Ok(Self {
            ncp,
            session_id: session_id.to_owned(),
            session_prefix,
            final_command,
            decision,
            challenge,
            application,
        })
    }

    /// Validated NCP realm prefix.
    #[must_use]
    pub fn realm(&self) -> &str {
        self.ncp.realm()
    }

    /// Validated NCP session id.
    #[must_use]
    pub fn session_id(&self) -> &str {
        &self.session_id
    }

    /// Exact controller intent route.
    ///
    /// # Errors
    /// Rejects an unsafe controller segment or an overlength complete route.
    pub fn intent(&self, controller_id: &str) -> Result<String, HaldirKeyError> {
        validate_entity(controller_id, MAX_ENTITY_BYTES)?;
        let route = format!("{}/haldir/intent/{controller_id}", self.session_prefix);
        check_route(&route)?;
        Ok(route)
    }

    /// Exact Gate decision-evidence route.
    #[must_use]
    pub fn decision(&self) -> &str {
        &self.decision
    }

    /// Exact Gate challenge route.
    #[must_use]
    pub fn challenge(&self) -> &str {
        &self.challenge
    }

    /// Exact named NCP sensor/state route, delegated to the pinned NCP builder.
    ///
    /// # Errors
    /// Rejects an unsafe source segment or an overlength complete route.
    pub fn state(&self, source_name: &str) -> Result<String, HaldirKeyError> {
        validate_entity(source_name, MAX_ENTITY_BYTES)?;
        let route = self
            .ncp
            .try_sensor_named(&self.session_id, source_name)
            .map_err(|_| HaldirKeyError::NcpRoute)?;
        check_route(&route)?;
        Ok(route)
    }

    /// Exact Crebain application-evidence route.
    #[must_use]
    pub fn application(&self) -> &str {
        &self.application
    }

    /// Exact standard NCP base command route built by pinned `ncp-core`.
    #[must_use]
    pub fn final_command(&self) -> &str {
        &self.final_command
    }
}

fn validate_entity(value: &str, max_bytes: usize) -> Result<(), HaldirKeyError> {
    if !valid_haldir_id(value, max_bytes) {
        Err(HaldirKeyError::InvalidEntity)
    } else {
        Ok(())
    }
}

fn valid_haldir_id(value: &str, max_bytes: usize) -> bool {
    !value.is_empty()
        && value.len() <= max_bytes
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b':'))
}

fn extension_route(session_prefix: &str, leaf: &str) -> Result<String, HaldirKeyError> {
    let route = format!("{session_prefix}/haldir/{leaf}");
    check_route(&route)?;
    Ok(route)
}

fn check_route(route: &str) -> Result<(), HaldirKeyError> {
    if route.len() > MAX_ROUTE_BYTES {
        Err(HaldirKeyError::RouteTooLong)
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_routes_match_pinned_ncp_and_haldir_profiles() {
        let keys = HaldirKeys::try_new("range-a", "sess-1").unwrap();

        assert_eq!(
            keys.final_command(),
            ncp_core::Keys::try_new("range-a")
                .unwrap()
                .try_command("sess-1")
                .unwrap()
        );
        assert_eq!(
            keys.intent("survey-v1").unwrap(),
            "range-a/session/sess-1/haldir/intent/survey-v1"
        );
        assert_eq!(
            keys.state("pose").unwrap(),
            "range-a/session/sess-1/sensor/pose"
        );
        assert_eq!(keys.decision(), "range-a/session/sess-1/haldir/decision");
        assert_eq!(keys.challenge(), "range-a/session/sess-1/haldir/challenge");
        assert_eq!(
            keys.application(),
            "range-a/session/sess-1/haldir/application"
        );
    }

    #[test]
    fn unsafe_or_overlength_inputs_never_widen_routes() {
        assert_eq!(
            HaldirKeys::try_new("range/**", "sess-1").unwrap_err(),
            HaldirKeyError::InvalidRealm
        );
        assert_eq!(
            HaldirKeys::try_new("range/a", "sess-1").unwrap_err(),
            HaldirKeyError::InvalidRealm
        );
        assert_eq!(
            HaldirKeys::try_new("é", "sess-1").unwrap_err(),
            HaldirKeyError::InvalidRealm
        );
        assert_eq!(
            HaldirKeys::try_new("range-a", "sess/other").unwrap_err(),
            HaldirKeyError::InvalidSession
        );
        let keys = HaldirKeys::try_new("range-a", "sess-1").unwrap();
        assert_eq!(
            keys.intent("controller/*").unwrap_err(),
            HaldirKeyError::InvalidEntity
        );
        assert_eq!(
            keys.intent("controller!").unwrap_err(),
            HaldirKeyError::InvalidEntity
        );
        assert_eq!(
            keys.state(&"x".repeat(MAX_ENTITY_BYTES + 1)).unwrap_err(),
            HaldirKeyError::InvalidEntity
        );
    }

    #[test]
    fn complete_signed_route_bound_is_enforced_defensively() {
        assert_eq!(
            check_route(&"x".repeat(MAX_ROUTE_BYTES + 1)).unwrap_err(),
            HaldirKeyError::RouteTooLong
        );
    }
}
