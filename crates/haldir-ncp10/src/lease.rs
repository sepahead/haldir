//! The commander lease that Gate carries on every NCP 1.0 command.
//!
//! NCP 1.0 rejects an Active command without an authority lease. Under
//! `1.0.0-rc.1` the commander issues its own lease and the body's authority
//! machine enforces it; NCP ADR-006 later moves issuance to the body.
//! [`NcpCommanderLease`] issues the lease to the transport principal and final
//! route named by Gate's exclusive-route ACL evidence, so NCP authority never
//! reaches beyond what the deployment already granted.
//!
//! The body returns no authority feedback under rc.1, so the lease needs none:
//!
//! - A lease never changes. Every command carries it unchanged.
//! - Once two thirds of its interval has elapsed, the next command carries a
//!   newer term with a fresh lease id and interval. NCP accepts a newer term as
//!   a transfer from the holder while the old lease is live, and as a fresh
//!   acquisition once it has lapsed.
//! - Gate never renews in place. NCP refuses to renew a lapsed lease, so a lost
//!   renewal could leave Gate holding a lease that the body has let lapse. A
//!   newer term is accepted in either case: lost commands never cost authority.
//!
//! A term must exceed every term the body has seen in the session, including
//! the terms of earlier Gate boots. Terms therefore come from Gate's durable
//! boot counter: `term = boot_counter · 2^24 + n`, where `n ≥ 1` counts the
//! acquisitions of this boot. No term repeats, and none needs a durable write.
//!
//! Acquisition needs UTC, for the lease's audit bounds, and entropy, for its id.
//! Without them no term is acquired, and a lease already held stays in use
//! until its deadline.

use core::num::NonZeroU64;

use haldir_contracts::digest::DigestV1;
use haldir_contracts::ids::{GateId, GateOutputEpoch, PrincipalId};
use haldir_contracts::scalar::CanonicalUuidV4String;
use haldir_contracts::session::NcpSessionIdentityV1;
use haldir_contracts::status::{AclExclusiveEvidenceV1, NcpLeaseEvidenceV1};

use crate::adapter::{
    NCP_JSON_SAFE_INTEGER_MAX, NCP_MAX_AUTHORITY_LEASE_MS, NCP_MAX_CLOCK_UNCERTAINTY_MS,
};

/// Terms available to one Gate boot: the low 24 bits of a term.
const TERMS_PER_BOOT: u64 = 1 << 24;
const NANOS_PER_MS: u64 = 1_000_000;

/// The interval of a Gate-issued commander lease.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct NcpLeaseInterval(u64);

impl NcpLeaseInterval {
    /// The shortest interval. Its final third, in which Gate already rotates to
    /// a newer term, spans NCP's bound on commander–body clock disagreement.
    pub const MIN: Self = Self(3 * NCP_MAX_CLOCK_UNCERTAINTY_MS);
    /// The longest interval NCP 1.0 accepts.
    pub const MAX: Self = Self(NCP_MAX_AUTHORITY_LEASE_MS);
    /// Half of NCP's maximum.
    pub const DEFAULT: Self = Self(NCP_MAX_AUTHORITY_LEASE_MS / 2);

    /// An interval of `ms` milliseconds, or `None` outside
    /// [`Self::MIN`]`..=`[`Self::MAX`].
    #[must_use]
    pub const fn from_millis(ms: u64) -> Option<Self> {
        if Self::MIN.0 <= ms && ms <= Self::MAX.0 {
            Some(Self(ms))
        } else {
            None
        }
    }

    /// The interval in milliseconds.
    #[must_use]
    pub const fn as_millis(self) -> u64 {
        self.0
    }

    /// The final third of the interval, in which Gate rotates to a newer term.
    /// While Gate can acquire terms, every lease it carries outlives a command
    /// validity of at most this length.
    #[must_use]
    pub const fn rotation_margin_ms(self) -> u64 {
        self.0 / 3
    }
}

impl Default for NcpLeaseInterval {
    fn default() -> Self {
        Self::DEFAULT
    }
}

/// The NCP commander lease of one Gate boot on one plant session.
#[derive(Debug, Clone)]
pub struct NcpCommanderLease {
    principal: PrincipalId,
    final_route_digest: DigestV1,
    holder_entity: GateId,
    session: NcpSessionIdentityV1,
    output_epoch: GateOutputEpoch,
    interval: NcpLeaseInterval,
    next_term: NonZeroU64,
    term_end: u64,
    current: Option<NcpLeaseEvidenceV1>,
}

impl NcpCommanderLease {
    /// The lease that `gate` holds on `session` for `output_epoch`, issued to the
    /// principal and route that `route` authorizes, with terms drawn from the
    /// durable `boot_counter`. `None` once that counter has outgrown the
    /// JSON-safe term space, after 2^29 boots.
    #[must_use]
    pub fn new(
        route: &AclExclusiveEvidenceV1,
        gate: &GateId,
        session: NcpSessionIdentityV1,
        output_epoch: GateOutputEpoch,
        interval: NcpLeaseInterval,
        boot_counter: u64,
    ) -> Option<Self> {
        let first = boot_counter.checked_mul(TERMS_PER_BOOT)?;
        let term_end = first
            .checked_add(TERMS_PER_BOOT)
            .filter(|end| *end <= NCP_JSON_SAFE_INTEGER_MAX + 1)?;
        Some(Self {
            principal: route.gate_transport_principal.clone(),
            final_route_digest: route.final_route_digest,
            holder_entity: gate.clone(),
            session,
            output_epoch,
            interval,
            next_term: NonZeroU64::MIN.saturating_add(first),
            term_end,
            current: None,
        })
    }

    /// The lease the next command carries at Gate-local monotonic time `now_ns`.
    ///
    /// A newer term is acquired when no lease is held or the held one has entered
    /// the final third of its interval. Acquisition needs `utc_ms`, the current
    /// UTC time, and `entropy`, which yields 16 random bytes for the lease id and
    /// is called only to acquire. When either is missing, a lease already held
    /// stays in use until its deadline.
    pub fn for_command(
        &mut self,
        now_ns: u64,
        utc_ms: Option<u64>,
        entropy: impl FnOnce() -> Option<[u8; 16]>,
    ) -> Option<&NcpLeaseEvidenceV1> {
        let remaining_ns = self
            .current
            .as_ref()
            .and_then(|lease| lease.expires_mono_ns)
            .map_or(0, |deadline| deadline.saturating_sub(now_ns));
        if remaining_ns <= self.interval.rotation_margin_ms() * NANOS_PER_MS {
            if let Some(next) = utc_ms.and_then(|utc_ms| self.acquire(now_ns, utc_ms, entropy)) {
                self.current = Some(next);
            } else if remaining_ns == 0 {
                self.current = None;
            }
        }
        self.current.as_ref()
    }

    fn acquire(
        &mut self,
        now_ns: u64,
        utc_ms: u64,
        entropy: impl FnOnce() -> Option<[u8; 16]>,
    ) -> Option<NcpLeaseEvidenceV1> {
        let term = self.next_term;
        if term.get() >= self.term_end {
            return None;
        }
        let interval_ms = self.interval.as_millis();
        let expires_at_utc_ms = utc_ms
            .checked_add(interval_ms)
            .filter(|ms| *ms <= NCP_JSON_SAFE_INTEGER_MAX)?;
        let expires_mono_ns = now_ns.checked_add(interval_ms * NANOS_PER_MS)?;
        let lease_id = CanonicalUuidV4String::from_random_bytes(entropy()?);
        self.next_term = term.saturating_add(1);
        Some(NcpLeaseEvidenceV1 {
            gate_transport_principal: self.principal.clone(),
            final_route_digest: self.final_route_digest,
            session: self.session.clone(),
            authority_term: term,
            lease_id,
            authorized_output_epoch: self.output_epoch,
            expires_mono_ns: Some(expires_mono_ns),
            issuer_principal: self.principal.clone(),
            holder_entity: self.holder_entity.clone(),
            issued_at_utc_ms: utc_ms,
            expires_at_utc_ms,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use haldir_contracts::digest::DigestDomain;
    use haldir_contracts::scalar::AsciiId;
    use proptest::prelude::*;

    const UTC0: u64 = 1_700_000_000_000;

    fn route() -> AclExclusiveEvidenceV1 {
        AclExclusiveEvidenceV1 {
            gate_transport_principal: PrincipalId::new("gate.transport").unwrap(),
            final_route_digest: DigestV1::compute(DigestDomain::TransportKey, b"route"),
            certificate_fingerprint: DigestV1::compute(DigestDomain::Payload, b"certificate"),
            acl_policy_digest: DigestV1::compute(DigestDomain::Payload, b"acl"),
            verified_at_mono_ns: 0,
        }
    }

    fn session() -> NcpSessionIdentityV1 {
        NcpSessionIdentityV1 {
            session_id: AsciiId::new("sess-1").unwrap(),
            generation: CanonicalUuidV4String::from_random_bytes([1; 16]),
        }
    }

    fn epoch() -> GateOutputEpoch {
        GateOutputEpoch::new(CanonicalUuidV4String::from_random_bytes([5; 16]))
    }

    fn commander(boot_counter: u64) -> NcpCommanderLease {
        NcpCommanderLease::new(
            &route(),
            &GateId::new("gate-a").unwrap(),
            session(),
            epoch(),
            NcpLeaseInterval::DEFAULT,
            boot_counter,
        )
        .unwrap()
    }

    /// The lease carried at `at_ms`, with UTC and entropy available.
    fn carried(lease: &mut NcpCommanderLease, at_ms: u64) -> NcpLeaseEvidenceV1 {
        let seed = u8::try_from(at_ms / 1_000 % 251).unwrap();
        lease
            .for_command(at_ms * NANOS_PER_MS, Some(UTC0 + at_ms), || {
                Some([seed; 16])
            })
            .cloned()
            .unwrap()
    }

    #[test]
    fn intervals_follow_ncp_bounds() {
        assert_eq!(NcpLeaseInterval::MIN.as_millis(), 15_000);
        assert_eq!(NcpLeaseInterval::MAX.as_millis(), 60_000);
        assert_eq!(NcpLeaseInterval::default().as_millis(), 30_000);
        assert_eq!(NcpLeaseInterval::DEFAULT.rotation_margin_ms(), 10_000);
        assert_eq!(NcpLeaseInterval::from_millis(14_999), None);
        assert_eq!(NcpLeaseInterval::from_millis(60_001), None);
        assert_eq!(
            NcpLeaseInterval::from_millis(15_000),
            Some(NcpLeaseInterval::MIN)
        );
        assert_eq!(
            NcpLeaseInterval::from_millis(60_000),
            Some(NcpLeaseInterval::MAX)
        );
    }

    #[test]
    fn the_first_command_acquires_a_lease_bound_to_the_gate() {
        let lease = carried(&mut commander(3), 10);
        assert_eq!(lease.authority_term.get(), 3 * TERMS_PER_BOOT + 1);
        assert_eq!(
            lease.gate_transport_principal,
            route().gate_transport_principal
        );
        assert_eq!(lease.issuer_principal, route().gate_transport_principal);
        assert_eq!(lease.final_route_digest, route().final_route_digest);
        assert_eq!(lease.holder_entity.as_str(), "gate-a");
        assert_eq!(lease.session, session());
        assert_eq!(lease.authorized_output_epoch, epoch());
        assert_eq!(lease.issued_at_utc_ms, UTC0 + 10);
        assert_eq!(lease.expires_at_utc_ms, UTC0 + 10 + 30_000);
        assert_eq!(lease.expires_mono_ns, Some((10 + 30_000) * NANOS_PER_MS));
    }

    #[test]
    fn a_lease_is_carried_unchanged_until_its_final_third() {
        let mut lease = commander(1);
        let first = carried(&mut lease, 0);
        assert_eq!(carried(&mut lease, 19_999), first);
        let second = carried(&mut lease, 20_000);
        assert_eq!(second.authority_term.get(), first.authority_term.get() + 1);
        assert_ne!(second.lease_id, first.lease_id);
        assert_eq!(second.issued_at_utc_ms, UTC0 + 20_000);
        assert_eq!(second.expires_mono_ns, Some(50_000 * NANOS_PER_MS));
    }

    #[test]
    fn a_lapsed_lease_is_replaced_by_a_newer_term() {
        let mut lease = commander(1);
        let first = carried(&mut lease, 0);
        let after_lapse = carried(&mut lease, 31_000);
        assert_eq!(
            after_lapse.authority_term.get(),
            first.authority_term.get() + 1
        );
        assert_ne!(after_lapse.lease_id, first.lease_id);
    }

    #[test]
    fn without_utc_or_entropy_no_term_is_acquired() {
        let mut lease = commander(1);
        assert!(lease.for_command(0, None, || Some([1; 16])).is_none());
        assert!(lease.for_command(0, Some(UTC0), || None).is_none());
        // Failed attempts consume no term.
        assert_eq!(
            carried(&mut lease, 0).authority_term.get(),
            TERMS_PER_BOOT + 1
        );
    }

    #[test]
    fn a_held_lease_outlives_a_failed_rotation_but_not_its_deadline() {
        let mut lease = commander(1);
        let first = carried(&mut lease, 0);
        let at = |ms: u64| ms * NANOS_PER_MS;
        assert_eq!(lease.for_command(at(25_000), None, || None), Some(&first));
        assert_eq!(lease.for_command(at(29_999), None, || None), Some(&first));
        assert_eq!(lease.for_command(at(30_000), None, || None), None);
    }

    #[test]
    fn terms_of_a_later_boot_exceed_every_term_of_an_earlier_boot() {
        let mut earlier = commander(7);
        earlier.next_term = NonZeroU64::new(8 * TERMS_PER_BOOT - 1).unwrap();
        let last = carried(&mut earlier, 0);
        assert_eq!(last.authority_term.get(), 8 * TERMS_PER_BOOT - 1);
        // The boot's term space is spent: the lease lapses and nothing replaces it.
        assert!(
            earlier
                .for_command(31_000 * NANOS_PER_MS, Some(UTC0), || Some([2; 16]))
                .is_none()
        );
        let first_of_next = carried(&mut commander(8), 0);
        assert!(first_of_next.authority_term > last.authority_term);
    }

    #[test]
    fn boot_counters_beyond_the_term_space_are_refused() {
        let largest = (NCP_JSON_SAFE_INTEGER_MAX + 1) / TERMS_PER_BOOT - 1;
        let mut last_boot = commander(largest);
        last_boot.next_term = NonZeroU64::new(NCP_JSON_SAFE_INTEGER_MAX).unwrap();
        assert_eq!(
            carried(&mut last_boot, 0).authority_term.get(),
            NCP_JSON_SAFE_INTEGER_MAX
        );
        for boot_counter in [largest + 1, u64::MAX] {
            assert!(
                NcpCommanderLease::new(
                    &route(),
                    &GateId::new("gate-a").unwrap(),
                    session(),
                    epoch(),
                    NcpLeaseInterval::DEFAULT,
                    boot_counter,
                )
                .is_none()
            );
        }
    }

    proptest! {
        /// Over any schedule of commands, clock and entropy outages: every lease
        /// carried is live, terms only grow, a lease id changes exactly when its
        /// term does, and with UTC and entropy available every lease outlives the
        /// rotation margin.
        #[test]
        fn carried_leases_are_live_monotone_and_outlive_the_margin(
            steps in proptest::collection::vec((0u64..40_000, any::<bool>(), any::<bool>()), 1..64)
        ) {
            let mut lease = commander(5);
            let mut now_ms = 0;
            let mut previous: Option<NcpLeaseEvidenceV1> = None;
            for (step, (step_ms, utc_up, entropy_up)) in steps.into_iter().enumerate() {
                now_ms += step_ms;
                let now_ns = now_ms * NANOS_PER_MS;
                let utc = utc_up.then_some(UTC0 + now_ms);
                let seed = u8::try_from(step).unwrap();
                let Some(carried) = lease
                    .for_command(now_ns, utc, || entropy_up.then_some([seed; 16]))
                    .cloned()
                else {
                    prop_assert!(!(utc_up && entropy_up));
                    continue;
                };
                let deadline = carried.expires_mono_ns.unwrap();
                prop_assert!(now_ns < deadline);
                if utc_up && entropy_up {
                    let margin_ns = NcpLeaseInterval::DEFAULT.rotation_margin_ms() * NANOS_PER_MS;
                    prop_assert!(deadline - now_ns > margin_ns);
                }
                if let Some(previous) = &previous {
                    prop_assert!(carried.authority_term >= previous.authority_term);
                    prop_assert_eq!(
                        carried.authority_term == previous.authority_term,
                        carried.lease_id == previous.lease_id
                    );
                }
                previous = Some(carried);
            }
        }
    }
}
