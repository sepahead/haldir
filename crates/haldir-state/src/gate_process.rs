//! Gate process-state machine with guarded transitions (spec §Gate process state).
//!
//! `FaultLatched` is terminal and never auto-clears from a later valid input.

use haldir_contracts::status::GateProcessStateV1 as S;

/// A rejected process-state transition.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InvalidTransition;

/// Whether a transition `from -> to` is permitted. A transition into
/// `FaultLatched` is always permitted; a transition out of it never is.
#[must_use]
pub fn can_transition(from: S, to: S) -> bool {
    if to == S::FaultLatched {
        return from != S::FaultLatched;
    }
    if from == S::FaultLatched {
        return false;
    }
    matches!(
        (from, to),
        (S::Booting, S::Recovering)
            | (S::Recovering, S::ReadyNoSession)
            | (S::ReadyNoSession, S::SessionBound)
            | (S::SessionBound, S::Active)
            | (S::SessionBound, S::ReadyNoSession)
            | (S::Active, S::SessionBound)
            | (S::Active, S::Quiescing)
            | (S::Quiescing, S::SessionBound)
    )
}

/// The guarded Gate process-state machine.
#[derive(Debug, Clone)]
pub struct GateProcessMachine {
    state: S,
}

impl GateProcessMachine {
    /// A machine in `BOOTING`.
    #[must_use]
    pub fn new() -> Self {
        Self { state: S::Booting }
    }

    /// The current state.
    #[must_use]
    pub const fn state(&self) -> S {
        self.state
    }

    /// Attempt a guarded transition.
    ///
    /// # Errors
    /// Returns [`InvalidTransition`] if the transition is not permitted.
    pub fn transition(&mut self, to: S) -> Result<(), InvalidTransition> {
        if can_transition(self.state, to) {
            self.state = to;
            Ok(())
        } else {
            Err(InvalidTransition)
        }
    }

    /// Latch a fault unconditionally (from any non-fault state).
    pub fn latch_fault(&mut self) {
        if self.state != S::FaultLatched {
            self.state = S::FaultLatched;
        }
    }

    /// Whether the machine is `ACTIVE`.
    #[must_use]
    pub fn is_active(&self) -> bool {
        self.state == S::Active
    }
}

impl Default for GateProcessMachine {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fault_latched_is_terminal() {
        let mut m = GateProcessMachine::new();
        m.latch_fault();
        assert_eq!(m.state(), S::FaultLatched);
        assert!(
            m.transition(S::Active).is_err(),
            "fault must not self-clear"
        );
        assert!(m.transition(S::ReadyNoSession).is_err());
    }

    #[test]
    fn normal_progression() {
        let mut m = GateProcessMachine::new();
        m.transition(S::Recovering).unwrap();
        m.transition(S::ReadyNoSession).unwrap();
        m.transition(S::SessionBound).unwrap();
        m.transition(S::Active).unwrap();
        assert!(m.is_active());
        // cannot jump straight back to ReadyNoSession from Active
        assert!(m.transition(S::ReadyNoSession).is_err());
        m.transition(S::SessionBound).unwrap();
    }
}
