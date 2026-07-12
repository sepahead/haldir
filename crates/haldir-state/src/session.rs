//! NCP session binding (spec S1). Any new generation for the same session id
//! invalidates all dependent state before side effects; that cascade is driven by
//! the vehicle actor.

use haldir_contracts::session::NcpSessionIdentityV1;

/// The effect of binding a session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionBindOutcome {
    /// A first binding from unbound.
    NewBinding,
    /// The identical pair was already bound (no change).
    Unchanged,
    /// A different generation/pair — all dependent state must be invalidated.
    GenerationChanged,
}

/// The current session binding.
#[derive(Debug, Clone, Default)]
pub struct SessionState {
    current: Option<NcpSessionIdentityV1>,
}

impl SessionState {
    /// An unbound session.
    #[must_use]
    pub fn new() -> Self {
        Self { current: None }
    }

    /// Bind (or rebind) a session, reporting whether dependent state must be reset.
    pub fn bind(&mut self, session: NcpSessionIdentityV1) -> SessionBindOutcome {
        let outcome = match &self.current {
            None => SessionBindOutcome::NewBinding,
            Some(cur) if *cur == session => SessionBindOutcome::Unchanged,
            Some(_) => SessionBindOutcome::GenerationChanged,
        };
        self.current = Some(session);
        outcome
    }

    /// The current session pair, if bound.
    #[must_use]
    pub fn current(&self) -> Option<&NcpSessionIdentityV1> {
        self.current.as_ref()
    }

    /// Exact-pair match against the bound session (false if unbound).
    #[must_use]
    pub fn matches(&self, session: &NcpSessionIdentityV1) -> bool {
        self.current.as_ref() == Some(session)
    }
}
