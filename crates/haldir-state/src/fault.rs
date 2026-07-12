//! A latched fault that cannot self-clear (spec `FAULT_LATCHED`).
//!
//! Once latched, only a process restart (a new object) clears it. A later valid
//! input never re-enables output.

/// A one-way fault latch carrying a stable reason code.
#[derive(Debug, Clone, Default)]
pub struct FaultLatch {
    reason: Option<&'static str>,
}

impl FaultLatch {
    /// An un-latched fault.
    #[must_use]
    pub const fn new() -> Self {
        Self { reason: None }
    }

    /// Latch the fault with `reason`. The first reason wins; later calls are no-ops.
    pub fn latch(&mut self, reason: &'static str) {
        if self.reason.is_none() {
            self.reason = Some(reason);
        }
    }

    /// Whether the fault is latched.
    #[must_use]
    pub const fn is_latched(&self) -> bool {
        self.reason.is_some()
    }

    /// The latched reason, if any.
    #[must_use]
    pub const fn reason(&self) -> Option<&'static str> {
        self.reason
    }
}
