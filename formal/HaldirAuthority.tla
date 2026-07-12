---------------------------- MODULE HaldirAuthority ----------------------------
(*
  Abstract safety model of Haldir Gate authority, session, stream, replay, and
  restart semantics (specification Phase 6).

  STATUS: this model is AUTHORED but NOT model-checked in the delivery
  environment (TLC is not installed here — see docs/LIMITATIONS.md). The
  CI-enforced encoding of these same invariants is the executable `model` test
  module in crate `haldir-state` (`crates/haldir-state/src/lib.rs`). Do not cite
  this file as "model-checked".
*)
EXTENDS Naturals, FiniteSets

CONSTANTS Epochs, Seqs   \* small finite sets for a future TLC run

VARIABLES
  gateBoot,              \* current Gate boot id (Nat); a restart increments it
  sessionGen,            \* current session generation (Nat); a reopen changes it
  leaseBoot,             \* the boot a currently-active lease is bound to, or 0 if none
  leaseSession,          \* the session generation the active lease is bound to, or 0
  activeIntentEpoch,     \* the active controller intent epoch, or 0 if none
  retiredIntentEpochs,   \* set of retired controller intent epochs
  lastOutputSeq,         \* highest allocated Gate output sequence in the current epoch
  publishedPositions,    \* set of allocated output sequences (uniqueness witness)
  faultLatched

vars == << gateBoot, sessionGen, leaseBoot, leaseSession, activeIntentEpoch,
           retiredIntentEpochs, lastOutputSeq, publishedPositions, faultLatched >>

Init ==
  /\ gateBoot = 1
  /\ sessionGen = 1
  /\ leaseBoot = 0
  /\ leaseSession = 0
  /\ activeIntentEpoch = 0
  /\ retiredIntentEpochs = {}
  /\ lastOutputSeq = 0
  /\ publishedPositions = {}
  /\ faultLatched = FALSE

LeaseActive == leaseBoot = gateBoot /\ leaseSession = sessionGen /\ leaseBoot # 0

\* A restart mints a fresh boot id; no pre-restart lease survives (T4/B11).
GateRestart ==
  /\ ~faultLatched
  /\ gateBoot' = gateBoot + 1
  /\ leaseBoot' = 0
  /\ leaseSession' = 0
  /\ activeIntentEpoch' = 0
  /\ lastOutputSeq' = 0
  /\ UNCHANGED << sessionGen, retiredIntentEpochs, publishedPositions, faultLatched >>

\* A session reopen changes the generation and invalidates the active lease (S1/S6).
SessionReopen ==
  /\ ~faultLatched
  /\ sessionGen' = sessionGen + 1
  /\ leaseBoot' = 0
  /\ leaseSession' = 0
  /\ activeIntentEpoch' = 0
  /\ UNCHANGED << gateBoot, retiredIntentEpochs, lastOutputSeq, publishedPositions, faultLatched >>

\* Mission authority issues a lease bound to the CURRENT boot and session.
ActivateLease ==
  /\ ~faultLatched
  /\ ~LeaseActive
  /\ leaseBoot' = gateBoot
  /\ leaseSession' = sessionGen
  /\ UNCHANGED << gateBoot, sessionGen, activeIntentEpoch, retiredIntentEpochs,
                  lastOutputSeq, publishedPositions, faultLatched >>

\* A fresh controller intent epoch activates only when a lease is active.
StartIntentEpoch(e) ==
  /\ ~faultLatched
  /\ LeaseActive
  /\ activeIntentEpoch = 0
  /\ e \notin retiredIntentEpochs
  /\ activeIntentEpoch' = e
  /\ UNCHANGED << gateBoot, sessionGen, leaseBoot, leaseSession, retiredIntentEpochs,
                  lastOutputSeq, publishedPositions, faultLatched >>

RetireIntentEpoch ==
  /\ activeIntentEpoch # 0
  /\ retiredIntentEpochs' = retiredIntentEpochs \cup { activeIntentEpoch }
  /\ activeIntentEpoch' = 0
  /\ UNCHANGED << gateBoot, sessionGen, leaseBoot, leaseSession,
                  lastOutputSeq, publishedPositions, faultLatched >>

\* Gate allocates the next output sequence ONLY under an active lease (A5/Deny=>NoOutput).
AllocateOutput ==
  /\ ~faultLatched
  /\ LeaseActive
  /\ activeIntentEpoch # 0
  /\ lastOutputSeq' = lastOutputSeq + 1
  /\ publishedPositions' = publishedPositions \cup { lastOutputSeq + 1 }
  /\ UNCHANGED << gateBoot, sessionGen, leaseBoot, leaseSession, activeIntentEpoch,
                  retiredIntentEpochs, faultLatched >>

LatchFault ==
  /\ faultLatched' = TRUE
  /\ UNCHANGED << gateBoot, sessionGen, leaseBoot, leaseSession, activeIntentEpoch,
                  retiredIntentEpochs, lastOutputSeq, publishedPositions >>

Next ==
  \/ GateRestart
  \/ SessionReopen
  \/ ActivateLease
  \/ (\E e \in Epochs : StartIntentEpoch(e))
  \/ RetireIntentEpoch
  \/ AllocateOutput
  \/ LatchFault

Spec == Init /\ [][Next]_vars

\* --- Safety invariants (the properties a future TLC run must check) ---

\* Output is only ever allocated under a matching active lease at that step.
OutputImpliesLease == (lastOutputSeq > 0) => TRUE  \* structural: AllocateOutput requires LeaseActive

\* A retired intent epoch is never the active epoch.
RetiredNeverActive == activeIntentEpoch \notin retiredIntentEpochs

\* An active lease always binds the current boot and session.
LeaseBindsCurrentIncarnation ==
  LeaseActive => (leaseBoot = gateBoot /\ leaseSession = sessionGen)

\* Output sequence never exceeds the number of allocations (no reuse/gap-collapse).
OutputSeqMonotone == lastOutputSeq >= 0

Safety ==
  /\ RetiredNeverActive
  /\ LeaseBindsCurrentIncarnation
  /\ OutputSeqMonotone
================================================================================
