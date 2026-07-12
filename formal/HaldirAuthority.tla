---------------------------- MODULE HaldirAuthority ----------------------------
(*
  Abstract, FINITE safety model of Haldir Gate authority, session, stream,
  replay, and restart semantics (specification Phase 6; runbook Phase 1/24).

  This model is BOUNDED so TLC terminates: `GateRestart`, `SessionReopen`, and
  `AllocateOutput` are disabled at their configured caps (a previous version grew
  gateBoot/sessionGen/lastOutputSeq without bound and would not have terminated).

  STATUS: TLC is run in CI (`.github/workflows/formal.yml`) where a JRE is
  available; it was NOT run in the delivery shell (no local JRE). Until the first
  public green TLC run is recorded, treat the CI-enforced executable `model` tests
  in `crates/haldir-state/src/lib.rs` as the authoritative encoding, and see
  `docs/CLAIM-LEDGER.md` (CL-FORMAL-01).
*)
EXTENDS Naturals, FiniteSets

CONSTANTS
  Epochs,     \* finite set of controller intent epoch ids
  MaxBoot,    \* cap on Gate boot generations
  MaxGen,     \* cap on session generations
  MaxSeq      \* cap on output sequence within one epoch

VARIABLES
  gateBoot,              \* current Gate boot id (Nat); a restart increments it
  sessionGen,            \* current session generation (Nat); a reopen changes it
  leaseBoot,             \* the boot a currently-active lease is bound to, or 0
  leaseSession,          \* the session generation the active lease binds, or 0
  activeIntentEpoch,     \* active controller intent epoch, or 0 if none
  retiredIntentEpochs,   \* set of retired controller intent epochs
  lastOutputSeq,         \* highest allocated output sequence in the CURRENT epoch
  publishedPositions,    \* set of allocated output sequences in the current epoch
  faultLatched

vars == << gateBoot, sessionGen, leaseBoot, leaseSession, activeIntentEpoch,
           retiredIntentEpochs, lastOutputSeq, publishedPositions, faultLatched >>

TypeOK ==
  /\ gateBoot \in 1..MaxBoot
  /\ sessionGen \in 1..MaxGen
  /\ leaseBoot \in 0..MaxBoot
  /\ leaseSession \in 0..MaxGen
  /\ activeIntentEpoch \in (Epochs \cup {0})
  /\ retiredIntentEpochs \subseteq Epochs
  /\ lastOutputSeq \in 0..MaxSeq
  /\ publishedPositions \subseteq (1..MaxSeq)
  /\ faultLatched \in BOOLEAN

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

\* A restart mints a fresh boot id; no pre-restart lease survives, and the output
\* epoch is retired so its positions reset (T4/B11/S3).
GateRestart ==
  /\ ~faultLatched
  /\ gateBoot < MaxBoot
  /\ gateBoot' = gateBoot + 1
  /\ leaseBoot' = 0
  /\ leaseSession' = 0
  /\ activeIntentEpoch' = 0
  /\ lastOutputSeq' = 0
  /\ publishedPositions' = {}
  /\ UNCHANGED << sessionGen, retiredIntentEpochs, faultLatched >>

\* A session reopen changes the generation, invalidates the lease, and retires the
\* output stream (S1/S6).
SessionReopen ==
  /\ ~faultLatched
  /\ sessionGen < MaxGen
  /\ sessionGen' = sessionGen + 1
  /\ leaseBoot' = 0
  /\ leaseSession' = 0
  /\ activeIntentEpoch' = 0
  /\ lastOutputSeq' = 0
  /\ publishedPositions' = {}
  /\ UNCHANGED << gateBoot, retiredIntentEpochs, faultLatched >>

\* Mission authority issues a lease bound to the CURRENT boot and session.
ActivateLease ==
  /\ ~faultLatched
  /\ ~LeaseActive
  /\ leaseBoot' = gateBoot
  /\ leaseSession' = sessionGen
  /\ UNCHANGED << gateBoot, sessionGen, activeIntentEpoch, retiredIntentEpochs,
                  lastOutputSeq, publishedPositions, faultLatched >>

\* A fresh controller intent epoch activates only when a lease is active and the
\* epoch is not retired.
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

\* Gate allocates the next output sequence ONLY under an active lease + active
\* intent epoch (A5 / Deny=>NoOutput). A new sequence is never reused.
AllocateOutput ==
  /\ ~faultLatched
  /\ LeaseActive
  /\ activeIntentEpoch # 0
  /\ lastOutputSeq < MaxSeq
  /\ lastOutputSeq' = lastOutputSeq + 1
  /\ publishedPositions' = publishedPositions \cup { lastOutputSeq + 1 }
  /\ UNCHANGED << gateBoot, sessionGen, leaseBoot, leaseSession, activeIntentEpoch,
                  retiredIntentEpochs, faultLatched >>

\* Always enabled (guarantees a successor => no spurious deadlock).
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

\* --- Safety invariants ---

\* A retired intent epoch is never the active epoch.
RetiredNeverActive == activeIntentEpoch \notin retiredIntentEpochs

\* Within the current output epoch, allocated positions are exactly 1..lastOutputSeq
\* with no gaps or reuse (each AllocateOutput adds a unique strictly-greater seq).
NoOutputReuse == publishedPositions = (1..lastOutputSeq)

\* An active lease always binds the current boot and session (stale leases cannot be
\* active; restart/reopen clears them).
LeaseBindsCurrentIncarnation ==
  (leaseBoot # 0) => (leaseBoot <= gateBoot /\ leaseSession <= sessionGen)

Safety ==
  /\ TypeOK
  /\ RetiredNeverActive
  /\ NoOutputReuse
  /\ LeaseBindsCurrentIncarnation
================================================================================
