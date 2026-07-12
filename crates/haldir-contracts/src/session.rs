//! NCP session identity and stream/source position types.
//!
//! These are Haldir's **own** stable semantic types (punch-list H15): the NCP
//! adapter converts them to/from wire structs, but `haldir-contracts` never
//! depends on `haldir-ncp08`.

use crate::ids::{GateOutputEpoch, IntentEpoch, IntentSeq, OutputSeq, SourceSeq};
use crate::scalar::{AsciiId, BoundedAscii, CanonicalUuidV4String};

canonical_struct! {
    /// The inseparable NCP session identity pair `(session_id, generation)`,
    /// validated atomically before any side effect (spec S1).
    pub struct NcpSessionIdentityV1 {
        req 1 session_id: AsciiId<64>,
        req 2 generation: CanonicalUuidV4String,
    }
}

canonical_struct! {
    /// A causal source reference: the upstream frame that directly caused an output.
    /// Source sequence is correlation, not delivery order (spec S7).
    pub struct NcpSourceRefV1 {
        req 1 source_key: BoundedAscii<256>,
        req 2 stream_epoch: CanonicalUuidV4String,
        req 3 stream_seq: SourceSeq,
    }
}

canonical_struct! {
    /// A Gate-output stream position `(epoch, seq)` in the Gate namespace.
    pub struct NcpStreamPositionV1 {
        req 1 epoch: GateOutputEpoch,
        req 2 seq: OutputSeq,
    }
}

canonical_struct! {
    /// A controller-intent stream position `(epoch, seq)` in the controller namespace.
    pub struct HaldirIntentPositionV1 {
        req 1 epoch: IntentEpoch,
        req 2 seq: IntentSeq,
    }
}
