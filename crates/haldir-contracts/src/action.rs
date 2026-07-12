//! The small, typed initial command profile.
//!
//! The first action profile is deliberately tiny: `Hold` and body/local-NED
//! velocity. New actions (takeoff/land/mode/arm/waypoint) require a new reviewed
//! action class and plant state machine — never a magic velocity vector or a
//! free-text command name.

use crate::cbor::{CanonicalValue, CborReader, CborWriter};
use crate::error::DecodeError;
use core::num::NonZeroU32;

/// A coarse action class used in lease/policy allowlists.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum ActionClassV1 {
    /// Hold / zero-velocity request.
    Hold,
    /// Local-NED velocity request.
    VelocityLocalNed,
}

impl CanonicalValue for ActionClassV1 {
    fn encode(&self, w: &mut CborWriter) {
        match self {
            Self::Hold => w.uint(1),
            Self::VelocityLocalNed => w.uint(2),
        }
    }
    fn decode(r: &mut CborReader<'_>) -> Result<Self, DecodeError> {
        match r.read_uint()? {
            1 => Ok(Self::Hold),
            2 => Ok(Self::VelocityLocalNed),
            _ => Err(DecodeError::BadEnumTag),
        }
    }
}

/// A supported coordinate frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum CoordinateFrameV1 {
    /// Local north-east-down navigation frame.
    LocalNed,
}

impl CanonicalValue for CoordinateFrameV1 {
    fn encode(&self, w: &mut CborWriter) {
        match self {
            Self::LocalNed => w.uint(1),
        }
    }
    fn decode(r: &mut CborReader<'_>) -> Result<Self, DecodeError> {
        match r.read_uint()? {
            1 => Ok(Self::LocalNed),
            _ => Err(DecodeError::BadEnumTag),
        }
    }
}

/// A requested semantic action. This is NOT an NCP frame: it carries no final
/// stream sequence, publisher timestamp, plant authority, or serialized frame.
///
/// Fixed-point integer units are used throughout; the NCP adapter performs the
/// one documented, checked conversion to the wire representation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequestedActionV1 {
    /// Hold at zero velocity for a bounded validity window.
    Hold {
        /// Requested validity in milliseconds.
        requested_validity_ms: NonZeroU32,
    },
    /// Local-NED velocity setpoint (mm/s) for a bounded validity window.
    VelocityLocalNed {
        /// North component, mm/s.
        north_mm_s: i32,
        /// East component, mm/s.
        east_mm_s: i32,
        /// Down component, mm/s.
        down_mm_s: i32,
        /// Requested validity in milliseconds.
        requested_validity_ms: NonZeroU32,
    },
}

impl RequestedActionV1 {
    /// The coarse action class for this action.
    #[must_use]
    pub const fn class(&self) -> ActionClassV1 {
        match self {
            Self::Hold { .. } => ActionClassV1::Hold,
            Self::VelocityLocalNed { .. } => ActionClassV1::VelocityLocalNed,
        }
    }

    /// The requested validity window in milliseconds.
    #[must_use]
    pub const fn requested_validity_ms(&self) -> NonZeroU32 {
        match self {
            Self::Hold {
                requested_validity_ms,
            }
            | Self::VelocityLocalNed {
                requested_validity_ms,
                ..
            } => *requested_validity_ms,
        }
    }
}

impl CanonicalValue for RequestedActionV1 {
    fn encode(&self, w: &mut CborWriter) {
        // Single-pair map { variant_tag: variant_body_map }.
        w.map_header(1);
        match self {
            Self::Hold {
                requested_validity_ms,
            } => {
                w.uint(1);
                w.map_header(1);
                w.uint(1);
                requested_validity_ms.encode(w);
            }
            Self::VelocityLocalNed {
                north_mm_s,
                east_mm_s,
                down_mm_s,
                requested_validity_ms,
            } => {
                w.uint(2);
                w.map_header(4);
                w.uint(1);
                north_mm_s.encode(w);
                w.uint(2);
                east_mm_s.encode(w);
                w.uint(3);
                down_mm_s.encode(w);
                w.uint(4);
                requested_validity_ms.encode(w);
            }
        }
    }

    fn decode(r: &mut CborReader<'_>) -> Result<Self, DecodeError> {
        let n = r.read_map_len()?;
        if n != 1 {
            r.end_container();
            return Err(DecodeError::BadEnumTag);
        }
        let tag = r.read_map_key()?;
        let action = match tag {
            1 => {
                let bn = r.read_map_len()?;
                let mut validity: Option<NonZeroU32> = None;
                let mut last: Option<u64> = None;
                for _ in 0..bn {
                    let k = r.read_map_key()?;
                    if let Some(p) = last
                        && k <= p
                    {
                        return Err(DecodeError::NonCanonicalMapOrder);
                    }
                    last = Some(k);
                    match k {
                        1 => validity = Some(NonZeroU32::decode(r)?),
                        other => return Err(DecodeError::UnknownField { key: other }),
                    }
                }
                r.end_container();
                Self::Hold {
                    requested_validity_ms: validity.ok_or(DecodeError::MissingField { key: 1 })?,
                }
            }
            2 => {
                let bn = r.read_map_len()?;
                let mut north: Option<i32> = None;
                let mut east: Option<i32> = None;
                let mut down: Option<i32> = None;
                let mut validity: Option<NonZeroU32> = None;
                let mut last: Option<u64> = None;
                for _ in 0..bn {
                    let k = r.read_map_key()?;
                    if let Some(p) = last
                        && k <= p
                    {
                        return Err(DecodeError::NonCanonicalMapOrder);
                    }
                    last = Some(k);
                    match k {
                        1 => north = Some(i32::decode(r)?),
                        2 => east = Some(i32::decode(r)?),
                        3 => down = Some(i32::decode(r)?),
                        4 => validity = Some(NonZeroU32::decode(r)?),
                        other => return Err(DecodeError::UnknownField { key: other }),
                    }
                }
                r.end_container();
                Self::VelocityLocalNed {
                    north_mm_s: north.ok_or(DecodeError::MissingField { key: 1 })?,
                    east_mm_s: east.ok_or(DecodeError::MissingField { key: 2 })?,
                    down_mm_s: down.ok_or(DecodeError::MissingField { key: 3 })?,
                    requested_validity_ms: validity.ok_or(DecodeError::MissingField { key: 4 })?,
                }
            }
            _ => return Err(DecodeError::BadEnumTag),
        };
        r.end_container();
        Ok(action)
    }
}
