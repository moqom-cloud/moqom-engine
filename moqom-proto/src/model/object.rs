//! Object status, per draft-19 §11.2.1.1 and the registry in §15.9.

use bytes::{Buf, BufMut};

use crate::error::DecodeError;
use crate::varint::VarInt;

/// The status of an object delivered via a subscription.
///
/// Only three values are registered in draft-19. Earlier drafts carried
/// "Object Does Not Exist" (`0x1`) and a group equivalent (`0x2`); both were
/// removed, and non-existence is now conveyed by gap properties instead. An
/// implementation still accepting them would be accepting a protocol violation.
///
/// Status is **absent entirely on objects delivered by FETCH** and present only
/// under a subscription, which is a framing concern rather than a property of
/// this type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
#[repr(u8)]
pub enum ObjectStatus {
    /// A normal object. The only status permitted to carry a payload.
    ///
    /// Implicit for any non-zero-length object; a zero-length object encodes
    /// it explicitly, since otherwise it could not be distinguished from a
    /// terminal marker.
    #[default]
    Normal = 0x0,

    /// No object with this group and an object ID at or above this one exists.
    EndOfGroup = 0x3,

    /// No object at or after this location exists.
    EndOfTrack = 0x4,
}

impl ObjectStatus {
    /// Whether this status permits a non-empty payload.
    ///
    /// Only [`ObjectStatus::Normal`] does. Receiving a payload on any other
    /// status is a `PROTOCOL_VIOLATION`.
    #[must_use]
    pub const fn permits_payload(self) -> bool {
        matches!(self, Self::Normal)
    }

    /// Whether this status terminates a group or the whole track.
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::EndOfGroup | Self::EndOfTrack)
    }

    /// Check a status against an observed payload length.
    ///
    /// # Errors
    /// [`DecodeError::Invalid`] if a non-normal status carries a payload.
    pub const fn check_payload_len(self, len: usize) -> Result<(), DecodeError> {
        if len > 0 && !self.permits_payload() {
            return Err(DecodeError::Invalid(
                "non-normal object status carries a payload",
            ));
        }
        Ok(())
    }

    /// The wire value.
    #[must_use]
    pub const fn as_u64(self) -> u64 {
        self as u64
    }

    /// Encoded size in bytes. Always 1, since every registered value is small.
    #[must_use]
    pub const fn encoded_len(self) -> usize {
        1
    }

    /// Append the wire representation to `buf`.
    pub fn encode<B: BufMut>(self, buf: &mut B) {
        VarInt::from_u32(self as u32).encode(buf);
    }

    /// Read a status from `buf`.
    ///
    /// # Errors
    /// [`DecodeError::Short`] if incomplete; [`DecodeError::Invalid`] for any
    /// unregistered value, which draft-19 §11.2.1.1 makes a session error
    /// rather than something to skip.
    pub fn decode<B: Buf>(buf: &mut B) -> Result<Self, DecodeError> {
        Self::from_u64(VarInt::decode(buf)?.get())
    }

    /// Convert a wire value to a status.
    ///
    /// # Errors
    /// [`DecodeError::Invalid`] for unregistered values.
    pub const fn from_u64(value: u64) -> Result<Self, DecodeError> {
        match value {
            0x0 => Ok(Self::Normal),
            0x3 => Ok(Self::EndOfGroup),
            0x4 => Ok(Self::EndOfTrack),
            _ => Err(DecodeError::Invalid("unregistered object status")),
        }
    }
}

impl std::fmt::Display for ObjectStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Normal => "normal",
            Self::EndOfGroup => "end-of-group",
            Self::EndOfTrack => "end-of-track",
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registered_values_round_trip() {
        for (status, wire) in [
            (ObjectStatus::Normal, 0x0u64),
            (ObjectStatus::EndOfGroup, 0x3),
            (ObjectStatus::EndOfTrack, 0x4),
        ] {
            assert_eq!(status.as_u64(), wire);
            assert_eq!(ObjectStatus::from_u64(wire).unwrap(), status);

            let mut buf = Vec::new();
            status.encode(&mut buf);
            assert_eq!(buf.len(), status.encoded_len());

            let mut cursor = buf.as_slice();
            assert_eq!(ObjectStatus::decode(&mut cursor).unwrap(), status);
            assert!(cursor.is_empty());
        }
    }

    /// 0x1 and 0x2 were "Object Does Not Exist" and its group equivalent in
    /// earlier drafts and are gone from draft-19. Accepting them would be
    /// accepting a protocol violation, so this pins the removal.
    #[test]
    fn withdrawn_and_unknown_statuses_are_fatal() {
        for value in [0x1u64, 0x2, 0x5, 0xff, u64::MAX] {
            let err = ObjectStatus::from_u64(value).unwrap_err();
            assert!(
                err.is_fatal(),
                "status {value:#x} should be a session error"
            );
        }
    }

    #[test]
    fn only_normal_permits_a_payload() {
        assert!(ObjectStatus::Normal.permits_payload());
        assert!(!ObjectStatus::EndOfGroup.permits_payload());
        assert!(!ObjectStatus::EndOfTrack.permits_payload());

        assert!(ObjectStatus::Normal.check_payload_len(1200).is_ok());
        assert!(ObjectStatus::EndOfGroup.check_payload_len(0).is_ok());
        assert!(
            ObjectStatus::EndOfTrack
                .check_payload_len(1)
                .unwrap_err()
                .is_fatal()
        );
    }

    #[test]
    fn terminality() {
        assert!(!ObjectStatus::Normal.is_terminal());
        assert!(ObjectStatus::EndOfGroup.is_terminal());
        assert!(ObjectStatus::EndOfTrack.is_terminal());
    }
}
