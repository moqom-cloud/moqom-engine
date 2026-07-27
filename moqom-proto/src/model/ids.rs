//! Identifiers in the object data model, and the [`Location`] that orders them.
//!
//! Group, Subgroup, and Object IDs are all variable-length integers on the
//! wire, so nothing but the type system stops them being swapped at a call
//! site. Distinct newtypes cost nothing at runtime and turn a silent
//! wrong-object bug into a compile error — worth it in a codebase where the
//! relay threads all three through every hot path.

use crate::error::DecodeError;
use crate::varint::VarInt;

macro_rules! varint_id {
    ($(#[$meta:meta])* $name:ident) => {
        $(#[$meta])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
        pub struct $name(VarInt);

        impl $name {
            /// Zero.
            pub const ZERO: Self = Self(VarInt::ZERO);

            /// Wrap a variable-length integer.
            #[must_use]
            pub const fn new(value: VarInt) -> Self {
                Self(value)
            }

            /// The underlying value.
            #[must_use]
            pub const fn get(self) -> u64 {
                self.0.get()
            }

            /// The underlying variable-length integer.
            #[must_use]
            pub const fn as_varint(self) -> VarInt {
                self.0
            }

            /// The next identifier, or `None` at the varint ceiling.
            #[must_use]
            pub fn next(self) -> Option<Self> {
                VarInt::new(self.get().checked_add(1)?).ok().map(Self)
            }
        }

        impl From<u32> for $name {
            fn from(v: u32) -> Self {
                Self(VarInt::from_u32(v))
            }
        }

        impl From<VarInt> for $name {
            fn from(v: VarInt) -> Self {
                Self(v)
            }
        }

        impl std::fmt::Display for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                self.0.fmt(f)
            }
        }
    };
}

varint_id! {
    /// Identifies a group within a track.
    ///
    /// Publishers SHOULD emit these increasing with media time, but the spec
    /// permits tracks that do not, and those tracks are restricted to the
    /// subset of MOQT that never compares group IDs. Nothing here enforces
    /// monotonicity.
    GroupId
}

varint_id! {
    /// Identifies a subgroup within a group.
    ///
    /// Scoped to its group: the same value in two groups implies no
    /// relationship whatsoever.
    SubgroupId
}

varint_id! {
    /// Identifies an object within a group.
    ObjectId
}

/// A specific object in a group within a track, per draft-19 §1.4.2.
///
/// Field order matters: the derived ordering is exactly the comparison the
/// specification defines, `A.Group < B.Group || (A.Group == B.Group &&
/// A.Object < B.Object)`. Reordering the fields would silently change protocol
/// semantics, so the `ordering_matches_spec` test pins it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Location {
    /// Group identifier.
    pub group: GroupId,
    /// Object identifier within the group.
    pub object: ObjectId,
}

impl Location {
    /// The earliest possible location.
    pub const ZERO: Self = Self {
        group: GroupId::ZERO,
        object: ObjectId::ZERO,
    };

    /// Construct a location.
    #[must_use]
    pub const fn new(group: GroupId, object: ObjectId) -> Self {
        Self { group, object }
    }

    /// Encode as two variable-length integers.
    pub fn encode<B: bytes::BufMut>(self, buf: &mut B) {
        self.group.as_varint().encode(buf);
        self.object.as_varint().encode(buf);
    }

    /// Encoded size in bytes.
    #[must_use]
    pub fn encoded_len(self) -> usize {
        self.group.as_varint().size() + self.object.as_varint().size()
    }

    /// Decode two variable-length integers.
    ///
    /// # Errors
    /// [`DecodeError::Short`] if fewer than two complete varints are present.
    pub fn decode<B: bytes::Buf>(buf: &mut B) -> Result<Self, DecodeError> {
        let group = GroupId::new(VarInt::decode(buf)?);
        let object = ObjectId::new(VarInt::decode(buf)?);
        Ok(Self { group, object })
    }

    /// The start of the next group, which is where a subscriber resuming at a
    /// group boundary begins.
    #[must_use]
    pub fn next_group(self) -> Option<Self> {
        Some(Self {
            group: self.group.next()?,
            object: ObjectId::ZERO,
        })
    }
}

impl std::fmt::Display for Location {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{{{},{}}}", self.group, self.object)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Pins draft-19 §1.4.2: `A < B` iff `A.Group < B.Group || (A.Group ==
    /// B.Group && A.Object < B.Object)`. This holds only because `group`
    /// precedes `object` in the struct, so it is worth asserting rather than
    /// trusting the field order to survive a refactor.
    #[test]
    fn ordering_matches_spec() {
        let loc = |g: u32, o: u32| Location::new(GroupId::from(g), ObjectId::from(o));

        assert!(
            loc(0, 5) < loc(1, 0),
            "lower group wins regardless of object"
        );
        assert!(loc(1, 0) < loc(1, 1), "same group falls back to object");
        assert_eq!(loc(2, 3), loc(2, 3));
        assert!(loc(9, 9) > loc(8, 100));

        let mut sorted = vec![loc(1, 2), loc(0, 9), loc(1, 0), loc(0, 0)];
        sorted.sort_unstable();
        assert_eq!(sorted, vec![loc(0, 0), loc(0, 9), loc(1, 0), loc(1, 2)]);
    }

    #[test]
    fn location_round_trips() {
        let original = Location::new(GroupId::from(16_384u32), ObjectId::from(3u32));

        let mut buf = Vec::new();
        original.encode(&mut buf);
        assert_eq!(buf.len(), original.encoded_len());
        assert_eq!(buf.len(), 5, "4-byte group plus 1-byte object");

        let mut cursor = buf.as_slice();
        assert_eq!(Location::decode(&mut cursor).unwrap(), original);
        assert!(cursor.is_empty());
    }

    #[test]
    fn truncated_location_is_short_not_fatal() {
        let mut buf = Vec::new();
        Location::new(GroupId::from(1u32), ObjectId::from(2u32)).encode(&mut buf);
        buf.truncate(1);

        let mut cursor = buf.as_slice();
        let err = Location::decode(&mut cursor).unwrap_err();
        assert!(!err.is_fatal());
    }

    #[test]
    fn next_group_resets_the_object() {
        let loc = Location::new(GroupId::from(4u32), ObjectId::from(99u32));
        assert_eq!(
            loc.next_group().unwrap(),
            Location::new(GroupId::from(5u32), ObjectId::ZERO)
        );
    }

    #[test]
    fn next_saturates_at_the_varint_ceiling() {
        let max = GroupId::new(VarInt::MAX);
        assert!(max.next().is_none());
        assert_eq!(GroupId::ZERO.next().unwrap().get(), 1);
    }
}
