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

varint_id! {
    /// Identifies a track on the data plane, per draft-19 §11.1.
    ///
    /// Subgroup headers and datagrams carry this instead of the full track
    /// name, which would otherwise repeat a tuple of byte strings on every
    /// object. The publisher assigns it in `SUBSCRIBE_OK` or `PUBLISH`, and it
    /// is scoped to the session — the same track has different aliases on
    /// different connections, and on the two sides of a relay.
    TrackAlias
}

/// An absolute Object ID accumulated from a stream's deltas.
///
/// Subgroup and fetch streams do not put absolute Object IDs on the wire. They
/// carry deltas and the receiver accumulates, and that is what sets the range:
/// the draft caps the accumulated value at 2^64-1 (§11.4.2, §11.4.4.1), which
/// is four times wider than a `vi64` can hold. It is legal precisely *because*
/// the wide value is never itself encoded — only the differences between
/// consecutive values are, and those stay small in any real stream.
///
/// [`ObjectId`] is the narrower type, for the places that do encode an Object
/// ID absolutely: datagrams, [`Location`], and the first object on a stream.
/// Those are bounded by the varint maximum, so converting to it is fallible.
/// That conversion is the honest boundary between "this object exists" and
/// "this object can be named in a control message" — and the reason the two
/// types are separate rather than one type with a range check bolted on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct ObjectSeq(u64);

impl ObjectSeq {
    /// Zero.
    pub const ZERO: Self = Self(0);

    /// The largest value the draft permits.
    pub const MAX: Self = Self(u64::MAX);

    /// Wrap a raw value. Every `u64` is a valid Object ID.
    #[must_use]
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    /// The raw value.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }

    /// Advance by `delta`, or `None` past 2^64-1.
    ///
    /// Overflow here is a `PROTOCOL_VIOLATION` rather than something to
    /// saturate: a peer that wraps the object counter has lost the ordering the
    /// whole subscription depends on.
    #[must_use]
    pub const fn checked_add(self, delta: u64) -> Option<Self> {
        match self.0.checked_add(delta) {
            Some(value) => Some(Self(value)),
            None => None,
        }
    }

    /// Narrow to an [`ObjectId`], or `None` above the varint maximum.
    ///
    /// Fails only for objects whose ID exceeded what a single varint can hold,
    /// which is unreachable without a peer deliberately starting near the
    /// ceiling. When it does fail, the object is still perfectly deliverable on
    /// its own stream — it just cannot be referenced by a control message, so
    /// callers should treat this as "not addressable" rather than "invalid".
    #[must_use]
    pub fn to_object_id(self) -> Option<ObjectId> {
        VarInt::new(self.0).ok().map(ObjectId::new)
    }
}

impl From<ObjectId> for ObjectSeq {
    fn from(id: ObjectId) -> Self {
        Self(id.get())
    }
}

impl From<u32> for ObjectSeq {
    fn from(v: u32) -> Self {
        Self(u64::from(v))
    }
}

impl std::fmt::Display for ObjectSeq {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
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

/// Where a range of history stops.
///
/// On the wire this is one location described as "the last object, plus one",
/// with a zero object meaning the whole group. Two readings of §10.12 disagree:
/// the prose calls the range inclusive and the field description says plus one.
/// Following only the prose returns one object too many; following only the
/// field description loses the last object of every fetch.
///
/// Both cases live here so the off-by-one is applied once, by
/// [`Self::from_wire`] and [`Self::wire`], instead of by every caller who has to
/// remember it exists.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FetchEnd {
    /// Through this object, inclusive.
    Through(Location),

    /// Through the end of this group, however many objects it turns out to
    /// hold. The only way to ask for the rest of a group without knowing how
    /// long it is — which a subscriber joining a live track never does.
    EndOfGroup(GroupId),
}

impl FetchEnd {
    /// Interpret the End Location field of a FETCH.
    ///
    /// # Panics
    /// Never: the subtraction is guarded by the zero check, and one less than a
    /// varint is always a varint.
    #[must_use]
    pub fn from_wire(end: Location) -> Self {
        if end.object == ObjectId::ZERO {
            Self::EndOfGroup(end.group)
        } else {
            // Safe because the object is nonzero, so subtracting one cannot
            // underflow the group.
            Self::Through(Location::new(
                end.group,
                ObjectId::new(
                    VarInt::new(end.object.get() - 1).expect("one less than a varint is a varint"),
                ),
            ))
        }
    }

    /// The End Location field to put on the wire.
    ///
    /// `None` for a `Through` whose object is the varint maximum, which cannot
    /// be expressed as a plus-one and is not a range anything real asks for.
    #[must_use]
    pub fn wire(self) -> Option<Location> {
        match self {
            Self::Through(location) => Some(Location::new(
                location.group,
                ObjectId::new(VarInt::new(location.object.get() + 1).ok()?),
            )),
            Self::EndOfGroup(group) => Some(Location::new(group, ObjectId::ZERO)),
        }
    }

    /// Whether `location` falls within a range ending here.
    #[must_use]
    pub fn covers(self, location: Location) -> bool {
        match self {
            Self::Through(last) => location <= last,
            Self::EndOfGroup(group) => location.group <= group,
        }
    }

    /// The last group the range can reach into.
    #[must_use]
    pub const fn last_group(self) -> GroupId {
        match self {
            Self::Through(location) => location.group,
            Self::EndOfGroup(group) => group,
        }
    }
}

impl std::fmt::Display for FetchEnd {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Through(location) => write!(f, "through {location}"),
            Self::EndOfGroup(group) => write!(f, "through the end of group {group}"),
        }
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

    fn loc(group: u32, object: u32) -> Location {
        Location::new(GroupId::from(group), ObjectId::from(object))
    }

    /// The plus-one is the whole point of the type, and it has to survive both
    /// directions: a range asking through object 9 arrives as 10 and has to be
    /// understood as 9 again.
    #[test]
    fn a_fetch_end_round_trips_through_the_wire_form() {
        for end in [
            FetchEnd::Through(loc(4, 9)),
            FetchEnd::Through(loc(0, 0)),
            FetchEnd::EndOfGroup(GroupId::from(7u32)),
        ] {
            let wire = end.wire().expect("representable");
            assert_eq!(FetchEnd::from_wire(wire), end);
        }
    }

    #[test]
    fn a_through_end_includes_its_own_object() {
        let end = FetchEnd::Through(loc(4, 9));
        assert_eq!(end.wire().unwrap(), loc(4, 10), "the wire form is plus one");
        assert!(end.covers(loc(4, 9)), "the named object is in the range");
        assert!(!end.covers(loc(4, 10)));
        assert!(!end.covers(loc(5, 0)));
    }

    /// A zero object is not "through object zero", it is "all of this group".
    /// Treating it as the former makes every whole-group fetch return one object.
    #[test]
    fn a_zero_object_means_the_whole_group() {
        let end = FetchEnd::from_wire(loc(7, 0));
        assert_eq!(end, FetchEnd::EndOfGroup(GroupId::from(7u32)));
        assert!(end.covers(loc(7, 0)));
        assert!(end.covers(loc(7, 999_999)));
        assert!(!end.covers(loc(8, 0)));
    }

    #[test]
    fn a_through_end_at_the_ceiling_has_no_wire_form() {
        let end = FetchEnd::Through(Location::new(GroupId::ZERO, ObjectId::new(VarInt::MAX)));
        assert!(end.wire().is_none());
    }
}
