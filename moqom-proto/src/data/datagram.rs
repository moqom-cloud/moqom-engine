//! `OBJECT_DATAGRAM`, per draft-19 §11.3.
//!
//! One object, one datagram, no retransmission. This is the path for objects
//! where arriving late is worse than not arriving — the reason MOQOM can beat a
//! stream-only design on tail latency, since a lost datagram costs nothing
//! downstream while a lost stream frame blocks everything behind it.
//!
//! The payload has no length field: it runs to the end of the datagram. So a
//! decoder here is only correct when handed exactly one datagram, which is what
//! the QUIC layer delivers.

use bytes::{Buf, BufMut, Bytes};

use crate::control::properties::Properties;
use crate::data::flags::DatagramType;
use crate::data::object::TerminalStatus;
use crate::error::DecodeError;
use crate::model::{GroupId, ObjectId, ObjectStatus, TrackAlias};
use crate::varint::VarInt;

/// Media bytes known not to be empty.
///
/// The distinction earns a type because of an interaction that is easy to miss:
/// a zero-length object must encode an explicit Normal status (§11.2.1.1), and
/// the draft forbids the `END_OF_GROUP` bit on a datagram that carries a status
/// (§11.3.1). So "ends the group" and "has no bytes" cannot both be true on the
/// wire — and an encoder that accepted both would have to silently drop one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NonEmptyPayload(Bytes);

impl NonEmptyPayload {
    /// Wrap `bytes`, or `None` if they are empty.
    #[must_use]
    pub fn new(bytes: impl Into<Bytes>) -> Option<Self> {
        let bytes = bytes.into();
        (!bytes.is_empty()).then_some(Self(bytes))
    }

    /// The bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &Bytes {
        &self.0
    }

    /// Consume and return the bytes.
    #[must_use]
    pub fn into_bytes(self) -> Bytes {
        self.0
    }
}

/// What a datagram carries in place of its payload region.
///
/// The variants exist to make the draft's exclusions unrepresentable rather
/// than merely checked: a terminal marker has nowhere to put a payload or
/// properties, and a zero-length object has no end-of-group flag to set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DatagramContent {
    /// A normal object with media bytes.
    Payload {
        /// The media.
        payload: NonEmptyPayload,
        /// Relay-visible metadata. Empty means the `PROPERTIES` bit is clear;
        /// the draft forbids setting the bit with a zero length, so the two are
        /// the same state and are stored as one.
        properties: Properties,
        /// No object in this group has a larger Object ID.
        end_of_group: bool,
    },
    /// A zero-length normal object.
    ///
    /// Has no `end_of_group`: it encodes with the `STATUS` bit, which the draft
    /// forbids combining with `END_OF_GROUP`. A publisher that needs to close a
    /// group sends a separate [`TerminalStatus::EndOfGroup`] object.
    Empty {
        /// Relay-visible metadata.
        properties: Properties,
    },
    /// An end-of-range marker.
    Terminal(TerminalStatus),
}

impl DatagramContent {
    /// A normal object carrying `payload` and nothing else.
    ///
    /// Picks [`Self::Payload`] or [`Self::Empty`] to match, so callers that do
    /// not care about the distinction do not have to know it exists.
    #[must_use]
    pub fn payload(payload: impl Into<Bytes>) -> Self {
        NonEmptyPayload::new(payload).map_or(
            Self::Empty {
                properties: Properties::new(),
            },
            |p| Self::Payload {
                payload: p,
                properties: Properties::new(),
                end_of_group: false,
            },
        )
    }

    /// The properties attached to this object, if it may carry any.
    #[must_use]
    pub const fn properties(&self) -> Option<&Properties> {
        match self {
            Self::Payload { properties, .. } | Self::Empty { properties } => Some(properties),
            Self::Terminal(_) => None,
        }
    }
}

/// A single object delivered in a QUIC datagram.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObjectDatagram {
    /// The track, by the alias the publisher assigned.
    pub track_alias: TrackAlias,
    /// The object's group.
    pub group: GroupId,
    /// The object's position in the group.
    pub object: ObjectId,
    /// Publisher priority, or `None` to inherit the subscription's.
    pub priority: Option<u8>,
    /// Payload or terminal marker.
    pub content: DatagramContent,
}

impl ObjectDatagram {
    /// A normal object with an inherited priority and no properties.
    #[must_use]
    pub fn new(
        track_alias: TrackAlias,
        group: GroupId,
        object: ObjectId,
        payload: impl Into<Bytes>,
    ) -> Self {
        Self {
            track_alias,
            group,
            object,
            priority: None,
            content: DatagramContent::payload(payload),
        }
    }

    /// The type code this datagram will encode with.
    #[must_use]
    pub fn datagram_type(&self) -> DatagramType {
        let (properties, carries_status, end_of_group) = match &self.content {
            DatagramContent::Payload {
                properties,
                end_of_group,
                ..
            } => (!properties.is_empty(), false, *end_of_group),
            // A zero-length object encodes an explicit Normal status
            // (§11.2.1.1) rather than relying on an empty payload region.
            DatagramContent::Empty { properties } => (!properties.is_empty(), true, false),
            DatagramContent::Terminal(_) => (false, true, false),
        };
        DatagramType::new(
            properties,
            self.object == ObjectId::ZERO,
            self.priority.is_none(),
            carries_status,
            end_of_group,
        )
    }

    /// Encoded size in bytes.
    #[must_use]
    pub fn encoded_len(&self) -> usize {
        let ty = self.datagram_type();
        let mut len = VarInt::from_u32(u32::from(ty.as_u8())).size();
        len += self.track_alias.as_varint().size();
        len += self.group.as_varint().size();
        if !ty.has_zero_object_id() {
            len += self.object.as_varint().size();
        }
        if self.priority.is_some() {
            len += 1;
        }
        if let Some(properties) = self.content.properties()
            && !properties.is_empty()
        {
            len += properties.encoded_len_prefixed();
        }
        match &self.content {
            DatagramContent::Payload { payload, .. } => len += payload.as_bytes().len(),
            DatagramContent::Empty { .. } => len += ObjectStatus::Normal.encoded_len(),
            DatagramContent::Terminal(status) => len += status.as_status().encoded_len(),
        }
        len
    }

    /// Append the datagram to `buf`.
    pub fn encode<B: BufMut>(&self, buf: &mut B) {
        let ty = self.datagram_type();
        VarInt::from_u32(u32::from(ty.as_u8())).encode(buf);
        self.track_alias.as_varint().encode(buf);
        self.group.as_varint().encode(buf);
        if !ty.has_zero_object_id() {
            self.object.as_varint().encode(buf);
        }
        if let Some(priority) = self.priority {
            buf.put_u8(priority);
        }
        if let Some(properties) = self.content.properties()
            && !properties.is_empty()
        {
            properties.encode_prefixed(buf);
        }
        match &self.content {
            DatagramContent::Payload { payload, .. } => buf.put_slice(payload.as_bytes()),
            DatagramContent::Empty { .. } => ObjectStatus::Normal.encode(buf),
            DatagramContent::Terminal(status) => status.as_status().encode(buf),
        }
    }

    /// Decode exactly one datagram.
    ///
    /// `buf` must hold one whole datagram and nothing else: with the `STATUS`
    /// bit clear the payload is defined as everything remaining, so any trailing
    /// bytes would be silently absorbed into the payload.
    ///
    /// # Errors
    /// [`DecodeError::Invalid`] for a malformed type code or a field
    /// combination the draft forbids; [`DecodeError::Short`] if the datagram is
    /// truncated.
    pub fn decode<B: Buf>(buf: &mut B) -> Result<Self, DecodeError> {
        let ty = DatagramType::from_u64(VarInt::decode(buf)?.get())?;
        let track_alias = TrackAlias::new(VarInt::decode(buf)?);
        let group = GroupId::new(VarInt::decode(buf)?);

        let object = if ty.has_zero_object_id() {
            ObjectId::ZERO
        } else {
            ObjectId::new(VarInt::decode(buf)?)
        };

        let priority = if ty.has_default_priority() {
            None
        } else {
            if !buf.has_remaining() {
                return Err(DecodeError::Short { needed: 1 });
            }
            Some(buf.get_u8())
        };

        let properties = if ty.has_properties() {
            let properties = Properties::decode_prefixed(buf)?;
            if properties.is_empty() {
                return Err(DecodeError::Invalid(
                    "PROPERTIES bit set with a zero-length property set",
                ));
            }
            properties
        } else {
            Properties::new()
        };

        let content = if ty.carries_status() {
            match ObjectStatus::decode(buf)? {
                ObjectStatus::Normal => DatagramContent::Empty { properties },
                other => {
                    if !properties.is_empty() {
                        return Err(DecodeError::Invalid(
                            "only normal objects may carry properties",
                        ));
                    }
                    DatagramContent::Terminal(TerminalStatus::try_from(other)?)
                }
            }
        } else {
            // The payload is defined as the rest of the datagram, so an empty
            // remainder is a zero-length object spelled non-canonically. It
            // normalises to the same value the canonical spelling decodes to.
            NonEmptyPayload::new(buf.copy_to_bytes(buf.remaining())).map_or(
                DatagramContent::Empty {
                    properties: properties.clone(),
                },
                |payload| DatagramContent::Payload {
                    payload,
                    properties,
                    end_of_group: ty.is_end_of_group(),
                },
            )
        };

        Ok(Self {
            track_alias,
            group,
            object,
            priority,
            content,
        })
    }
}

/// Datagram type for padding, used to probe for bandwidth (§11.5.2).
pub const PADDING_DATAGRAM_TYPE: u64 = 0x132B_3E29;

/// Stream type for padding (§11.5.1).
pub const PADDING_STREAM_TYPE: u64 = 0x132B_3E28;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::control::params::Parameter;

    fn props() -> Properties {
        let mut p = Properties::new();
        p.push(Parameter::varint(0x10, VarInt::from_u32(1)).unwrap());
        p
    }

    fn round_trip(datagram: &ObjectDatagram) {
        let mut buf = Vec::new();
        datagram.encode(&mut buf);
        assert_eq!(buf.len(), datagram.encoded_len(), "sizing");
        let mut cursor = buf.as_slice();
        assert_eq!(&ObjectDatagram::decode(&mut cursor).unwrap(), datagram);
        assert!(cursor.is_empty());
    }

    #[test]
    fn round_trips_across_the_field_combinations() {
        for object in [ObjectId::ZERO, ObjectId::from(9u32)] {
            for priority in [None, Some(7u8)] {
                for properties in [Properties::new(), props()] {
                    let mut contents = vec![
                        DatagramContent::Empty {
                            properties: properties.clone(),
                        },
                        DatagramContent::Terminal(TerminalStatus::EndOfGroup),
                        DatagramContent::Terminal(TerminalStatus::EndOfTrack),
                    ];
                    for end_of_group in [false, true] {
                        contents.push(DatagramContent::Payload {
                            payload: NonEmptyPayload::new(&b"frame"[..]).unwrap(),
                            properties: properties.clone(),
                            end_of_group,
                        });
                    }

                    for content in contents {
                        round_trip(&ObjectDatagram {
                            track_alias: TrackAlias::from(3u32),
                            group: GroupId::from(4u32),
                            object,
                            priority,
                            content,
                        });
                    }
                }
            }
        }
    }

    /// The reason [`NonEmptyPayload`] exists. A zero-length object encodes with
    /// the `STATUS` bit, and the draft forbids `END_OF_GROUP` alongside it, so
    /// two cannot both be expressed. An earlier model allowed both and silently
    /// dropped the flag; this pins the shape that makes that impossible.
    #[test]
    fn a_zero_length_object_has_no_end_of_group_to_lose() {
        let empty = DatagramContent::payload(Bytes::new());
        assert!(matches!(empty, DatagramContent::Empty { .. }));

        // Every constructible content either has bytes or has no flag.
        for content in [
            DatagramContent::payload(&b"x"[..]),
            DatagramContent::payload(Bytes::new()),
            DatagramContent::Terminal(TerminalStatus::EndOfGroup),
        ] {
            let datagram = ObjectDatagram {
                track_alias: TrackAlias::from(1u32),
                group: GroupId::ZERO,
                object: ObjectId::ZERO,
                priority: None,
                content,
            };
            let ty = datagram.datagram_type();
            assert!(!(ty.carries_status() && ty.is_end_of_group()));
            round_trip(&datagram);
        }
    }

    /// The payload runs to the end of the datagram, so a decoder handed extra
    /// bytes cannot tell them apart from media. Documented, and pinned here so
    /// nobody "fixes" it into silently dropping data.
    #[test]
    fn payload_absorbs_everything_remaining() {
        let datagram = ObjectDatagram::new(
            TrackAlias::from(1u32),
            GroupId::ZERO,
            ObjectId::ZERO,
            &b"abc"[..],
        );
        let mut buf = Vec::new();
        datagram.encode(&mut buf);
        buf.extend_from_slice(b"tail");

        let mut cursor = buf.as_slice();
        let decoded = ObjectDatagram::decode(&mut cursor).unwrap();
        match decoded.content {
            DatagramContent::Payload { payload, .. } => {
                assert_eq!(&payload.as_bytes()[..], b"abctail");
            }
            other => panic!("expected a payload, got {other:?}"),
        }
    }

    /// A zero-length object must say Normal explicitly rather than leaving an
    /// empty payload region, and must come back as the same value.
    #[test]
    fn empty_payload_encodes_an_explicit_normal_status() {
        let datagram = ObjectDatagram::new(
            TrackAlias::from(1u32),
            GroupId::ZERO,
            ObjectId::ZERO,
            Bytes::new(),
        );
        assert!(datagram.datagram_type().carries_status());
        round_trip(&datagram);
    }

    /// Accepting the non-canonical spelling matters: another implementation may
    /// send an empty payload region instead of an explicit status, and the
    /// value must be the same either way.
    #[test]
    fn empty_payload_region_decodes_as_a_zero_length_normal_object() {
        let canonical = ObjectDatagram::new(
            TrackAlias::from(1u32),
            GroupId::ZERO,
            ObjectId::ZERO,
            Bytes::new(),
        );

        // Same object with STATUS clear and simply no payload bytes.
        let ty = DatagramType::new(false, true, true, false, false);
        let bytes = [ty.as_u8(), 0x01, 0x00];
        let mut cursor = &bytes[..];
        assert_eq!(ObjectDatagram::decode(&mut cursor).unwrap(), canonical);
    }

    #[test]
    fn terminal_objects_reject_properties() {
        let ty = DatagramType::new(true, true, true, true, false);
        let mut buf = vec![ty.as_u8(), 0x01, 0x00];
        props().encode_prefixed(&mut buf);
        buf.push(0x03); // EndOfGroup

        let mut cursor = buf.as_slice();
        let err = ObjectDatagram::decode(&mut cursor).unwrap_err();
        assert!(err.is_fatal());
    }

    #[test]
    fn properties_bit_with_empty_set_is_rejected() {
        let ty = DatagramType::new(true, true, true, false, false);
        let bytes = [ty.as_u8(), 0x01, 0x00, 0x00];
        let mut cursor = &bytes[..];
        assert!(ObjectDatagram::decode(&mut cursor).unwrap_err().is_fatal());
    }

    #[test]
    fn truncation_is_short_not_fatal() {
        let mut datagram = ObjectDatagram::new(
            TrackAlias::from(300u32),
            GroupId::from(70_000u32),
            ObjectId::from(5u32),
            &b"payload"[..],
        );
        datagram.priority = Some(4);

        let mut buf = Vec::new();
        datagram.encode(&mut buf);

        for cut in 0..buf.len() {
            let mut cursor = &buf[..cut];
            if let Err(e) = ObjectDatagram::decode(&mut cursor) {
                assert!(!e.is_fatal(), "truncation at {cut} was fatal: {e}");
            }
        }
    }
}
