//! Subgroup streams, per draft-19 §11.4.
//!
//! A subgroup stream opens with a [`SubgroupHeader`] and then carries objects
//! back to back until the stream is finished or reset. Two things make this
//! different from every other codec in this crate, and both are stateful:
//!
//! 1. **Object IDs are delta-encoded.** An object's ID depends on the previous
//!    object on the same stream. A decoder that loses that state does not
//!    produce a wrong ID once, it produces wrong IDs forever after.
//! 2. **Field presence is decided by the header,** not per object. Whether
//!    properties are on the wire is a property of the stream. Read an object
//!    without the header's flags and every field lands at the wrong offset.
//!
//! So objects are read and written through [`SubgroupReader`] and
//! [`SubgroupWriter`], which own that state. There is deliberately no
//! standalone `SubgroupObject::decode`: it could not be correct, and offering
//! it would invite exactly the bug the reader exists to prevent.

use bytes::{Buf, BufMut, Bytes};

use crate::control::properties::Properties;
use crate::data::flags::{SubgroupIdMode, SubgroupType};
use crate::data::object::TerminalStatus;
use crate::error::DecodeError;
use crate::model::{GroupId, ObjectSeq, ObjectStatus, SubgroupId, TrackAlias};
use crate::varint::VarInt;

/// Refusals when writing a subgroup stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum SubgroupError {
    /// An object carried properties on a stream whose header did not declare
    /// them, so there is no field to put them in.
    ///
    /// Writing anyway would drop the properties silently. Since properties can
    /// carry the information a relay routes on, dropping them is worse than
    /// refusing the write.
    #[error("stream header did not declare properties, so this object's cannot be encoded")]
    PropertiesNotDeclared,

    /// Object IDs did not increase.
    ///
    /// The delta encoding has no way to express a repeat or a step backwards.
    #[error("object ID {next} does not follow {previous} on this subgroup")]
    NotIncreasing {
        /// The last ID written.
        previous: u64,
        /// The ID that was offered.
        next: u64,
    },

    /// The step between consecutive Object IDs is too large to encode.
    ///
    /// Both IDs are legal; the gap is not, because the delta is a `vi64`. On
    /// the first object the "gap" is the absolute ID, so this is also what
    /// stops a stream starting above the varint maximum.
    #[error("object ID gap from {previous:?} to {next} exceeds one varint")]
    GapTooLarge {
        /// The last ID written, or `None` if this was the first object.
        previous: Option<u64>,
        /// The ID that was offered.
        next: u64,
    },
}

/// The header that opens a subgroup stream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubgroupHeader {
    /// The track, by the alias the publisher assigned.
    pub track_alias: TrackAlias,
    /// The group this subgroup belongs to.
    pub group: GroupId,
    /// How the Subgroup ID is conveyed, and its value when explicit.
    pub subgroup: SubgroupSource,
    /// Publisher priority, or `None` to inherit the subscription's.
    pub priority: Option<u8>,
    /// Whether every object on this stream carries a properties field.
    ///
    /// A stream-wide decision: objects with nothing to say still write a
    /// zero-length set. That is the opposite of a datagram, where the bit and a
    /// zero length are the same state.
    pub properties_present: bool,
    /// This subgroup holds the largest Object ID in its group, so a `FIN` also
    /// means the group is complete.
    pub end_of_group: bool,
    /// The first object here is the first the original publisher sent.
    pub first_object: bool,
}

/// Where a stream's Subgroup ID comes from.
///
/// Mirrors [`SubgroupIdMode`] but carries the value for the explicit case, so a
/// header always knows its own Subgroup ID or knows that it does not yet.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SubgroupSource {
    /// The Subgroup ID is zero and absent from the wire.
    #[default]
    Zero,
    /// The Subgroup ID is the Object ID of the first object on the stream, and
    /// so is not known until that object arrives.
    FirstObjectId,
    /// The Subgroup ID is carried in the header.
    Explicit(SubgroupId),
}

impl SubgroupSource {
    const fn mode(self) -> SubgroupIdMode {
        match self {
            Self::Zero => SubgroupIdMode::Zero,
            Self::FirstObjectId => SubgroupIdMode::FirstObjectId,
            Self::Explicit(_) => SubgroupIdMode::Explicit,
        }
    }

    /// The Subgroup ID, when it is known without reading an object.
    #[must_use]
    pub const fn resolved(self) -> Option<SubgroupId> {
        match self {
            Self::Zero => Some(SubgroupId::ZERO),
            Self::FirstObjectId => None,
            Self::Explicit(id) => Some(id),
        }
    }
}

impl SubgroupHeader {
    /// A header for `subgroup` in `group`, inheriting priority and carrying no
    /// properties.
    #[must_use]
    pub const fn new(track_alias: TrackAlias, group: GroupId, subgroup: SubgroupSource) -> Self {
        Self {
            track_alias,
            group,
            subgroup,
            priority: None,
            properties_present: false,
            end_of_group: false,
            first_object: false,
        }
    }

    /// The type code this header will encode with.
    #[must_use]
    pub const fn stream_type(&self) -> SubgroupType {
        SubgroupType::new(
            self.properties_present,
            self.subgroup.mode(),
            self.end_of_group,
            self.priority.is_none(),
            self.first_object,
        )
    }

    /// Encoded size in bytes.
    #[must_use]
    pub fn encoded_len(&self) -> usize {
        let mut len = VarInt::from_u32(u32::from(self.stream_type().as_u8())).size();
        len += self.track_alias.as_varint().size();
        len += self.group.as_varint().size();
        if let SubgroupSource::Explicit(id) = self.subgroup {
            len += id.as_varint().size();
        }
        if self.priority.is_some() {
            len += 1;
        }
        len
    }

    /// Append the header to `buf`.
    pub fn encode<B: BufMut>(&self, buf: &mut B) {
        VarInt::from_u32(u32::from(self.stream_type().as_u8())).encode(buf);
        self.track_alias.as_varint().encode(buf);
        self.group.as_varint().encode(buf);
        if let SubgroupSource::Explicit(id) = self.subgroup {
            id.as_varint().encode(buf);
        }
        if let Some(priority) = self.priority {
            buf.put_u8(priority);
        }
    }

    /// Decode a header from the start of a stream.
    ///
    /// # Errors
    /// [`DecodeError::Invalid`] for a malformed or reserved type code;
    /// [`DecodeError::Short`] if the header is incomplete.
    pub fn decode<B: Buf>(buf: &mut B) -> Result<Self, DecodeError> {
        let ty = SubgroupType::from_u64(VarInt::decode(buf)?.get())?;
        let track_alias = TrackAlias::new(VarInt::decode(buf)?);
        let group = GroupId::new(VarInt::decode(buf)?);

        let subgroup = match ty.subgroup_id_mode()? {
            SubgroupIdMode::Zero => SubgroupSource::Zero,
            SubgroupIdMode::FirstObjectId => SubgroupSource::FirstObjectId,
            SubgroupIdMode::Explicit => {
                SubgroupSource::Explicit(SubgroupId::new(VarInt::decode(buf)?))
            }
        };

        let priority = if ty.has_default_priority() {
            None
        } else {
            if !buf.has_remaining() {
                return Err(DecodeError::Short { needed: 1 });
            }
            Some(buf.get_u8())
        };

        Ok(Self {
            track_alias,
            group,
            subgroup,
            priority,
            properties_present: ty.has_properties(),
            end_of_group: ty.is_end_of_group(),
            first_object: ty.is_first_object(),
        })
    }
}

/// What an object on a subgroup stream carries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SubgroupContent {
    /// A normal object.
    Normal {
        /// Media bytes. Empty is legal and encodes an explicit Normal status.
        payload: Bytes,
        /// Relay-visible metadata. Only encodable when the stream header
        /// declared `properties_present`.
        properties: Properties,
    },
    /// An end-of-range marker, which by definition has neither payload nor
    /// properties.
    Terminal(TerminalStatus),
}

/// One object on a subgroup stream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubgroupObject {
    /// Absolute Object ID, already resolved from the wire's delta.
    ///
    /// Wider than [`crate::model::ObjectId`] because accumulation can carry it
    /// past the varint maximum; see [`ObjectSeq`].
    pub object: ObjectSeq,
    /// Payload or terminal marker.
    pub content: SubgroupContent,
}

impl SubgroupObject {
    /// A normal object with a payload and no properties.
    #[must_use]
    pub fn new(object: impl Into<ObjectSeq>, payload: impl Into<Bytes>) -> Self {
        Self {
            object: object.into(),
            content: SubgroupContent::Normal {
                payload: payload.into(),
                properties: Properties::new(),
            },
        }
    }

    fn properties(&self) -> Option<&Properties> {
        match &self.content {
            SubgroupContent::Normal { properties, .. } => Some(properties),
            SubgroupContent::Terminal(_) => None,
        }
    }
}

/// Shared delta state between the reader and the writer.
#[derive(Debug, Clone, Copy, Default)]
struct DeltaState {
    previous: Option<ObjectSeq>,
    first_object_id: Option<ObjectSeq>,
}

impl DeltaState {
    /// Resolve a wire delta into an absolute Object ID.
    ///
    /// The accumulated value may exceed the varint maximum — see [`ObjectSeq`],
    /// which exists for exactly this. Only 2^64-1 is a real ceiling, and only
    /// because the draft says so.
    fn resolve(&self, delta: u64) -> Result<ObjectSeq, DecodeError> {
        match self.previous {
            None => Ok(ObjectSeq::new(delta)),
            Some(previous) => previous
                .checked_add(delta)
                .and_then(|v| v.checked_add(1))
                .ok_or(DecodeError::Invalid("object ID passed 2^64-1")),
        }
    }

    /// The wire delta for an absolute Object ID.
    ///
    /// Two ways this fails, and they are different problems:
    ///
    /// - The ID did not increase, which the encoding cannot express at all.
    /// - The gap since the previous object exceeds what one varint holds. The
    ///   IDs are legal; the *step* between them is not encodable. For the first
    ///   object this also caps the starting ID, since its delta is the absolute
    ///   value — which is why a stream can only reach the wide range by
    ///   accumulating, never by starting there.
    fn delta_for(&self, object: ObjectSeq) -> Result<VarInt, SubgroupError> {
        let raw = match self.previous {
            None => object.get(),
            Some(previous) => object
                .get()
                .checked_sub(previous.get())
                .and_then(|d| d.checked_sub(1))
                .ok_or(SubgroupError::NotIncreasing {
                    previous: previous.get(),
                    next: object.get(),
                })?,
        };

        VarInt::new(raw).map_err(|_| SubgroupError::GapTooLarge {
            previous: self.previous.map(ObjectSeq::get),
            next: object.get(),
        })
    }

    fn advance(&mut self, object: ObjectSeq) {
        if self.previous.is_none() {
            self.first_object_id = Some(object);
        }
        self.previous = Some(object);
    }
}

/// Reads objects from a subgroup stream, carrying the delta and flag state the
/// wire format depends on.
#[derive(Debug, Clone)]
pub struct SubgroupReader {
    properties_present: bool,
    source: SubgroupSource,
    state: DeltaState,
}

impl SubgroupReader {
    /// Start reading the stream this header opened.
    #[must_use]
    pub const fn new(header: &SubgroupHeader) -> Self {
        Self {
            properties_present: header.properties_present,
            source: header.subgroup,
            state: DeltaState {
                previous: None,
                first_object_id: None,
            },
        }
    }

    /// The stream's Subgroup ID, once it is known.
    ///
    /// `None` only while the header said `FirstObjectId` and no object has been
    /// read yet.
    #[must_use]
    pub fn subgroup(&self) -> Option<SubgroupId> {
        match self.source {
            // Always narrowable: the first object's delta *is* its absolute ID,
            // so it arrived as one varint and still fits in one.
            SubgroupSource::FirstObjectId => self
                .state
                .first_object_id
                .and_then(ObjectSeq::to_object_id)
                .map(|id| SubgroupId::new(id.as_varint())),
            other => other.resolved(),
        }
    }

    /// Number of objects read so far.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.state.previous.is_none()
    }

    /// Read the next object.
    ///
    /// On [`DecodeError::Short`] no state has advanced and `buf` is left as it
    /// was, so the caller can retry once more bytes arrive.
    ///
    /// # Errors
    /// [`DecodeError::Short`] if the object is incomplete;
    /// [`DecodeError::Invalid`] for a malformed status, an unrepresentable
    /// Object ID, or properties on a terminal object.
    pub fn read(&mut self, buf: &mut &[u8]) -> Result<SubgroupObject, DecodeError> {
        let mut cursor = *buf;
        let object = self.read_from(&mut cursor)?;
        *buf = cursor;
        self.state.advance(object.object);
        Ok(object)
    }

    fn read_from(&self, buf: &mut &[u8]) -> Result<SubgroupObject, DecodeError> {
        let delta = VarInt::decode(buf)?.get();
        let object = self.state.resolve(delta)?;

        let properties = if self.properties_present {
            Properties::decode_prefixed(buf)?
        } else {
            Properties::new()
        };

        let payload_len = VarInt::decode(buf)?.get();
        let payload_len = usize::try_from(payload_len)
            .map_err(|_| DecodeError::Invalid("payload length exceeds addressable memory"))?;

        if payload_len == 0 {
            let status = ObjectStatus::decode(buf)?;
            return match status {
                ObjectStatus::Normal => Ok(SubgroupObject {
                    object,
                    content: SubgroupContent::Normal {
                        payload: Bytes::new(),
                        properties,
                    },
                }),
                other => {
                    if !properties.is_empty() {
                        return Err(DecodeError::Invalid(
                            "only normal objects may carry properties",
                        ));
                    }
                    Ok(SubgroupObject {
                        object,
                        content: SubgroupContent::Terminal(TerminalStatus::try_from(other)?),
                    })
                }
            };
        }

        if buf.remaining() < payload_len {
            return Err(DecodeError::Short {
                needed: payload_len - buf.remaining(),
            });
        }
        let payload = buf.copy_to_bytes(payload_len);
        Ok(SubgroupObject {
            object,
            content: SubgroupContent::Normal {
                payload,
                properties,
            },
        })
    }
}

/// Writes objects to a subgroup stream, holding the same state as the reader.
#[derive(Debug, Clone)]
pub struct SubgroupWriter {
    properties_present: bool,
    state: DeltaState,
}

impl SubgroupWriter {
    /// Start writing the stream this header opens.
    #[must_use]
    pub const fn new(header: &SubgroupHeader) -> Self {
        Self {
            properties_present: header.properties_present,
            state: DeltaState {
                previous: None,
                first_object_id: None,
            },
        }
    }

    /// Bytes [`Self::write`] will append for this object.
    ///
    /// # Errors
    /// The same refusals as [`Self::write`], so a caller can size a buffer
    /// without risking a write that then fails partway.
    pub fn encoded_len(&self, object: &SubgroupObject) -> Result<usize, SubgroupError> {
        self.check(object)?;
        let mut len = self.state.delta_for(object.object)?.size();
        if self.properties_present {
            len += object
                .properties()
                .map_or(1, Properties::encoded_len_prefixed);
        }
        match &object.content {
            SubgroupContent::Normal { payload, .. } => {
                if payload.is_empty() {
                    len += VarInt::ZERO.size() + ObjectStatus::Normal.encoded_len();
                } else {
                    len += VarInt::from_u32(payload.len() as u32).size() + payload.len();
                }
            }
            SubgroupContent::Terminal(status) => {
                len += VarInt::ZERO.size() + status.as_status().encoded_len();
            }
        }
        Ok(len)
    }

    /// Append an object to the stream.
    ///
    /// # Errors
    /// [`SubgroupError::PropertiesNotDeclared`] if the object carries
    /// properties the header made no room for, or
    /// [`SubgroupError::NotIncreasing`] if the Object ID does not advance.
    pub fn write<B: BufMut>(
        &mut self,
        buf: &mut B,
        object: &SubgroupObject,
    ) -> Result<(), SubgroupError> {
        self.check(object)?;
        let delta = self.state.delta_for(object.object)?;
        delta.encode(buf);

        if self.properties_present {
            match object.properties() {
                Some(properties) => properties.encode_prefixed(buf),
                // A terminal object still needs the field the header promised.
                None => VarInt::ZERO.encode(buf),
            }
        }

        match &object.content {
            SubgroupContent::Normal { payload, .. } => {
                if payload.is_empty() {
                    VarInt::ZERO.encode(buf);
                    ObjectStatus::Normal.encode(buf);
                } else {
                    VarInt::from_u32(payload.len() as u32).encode(buf);
                    buf.put_slice(payload);
                }
            }
            SubgroupContent::Terminal(status) => {
                VarInt::ZERO.encode(buf);
                status.as_status().encode(buf);
            }
        }

        self.state.advance(object.object);
        Ok(())
    }

    fn check(&self, object: &SubgroupObject) -> Result<(), SubgroupError> {
        if !self.properties_present
            && let SubgroupContent::Normal { properties, .. } = &object.content
            && !properties.is_empty()
        {
            return Err(SubgroupError::PropertiesNotDeclared);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::control::params::Parameter;

    fn props() -> Properties {
        let mut p = Properties::new();
        p.push(Parameter::varint(0x10, VarInt::from_u32(1)).unwrap());
        p
    }

    fn header(properties_present: bool, subgroup: SubgroupSource) -> SubgroupHeader {
        SubgroupHeader {
            track_alias: TrackAlias::from(3u32),
            group: GroupId::from(9u32),
            subgroup,
            priority: Some(128),
            properties_present,
            end_of_group: false,
            first_object: true,
        }
    }

    #[test]
    fn header_round_trips_across_the_field_combinations() {
        let sources = [
            SubgroupSource::Zero,
            SubgroupSource::FirstObjectId,
            SubgroupSource::Explicit(SubgroupId::from(5u32)),
        ];
        for subgroup in sources {
            for properties_present in [false, true] {
                for priority in [None, Some(200u8)] {
                    for end_of_group in [false, true] {
                        for first_object in [false, true] {
                            let h = SubgroupHeader {
                                track_alias: TrackAlias::from(70_000u32),
                                group: GroupId::from(1u32),
                                subgroup,
                                priority,
                                properties_present,
                                end_of_group,
                                first_object,
                            };
                            let mut buf = Vec::new();
                            h.encode(&mut buf);
                            assert_eq!(buf.len(), h.encoded_len());
                            let mut cursor = buf.as_slice();
                            assert_eq!(SubgroupHeader::decode(&mut cursor).unwrap(), h);
                            assert!(cursor.is_empty());
                        }
                    }
                }
            }
        }
    }

    /// The whole point of the reader and writer: a sequence of objects has to
    /// survive the delta encoding intact, including the gaps.
    #[test]
    fn object_sequences_round_trip_through_the_deltas() {
        for properties_present in [false, true] {
            let h = header(properties_present, SubgroupSource::Zero);
            let objects = vec![
                SubgroupObject::new(ObjectSeq::from(4u32), &b"first"[..]),
                SubgroupObject::new(ObjectSeq::from(5u32), &b"second"[..]),
                // A gap, which the delta must carry.
                SubgroupObject::new(ObjectSeq::from(40u32), Bytes::new()),
                SubgroupObject {
                    object: ObjectSeq::from(41u32),
                    content: SubgroupContent::Normal {
                        payload: Bytes::from_static(b"props"),
                        properties: if properties_present {
                            props()
                        } else {
                            Properties::new()
                        },
                    },
                },
                SubgroupObject {
                    object: ObjectSeq::from(99u32),
                    content: SubgroupContent::Terminal(TerminalStatus::EndOfGroup),
                },
            ];

            let mut buf = Vec::new();
            let mut writer = SubgroupWriter::new(&h);
            for object in &objects {
                let expected = writer.encoded_len(object).unwrap();
                let before = buf.len();
                writer.write(&mut buf, object).unwrap();
                assert_eq!(
                    buf.len() - before,
                    expected,
                    "sizing for {:?}",
                    object.object
                );
            }

            let mut reader = SubgroupReader::new(&h);
            let mut cursor = buf.as_slice();
            for object in &objects {
                assert_eq!(&reader.read(&mut cursor).unwrap(), object);
            }
            assert!(cursor.is_empty());
        }
    }

    /// Sequential IDs are the common case and must cost one zero byte each.
    #[test]
    fn sequential_object_ids_encode_as_zero_deltas() {
        let h = header(false, SubgroupSource::Zero);
        let mut buf = Vec::new();
        let mut writer = SubgroupWriter::new(&h);
        for id in 0..4u32 {
            writer
                .write(
                    &mut buf,
                    &SubgroupObject::new(ObjectSeq::from(id), &b"x"[..]),
                )
                .unwrap();
        }
        // Per object: delta 0x00, length 0x01, payload 'x'.
        assert_eq!(buf, [0x00, 0x01, b'x'].repeat(4));
    }

    #[test]
    fn subgroup_id_from_first_object_resolves_after_the_first_read() {
        let h = header(false, SubgroupSource::FirstObjectId);
        let mut buf = Vec::new();
        let mut writer = SubgroupWriter::new(&h);
        writer
            .write(
                &mut buf,
                &SubgroupObject::new(ObjectSeq::from(12u32), &b"a"[..]),
            )
            .unwrap();

        let mut reader = SubgroupReader::new(&h);
        assert_eq!(reader.subgroup(), None);
        assert!(reader.is_empty());

        let mut cursor = buf.as_slice();
        reader.read(&mut cursor).unwrap();
        assert_eq!(reader.subgroup(), Some(SubgroupId::from(12u32)));
        assert!(!reader.is_empty());
    }

    #[test]
    fn non_increasing_object_ids_are_refused() {
        let h = header(false, SubgroupSource::Zero);
        let mut buf = Vec::new();
        let mut writer = SubgroupWriter::new(&h);
        writer
            .write(
                &mut buf,
                &SubgroupObject::new(ObjectSeq::from(5u32), &b"a"[..]),
            )
            .unwrap();

        for id in [0u32, 5] {
            let err = writer
                .write(
                    &mut buf,
                    &SubgroupObject::new(ObjectSeq::from(id), &b"b"[..]),
                )
                .unwrap_err();
            assert!(matches!(
                err,
                SubgroupError::NotIncreasing { previous: 5, .. }
            ));
        }
    }

    /// Silently dropping properties would lose data a relay may route on, so
    /// the write is refused instead.
    #[test]
    fn properties_without_a_declaring_header_are_refused() {
        let h = header(false, SubgroupSource::Zero);
        let mut writer = SubgroupWriter::new(&h);
        let object = SubgroupObject {
            object: ObjectSeq::ZERO,
            content: SubgroupContent::Normal {
                payload: Bytes::from_static(b"x"),
                properties: props(),
            },
        };
        assert_eq!(
            writer.write(&mut Vec::new(), &object).unwrap_err(),
            SubgroupError::PropertiesNotDeclared
        );
        assert_eq!(
            writer.encoded_len(&object).unwrap_err(),
            SubgroupError::PropertiesNotDeclared
        );
    }

    /// A stream that declares properties must write the field even for objects
    /// that have none, or every later field shifts.
    #[test]
    fn declared_properties_are_written_even_when_empty() {
        let h = header(true, SubgroupSource::Zero);
        let mut buf = Vec::new();
        let mut writer = SubgroupWriter::new(&h);
        writer
            .write(
                &mut buf,
                &SubgroupObject {
                    object: ObjectSeq::ZERO,
                    content: SubgroupContent::Terminal(TerminalStatus::EndOfTrack),
                },
            )
            .unwrap();
        // delta 0, properties length 0, payload length 0, status 0x04.
        assert_eq!(buf, vec![0x00, 0x00, 0x00, 0x04]);
    }

    /// A short read must leave the reader and the buffer untouched, or a
    /// retry after more bytes arrive would resume from a corrupted position.
    #[test]
    fn a_short_read_does_not_advance_state() {
        let h = header(false, SubgroupSource::Zero);
        let mut buf = Vec::new();
        let mut writer = SubgroupWriter::new(&h);
        writer
            .write(
                &mut buf,
                &SubgroupObject::new(ObjectSeq::from(1u32), &b"hello"[..]),
            )
            .unwrap();
        writer
            .write(
                &mut buf,
                &SubgroupObject::new(ObjectSeq::from(2u32), &b"world"[..]),
            )
            .unwrap();

        for cut in 1..buf.len() {
            let mut reader = SubgroupReader::new(&h);
            let mut cursor = &buf[..cut];
            let before = cursor;

            if reader.read(&mut cursor).is_err() {
                assert_eq!(cursor, before, "buffer moved on a failed read at {cut}");
                assert!(
                    reader.is_empty(),
                    "state advanced on a failed read at {cut}"
                );
            }
        }

        // And the whole thing still reads once complete.
        let mut reader = SubgroupReader::new(&h);
        let mut cursor = buf.as_slice();
        assert_eq!(
            reader.read(&mut cursor).unwrap().object,
            ObjectSeq::from(1u32)
        );
        assert_eq!(
            reader.read(&mut cursor).unwrap().object,
            ObjectSeq::from(2u32)
        );
    }

    /// Object IDs accumulate past the varint maximum, and that is legal: the
    /// absolute value never goes on the wire, only the deltas do. An earlier
    /// version capped this at the varint maximum and so rejected a conformant
    /// peer. The only ceiling is 2^64-1.
    #[test]
    fn object_ids_accumulate_past_the_varint_ceiling() {
        let h = header(false, SubgroupSource::Zero);
        let mut reader = SubgroupReader::new(&h);

        // Start as high as one varint allows, then step past it four times.
        let mut buf = Vec::new();
        VarInt::MAX.encode(&mut buf);
        buf.extend_from_slice(&[0x01, b'a']);
        for _ in 0..4 {
            buf.extend_from_slice(&[0x00, 0x01, b'b']);
        }

        let mut cursor = buf.as_slice();
        let mut seen = Vec::new();
        for _ in 0..5 {
            seen.push(reader.read(&mut cursor).unwrap().object);
        }
        assert!(cursor.is_empty());

        assert_eq!(seen[0].get(), crate::varint::MAX);
        assert_eq!(seen[4].get(), crate::varint::MAX + 4);
        // Past the varint ceiling, so it cannot be named in a control message —
        // but it is still a perfectly deliverable object.
        assert!(seen[4].to_object_id().is_none());

        // And it all re-encodes, because only the deltas are ever written.
        let mut out = Vec::new();
        let mut writer = SubgroupWriter::new(&h);
        for object in &seen {
            writer
                .write(&mut out, &SubgroupObject::new(*object, &b"a"[..]))
                .unwrap();
        }
        let mut reader = SubgroupReader::new(&h);
        let mut cursor = out.as_slice();
        for object in &seen {
            assert_eq!(reader.read(&mut cursor).unwrap().object, *object);
        }
    }

    /// The one real ceiling: overflowing 2^64-1 is a protocol violation.
    #[test]
    fn object_ids_past_2_pow_64_are_rejected() {
        let h = header(false, SubgroupSource::Zero);
        let mut reader = SubgroupReader::new(&h);

        // Climb with maximal deltas until the next one would overflow.
        let mut buf = Vec::new();
        VarInt::MAX.encode(&mut buf);
        buf.extend_from_slice(&[0x01, b'a']);
        let mut cursor = buf.as_slice();
        reader.read(&mut cursor).unwrap();

        let mut last = crate::varint::MAX;
        loop {
            let mut buf = Vec::new();
            VarInt::MAX.encode(&mut buf);
            buf.extend_from_slice(&[0x01, b'b']);
            let mut cursor = buf.as_slice();
            match reader.read(&mut cursor) {
                Ok(read) => {
                    assert!(read.object.get() > last);
                    last = read.object.get();
                }
                Err(e) => {
                    assert!(e.is_fatal(), "overflow must be fatal, got {e}");
                    break;
                }
            }
        }
    }

    /// A stream cannot *start* above the varint maximum: the first object's
    /// delta is its absolute ID. The wide range is reachable only by
    /// accumulating, and that asymmetry is what makes the scheme sound.
    #[test]
    fn a_stream_cannot_start_above_the_varint_maximum() {
        let h = header(false, SubgroupSource::Zero);
        let mut writer = SubgroupWriter::new(&h);
        let too_high = ObjectSeq::new(crate::varint::MAX + 1);
        assert_eq!(
            writer
                .write(&mut Vec::new(), &SubgroupObject::new(too_high, &b"a"[..]))
                .unwrap_err(),
            SubgroupError::GapTooLarge {
                previous: None,
                next: crate::varint::MAX + 1
            }
        );
    }

    /// A gap wider than one varint is unencodable even though both IDs are
    /// legal, which is a different failure from going backwards.
    #[test]
    fn an_unencodable_gap_is_distinct_from_going_backwards() {
        let h = header(false, SubgroupSource::Zero);
        let mut buf = Vec::new();
        let mut writer = SubgroupWriter::new(&h);
        writer
            .write(&mut buf, &SubgroupObject::new(1u32, &b"a"[..]))
            .unwrap();

        let far = ObjectSeq::new(crate::varint::MAX + 8);
        assert!(matches!(
            writer
                .write(&mut buf, &SubgroupObject::new(far, &b"b"[..]))
                .unwrap_err(),
            SubgroupError::GapTooLarge {
                previous: Some(1),
                ..
            }
        ));
        assert!(matches!(
            writer
                .write(&mut buf, &SubgroupObject::new(0u32, &b"b"[..]))
                .unwrap_err(),
            SubgroupError::NotIncreasing {
                previous: 1,
                next: 0
            }
        ));
    }

    #[test]
    fn payload_length_beyond_the_buffer_is_short_not_fatal() {
        let h = header(false, SubgroupSource::Zero);
        let mut reader = SubgroupReader::new(&h);
        // delta 0, length 63, one byte of payload.
        let bytes = [0x00, 0x3F, b'x'];
        let mut cursor = &bytes[..];
        let err = reader.read(&mut cursor).unwrap_err();
        assert!(!err.is_fatal(), "{err}");
    }

    #[test]
    fn terminal_objects_reject_properties() {
        let h = header(true, SubgroupSource::Zero);
        let mut buf = Vec::new();
        VarInt::ZERO.encode(&mut buf); // delta
        props().encode_prefixed(&mut buf);
        VarInt::ZERO.encode(&mut buf); // payload length
        buf.push(0x03); // EndOfGroup

        let mut reader = SubgroupReader::new(&h);
        let mut cursor = buf.as_slice();
        assert!(reader.read(&mut cursor).unwrap_err().is_fatal());
    }
}
