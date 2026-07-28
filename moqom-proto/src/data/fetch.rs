//! Fetch streams, per draft-19 §11.5.
//!
//! A fetch answers one request, so its stream carries a Request ID instead of a
//! track alias and the objects come back on a single stream regardless of how
//! they were originally sent. That is the first difference from a subgroup
//! stream. The second is that a fetch spans groups, so every record names its
//! own group — and the encoding leans hard on the fact that consecutive records
//! usually differ in almost nothing.
//!
//! Each record starts with Serialization Flags saying which fields are on the
//! wire. An absent field is inherited from the previous record: the group
//! carries over, the Object ID is the previous plus one, the priority and the
//! subgroup are whatever they were. So a run of consecutive objects in one group
//! at one priority costs a byte of flags and a payload length each. The state
//! that makes this work lives in [`FetchWriter`] and [`FetchReader`], and there
//! is deliberately no standalone `FetchRecord::decode` for the same reason there
//! is no `SubgroupObject::decode`: it could not be correct.
//!
//! # Gaps are records
//!
//! The two End of Range markers are what let a relay serve a partial cache
//! honestly. "These objects do not exist" and "I do not know whether these
//! objects exist" are different statements — the first is final and the second
//! is worth asking another relay about — and a receiver that could not tell them
//! apart would either wait forever for something that is never coming or give up
//! on something it could still have.

use bytes::{Buf, BufMut, Bytes};

use crate::control::properties::Properties;
use crate::control::request_id::RequestId;
use crate::error::DecodeError;
use crate::model::{GroupId, Location, ObjectId, SubgroupId};
use crate::varint::VarInt;

/// The stream type code that opens a fetch's data stream.
pub const FETCH_HEADER_TYPE: u64 = 0x5;

/// Which way a fetch walks through groups.
///
/// Descending is for seeking backwards: the most recent group first, so
/// something is on screen before the whole range has arrived. It changes the
/// meaning of every group delta on the stream, which is why the reader and the
/// writer both have to be told.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum GroupOrder {
    /// Oldest group first.
    #[default]
    Ascending,
    /// Newest group first. Objects within a group still ascend.
    Descending,
}

/// Refusals when writing a fetch stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum FetchError {
    /// Locations must advance along the stream, in the negotiated group order.
    #[error("location {next} does not advance past {previous}")]
    NotAdvancing {
        /// The last location written.
        previous: Location,
        /// The location that was offered.
        next: Location,
    },

    /// The step between groups is too large to encode.
    ///
    /// Both groups are legal; the distance between them is not, because it is a
    /// `vi64`.
    #[error("group gap from {previous} to {next} exceeds one varint")]
    GapTooLarge {
        /// The last group written.
        previous: u64,
        /// The group that was offered.
        next: u64,
    },
}

/// The header that opens a fetch's data stream.
///
/// Bound to its request by Request ID and by nothing else — there is no track
/// alias here, because the request already named the track.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FetchHeader {
    /// The fetch this stream answers.
    pub request_id: RequestId,
}

impl FetchHeader {
    /// A header for `request_id`.
    #[must_use]
    pub const fn new(request_id: RequestId) -> Self {
        Self { request_id }
    }

    /// Encoded size in bytes.
    #[must_use]
    pub fn encoded_len(&self) -> usize {
        VarInt::from_u32(FETCH_HEADER_TYPE as u32).size() + self.request_id.encoded_len()
    }

    /// Append the header to `buf`.
    pub fn encode<B: BufMut>(&self, buf: &mut B) {
        VarInt::from_u32(FETCH_HEADER_TYPE as u32).encode(buf);
        self.request_id.encode(buf);
    }

    /// Read a header, including its stream type code.
    ///
    /// # Errors
    /// [`DecodeError::Short`] if incomplete, or [`DecodeError::Invalid`] if the
    /// leading code is not `FETCH_HEADER` — which is how a fetch stream is told
    /// apart from a subgroup stream, since both arrive the same way.
    pub fn decode<B: Buf>(buf: &mut B) -> Result<Self, DecodeError> {
        let code = VarInt::decode(buf)?.get();
        if code != FETCH_HEADER_TYPE {
            return Err(DecodeError::Invalid("stream type is not FETCH_HEADER"));
        }
        Ok(Self {
            request_id: RequestId::decode(buf)?,
        })
    }
}

/// One object on a fetch stream.
///
/// Fully resolved: the deltas have been applied, so nothing here depends on what
/// came before it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FetchObject {
    /// Where the object sits in the track.
    pub location: Location,
    /// The subgroup it came from. Zero for objects that were sent on datagrams.
    pub subgroup: SubgroupId,
    /// Publisher priority.
    pub priority: u8,
    /// Relay-visible metadata.
    pub properties: Properties,
    /// Media bytes.
    pub payload: Bytes,
}

impl FetchObject {
    /// An object at `location` with a payload, no properties, and default
    /// priority.
    #[must_use]
    pub fn new(location: Location, payload: impl Into<Bytes>) -> Self {
        Self {
            location,
            subgroup: SubgroupId::ZERO,
            priority: 128,
            properties: Properties::new(),
            payload: payload.into(),
        }
    }
}

/// A record on a fetch stream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FetchRecord {
    /// An object.
    Object(FetchObject),

    /// Everything from after the previous record through this location does not
    /// exist.
    EndOfNonExistentRange(Location),

    /// Everything from after the previous record through this location has
    /// unknown status. What a relay serving a partial cache says about the part
    /// it does not hold.
    EndOfUnknownRange(Location),
}

impl FetchRecord {
    /// The location this record reaches.
    #[must_use]
    pub const fn location(&self) -> Location {
        match self {
            Self::Object(object) => object.location,
            Self::EndOfNonExistentRange(location) | Self::EndOfUnknownRange(location) => *location,
        }
    }
}

/// How a record names its subgroup.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SubgroupMode {
    Zero,
    SameAsPrior,
    PriorPlusOne,
    Present,
}

impl SubgroupMode {
    const fn bits(self) -> u64 {
        match self {
            Self::Zero => 0x0,
            Self::SameAsPrior => 0x1,
            Self::PriorPlusOne => 0x2,
            Self::Present => 0x3,
        }
    }

    const fn from_bits(bits: u64) -> Self {
        match bits {
            0x1 => Self::SameAsPrior,
            0x2 => Self::PriorPlusOne,
            0x3 => Self::Present,
            _ => Self::Zero,
        }
    }
}

/// Bit layout of a record's Serialization Flags.
///
/// Values below 128 are flags; the two End of Range values are above it and are
/// whole values rather than combinations, which is why this is not a bitflag
/// set.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FetchFlags(u64);

impl FetchFlags {
    const OBJECT_DELTA: u64 = 0x04;
    const GROUP_DELTA: u64 = 0x08;
    const PRIORITY: u64 = 0x10;
    const PROPERTIES: u64 = 0x20;
    const DATAGRAM: u64 = 0x40;
    const SUBGROUP_MASK: u64 = 0x03;

    const END_OF_NON_EXISTENT: u64 = 0x8C;
    const END_OF_UNKNOWN: u64 = 0x10C;

    /// Flags describing which of a record's optional fields are present.
    ///
    /// Takes the fields themselves rather than five booleans so that the flags
    /// cannot disagree with what gets written: every bit here is set from the
    /// same `Option` the writer later consults.
    fn describing(
        subgroup: SubgroupMode,
        group_delta: Option<u64>,
        object_delta: Option<u64>,
        priority: Option<u8>,
        properties: &Properties,
    ) -> Self {
        let mut value = subgroup.bits();
        if object_delta.is_some() {
            value |= Self::OBJECT_DELTA;
        }
        if group_delta.is_some() {
            value |= Self::GROUP_DELTA;
        }
        if priority.is_some() {
            value |= Self::PRIORITY;
        }
        if !properties.is_empty() {
            value |= Self::PROPERTIES;
        }
        Self(value)
    }

    fn from_code(code: u64) -> Result<Self, DecodeError> {
        if code < 128 || code == Self::END_OF_NON_EXISTENT || code == Self::END_OF_UNKNOWN {
            Ok(Self(code))
        } else {
            Err(DecodeError::Invalid(
                "serialization flags are neither flags nor an end-of-range marker",
            ))
        }
    }

    const fn is_end_of_range(self) -> bool {
        self.0 == Self::END_OF_NON_EXISTENT || self.0 == Self::END_OF_UNKNOWN
    }

    const fn has_object_delta(self) -> bool {
        self.0 & Self::OBJECT_DELTA != 0
    }

    const fn has_group_delta(self) -> bool {
        self.0 & Self::GROUP_DELTA != 0
    }

    const fn has_priority(self) -> bool {
        self.0 & Self::PRIORITY != 0
    }

    const fn has_properties(self) -> bool {
        self.0 & Self::PROPERTIES != 0
    }

    const fn is_datagram(self) -> bool {
        self.0 & Self::DATAGRAM != 0
    }

    /// The low bits are meaningless when the datagram bit is set, and the draft
    /// says to ignore them rather than to reject them.
    const fn subgroup(self) -> SubgroupMode {
        if self.is_datagram() {
            SubgroupMode::Zero
        } else {
            SubgroupMode::from_bits(self.0 & Self::SUBGROUP_MASK)
        }
    }

    /// Whether this record depends on a preceding one, which the first record on
    /// a stream may not.
    const fn references_prior(self) -> bool {
        if self.is_end_of_range() {
            return false;
        }
        if !self.has_group_delta() || !self.has_object_delta() || !self.has_priority() {
            return true;
        }
        matches!(
            self.subgroup(),
            SubgroupMode::SameAsPrior | SubgroupMode::PriorPlusOne
        )
    }
}

/// The delta state shared by [`FetchWriter`] and [`FetchReader`].
///
/// Split out because the two have to agree on exactly one thing — what "prior"
/// means after each record — and the End of Range case makes that non-obvious: a
/// marker moves the prior group and object but leaves the prior subgroup and
/// priority as they were, since §11.4.4.2 says a marker has neither.
#[derive(Debug, Clone, Copy, Default)]
struct FetchState {
    group: Option<u64>,
    object: Option<u64>,
    subgroup: Option<u64>,
    priority: Option<u8>,
}

impl FetchState {
    const fn is_empty(&self) -> bool {
        self.group.is_none()
    }

    fn location(&self) -> Option<Location> {
        let group = self.group?;
        let object = self.object?;
        Some(Location::new(
            GroupId::new(VarInt::new(group).ok()?),
            ObjectId::new(VarInt::new(object).ok()?),
        ))
    }

    fn advance_to_object(&mut self, object: &FetchObject) {
        self.group = Some(object.location.group.get());
        self.object = Some(object.location.object.get());
        self.subgroup = Some(object.subgroup.get());
        self.priority = Some(object.priority);
    }

    fn advance_to_marker(&mut self, location: Location) {
        self.group = Some(location.group.get());
        self.object = Some(location.object.get());
    }
}

/// What one record encodes to, decided once so that sizing and writing cannot
/// disagree.
struct Plan {
    flags: FetchFlags,
    group_delta: Option<u64>,
    object_delta: Option<u64>,
    subgroup: Option<u64>,
    priority: Option<u8>,
    properties: Properties,
    payload: Option<Bytes>,
}

/// Writes records onto one fetch stream.
#[derive(Debug, Clone)]
pub struct FetchWriter {
    order: GroupOrder,
    state: FetchState,
}

impl FetchWriter {
    /// Start writing a stream in `order`.
    #[must_use]
    pub fn new(order: GroupOrder) -> Self {
        Self {
            order,
            state: FetchState::default(),
        }
    }

    /// Whether nothing has been written yet.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.state.is_empty()
    }

    /// Encoded size of `record`.
    ///
    /// # Errors
    /// [`FetchError`] if the record cannot follow what has already been written.
    pub fn encoded_len(&self, record: &FetchRecord) -> Result<usize, FetchError> {
        Ok(Self::length(&self.plan(record)?))
    }

    /// Append a record to the stream.
    ///
    /// # Errors
    /// [`FetchError::NotAdvancing`] if the location does not move forwards in
    /// the stream's group order, or [`FetchError::GapTooLarge`] if the step
    /// between groups cannot be encoded.
    ///
    /// # Panics
    /// Never, for records built through the public API: IDs come from
    /// [`Location`] and [`SubgroupId`], which are varints already, and the
    /// deltas between them are checked before anything is written.
    pub fn write<B: BufMut>(
        &mut self,
        buf: &mut B,
        record: &FetchRecord,
    ) -> Result<(), FetchError> {
        let plan = self.plan(record)?;

        VarInt::new(plan.flags.0)
            .expect("flag values are constants within varint range")
            .encode(buf);
        for value in [plan.group_delta, plan.subgroup, plan.object_delta]
            .into_iter()
            .flatten()
        {
            VarInt::new(value)
                .expect("deltas are checked against the varint range when planned")
                .encode(buf);
        }
        if let Some(priority) = plan.priority {
            buf.put_u8(priority);
        }
        if !plan.properties.is_empty() {
            plan.properties.encode_prefixed(buf);
        }

        // Present even on a marker: §11.4.4.2 lists subgroup, priority, and
        // properties as absent and says nothing about the payload length, which
        // Figure 27 shows as unconditional. This is the one field here where the
        // draft is genuinely ambiguous and two implementations could disagree.
        let payload = plan.payload.unwrap_or_default();
        VarInt::new(payload.len() as u64)
            .expect("payload lengths come from memory and fit a varint")
            .encode(buf);
        buf.put_slice(&payload);

        match record {
            FetchRecord::Object(object) => self.state.advance_to_object(object),
            _ => self.state.advance_to_marker(record.location()),
        }
        Ok(())
    }

    fn length(plan: &Plan) -> usize {
        let mut length = VarInt::new(plan.flags.0).map_or(8, VarInt::size);
        for value in [plan.group_delta, plan.subgroup, plan.object_delta]
            .into_iter()
            .flatten()
        {
            length += VarInt::new(value).map_or(8, VarInt::size);
        }
        if plan.priority.is_some() {
            length += 1;
        }
        if !plan.properties.is_empty() {
            length += plan.properties.encoded_len_prefixed();
        }
        let payload = plan.payload.as_ref().map_or(0, Bytes::len);
        length + VarInt::new(payload as u64).map_or(8, VarInt::size) + payload
    }

    fn plan(&self, record: &FetchRecord) -> Result<Plan, FetchError> {
        match record {
            FetchRecord::Object(object) => self.plan_object(object),
            FetchRecord::EndOfNonExistentRange(location) => {
                self.plan_marker(FetchFlags(FetchFlags::END_OF_NON_EXISTENT), *location)
            }
            FetchRecord::EndOfUnknownRange(location) => {
                self.plan_marker(FetchFlags(FetchFlags::END_OF_UNKNOWN), *location)
            }
        }
    }

    fn group_delta(&self, group: u64, object: u64) -> Result<Option<u64>, FetchError> {
        let Some(previous) = self.state.group else {
            return Ok(Some(group));
        };
        if group == previous {
            return Ok(None);
        }

        let not_advancing = || {
            let previous_location = Location::new(
                GroupId::new(VarInt::new(previous).unwrap_or(VarInt::MAX)),
                ObjectId::new(VarInt::new(self.state.object.unwrap_or(0)).unwrap_or(VarInt::MAX)),
            );
            FetchError::NotAdvancing {
                previous: previous_location,
                next: Location::new(
                    GroupId::new(VarInt::new(group).unwrap_or(VarInt::MAX)),
                    ObjectId::new(VarInt::new(object).unwrap_or(VarInt::MAX)),
                ),
            }
        };

        let distance = match self.order {
            GroupOrder::Ascending => {
                if group <= previous {
                    return Err(not_advancing());
                }
                group - previous - 1
            }
            GroupOrder::Descending => {
                if group >= previous {
                    return Err(not_advancing());
                }
                previous - group - 1
            }
        };
        if VarInt::new(distance).is_err() {
            return Err(FetchError::GapTooLarge {
                previous,
                next: group,
            });
        }
        Ok(Some(distance))
    }

    fn plan_object(&self, object: &FetchObject) -> Result<Plan, FetchError> {
        let group = object.location.group.get();
        let id = object.location.object.get();
        let group_delta = self.group_delta(group, id)?;

        // When the group moves, an absolute Object ID goes out even though the
        // draft would allow inheriting prior+1. Inheriting across a group
        // boundary is legal, almost never what a publisher means, and produces a
        // plausible-looking wrong number rather than a parse failure.
        let object_delta = if self.state.is_empty() || group_delta.is_some() {
            Some(id)
        } else {
            match self.state.object {
                Some(previous) if id == previous + 1 => None,
                Some(previous) if id > previous => Some(id - previous),
                Some(previous) => {
                    return Err(FetchError::NotAdvancing {
                        previous: Location::new(
                            object.location.group,
                            ObjectId::new(VarInt::new(previous).unwrap_or(VarInt::MAX)),
                        ),
                        next: object.location,
                    });
                }
                None => Some(id),
            }
        };

        // `Zero` is preferred over `SameAsPrior` when both would do, and they
        // are the same size. It refers to nothing, so a record encoded this way
        // survives being the first on its stream — and whether a given record
        // ends up first is decided elsewhere.
        let subgroup = object.subgroup.get();
        let (mode, explicit) = if subgroup == 0 {
            (SubgroupMode::Zero, None)
        } else if self.state.subgroup == Some(subgroup) {
            (SubgroupMode::SameAsPrior, None)
        } else if self.state.subgroup.map(|prior| prior + 1) == Some(subgroup) {
            (SubgroupMode::PriorPlusOne, None)
        } else {
            (SubgroupMode::Present, Some(subgroup))
        };

        let priority = if self.state.priority == Some(object.priority) {
            None
        } else {
            Some(object.priority)
        };

        Ok(Plan {
            flags: FetchFlags::describing(
                mode,
                group_delta,
                object_delta,
                priority,
                &object.properties,
            ),
            group_delta,
            object_delta,
            subgroup: explicit,
            priority,
            properties: object.properties.clone(),
            payload: Some(object.payload.clone()),
        })
    }

    fn plan_marker(&self, marker: FetchFlags, location: Location) -> Result<Plan, FetchError> {
        if let Some(previous) = self.state.location()
            && self.order == GroupOrder::Ascending
            && location <= previous
        {
            return Err(FetchError::NotAdvancing {
                previous,
                next: location,
            });
        }

        // Absolute, not delta-encoded, and this is the one place where the draft
        // does not say which. §11.4.4.2 calls them "the Group ID and Object ID
        // fields"; Figure 27 names those same fields Group ID Delta and Object ID
        // Delta.
        //
        // Absolute is the reading that works. A marker's flags value is a fixed
        // constant with both delta bits set, so the fields cannot be elided — and
        // under the delta reading a group delta of 0 means *the next* group in
        // ascending order, which would make "objects 5 through 9 of this group do
        // not exist" inexpressible. That is the ordinary case for a relay serving
        // a partial cache, so a reading that cannot encode it is not the intended
        // one.
        Ok(Plan {
            flags: marker,
            group_delta: Some(location.group.get()),
            object_delta: Some(location.object.get()),
            subgroup: None,
            priority: None,
            properties: Properties::new(),
            payload: None,
        })
    }
}

/// Reads records from one fetch stream.
#[derive(Debug, Clone)]
pub struct FetchReader {
    order: GroupOrder,
    state: FetchState,
}

impl FetchReader {
    /// Start reading a stream in `order`.
    #[must_use]
    pub fn new(order: GroupOrder) -> Self {
        Self {
            order,
            state: FetchState::default(),
        }
    }

    /// Read the next record.
    ///
    /// On [`DecodeError::Short`] no state has advanced and `buf` is left as it
    /// was, so the caller can retry when more bytes arrive.
    ///
    /// # Errors
    /// [`DecodeError::Short`] if the record is incomplete;
    /// [`DecodeError::Invalid`] for flags that are neither flags nor a marker, a
    /// first record that refers to a previous one, an ID past the range a
    /// location can name, or a marker carrying a payload.
    pub fn read(&mut self, buf: &mut &[u8]) -> Result<FetchRecord, DecodeError> {
        let mut cursor = *buf;
        let (record, next) = self.read_from(&mut cursor)?;
        *buf = cursor;
        self.state = next;
        Ok(record)
    }

    fn read_from(&self, buf: &mut &[u8]) -> Result<(FetchRecord, FetchState), DecodeError> {
        let flags = FetchFlags::from_code(VarInt::decode(buf)?.get())?;
        if self.state.is_empty() && flags.references_prior() {
            return Err(DecodeError::Invalid(
                "first fetch record refers to a prior object",
            ));
        }

        let group_delta = flags
            .has_group_delta()
            .then(|| VarInt::decode(buf))
            .transpose()?
            .map(VarInt::get);
        let subgroup_field = matches!(flags.subgroup(), SubgroupMode::Present)
            .then(|| VarInt::decode(buf))
            .transpose()?
            .map(VarInt::get);
        let object_delta = flags
            .has_object_delta()
            .then(|| VarInt::decode(buf))
            .transpose()?
            .map(VarInt::get);

        if flags.is_end_of_range() {
            // Absolute rather than delta-encoded; see `plan_marker`.
            let location = location_of(group_delta.unwrap_or(0), object_delta.unwrap_or(0))?;
            if VarInt::decode(buf)?.get() != 0 {
                return Err(DecodeError::Invalid(
                    "end of range marker carried a payload",
                ));
            }
            let mut state = self.state;
            state.advance_to_marker(location);
            let record = if flags.0 == FetchFlags::END_OF_NON_EXISTENT {
                FetchRecord::EndOfNonExistentRange(location)
            } else {
                FetchRecord::EndOfUnknownRange(location)
            };
            return Ok((record, state));
        }

        let (group, object) = self.resolve(group_delta, object_delta)?;

        let subgroup = match flags.subgroup() {
            SubgroupMode::Zero => 0,
            SubgroupMode::Present => subgroup_field.unwrap_or(0),
            SubgroupMode::SameAsPrior => self.state.subgroup.unwrap_or(0),
            SubgroupMode::PriorPlusOne => self.state.subgroup.unwrap_or(0) + 1,
        };

        let priority = if flags.has_priority() {
            if !buf.has_remaining() {
                return Err(DecodeError::Short { needed: 1 });
            }
            buf.get_u8()
        } else {
            self.state.priority.unwrap_or(128)
        };

        let properties = if flags.has_properties() {
            Properties::decode_prefixed(buf)?
        } else {
            Properties::new()
        };

        let length = VarInt::decode(buf)?.get();
        let length = usize::try_from(length)
            .map_err(|_| DecodeError::Invalid("payload length exceeds addressable memory"))?;
        if buf.remaining() < length {
            return Err(DecodeError::Short {
                needed: length - buf.remaining(),
            });
        }

        let object = FetchObject {
            location: location_of(group, object)?,
            subgroup: SubgroupId::new(
                VarInt::new(subgroup)
                    .map_err(|_| DecodeError::Invalid("subgroup ID exceeds the varint maximum"))?,
            ),
            priority,
            properties,
            payload: buf.copy_to_bytes(length),
        };
        let mut state = self.state;
        state.advance_to_object(&object);
        Ok((FetchRecord::Object(object), state))
    }

    /// Resolve an object's absolute group and Object ID from whichever deltas
    /// were on the wire.
    ///
    /// Accumulation is unbounded here — a stream may legally walk an Object ID
    /// past the varint ceiling even though a location cannot name where it
    /// landed — so overflow is checked against `u64` and the narrowing to a
    /// [`Location`] happens later.
    fn resolve(
        &self,
        group_delta: Option<u64>,
        object_delta: Option<u64>,
    ) -> Result<(u64, u64), DecodeError> {
        let inherited = self.state.object.unwrap_or(0);
        let group = match group_delta {
            // Absent means the same group. The first record on a stream is
            // required to carry a delta, so there is always a prior group here.
            None => self.state.group.unwrap_or(0),
            Some(delta) => match self.state.group {
                None => delta,
                Some(previous) => match self.order {
                    GroupOrder::Ascending => previous
                        .checked_add(delta + 1)
                        .ok_or(DecodeError::Invalid("group ID passed 2^64-1"))?,
                    GroupOrder::Descending => previous.checked_sub(delta + 1).ok_or(
                        DecodeError::Invalid("descending group ID passed below zero"),
                    )?,
                },
            },
        };

        // The same field means two different things depending on whether the
        // group moved: an absolute ID within the new group, or a step within the
        // current one.
        let object = match (group_delta.is_some(), object_delta) {
            (true, Some(absolute)) => absolute,
            (false, Some(delta)) => inherited
                .checked_add(delta)
                .ok_or(DecodeError::Invalid("object ID passed 2^64-1"))?,
            (_, None) => inherited
                .checked_add(1)
                .ok_or(DecodeError::Invalid("object ID passed 2^64-1"))?,
        };
        Ok((group, object))
    }
}

/// Build a location, refusing IDs past what one can name.
///
/// Accumulated IDs are allowed up to 2^64-1 on a stream, and a [`Location`]
/// holds varints. An object past that ceiling is deliverable and unnameable,
/// which for a fetch is the same as unusable: the range that asked for it could
/// not have named it either.
fn location_of(group: u64, object: u64) -> Result<Location, DecodeError> {
    let group = VarInt::new(group)
        .map_err(|_| DecodeError::Invalid("group ID exceeds what a location can name"))?;
    let object = VarInt::new(object)
        .map_err(|_| DecodeError::Invalid("object ID exceeds what a location can name"))?;
    Ok(Location::new(GroupId::new(group), ObjectId::new(object)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::control::Role;
    use crate::control::params::Parameter;

    fn loc(group: u32, object: u32) -> Location {
        Location::new(GroupId::from(group), ObjectId::from(object))
    }

    fn object(group: u32, id: u32, payload: &'static [u8]) -> FetchObject {
        FetchObject::new(loc(group, id), Bytes::from_static(payload))
    }

    /// Write a run of records and read it back, asserting sizes along the way.
    fn round_trip(order: GroupOrder, records: &[FetchRecord]) -> Vec<FetchRecord> {
        let mut writer = FetchWriter::new(order);
        let mut buf = Vec::new();
        for record in records {
            let expected = writer.encoded_len(record).expect("plannable");
            let before = buf.len();
            writer.write(&mut buf, record).expect("writable");
            assert_eq!(
                buf.len() - before,
                expected,
                "size disagreed for {record:?}"
            );
        }

        let mut reader = FetchReader::new(order);
        let mut cursor = buf.as_slice();
        let mut read = Vec::new();
        while !cursor.is_empty() {
            read.push(reader.read(&mut cursor).expect("readable"));
        }
        read
    }

    #[test]
    fn the_header_round_trips_and_rejects_other_stream_types() {
        let header = FetchHeader::new(Role::Client.first_request_id());
        let mut buf = Vec::new();
        header.encode(&mut buf);
        assert_eq!(buf.len(), header.encoded_len());
        assert_eq!(FetchHeader::decode(&mut buf.as_slice()).unwrap(), header);

        // A subgroup stream starts with a different code, and telling the two
        // apart by their first varint is the only way to tell them apart at all.
        let mut subgroup = Vec::new();
        VarInt::from_u32(0x10).encode(&mut subgroup);
        subgroup.push(0);
        assert!(
            FetchHeader::decode(&mut subgroup.as_slice())
                .unwrap_err()
                .is_fatal()
        );
    }

    #[test]
    fn consecutive_objects_in_one_group_cost_almost_nothing() {
        let records: Vec<FetchRecord> = (0..4)
            .map(|id| FetchRecord::Object(object(7, id, b"xy")))
            .collect();

        let mut writer = FetchWriter::new(GroupOrder::Ascending);
        let mut buf = Vec::new();
        for record in &records {
            writer.write(&mut buf, record).expect("writable");
        }

        // The first record states everything: flags, group, object, priority,
        // payload length, two bytes of payload. The next three inherit the group,
        // the priority, and the object ID, so they cost flags, a length, and the
        // payload — four bytes each to carry two bytes of media.
        assert_eq!(buf.len(), 7 + 3 * 4);
        assert_eq!(round_trip(GroupOrder::Ascending, &records), records);
    }

    #[test]
    fn a_full_record_round_trips() {
        let mut properties = Properties::new();
        properties.push(Parameter::varint(0x08, VarInt::from_u32(90_000)).unwrap());

        let record = FetchRecord::Object(FetchObject {
            location: loc(3, 9),
            subgroup: SubgroupId::from(4u32),
            priority: 200,
            properties,
            payload: Bytes::from_static(b"payload"),
        });
        assert_eq!(
            round_trip(GroupOrder::Ascending, std::slice::from_ref(&record)),
            vec![record]
        );
    }

    #[test]
    fn a_group_boundary_restates_the_object_id() {
        let records = vec![
            FetchRecord::Object(object(1, 5, b"a")),
            FetchRecord::Object(object(2, 0, b"b")),
        ];
        assert_eq!(round_trip(GroupOrder::Ascending, &records), records);
    }

    /// The case a relay serving a partial cache produces constantly: some of a
    /// group is held and some of it is not.
    #[test]
    fn markers_interleave_with_objects() {
        let records = vec![
            FetchRecord::Object(object(1, 0, b"a")),
            FetchRecord::EndOfNonExistentRange(loc(1, 4)),
            FetchRecord::Object(object(1, 5, b"b")),
            FetchRecord::EndOfUnknownRange(loc(2, 9)),
        ];
        assert_eq!(round_trip(GroupOrder::Ascending, &records), records);
    }

    /// A marker has no subgroup or priority of its own, so the object after one
    /// inherits from the last real object rather than from the marker.
    #[test]
    fn a_marker_does_not_disturb_subgroup_or_priority() {
        let mut first = object(1, 0, b"a");
        first.subgroup = SubgroupId::from(6u32);
        first.priority = 32;
        let mut second = object(1, 5, b"b");
        second.subgroup = SubgroupId::from(6u32);
        second.priority = 32;

        let records = vec![
            FetchRecord::Object(first),
            FetchRecord::EndOfNonExistentRange(loc(1, 4)),
            FetchRecord::Object(second.clone()),
        ];
        let read = round_trip(GroupOrder::Ascending, &records);
        assert_eq!(read, records);

        // And it cost nothing to inherit them: the second object carries neither
        // field, which is only correct because the marker left them alone.
        let mut writer = FetchWriter::new(GroupOrder::Ascending);
        let mut buf = Vec::new();
        for record in &records[..2] {
            writer.write(&mut buf, record).unwrap();
        }
        let plan = writer.plan(&FetchRecord::Object(second)).unwrap();
        assert!(plan.priority.is_none());
        assert!(plan.subgroup.is_none());
    }

    #[test]
    fn descending_order_walks_groups_backwards() {
        let records = vec![
            FetchRecord::Object(object(9, 0, b"a")),
            FetchRecord::Object(object(9, 1, b"b")),
            FetchRecord::Object(object(7, 0, b"c")),
        ];
        assert_eq!(round_trip(GroupOrder::Descending, &records), records);

        // The same stream read as ascending resolves group 7 to something else
        // entirely, which is why the order is not inferable from the bytes.
        let mut writer = FetchWriter::new(GroupOrder::Descending);
        let mut buf = Vec::new();
        for record in &records {
            writer.write(&mut buf, record).unwrap();
        }
        let mut reader = FetchReader::new(GroupOrder::Ascending);
        let mut cursor = buf.as_slice();
        let mut misread = Vec::new();
        while !cursor.is_empty() {
            misread.push(reader.read(&mut cursor).unwrap());
        }
        assert_ne!(misread, records);
    }

    #[test]
    fn a_stream_must_advance() {
        let mut writer = FetchWriter::new(GroupOrder::Ascending);
        let mut buf = Vec::new();
        writer
            .write(&mut buf, &FetchRecord::Object(object(5, 3, b"a")))
            .unwrap();

        assert!(matches!(
            writer.write(&mut buf, &FetchRecord::Object(object(4, 0, b"b"))),
            Err(FetchError::NotAdvancing { .. })
        ));
        assert!(matches!(
            writer.write(&mut buf, &FetchRecord::Object(object(5, 2, b"b"))),
            Err(FetchError::NotAdvancing { .. })
        ));
        assert!(matches!(
            writer.write(&mut buf, &FetchRecord::EndOfNonExistentRange(loc(5, 3))),
            Err(FetchError::NotAdvancing { .. })
        ));
    }

    #[test]
    fn a_short_record_leaves_the_cursor_alone() {
        let mut writer = FetchWriter::new(GroupOrder::Ascending);
        let mut buf = Vec::new();
        writer
            .write(&mut buf, &FetchRecord::Object(object(1, 0, b"abcdef")))
            .unwrap();

        for cut in 1..buf.len() {
            let mut reader = FetchReader::new(GroupOrder::Ascending);
            let truncated = &buf[..cut];
            let mut cursor = truncated;
            let err = reader.read(&mut cursor).unwrap_err();
            assert!(!err.is_fatal(), "cut at {cut} should be short, was {err:?}");
            assert_eq!(
                cursor.len(),
                truncated.len(),
                "cursor moved on a short read"
            );
        }
    }

    #[test]
    fn a_first_record_may_not_refer_to_a_prior_one() {
        // Flags with no group delta, which can only mean "the same group as the
        // record before" — and there is none.
        let mut buf = Vec::new();
        VarInt::from_u32(0x14).encode(&mut buf);
        buf.push(0);
        VarInt::ZERO.encode(&mut buf);

        let mut reader = FetchReader::new(GroupOrder::Ascending);
        assert!(reader.read(&mut buf.as_slice()).unwrap_err().is_fatal());
    }

    #[test]
    fn unregistered_flag_values_are_fatal() {
        for code in [128u64, 129, 0x8D, 0x200] {
            let mut buf = Vec::new();
            VarInt::new(code).unwrap().encode(&mut buf);
            buf.extend_from_slice(&[0, 0, 0]);
            let mut reader = FetchReader::new(GroupOrder::Ascending);
            assert!(
                reader.read(&mut buf.as_slice()).unwrap_err().is_fatal(),
                "flags {code:#x} should be refused"
            );
        }
    }

    /// The datagram bit says the object had no subgroup, and the draft says to
    /// ignore the low bits rather than reject them — so a record with both set
    /// reads as subgroup zero instead of failing.
    #[test]
    fn the_datagram_bit_ignores_the_subgroup_bits() {
        let flags = FetchFlags(
            FetchFlags::DATAGRAM
                | 0x03
                | FetchFlags::GROUP_DELTA
                | FetchFlags::OBJECT_DELTA
                | FetchFlags::PRIORITY,
        );
        assert!(matches!(flags.subgroup(), SubgroupMode::Zero));
        assert!(!flags.references_prior());
    }
}
