//! FETCH and `FETCH_OK`, per draft-19 §10.12 and §10.13.
//!
//! FETCH is how already-published objects are retrieved, and it is the half of
//! MOQT that `SUBSCRIBE` deliberately does not cover: a subscription delivers
//! only what is published from now on. Every "start playback a few seconds
//! behind live" feature is a fetch joined to a subscription.

use bytes::{Buf, BufMut};

use crate::control::MessageType;
use crate::control::frame::MessageBody;
use crate::control::params::Parameters;
use crate::control::properties::Properties;
use crate::control::request_id::RequestId;
use crate::error::DecodeError;
use crate::model::{FullTrackName, Location};
use crate::varint::VarInt;

/// What a fetch is asking for.
///
/// The draft encodes this as a Fetch Type code followed by whichever structure
/// that code selects, with the two structures sharing no fields. Modelling it
/// as an enum keeps the type code and the body from disagreeing — a
/// standalone fetch cannot accidentally carry a joining request ID, and a
/// joining fetch cannot carry a track name it is supposed to inherit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FetchKind {
    /// Retrieve a range from a named track, independent of any subscription.
    Standalone {
        /// The track to read from.
        track: FullTrackName,
        /// First location in the range, inclusive.
        start: Location,
        /// Last location plus one. An object component of `0` means the whole
        /// group is wanted.
        end: Location,
    },

    /// Retrieve the groups immediately before a subscription's live edge,
    /// counting backwards from it.
    ///
    /// The publisher derives the track and the end of the range from the
    /// subscription, so the two are guaranteed contiguous with no gap and no
    /// overlap. Computing the boundary client-side would race the live edge.
    RelativeJoining {
        /// The subscription to join, which must be Established or Pending.
        request_id: RequestId,
        /// How many groups back from the subscription's start to begin.
        preceding_groups: VarInt,
    },

    /// Retrieve from an absolute group up to a subscription's live edge.
    AbsoluteJoining {
        /// The subscription to join.
        request_id: RequestId,
        /// The group to start from.
        start_group: VarInt,
    },
}

impl FetchKind {
    /// Standalone.
    const STANDALONE: u8 = 0x1;
    /// Relative joining.
    const RELATIVE: u8 = 0x2;
    /// Absolute joining.
    const ABSOLUTE: u8 = 0x3;

    const fn type_varint(&self) -> VarInt {
        VarInt::from_u32(self.type_code() as u32)
    }

    /// The Fetch Type code.
    #[must_use]
    pub const fn type_code(&self) -> u8 {
        match self {
            Self::Standalone { .. } => Self::STANDALONE,
            Self::RelativeJoining { .. } => Self::RELATIVE,
            Self::AbsoluteJoining { .. } => Self::ABSOLUTE,
        }
    }

    fn encoded_len(&self) -> usize {
        let code = self.type_varint().size();
        code + match self {
            Self::Standalone { track, start, end } => {
                track.encoded_len() + start.encoded_len() + end.encoded_len()
            }
            Self::RelativeJoining {
                request_id,
                preceding_groups: value,
            }
            | Self::AbsoluteJoining {
                request_id,
                start_group: value,
            } => request_id.encoded_len() + value.size(),
        }
    }

    fn encode<B: BufMut>(&self, buf: &mut B) {
        self.type_varint().encode(buf);
        match self {
            Self::Standalone { track, start, end } => {
                track.encode(buf);
                start.encode(buf);
                end.encode(buf);
            }
            Self::RelativeJoining {
                request_id,
                preceding_groups: value,
            }
            | Self::AbsoluteJoining {
                request_id,
                start_group: value,
            } => {
                request_id.encode(buf);
                value.encode(buf);
            }
        }
    }

    fn decode<B: Buf>(buf: &mut B) -> Result<Self, DecodeError> {
        let code = VarInt::decode(buf)?.get();
        Ok(match u8::try_from(code).unwrap_or(u8::MAX) {
            Self::STANDALONE => Self::Standalone {
                track: FullTrackName::decode(buf)?,
                start: Location::decode(buf)?,
                end: Location::decode(buf)?,
            },
            Self::RELATIVE => Self::RelativeJoining {
                request_id: RequestId::decode(buf)?,
                preceding_groups: VarInt::decode(buf)?,
            },
            Self::ABSOLUTE => Self::AbsoluteJoining {
                request_id: RequestId::decode(buf)?,
                start_group: VarInt::decode(buf)?,
            },
            _ => return Err(DecodeError::Invalid("unknown fetch type")),
        })
    }
}

/// Request a range of already-published objects.
///
/// Opens its own bidirectional stream; the objects come back on a separate
/// unidirectional stream, which the publisher may start writing before it sends
/// [`FetchOk`]. Object Forwarding Preference does not apply — a fetch response
/// is always one stream regardless of how the objects were originally sent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fetch {
    /// Identifies this request. See [`RequestId`].
    pub request_id: RequestId,
    /// What is being fetched.
    pub kind: FetchKind,
    /// Request parameters, including group order and filters.
    pub parameters: Parameters,
}

impl Fetch {
    /// A fetch with no parameters.
    #[must_use]
    pub fn new(request_id: RequestId, kind: FetchKind) -> Self {
        Self {
            request_id,
            kind,
            parameters: Parameters::new(),
        }
    }

    /// Encoded size of the message body.
    #[must_use]
    pub fn encoded_len(&self) -> usize {
        self.request_id.encoded_len()
            + self.kind.encoded_len()
            + self.parameters.encoded_len_counted()
    }

    /// Append the message body to `buf`.
    pub fn encode<B: BufMut>(&self, buf: &mut B) {
        self.request_id.encode(buf);
        self.kind.encode(buf);
        self.parameters.encode_counted(buf);
    }

    /// Read a message body.
    ///
    /// # Errors
    /// [`DecodeError::Short`] if incomplete; [`DecodeError::Invalid`] for an
    /// unknown fetch type or any field that violates its constraints.
    pub fn decode<B: Buf>(buf: &mut B) -> Result<Self, DecodeError> {
        Ok(Self {
            request_id: RequestId::decode(buf)?,
            kind: FetchKind::decode(buf)?,
            parameters: Parameters::decode_counted(buf)?,
        })
    }
}

impl MessageBody for Fetch {
    const MESSAGE_TYPE: MessageType = MessageType::Fetch;

    fn encoded_len(&self) -> usize {
        Self::encoded_len(self)
    }

    fn encode<B: BufMut>(&self, buf: &mut B) {
        Self::encode(self, buf);
    }
}

/// Accepts a fetch, and reports the range that will actually be delivered.
///
/// The end location is the useful part: a fetch may ask for more than exists,
/// and this is where the request is clipped to reality. It cannot be sent until
/// the publisher knows that boundary, which is why objects may already be
/// flowing on the data stream by the time it arrives.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FetchOk {
    /// Whether [`FetchOk::end`] is the final object in the track, meaning no
    /// later fetch will ever return more.
    pub end_of_track: bool,
    /// Last location plus one, clipped to what has been published.
    pub end: Location,
    /// Response parameters.
    pub parameters: Parameters,
    /// Track Properties, which run to the end of the message.
    pub properties: Properties,
}

impl FetchOk {
    /// An acceptance carrying only a range.
    #[must_use]
    pub fn new(end: Location) -> Self {
        Self {
            end_of_track: false,
            end,
            parameters: Parameters::new(),
            properties: Properties::new(),
        }
    }

    /// Encoded size of the message body.
    #[must_use]
    pub fn encoded_len(&self) -> usize {
        1 + self.end.encoded_len()
            + self.parameters.encoded_len_counted()
            + self.properties.encoded_len()
    }

    /// Append the message body to `buf`.
    pub fn encode<B: BufMut>(&self, buf: &mut B) {
        buf.put_u8(u8::from(self.end_of_track));
        self.end.encode(buf);
        self.parameters.encode_counted(buf);
        self.properties.encode(buf);
    }

    /// Read a message body.
    ///
    /// End Of Track is a fixed byte the draft describes as 1 or 0. Any nonzero
    /// value is read as true rather than rejected: a future draft could assign
    /// meaning to the other bits, and refusing them would turn a forward-
    /// compatible extension into a session close.
    ///
    /// `buf` must hold exactly one body, since Track Properties are defined as
    /// the remainder of the message.
    ///
    /// # Errors
    /// [`DecodeError::Short`] if incomplete; [`DecodeError::Invalid`] if any
    /// field violates its constraints.
    pub fn decode<B: Buf>(buf: &mut B) -> Result<Self, DecodeError> {
        if !buf.has_remaining() {
            return Err(DecodeError::Short { needed: 1 });
        }
        Ok(Self {
            end_of_track: buf.get_u8() != 0,
            end: Location::decode(buf)?,
            parameters: Parameters::decode_counted(buf)?,
            properties: Properties::decode_to_end(buf)?,
        })
    }
}

impl MessageBody for FetchOk {
    const MESSAGE_TYPE: MessageType = MessageType::FetchOk;

    fn encoded_len(&self) -> usize {
        Self::encoded_len(self)
    }

    fn encode<B: BufMut>(&self, buf: &mut B) {
        Self::encode(self, buf);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::control::Role;
    use crate::control::params::Parameter;
    use crate::model::{GroupId, ObjectId, TrackNamespace};

    fn track() -> FullTrackName {
        FullTrackName::new(
            TrackNamespace::from_parts([&b"moqom"[..], b"room-1"]).unwrap(),
            bytes::Bytes::from_static(b"video"),
        )
        .unwrap()
    }

    fn loc(g: u32, o: u32) -> Location {
        Location::new(GroupId::from(g), ObjectId::from(o))
    }

    fn kinds() -> Vec<FetchKind> {
        let id = Role::Client.first_request_id();
        vec![
            FetchKind::Standalone {
                track: track(),
                start: loc(10, 0),
                end: loc(20, 0),
            },
            FetchKind::RelativeJoining {
                request_id: id,
                preceding_groups: VarInt::from(3u32),
            },
            FetchKind::AbsoluteJoining {
                request_id: id,
                start_group: VarInt::from(900u32),
            },
        ]
    }

    #[test]
    fn every_fetch_kind_round_trips() {
        for kind in kinds() {
            let mut value = Fetch::new(Role::Client.first_request_id(), kind);
            value
                .parameters
                .push(Parameter::varint(0x22, VarInt::from_u32(1)).unwrap());

            let mut buf = Vec::new();
            value.encode(&mut buf);
            assert_eq!(buf.len(), value.encoded_len());
            let mut cursor = buf.as_slice();
            assert_eq!(Fetch::decode(&mut cursor).unwrap(), value);
            assert!(cursor.is_empty());
        }
    }

    #[test]
    fn fetch_type_codes_match_the_draft() {
        let codes: Vec<u8> = kinds().iter().map(FetchKind::type_code).collect();
        assert_eq!(codes, vec![0x1, 0x2, 0x3]);
    }

    /// The two joining variants differ only in how their integer is
    /// interpreted, so a swapped type code would produce a plausible-looking
    /// message that fetches the wrong range.
    #[test]
    fn the_joining_variants_do_not_alias() {
        let id = Role::Client.first_request_id();
        let relative = Fetch::new(
            id,
            FetchKind::RelativeJoining {
                request_id: id,
                preceding_groups: VarInt::from(5u32),
            },
        );
        let absolute = Fetch::new(
            id,
            FetchKind::AbsoluteJoining {
                request_id: id,
                start_group: VarInt::from(5u32),
            },
        );

        let mut a = Vec::new();
        relative.encode(&mut a);
        let mut b = Vec::new();
        absolute.encode(&mut b);
        assert_ne!(a, b);
        assert_eq!(Fetch::decode(&mut a.as_slice()).unwrap(), relative);
        assert_eq!(Fetch::decode(&mut b.as_slice()).unwrap(), absolute);
    }

    #[test]
    fn an_unknown_fetch_type_is_fatal() {
        let mut buf = Vec::new();
        Role::Client.first_request_id().encode(&mut buf);
        VarInt::from(4u32).encode(&mut buf);
        buf.push(0);
        assert!(Fetch::decode(&mut buf.as_slice()).unwrap_err().is_fatal());
    }

    #[test]
    fn fetch_ok_round_trips() {
        for end_of_track in [false, true] {
            let mut value = FetchOk::new(loc(20, 5));
            value.end_of_track = end_of_track;
            value
                .properties
                .push(Parameter::varint(0x08, VarInt::from_u32(90_000)).unwrap());

            let mut buf = Vec::new();
            value.encode(&mut buf);
            assert_eq!(buf.len(), value.encoded_len());
            let mut cursor = buf.as_slice();
            assert_eq!(FetchOk::decode(&mut cursor).unwrap(), value);
            assert!(cursor.is_empty());
        }
    }

    /// Leniency on the way in has to stay idempotent: a nonzero byte reads as
    /// true, re-encodes as 1, and reads as true again.
    #[test]
    fn a_nonzero_end_of_track_byte_is_true_and_stays_true() {
        let mut buf = vec![0x7F];
        loc(1, 1).encode(&mut buf);
        buf.push(0);

        let once = FetchOk::decode(&mut buf.as_slice()).unwrap();
        assert!(once.end_of_track);

        let mut again = Vec::new();
        once.encode(&mut again);
        assert_eq!(again[0], 1);
        assert_eq!(FetchOk::decode(&mut again.as_slice()).unwrap(), once);
    }

    #[test]
    fn a_truncated_end_of_track_byte_is_short_not_fatal() {
        assert!(!FetchOk::decode(&mut &[][..]).unwrap_err().is_fatal());
    }
}
