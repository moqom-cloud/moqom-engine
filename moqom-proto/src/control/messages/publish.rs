//! PUBLISH and `PUBLISH_DONE`, per draft-19 §10.10 and §10.11, and
//! `PUBLISH_STATE_NOTIFY`, per draft-22 §9.10.

use bytes::{Buf, BufMut};

use crate::control::MessageType;
use crate::control::frame::MessageBody;
use crate::control::params::Parameters;
use crate::control::properties::Properties;
use crate::control::reason::ReasonPhrase;
use crate::control::request_id::RequestId;
use crate::control::typed::Context;
use crate::draft::Draft;
use crate::error::DecodeError;
use crate::model::{FullTrackName, TrackAlias};
use crate::varint::VarInt;

/// Offer a track to a peer, creating a subscription the peer did not ask for.
///
/// The mirror image of `SUBSCRIBE`: the publisher opens the stream and assigns
/// the [`TrackAlias`] itself. This is how a relay pushes tracks to a subscriber
/// that used `SUBSCRIBE_TRACKS`, and how an ingest node hands a track to a
/// relay without a round trip.
///
/// Objects can start flowing before the peer accepts, unless the `FORWARD`
/// parameter is `0`. A peer that does not want the track answers
/// `REQUEST_ERROR` with `UNINTERESTED` and sends `STOP_SENDING` on the data
/// streams — declining is not free, and this is the message that makes an
/// unsolicited push safe to use.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Publish {
    /// Identifies this request. See [`RequestId`].
    pub request_id: RequestId,
    /// The track on offer.
    pub track: FullTrackName,
    /// The short identifier this track will use in subgroup headers and
    /// datagrams. Chosen by the publisher, unlike in `SUBSCRIBE_OK`.
    pub track_alias: TrackAlias,
    /// Request parameters, including `FORWARD` and authorization.
    pub parameters: Parameters,
    /// Track Properties, which run to the end of the message.
    pub properties: Properties,
}

impl Publish {
    /// An offer with no parameters or properties.
    #[must_use]
    pub fn new(request_id: RequestId, track: FullTrackName, track_alias: TrackAlias) -> Self {
        Self {
            request_id,
            track,
            track_alias,
            parameters: Parameters::new(),
            properties: Properties::new(),
        }
    }

    /// Encoded size of the message body.
    #[must_use]
    pub fn encoded_len(&self) -> usize {
        self.request_id.encoded_len()
            + self.track.encoded_len()
            + self.track_alias.as_varint().size()
            + self.parameters.encoded_len_counted()
            + self.properties.encoded_len()
    }

    /// Append the message body to `buf`.
    pub fn encode<B: BufMut>(&self, buf: &mut B) {
        self.request_id.encode(buf);
        self.track.encode(buf);
        self.track_alias.as_varint().encode(buf);
        self.parameters.encode_counted(buf);
        self.properties.encode(buf);
    }

    /// Read a message body.
    ///
    /// `buf` must hold exactly one body, since Track Properties are defined as
    /// the remainder of the message.
    ///
    /// # Errors
    /// [`DecodeError::Short`] if incomplete; [`DecodeError::Invalid`] if any
    /// field violates its constraints.
    pub fn decode<B: Buf>(buf: &mut B) -> Result<Self, DecodeError> {
        let request_id = RequestId::decode(buf)?;
        let track = FullTrackName::decode(buf)?;
        let track_alias = TrackAlias::new(VarInt::decode(buf)?);
        let parameters = Parameters::decode_counted(buf)?;
        if Draft::current().typed_parameters() {
            Context::Publish.check(&parameters)?;
        }
        Ok(Self {
            request_id,
            track,
            track_alias,
            parameters,
            properties: Properties::decode_to_end(buf)?,
        })
    }
}

/// The publisher changed a subscription's state for a reason of its own —
/// paused it, moved its filter, or wants to report a new Largest Object at
/// the point the change took effect. Draft-22 §9.10.
///
/// Sent on the subscription's request stream by the publisher only, and
/// answered by nothing: it is not a request and not subject to
/// `MAX_REQUEST_UPDATES`. Carries only what changed; an absent parameter is
/// unchanged. The only parameters allowed are `LARGEST_OBJECT`, `FORWARD` and
/// `LOCATION_FILTER`, and the publisher must include `LARGEST_OBJECT` when it
/// knows it.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PublishStateNotify {
    /// What changed.
    pub parameters: Parameters,
}

impl PublishStateNotify {
    /// Encoded size of the message body.
    #[must_use]
    pub fn encoded_len(&self) -> usize {
        self.parameters.encoded_len_counted()
    }

    /// Append the message body to `buf`.
    pub fn encode<B: BufMut>(&self, buf: &mut B) {
        self.parameters.encode_counted(buf);
    }

    /// Read a message body.
    ///
    /// # Errors
    /// [`DecodeError::Short`] if incomplete; [`DecodeError::Invalid`] for a
    /// parameter the message does not allow.
    pub fn decode<B: Buf>(buf: &mut B) -> Result<Self, DecodeError> {
        let parameters = Parameters::decode_counted(buf)?;
        Context::PublishStateNotify.check(&parameters)?;
        Ok(Self { parameters })
    }
}

impl MessageBody for PublishStateNotify {
    const MESSAGE_TYPE: MessageType = MessageType::PublishStateNotify;

    fn encoded_len(&self) -> usize {
        Self::encoded_len(self)
    }

    fn encode<B: BufMut>(&self, buf: &mut B) {
        Self::encode(self, buf);
    }
}

impl MessageBody for Publish {
    const MESSAGE_TYPE: MessageType = MessageType::Publish;

    fn encoded_len(&self) -> usize {
        Self::encoded_len(self)
    }

    fn encode<B: BufMut>(&self, buf: &mut B) {
        Self::encode(self, buf);
    }
}

/// Why a subscription ended, per draft-19 §10.11.
///
/// A `u64` newtype rather than an enum: the draft's own list is already
/// non-contiguous (`MALFORMED_TRACK` sits at `0x12`, out of sequence with the
/// rest), and applications are expected to extend it. An unknown code must be
/// carried through a relay intact rather than rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PublishDoneStatus(pub VarInt);

impl PublishDoneStatus {
    /// An implementation-specific or generic error.
    pub const INTERNAL_ERROR: Self = Self(VarInt::from_u32(0x0));
    /// The subscriber is no longer authorized for this track.
    pub const UNAUTHORIZED: Self = Self(VarInt::from_u32(0x1));
    /// The track is no longer being published.
    pub const TRACK_ENDED: Self = Self(VarInt::from_u32(0x2));
    /// The publisher reached the end of the subscription's location filter.
    ///
    /// Draft-19 only: draft-22 §12.4 removed it, leaving `0x3` unassigned.
    /// [`Self::in_draft`] maps it to [`Self::TRACK_ENDED`] there.
    pub const SUBSCRIPTION_ENDED: Self = Self(VarInt::from_u32(0x3));
    /// Either side issued a `GOAWAY`.
    pub const GOING_AWAY: Self = Self(VarInt::from_u32(0x4));
    /// The publisher's send queue for this subscriber exceeded its limit.
    ///
    /// The one status a congestion controller can cause, and therefore the one
    /// worth alerting on: it means a subscriber was dropped for being slow
    /// rather than for anything it did.
    pub const TOO_FAR_BEHIND: Self = Self(VarInt::from_u32(0x5));
    /// The subscription outlived the timeout given in `SUBSCRIBE_OK`.
    pub const EXPIRED: Self = Self(VarInt::from_u32(0x6));
    /// A `REQUEST_UPDATE` failed, which also terminates the subscription.
    pub const UPDATE_FAILED: Self = Self(VarInt::from_u32(0x8));
    /// The publisher is overloaded and is shedding subscriptions.
    pub const EXCESSIVE_LOAD: Self = Self(VarInt::from_u32(0x9));
    /// A relay found the track malformed. Out of sequence in the draft.
    pub const MALFORMED_TRACK: Self = Self(VarInt::from_u32(0x12));

    /// Construct from a raw code.
    ///
    /// # Errors
    /// [`crate::error::BoundsExceeded`] above the varint maximum. Taking a
    /// `VarInt` rather than a `u64` is what keeps encoding infallible.
    pub const fn new(code: u64) -> Result<Self, crate::error::BoundsExceeded> {
        match VarInt::new(code) {
            Ok(v) => Ok(Self(v)),
            Err(e) => Err(e),
        }
    }

    /// The raw code.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0.get()
    }

    /// The code to send under `draft`: draft-22 has no `SUBSCRIPTION_ENDED`,
    /// and the end of a filter is, for that subscriber, the end of the track.
    #[must_use]
    pub fn in_draft(self, draft: Draft) -> Self {
        if draft == Draft::D22 && self == Self::SUBSCRIPTION_ENDED {
            Self::TRACK_ENDED
        } else {
            self
        }
    }

    /// Whether this status reports a failure rather than an orderly end.
    ///
    /// `TRACK_ENDED` and `SUBSCRIPTION_ENDED` are the expected ways for a
    /// subscription to finish; everything else, including unrecognised codes,
    /// is treated as a failure. Erring that way keeps an unknown code from
    /// being silently counted as a clean shutdown in metrics.
    #[must_use]
    pub fn is_error(self) -> bool {
        !matches!(self, Self::TRACK_ENDED | Self::SUBSCRIPTION_ENDED)
    }
}

impl std::fmt::Display for PublishDoneStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let name = match *self {
            Self::INTERNAL_ERROR => "INTERNAL_ERROR",
            Self::UNAUTHORIZED => "UNAUTHORIZED",
            Self::TRACK_ENDED => "TRACK_ENDED",
            Self::SUBSCRIPTION_ENDED => "SUBSCRIPTION_ENDED",
            Self::GOING_AWAY => "GOING_AWAY",
            Self::TOO_FAR_BEHIND => "TOO_FAR_BEHIND",
            Self::EXPIRED => "EXPIRED",
            Self::UPDATE_FAILED => "UPDATE_FAILED",
            Self::EXCESSIVE_LOAD => "EXCESSIVE_LOAD",
            Self::MALFORMED_TRACK => "MALFORMED_TRACK",
            other => return write!(f, "UNKNOWN({:#x})", other.get()),
        };
        f.write_str(name)
    }
}

/// How many data streams a subscription used.
///
/// The subscriber compares this against the streams it actually saw to know
/// when nothing further is coming, which is what lets it drop subscription
/// state without waiting out a timeout. The draft reserves the varint maximum
/// to mean "I could not count", so that sentinel is a variant here rather than
/// a magic number a caller has to remember to check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamCount {
    /// The exact number of streams opened, including empty ones.
    Exact(u64),
    /// The publisher could not determine the count.
    ///
    /// Encoded as the varint maximum. A subscriber that sees this has to fall
    /// back to a timeout.
    Unknown,
}

impl StreamCount {
    /// The reserved value meaning [`StreamCount::Unknown`] in the ambient
    /// draft: the largest integer it can encode, which is `2^62 - 1` under
    /// RFC 9000 varints and `2^64 - 1` under `vi64` (draft-22 §9.9).
    fn unknown_sentinel() -> u64 {
        if Draft::current().uses_vi64() {
            u64::MAX
        } else {
            crate::varint::MAX
        }
    }

    fn wire(self) -> u64 {
        match self {
            // Saturating is right here and only here: an exact count at or
            // above the sentinel is indistinguishable from "I lost count", and
            // that is the meaning the draft assigns to the value anyway.
            Self::Exact(n) => n.min(Self::unknown_sentinel()),
            Self::Unknown => Self::unknown_sentinel(),
        }
    }

    fn from_wire(v: u64) -> Self {
        if v == Self::unknown_sentinel() {
            Self::Unknown
        } else {
            Self::Exact(v)
        }
    }
}

/// The final message on a subscription's request stream.
///
/// Note there is no request ID: the stream identifies the subscription. The
/// publisher must not send this until every stream it will open is open and
/// every datagram is sent — but "sent" is not "delivered", so objects can still
/// arrive afterwards. A subscriber that tears down state immediately will drop
/// them; the draft's advice is to wait out the longer of the two delivery
/// timeouts, or until [`StreamCount`] is satisfied.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublishDone {
    /// Why the subscription ended.
    pub status: PublishDoneStatus,
    /// How many data streams the publisher opened for this subscription.
    pub stream_count: StreamCount,
    /// Human-readable detail, for logs rather than for logic.
    pub reason: ReasonPhrase,
}

impl PublishDone {
    /// A termination with no reason phrase.
    #[must_use]
    pub fn new(status: PublishDoneStatus, stream_count: StreamCount) -> Self {
        Self {
            status,
            stream_count,
            reason: ReasonPhrase::empty(),
        }
    }

    /// Encoded size of the message body.
    #[must_use]
    pub fn encoded_len(&self) -> usize {
        self.status.0.size()
            + crate::varint::size_u64(self.stream_count.wire())
            + self.reason.encoded_len()
    }

    /// Append the message body to `buf`.
    pub fn encode<B: BufMut>(&self, buf: &mut B) {
        self.status.0.encode(buf);
        crate::varint::encode_u64(self.stream_count.wire(), buf);
        self.reason.encode(buf);
    }

    /// Read a message body.
    ///
    /// # Errors
    /// [`DecodeError::Short`] if incomplete; [`DecodeError::Invalid`] if the
    /// reason phrase violates its constraints.
    pub fn decode<B: Buf>(buf: &mut B) -> Result<Self, DecodeError> {
        Ok(Self {
            status: PublishDoneStatus(VarInt::decode(buf)?),
            stream_count: StreamCount::from_wire(crate::varint::decode_u64(buf)?),
            reason: ReasonPhrase::decode(buf)?,
        })
    }
}

impl MessageBody for PublishDone {
    const MESSAGE_TYPE: MessageType = MessageType::PublishDone;

    fn encoded_len(&self) -> usize {
        Self::encoded_len(self)
    }

    fn encode<B: BufMut>(&self, buf: &mut B) {
        Self::encode(self, buf);
    }
}

/// Modify a request that is already in flight, on its own request stream.
///
/// One message covers narrowing a subscription, widening it, repointing a
/// namespace prefix, and refreshing an authorization token, because in every
/// case the change is expressed as parameters. Absent parameters keep their
/// previous value, and **there is no way to remove one** — a parameter can only
/// be overwritten, which shapes how a control plane has to model defaults.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestUpdate {
    /// The request being modified.
    pub request_id: RequestId,
    /// Parameters to overwrite. Omitted parameters are left as they were.
    pub parameters: Parameters,
}

impl RequestUpdate {
    /// An update carrying no parameters, which changes nothing.
    #[must_use]
    pub fn new(request_id: RequestId) -> Self {
        Self {
            request_id,
            parameters: Parameters::new(),
        }
    }

    /// Encoded size of the message body.
    #[must_use]
    pub fn encoded_len(&self) -> usize {
        self.request_id.encoded_len() + self.parameters.encoded_len_counted()
    }

    /// Append the message body to `buf`.
    pub fn encode<B: BufMut>(&self, buf: &mut B) {
        self.request_id.encode(buf);
        self.parameters.encode_counted(buf);
    }

    /// Read a message body.
    ///
    /// # Errors
    /// [`DecodeError::Short`] if incomplete; [`DecodeError::Invalid`] if any
    /// field violates its constraints.
    ///
    /// Under draft-22 this checks the parameters against the union of what
    /// any update may carry; which subset applies depends on the request
    /// being updated, which only the session knows, so it checks again with
    /// the precise [`Context`].
    pub fn decode<B: Buf>(buf: &mut B) -> Result<Self, DecodeError> {
        let request_id = RequestId::decode(buf)?;
        let parameters = Parameters::decode_counted(buf)?;
        if Draft::current().typed_parameters() {
            Context::RequestUpdate.check(&parameters)?;
        }
        Ok(Self {
            request_id,
            parameters,
        })
    }
}

impl MessageBody for RequestUpdate {
    const MESSAGE_TYPE: MessageType = MessageType::RequestUpdate;

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
    use crate::model::TrackNamespace;

    fn track() -> FullTrackName {
        FullTrackName::new(
            TrackNamespace::from_parts([&b"moqom"[..], b"room-1"]).unwrap(),
            bytes::Bytes::from_static(b"video"),
        )
        .unwrap()
    }

    #[test]
    fn publish_round_trips() {
        let mut value = Publish::new(
            Role::Server.first_request_id(),
            track(),
            TrackAlias::from(7u32),
        );
        value
            .parameters
            .push(Parameter::varint(0x10, VarInt::from_u32(0)).unwrap());
        value
            .properties
            .push(Parameter::bytes(0x0D, &b"config"[..]).unwrap());

        let mut buf = Vec::new();
        value.encode(&mut buf);
        assert_eq!(buf.len(), value.encoded_len());
        let mut cursor = buf.as_slice();
        assert_eq!(Publish::decode(&mut cursor).unwrap(), value);
        assert!(cursor.is_empty());
    }

    #[test]
    fn publish_done_round_trips() {
        for status in [
            PublishDoneStatus::TRACK_ENDED,
            PublishDoneStatus::MALFORMED_TRACK,
            PublishDoneStatus::new(0xDEAD).unwrap(),
        ] {
            for count in [
                StreamCount::Exact(0),
                StreamCount::Exact(4096),
                StreamCount::Unknown,
            ] {
                let mut value = PublishDone::new(status, count);
                value.reason = ReasonPhrase::new("upstream vanished").unwrap();

                let mut buf = Vec::new();
                value.encode(&mut buf);
                assert_eq!(buf.len(), value.encoded_len());
                let mut cursor = buf.as_slice();
                assert_eq!(PublishDone::decode(&mut cursor).unwrap(), value);
                assert!(cursor.is_empty());
            }
        }
    }

    /// The sentinel is a real value on the wire, so a publisher that genuinely
    /// opened that many streams is indistinguishable from one that lost count.
    /// The draft accepts that; this pins which way the ambiguity resolves.
    #[test]
    fn the_maximum_stream_count_decodes_as_unknown() {
        let value = PublishDone::new(
            PublishDoneStatus::TRACK_ENDED,
            StreamCount::Exact(crate::varint::MAX),
        );
        let mut buf = Vec::new();
        value.encode(&mut buf);
        assert_eq!(
            PublishDone::decode(&mut buf.as_slice())
                .unwrap()
                .stream_count,
            StreamCount::Unknown
        );
    }

    /// An unrecognised status must survive a relay and must not be mistaken
    /// for a clean shutdown.
    #[test]
    fn unknown_statuses_are_preserved_and_treated_as_errors() {
        let unknown = PublishDoneStatus::new(0x4242).unwrap();
        assert!(unknown.is_error());
        assert_eq!(unknown.to_string(), "UNKNOWN(0x4242)");
        assert!(!PublishDoneStatus::TRACK_ENDED.is_error());
        assert!(!PublishDoneStatus::SUBSCRIPTION_ENDED.is_error());
        assert!(PublishDoneStatus::TOO_FAR_BEHIND.is_error());
    }

    #[test]
    fn status_codes_match_the_draft() {
        assert_eq!(PublishDoneStatus::INTERNAL_ERROR.get(), 0x0);
        assert_eq!(PublishDoneStatus::UNAUTHORIZED.get(), 0x1);
        assert_eq!(PublishDoneStatus::TRACK_ENDED.get(), 0x2);
        assert_eq!(PublishDoneStatus::SUBSCRIPTION_ENDED.get(), 0x3);
        assert_eq!(PublishDoneStatus::GOING_AWAY.get(), 0x4);
        assert_eq!(PublishDoneStatus::TOO_FAR_BEHIND.get(), 0x5);
        assert_eq!(PublishDoneStatus::EXPIRED.get(), 0x6);
        assert_eq!(PublishDoneStatus::UPDATE_FAILED.get(), 0x8);
        assert_eq!(PublishDoneStatus::EXCESSIVE_LOAD.get(), 0x9);
        assert_eq!(PublishDoneStatus::MALFORMED_TRACK.get(), 0x12);
    }

    #[test]
    fn request_update_round_trips() {
        let mut value = RequestUpdate::new(Role::Client.first_request_id());
        value
            .parameters
            .push(Parameter::varint(0x20, VarInt::from_u32(128)).unwrap());

        let mut buf = Vec::new();
        value.encode(&mut buf);
        assert_eq!(buf.len(), value.encoded_len());
        let mut cursor = buf.as_slice();
        assert_eq!(RequestUpdate::decode(&mut cursor).unwrap(), value);
        assert!(cursor.is_empty());
    }
}
