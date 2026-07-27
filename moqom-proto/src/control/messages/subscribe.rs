//! SUBSCRIBE and `SUBSCRIBE_OK`, per draft-19 §10.7 and §10.8.

use bytes::{Buf, BufMut};

use crate::control::params::Parameters;
use crate::control::properties::Properties;
use crate::control::request_id::RequestId;
use crate::error::DecodeError;
use crate::model::{FullTrackName, TrackAlias};
use crate::varint::VarInt;

/// Request delivery of newly published objects for a track.
///
/// Only *new* objects. Anything already published is reached with FETCH, and a
/// subscription that appears to be missing the start of a stream is usually
/// this distinction rather than a bug.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Subscribe {
    /// Identifies this request. See [`RequestId`].
    pub request_id: RequestId,
    /// The track being requested.
    pub track: FullTrackName,
    /// Request parameters, including filters and authorization.
    pub parameters: Parameters,
}

impl Subscribe {
    /// A subscription with no parameters.
    #[must_use]
    pub fn new(request_id: RequestId, track: FullTrackName) -> Self {
        Self {
            request_id,
            track,
            parameters: Parameters::new(),
        }
    }

    /// Encoded size of the message body.
    #[must_use]
    pub fn encoded_len(&self) -> usize {
        self.request_id.encoded_len()
            + self.track.encoded_len()
            + self.parameters.encoded_len_counted()
    }

    /// Append the message body to `buf`.
    pub fn encode<B: BufMut>(&self, buf: &mut B) {
        self.request_id.encode(buf);
        self.track.encode(buf);
        self.parameters.encode_counted(buf);
    }

    /// Read a message body.
    ///
    /// # Errors
    /// [`DecodeError::Short`] if incomplete; [`DecodeError::Invalid`] if any
    /// field violates its constraints.
    pub fn decode<B: Buf>(buf: &mut B) -> Result<Self, DecodeError> {
        Ok(Self {
            request_id: RequestId::decode(buf)?,
            track: FullTrackName::decode(buf)?,
            parameters: Parameters::decode_counted(buf)?,
        })
    }
}

/// Accepts a subscription, and is the first response on the request stream.
///
/// Note the absence of a request ID: the bidirectional stream this arrives on
/// is the correlation, so there is nothing to match against.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubscribeOk {
    /// The short identifier this track will use in subgroup headers and
    /// datagrams for the rest of the session.
    pub track_alias: TrackAlias,
    /// Response parameters.
    pub parameters: Parameters,
    /// Track Properties, which run to the end of the message.
    ///
    /// A mandatory property here that the subscriber does not understand means
    /// the subscription must be cancelled rather than merely ignored — see
    /// [`Properties::unsupported_mandatory`].
    pub properties: Properties,
}

impl SubscribeOk {
    /// An acceptance carrying only a track alias.
    #[must_use]
    pub fn new(track_alias: TrackAlias) -> Self {
        Self {
            track_alias,
            parameters: Parameters::new(),
            properties: Properties::new(),
        }
    }

    /// Encoded size of the message body.
    #[must_use]
    pub fn encoded_len(&self) -> usize {
        self.track_alias.as_varint().size()
            + self.parameters.encoded_len_counted()
            + self.properties.encoded_len()
    }

    /// Append the message body to `buf`.
    pub fn encode<B: BufMut>(&self, buf: &mut B) {
        self.track_alias.as_varint().encode(buf);
        self.parameters.encode_counted(buf);
        self.properties.encode(buf);
    }

    /// Read a message body.
    ///
    /// `buf` must contain exactly one message body and nothing after it, since
    /// Track Properties are defined as the remainder of the message. The frame
    /// layer provides the body already delimited.
    ///
    /// # Errors
    /// [`DecodeError::Short`] if incomplete; [`DecodeError::Invalid`] if any
    /// field violates its constraints.
    pub fn decode<B: Buf>(buf: &mut B) -> Result<Self, DecodeError> {
        Ok(Self {
            track_alias: TrackAlias::new(VarInt::decode(buf)?),
            parameters: Parameters::decode_counted(buf)?,
            properties: Properties::decode_to_end(buf)?,
        })
    }
}

impl crate::control::frame::MessageBody for Subscribe {
    const MESSAGE_TYPE: crate::control::MessageType = crate::control::MessageType::Subscribe;

    fn encoded_len(&self) -> usize {
        Self::encoded_len(self)
    }

    fn encode<B: BufMut>(&self, buf: &mut B) {
        Self::encode(self, buf);
    }
}

impl crate::control::frame::MessageBody for SubscribeOk {
    const MESSAGE_TYPE: crate::control::MessageType = crate::control::MessageType::SubscribeOk;

    fn encoded_len(&self) -> usize {
        Self::encoded_len(self)
    }

    fn encode<B: BufMut>(&self, buf: &mut B) {
        Self::encode(self, buf);
    }
}

/// Ask what state a track is in without subscribing to it, per draft-19 §10.14.
///
/// Byte-for-byte the same body as [`Subscribe`], and the receiver handles it
/// the same way, except that it creates no subscription state and sends no
/// objects. The answer is a `REQUEST_OK` carrying the Largest Object and Track
/// Properties the publisher would have put in a `SUBSCRIBE_OK`.
///
/// It is a separate type rather than a flag on [`Subscribe`] because it must
/// not carry delivery parameters such as `SUBSCRIBER_PRIORITY` — there is no
/// delivery to prioritise — and because the two differ in what may follow:
/// there is no `PUBLISH_DONE` for a track status, and no `REQUEST_UPDATE`
/// either. Sharing one type would make those distinctions runtime conditions
/// instead of the compile-time ones they should be.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrackStatus {
    /// Identifies this request. See [`RequestId`].
    pub request_id: RequestId,
    /// The track being asked about.
    pub track: FullTrackName,
    /// Request parameters. Delivery parameters do not belong here.
    pub parameters: Parameters,
}

impl TrackStatus {
    /// A query with no parameters.
    #[must_use]
    pub fn new(request_id: RequestId, track: FullTrackName) -> Self {
        Self {
            request_id,
            track,
            parameters: Parameters::new(),
        }
    }

    /// Encoded size of the message body.
    #[must_use]
    pub fn encoded_len(&self) -> usize {
        self.request_id.encoded_len()
            + self.track.encoded_len()
            + self.parameters.encoded_len_counted()
    }

    /// Append the message body to `buf`.
    pub fn encode<B: BufMut>(&self, buf: &mut B) {
        self.request_id.encode(buf);
        self.track.encode(buf);
        self.parameters.encode_counted(buf);
    }

    /// Read a message body.
    ///
    /// # Errors
    /// [`DecodeError::Short`] if incomplete; [`DecodeError::Invalid`] if any
    /// field violates its constraints.
    pub fn decode<B: Buf>(buf: &mut B) -> Result<Self, DecodeError> {
        Ok(Self {
            request_id: RequestId::decode(buf)?,
            track: FullTrackName::decode(buf)?,
            parameters: Parameters::decode_counted(buf)?,
        })
    }
}

impl crate::control::frame::MessageBody for TrackStatus {
    const MESSAGE_TYPE: crate::control::MessageType = crate::control::MessageType::TrackStatus;

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
    use crate::control::params::Parameter;
    use crate::model::TrackNamespace;

    fn track() -> FullTrackName {
        FullTrackName::new(
            TrackNamespace::from_parts([&b"moqom"[..], &b"room-42"[..]]).unwrap(),
            bytes::Bytes::from_static(b"video/hd"),
        )
        .unwrap()
    }

    #[test]
    fn subscribe_round_trips() {
        let mut msg = Subscribe::new(RequestId::new(4).unwrap(), track());
        msg.parameters
            .push(Parameter::bytes(3, &b"auth-token"[..]).unwrap());
        msg.parameters
            .push(Parameter::varint(6, VarInt::from_u32(2)).unwrap());

        let mut buf = Vec::new();
        msg.encode(&mut buf);
        assert_eq!(buf.len(), msg.encoded_len());

        let mut cursor = buf.as_slice();
        assert_eq!(Subscribe::decode(&mut cursor).unwrap(), msg);
        assert!(cursor.is_empty());
    }

    #[test]
    fn subscribe_round_trips_without_parameters() {
        let msg = Subscribe::new(RequestId::new(0).unwrap(), track());
        let mut buf = Vec::new();
        msg.encode(&mut buf);

        let mut cursor = buf.as_slice();
        assert_eq!(Subscribe::decode(&mut cursor).unwrap(), msg);
    }

    #[test]
    fn subscribe_ok_round_trips() {
        let mut msg = SubscribeOk::new(TrackAlias::from(7u32));
        msg.parameters
            .push(Parameter::varint(0, VarInt::from_u32(1)).unwrap());
        msg.properties
            .push(Parameter::bytes(0x4001, &b"config"[..]).unwrap());

        let mut buf = Vec::new();
        msg.encode(&mut buf);
        assert_eq!(buf.len(), msg.encoded_len());

        let mut cursor = buf.as_slice();
        assert_eq!(SubscribeOk::decode(&mut cursor).unwrap(), msg);
        assert!(cursor.is_empty());
    }

    /// The parameter count is the only thing separating parameters from the
    /// properties that follow, so a message with both must split them at the
    /// right place — an off-by-one here reads a property as a parameter and
    /// still decodes cleanly.
    #[test]
    fn parameters_and_properties_are_separated_by_the_count() {
        let mut msg = SubscribeOk::new(TrackAlias::from(1u32));
        msg.parameters
            .push(Parameter::varint(2, VarInt::from_u32(10)).unwrap());
        msg.parameters
            .push(Parameter::varint(4, VarInt::from_u32(20)).unwrap());
        msg.properties
            .push(Parameter::varint(6, VarInt::from_u32(30)).unwrap());
        msg.properties
            .push(Parameter::varint(8, VarInt::from_u32(40)).unwrap());

        let mut buf = Vec::new();
        msg.encode(&mut buf);

        let mut cursor = buf.as_slice();
        let decoded = SubscribeOk::decode(&mut cursor).unwrap();
        assert_eq!(decoded.parameters.len(), 2);
        assert_eq!(decoded.properties.len(), 2);
        assert_eq!(decoded, msg);
    }

    #[test]
    fn subscribe_ok_round_trips_with_neither_parameters_nor_properties() {
        let msg = SubscribeOk::new(TrackAlias::ZERO);
        let mut buf = Vec::new();
        msg.encode(&mut buf);
        assert_eq!(buf, vec![0x00, 0x00], "alias zero, then a count of zero");

        let mut cursor = buf.as_slice();
        assert_eq!(SubscribeOk::decode(&mut cursor).unwrap(), msg);
    }

    /// Body decoders report truncation as short, and the caller converts it to
    /// a violation because the frame layer only hands over complete bodies.
    #[test]
    fn truncation_is_short_for_both() {
        let subscribe = Subscribe::new(RequestId::new(2).unwrap(), track());
        let mut buf = Vec::new();
        subscribe.encode(&mut buf);
        for cut in 0..buf.len() {
            let mut cursor = &buf[..cut];
            let err = Subscribe::decode(&mut cursor).unwrap_err();
            assert!(!err.is_fatal(), "subscribe {cut}: {err:?}");
            assert!(err.in_complete_message().is_fatal());
        }

        let mut ok = SubscribeOk::new(TrackAlias::from(3u32));
        ok.parameters
            .push(Parameter::bytes(1, &b"xyz"[..]).unwrap());
        let mut buf = Vec::new();
        ok.encode(&mut buf);
        for cut in 0..buf.len() {
            let mut cursor = &buf[..cut];
            let err = SubscribeOk::decode(&mut cursor).unwrap_err();
            assert!(!err.is_fatal(), "subscribe_ok {cut}: {err:?}");
        }
    }
}
