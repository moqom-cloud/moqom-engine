//! Draft-16 control messages: the subset a client of Cloudflare's relays
//! needs.
//!
//! Draft-16 is a different protocol from MOQOM's draft-19 in the ways that
//! matter here, even though the integers and parameters are spelled the same
//! (RFC 9000 varints; Key-Value-Pairs typed by parity with delta-encoded
//! types, §1.4.2):
//!
//! - SETUP is two messages, `CLIENT_SETUP` (0x20) and `SERVER_SETUP` (0x21),
//!   each a count of Setup Parameters.
//! - Every control message goes on the one bidirectional control stream the
//!   client opens (§3.3), and carries its Request ID, except
//!   `SUBSCRIBE_NAMESPACE`, which §9.25 sends on a bidirectional stream of
//!   its own.
//! - Request IDs are flow-controlled: a client may only use IDs below the
//!   server's `MAX_REQUEST_ID`, and its own are even, from 0 (§9.1).
//! - A subscription ends with `UNSUBSCRIBE` or `PUBLISH_DONE`, not a stream
//!   reset.
//!
//! Covered: `CLIENT_SETUP`, `SERVER_SETUP`, `MAX_REQUEST_ID`,
//! `REQUESTS_BLOCKED`, `REQUEST_OK`, `REQUEST_ERROR`, `SUBSCRIBE`,
//! `SUBSCRIBE_OK`, `UNSUBSCRIBE`, `PUBLISH`, `PUBLISH_OK`, `PUBLISH_DONE`,
//! `PUBLISH_NAMESPACE`, `NAMESPACE`, `PUBLISH_NAMESPACE_DONE`,
//! `NAMESPACE_DONE`, `SUBSCRIBE_NAMESPACE` and `TRACK_STATUS`. Every other
//! type draft-16 defines (`FETCH`, `REQUEST_UPDATE`, `GOAWAY`, …) decodes as
//! [`Message::Unsupported`] so the session can close with
//! `PROTOCOL_VIOLATION` knowingly rather than desynchronise; a type draft-16
//! does not define is an error, which §9 makes fatal anyway.
//!
//! The data plane needs nothing here: draft-16 subgroups are MOQOM's
//! draft-19 subgroups without the `FIRST_OBJECT` bit, which the subgroup
//! codec rejects under [`Draft::D16`].
//!
//! # Adding a draft
//!
//! The message set is shared and every layout decision takes the draft, so
//! a later draft with the same stream model is a new arm in [`kind_of`] and
//! [`code_of`] plus whatever layouts moved, each behind a draft comparison
//! in [`Message::encode_body`] and [`Message::decode_body`].

use bytes::{Buf, BufMut, Bytes, BytesMut};

use crate::control::{Parameter, Parameters, Properties, ReasonPhrase, RequestId};
use crate::draft::Draft;
use crate::error::DecodeError;
use crate::model::{FullTrackName, Location, TrackAlias, TrackNamespace};
use crate::varint::VarInt;

/// Setup Parameter types (§9.3.1). A namespace of their own, distinct from
/// Message Parameters.
pub mod setup_param {
    /// `PATH` (bytes): the path of the `MoQ` URI over native QUIC.
    pub const PATH: u64 = 0x01;
    /// `MAX_REQUEST_ID` (varint): the first Request ID the receiver may not
    /// use. 0 when absent, meaning no requests at all.
    pub const MAX_REQUEST_ID: u64 = 0x02;
    /// `AUTHORIZATION TOKEN` (bytes, a Token structure).
    pub const AUTHORIZATION_TOKEN: u64 = 0x03;
    /// `MAX_AUTH_TOKEN_CACHE_SIZE` (varint).
    pub const MAX_AUTH_TOKEN_CACHE_SIZE: u64 = 0x04;
    /// `AUTHORITY` (bytes): the authority of the `MoQ` URI over native QUIC.
    pub const AUTHORITY: u64 = 0x05;
    /// `MOQT_IMPLEMENTATION` (bytes).
    pub const MOQT_IMPLEMENTATION: u64 = 0x07;
}

/// Message Parameter types (§9.2.2).
pub mod param {
    /// `AUTHORIZATION TOKEN` (bytes, a Token structure). May repeat.
    pub const AUTHORIZATION_TOKEN: u64 = 0x03;
    /// `DELIVERY TIMEOUT` (varint, milliseconds).
    pub const DELIVERY_TIMEOUT: u64 = 0x02;
    /// `EXPIRES` (varint, milliseconds; 0 means none).
    pub const EXPIRES: u64 = 0x08;
    /// `LARGEST OBJECT` (bytes, a Location).
    pub const LARGEST_OBJECT: u64 = 0x09;
    /// `FORWARD` (varint, 0 or 1; 1 when absent except on `REQUEST_UPDATE`).
    pub const FORWARD: u64 = 0x10;
    /// `SUBSCRIBER PRIORITY` (varint, 0–255; 128 when absent).
    pub const SUBSCRIBER_PRIORITY: u64 = 0x20;
    /// `SUBSCRIPTION FILTER` (bytes, a [`Filter`]).
    pub const SUBSCRIPTION_FILTER: u64 = 0x21;
    /// `GROUP ORDER` (varint: 1 ascending, 2 descending).
    pub const GROUP_ORDER: u64 = 0x22;
    /// `NEW GROUP REQUEST` (varint).
    pub const NEW_GROUP_REQUEST: u64 = 0x32;
}

/// `SUBSCRIBE_NAMESPACE` Subscribe Options (§9.25).
pub mod subscribe_options {
    /// Only `PUBLISH` for matching tracks.
    pub const PUBLISH: u64 = 0x00;
    /// Only `NAMESPACE` / `NAMESPACE_DONE`.
    pub const NAMESPACE: u64 = 0x01;
    /// Both.
    pub const BOTH: u64 = 0x02;
}

/// A Subscription Filter (§5.1.2), carried in `SUBSCRIPTION_FILTER`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Filter {
    /// `0x1`: from the start of the group after the Largest Object.
    NextGroupStart,
    /// `0x2`: from just after the Largest Object.
    LargestObject,
    /// `0x3`: from `start`, open-ended.
    AbsoluteStart(Location),
    /// `0x4`: from `start` through the end of group `end_group`, which must
    /// not precede `start.group`.
    AbsoluteRange {
        /// First Location.
        start: Location,
        /// Last group, inclusive.
        end_group: VarInt,
    },
}

impl Filter {
    /// Encode the filter's bytes (the parameter value, without its length).
    pub fn encode<B: BufMut>(&self, buf: &mut B) {
        Draft::D16.scope(|| match *self {
            Self::NextGroupStart => VarInt::from_u32(0x1).encode(buf),
            Self::LargestObject => VarInt::from_u32(0x2).encode(buf),
            Self::AbsoluteStart(start) => {
                VarInt::from_u32(0x3).encode(buf);
                start.encode(buf);
            }
            Self::AbsoluteRange { start, end_group } => {
                VarInt::from_u32(0x4).encode(buf);
                start.encode(buf);
                end_group.encode(buf);
            }
        });
    }

    /// Decode a filter that must fill `bytes` exactly.
    ///
    /// # Errors
    /// [`DecodeError::Invalid`] for an unknown filter type, an end group
    /// before the start, or bytes left over — each a `PROTOCOL_VIOLATION`.
    pub fn decode(mut bytes: &[u8]) -> Result<Self, DecodeError> {
        let filter = Draft::D16
            .scope(|| -> Result<Self, DecodeError> {
                let buf = &mut bytes;
                Ok(match VarInt::decode(buf)?.get() {
                    0x1 => Self::NextGroupStart,
                    0x2 => Self::LargestObject,
                    0x3 => Self::AbsoluteStart(Location::decode(buf)?),
                    0x4 => {
                        let start = Location::decode(buf)?;
                        let end_group = VarInt::decode(buf)?;
                        if end_group < start.group.as_varint() {
                            return Err(DecodeError::Invalid("End Group precedes Start Location"));
                        }
                        Self::AbsoluteRange { start, end_group }
                    }
                    _ => return Err(DecodeError::Invalid("unknown subscription filter type")),
                })
            })
            .map_err(DecodeError::in_complete_message)?;
        if !bytes.is_empty() {
            return Err(DecodeError::Invalid(
                "subscription filter shorter than its parameter",
            ));
        }
        Ok(filter)
    }

    /// The `SUBSCRIPTION_FILTER` parameter carrying this filter.
    #[must_use]
    pub fn parameter(&self) -> Parameter {
        let mut value = BytesMut::new();
        self.encode(&mut value);
        Parameter::bytes(param::SUBSCRIPTION_FILTER, value.freeze())
            .unwrap_or_else(|_| unreachable!("an odd type and a short value"))
    }
}

/// The Location a `LARGEST_OBJECT` parameter carries, if present and
/// well-formed.
#[must_use]
pub fn largest_object(parameters: &Parameters) -> Option<Location> {
    let mut bytes = &parameters.get(param::LARGEST_OBJECT)?.as_bytes()?[..];
    let location = Draft::D16.scope(|| Location::decode(&mut bytes)).ok()?;
    bytes.is_empty().then_some(location)
}

/// A request naming a track: the body of `SUBSCRIBE` and of `TRACK_STATUS`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrackRequest {
    /// This request's ID: even from a client, odd from a server.
    pub request_id: RequestId,
    /// The track.
    pub track: FullTrackName,
    /// Message Parameters.
    pub parameters: Parameters,
}

/// A draft-16 control message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Message {
    /// `CLIENT_SETUP` (0x20): Setup Parameters.
    ClientSetup(Parameters),
    /// `SERVER_SETUP` (0x21): Setup Parameters.
    ServerSetup(Parameters),
    /// `MAX_REQUEST_ID` (0x15): the new first unusable Request ID.
    MaxRequestId(VarInt),
    /// `REQUESTS_BLOCKED` (0x1A): the limit the sender is blocked on.
    RequestsBlocked(VarInt),
    /// `REQUEST_OK` (0x7).
    RequestOk {
        /// The request accepted.
        request_id: RequestId,
        /// Message Parameters.
        parameters: Parameters,
    },
    /// `REQUEST_ERROR` (0x5).
    RequestError {
        /// The request refused.
        request_id: RequestId,
        /// §13.4.2.
        code: VarInt,
        /// Milliseconds before retrying, plus one; 0 means do not retry.
        retry_interval: VarInt,
        /// Why.
        reason: ReasonPhrase,
    },
    /// `SUBSCRIBE` (0x3).
    Subscribe(TrackRequest),
    /// `SUBSCRIBE_OK` (0x4).
    SubscribeOk {
        /// The `SUBSCRIBE` accepted.
        request_id: RequestId,
        /// The alias objects for this track will carry.
        track_alias: TrackAlias,
        /// Message Parameters.
        parameters: Parameters,
        /// Track Extensions, to the end of the message.
        extensions: Properties,
    },
    /// `UNSUBSCRIBE` (0xA).
    Unsubscribe {
        /// The subscription to end.
        request_id: RequestId,
    },
    /// `PUBLISH` (0x1D).
    Publish {
        /// This request's ID.
        request_id: RequestId,
        /// The track offered.
        track: FullTrackName,
        /// The alias its objects will carry.
        track_alias: TrackAlias,
        /// Message Parameters.
        parameters: Parameters,
        /// Track Extensions, to the end of the message.
        extensions: Properties,
    },
    /// `PUBLISH_OK` (0x1E).
    PublishOk {
        /// The `PUBLISH` accepted.
        request_id: RequestId,
        /// Message Parameters.
        parameters: Parameters,
    },
    /// `PUBLISH_DONE` (0xB).
    PublishDone {
        /// The subscription that ended.
        request_id: RequestId,
        /// §13.4.3.
        status: VarInt,
        /// Data streams opened for it, so the receiver knows when it has
        /// them all.
        stream_count: VarInt,
        /// Why.
        reason: ReasonPhrase,
    },
    /// `PUBLISH_NAMESPACE` (0x6).
    PublishNamespace {
        /// This request's ID.
        request_id: RequestId,
        /// The namespace.
        namespace: TrackNamespace,
        /// Message Parameters.
        parameters: Parameters,
    },
    /// `NAMESPACE` (0x8), on a `SUBSCRIBE_NAMESPACE` stream.
    Namespace {
        /// Relative to the prefix subscribed to.
        suffix: TrackNamespace,
    },
    /// `PUBLISH_NAMESPACE_DONE` (0x9).
    PublishNamespaceDone {
        /// The `PUBLISH_NAMESPACE` withdrawn.
        request_id: RequestId,
    },
    /// `NAMESPACE_DONE` (0xE), on a `SUBSCRIBE_NAMESPACE` stream.
    NamespaceDone {
        /// Relative to the prefix subscribed to.
        suffix: TrackNamespace,
    },
    /// `SUBSCRIBE_NAMESPACE` (0x11), on its own bidirectional stream.
    SubscribeNamespace {
        /// This request's ID.
        request_id: RequestId,
        /// The prefix.
        prefix: TrackNamespace,
        /// See [`subscribe_options`].
        options: VarInt,
        /// Message Parameters.
        parameters: Parameters,
    },
    /// `TRACK_STATUS` (0xD), answered with `REQUEST_OK` or `REQUEST_ERROR`.
    TrackStatus(TrackRequest),
    /// A message the draft defines and this subset does not handle.
    Unsupported {
        /// Its type.
        message_type: u64,
        /// Its payload, undecoded.
        body: Bytes,
    },
}

/// The messages, independent of how any draft numbers them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    ClientSetup,
    ServerSetup,
    MaxRequestId,
    RequestsBlocked,
    RequestOk,
    RequestError,
    Subscribe,
    SubscribeOk,
    Unsubscribe,
    Publish,
    PublishOk,
    PublishDone,
    PublishNamespace,
    Namespace,
    PublishNamespaceDone,
    NamespaceDone,
    SubscribeNamespace,
    TrackStatus,
}

/// Draft-16's numbering (§9, Table 1).
const D16_TYPES: &[(u64, Kind)] = &[
    (0x20, Kind::ClientSetup),
    (0x21, Kind::ServerSetup),
    (0x15, Kind::MaxRequestId),
    (0x1A, Kind::RequestsBlocked),
    (0x07, Kind::RequestOk),
    (0x05, Kind::RequestError),
    (0x03, Kind::Subscribe),
    (0x04, Kind::SubscribeOk),
    (0x0A, Kind::Unsubscribe),
    (0x1D, Kind::Publish),
    (0x1E, Kind::PublishOk),
    (0x0B, Kind::PublishDone),
    (0x06, Kind::PublishNamespace),
    (0x08, Kind::Namespace),
    (0x09, Kind::PublishNamespaceDone),
    (0x0E, Kind::NamespaceDone),
    (0x11, Kind::SubscribeNamespace),
    (0x0D, Kind::TrackStatus),
];

/// Types draft-16 defines that this subset does not: `REQUEST_UPDATE`,
/// `GOAWAY`, `FETCH`, `FETCH_CANCEL`, `FETCH_OK`, `PUBLISH_NAMESPACE_CANCEL`.
const D16_UNSUPPORTED: &[u64] = &[0x02, 0x10, 0x16, 0x17, 0x18, 0x0C];

/// A draft's numbering: the types it handles, and the ones it defines but
/// this subset does not.
type Table = (&'static [(u64, Kind)], &'static [u64]);

fn table(draft: Draft) -> Result<Table, DecodeError> {
    match draft {
        Draft::D16 => Ok((D16_TYPES, D16_UNSUPPORTED)),
        _ => Err(DecodeError::Invalid(
            "the draft-16 codec only speaks draft-16",
        )),
    }
}

fn kind_of(draft: Draft, code: u64) -> Result<Option<Kind>, DecodeError> {
    let (known, unsupported) = table(draft)?;
    if let Some((_, kind)) = known.iter().find(|(c, _)| *c == code) {
        return Ok(Some(*kind));
    }
    if unsupported.contains(&code) {
        return Ok(None);
    }
    Err(DecodeError::Invalid("unknown control message type"))
}

fn code_of(draft: Draft, kind: Kind) -> u64 {
    let (known, _) = table(draft).unwrap_or((D16_TYPES, D16_UNSUPPORTED));
    known
        .iter()
        .find(|(_, k)| *k == kind)
        .map_or_else(|| unreachable!("every kind is numbered"), |(c, _)| *c)
}

impl Message {
    fn kind(&self) -> Option<Kind> {
        Some(match self {
            Self::ClientSetup(_) => Kind::ClientSetup,
            Self::ServerSetup(_) => Kind::ServerSetup,
            Self::MaxRequestId(_) => Kind::MaxRequestId,
            Self::RequestsBlocked(_) => Kind::RequestsBlocked,
            Self::RequestOk { .. } => Kind::RequestOk,
            Self::RequestError { .. } => Kind::RequestError,
            Self::Subscribe(_) => Kind::Subscribe,
            Self::SubscribeOk { .. } => Kind::SubscribeOk,
            Self::Unsubscribe { .. } => Kind::Unsubscribe,
            Self::Publish { .. } => Kind::Publish,
            Self::PublishOk { .. } => Kind::PublishOk,
            Self::PublishDone { .. } => Kind::PublishDone,
            Self::PublishNamespace { .. } => Kind::PublishNamespace,
            Self::Namespace { .. } => Kind::Namespace,
            Self::PublishNamespaceDone { .. } => Kind::PublishNamespaceDone,
            Self::NamespaceDone { .. } => Kind::NamespaceDone,
            Self::SubscribeNamespace { .. } => Kind::SubscribeNamespace,
            Self::TrackStatus(_) => Kind::TrackStatus,
            Self::Unsupported { .. } => return None,
        })
    }

    /// The message type this has on the wire in `draft`.
    #[must_use]
    pub fn message_type(&self, draft: Draft) -> u64 {
        match (self, self.kind()) {
            (Self::Unsupported { message_type, .. }, _) => *message_type,
            (_, Some(kind)) => code_of(draft, kind),
            (_, None) => unreachable!("only Unsupported has no kind"),
        }
    }

    /// Append the framed message — Type (i), Length (16), payload — to `buf`.
    ///
    /// # Errors
    /// [`DecodeError::Invalid`] if the payload exceeds 2^16 − 1 bytes or
    /// `draft` is not one this codec speaks.
    pub fn encode<B: BufMut>(&self, draft: Draft, buf: &mut B) -> Result<(), DecodeError> {
        table(draft)?;
        let mut body = BytesMut::new();
        draft.scope(|| self.encode_body(&mut body));
        let len = u16::try_from(body.len())
            .map_err(|_| DecodeError::Invalid("control message longer than 2^16-1"))?;
        draft.scope(|| {
            VarInt::new(self.message_type(draft))
                .unwrap_or_else(|_| unreachable!("message types are small"))
                .encode(buf);
        });
        buf.put_u16(len);
        buf.put_slice(&body);
        Ok(())
    }

    /// The framed encoding as bytes.
    ///
    /// # Errors
    /// As [`Self::encode`].
    pub fn to_bytes(&self, draft: Draft) -> Result<Bytes, DecodeError> {
        let mut buf = BytesMut::new();
        self.encode(draft, &mut buf)?;
        Ok(buf.freeze())
    }

    fn encode_body(&self, buf: &mut BytesMut) {
        match self {
            Self::ClientSetup(parameters) | Self::ServerSetup(parameters) => {
                parameters.encode_counted(buf);
            }
            Self::MaxRequestId(value) | Self::RequestsBlocked(value) => value.encode(buf),
            Self::RequestOk {
                request_id,
                parameters,
            }
            | Self::PublishOk {
                request_id,
                parameters,
            } => {
                request_id.encode(buf);
                parameters.encode_counted(buf);
            }
            Self::RequestError {
                request_id,
                code,
                retry_interval,
                reason,
            } => {
                request_id.encode(buf);
                code.encode(buf);
                retry_interval.encode(buf);
                reason.encode(buf);
            }
            Self::Subscribe(request) | Self::TrackStatus(request) => {
                request.request_id.encode(buf);
                request.track.encode(buf);
                request.parameters.encode_counted(buf);
            }
            Self::SubscribeOk {
                request_id,
                track_alias,
                parameters,
                extensions,
            } => {
                request_id.encode(buf);
                track_alias.as_varint().encode(buf);
                parameters.encode_counted(buf);
                extensions.encode(buf);
            }
            Self::Unsubscribe { request_id } | Self::PublishNamespaceDone { request_id } => {
                request_id.encode(buf);
            }
            Self::Publish {
                request_id,
                track,
                track_alias,
                parameters,
                extensions,
            } => {
                request_id.encode(buf);
                track.encode(buf);
                track_alias.as_varint().encode(buf);
                parameters.encode_counted(buf);
                extensions.encode(buf);
            }
            Self::PublishDone {
                request_id,
                status,
                stream_count,
                reason,
            } => {
                request_id.encode(buf);
                status.encode(buf);
                stream_count.encode(buf);
                reason.encode(buf);
            }
            Self::PublishNamespace {
                request_id,
                namespace,
                parameters,
            } => {
                request_id.encode(buf);
                namespace.encode(buf);
                parameters.encode_counted(buf);
            }
            Self::Namespace { suffix } | Self::NamespaceDone { suffix } => suffix.encode(buf),
            Self::SubscribeNamespace {
                request_id,
                prefix,
                options,
                parameters,
            } => {
                request_id.encode(buf);
                prefix.encode(buf);
                options.encode(buf);
                parameters.encode_counted(buf);
            }
            Self::Unsupported { body, .. } => buf.put_slice(body),
        }
    }

    /// Read one framed message off the front of `buf`.
    ///
    /// # Errors
    /// - [`DecodeError::Short`] until the whole message is present; nothing
    ///   is consumed in that case.
    /// - [`DecodeError::Invalid`] for a type draft-16 does not define, a
    ///   payload that does not fill its length exactly, or a malformed field.
    ///   Each closes the session with `PROTOCOL_VIOLATION` (§9).
    pub fn decode(draft: Draft, buf: &mut &[u8]) -> Result<Self, DecodeError> {
        table(draft)?;
        let mut cursor = *buf;
        let message_type = draft.scope(|| VarInt::decode(&mut cursor))?.get();
        if cursor.remaining() < 2 {
            return Err(DecodeError::Short {
                needed: 2 - cursor.remaining(),
            });
        }
        let len = usize::from(cursor.get_u16());
        if cursor.remaining() < len {
            return Err(DecodeError::Short {
                needed: len - cursor.remaining(),
            });
        }
        let (body, rest) = cursor.split_at(len);
        let kind = kind_of(draft, message_type)?;
        let message = match kind {
            None => Self::Unsupported {
                message_type,
                body: Bytes::copy_from_slice(body),
            },
            Some(kind) => {
                let mut body = body;
                let message = draft
                    .scope(|| Self::decode_body(kind, &mut body))
                    .map_err(DecodeError::in_complete_message)?;
                if !body.is_empty() {
                    return Err(DecodeError::Invalid("bytes left over after message body"));
                }
                message
            }
        };
        *buf = rest;
        Ok(message)
    }

    fn decode_body(kind: Kind, buf: &mut &[u8]) -> Result<Self, DecodeError> {
        let request_id = |buf: &mut &[u8]| RequestId::decode(buf);
        Ok(match kind {
            Kind::ClientSetup => Self::ClientSetup(Parameters::decode_counted(buf)?),
            Kind::ServerSetup => Self::ServerSetup(Parameters::decode_counted(buf)?),
            Kind::MaxRequestId => Self::MaxRequestId(VarInt::decode(buf)?),
            Kind::RequestsBlocked => Self::RequestsBlocked(VarInt::decode(buf)?),
            Kind::RequestOk => Self::RequestOk {
                request_id: request_id(buf)?,
                parameters: Parameters::decode_counted(buf)?,
            },
            Kind::PublishOk => Self::PublishOk {
                request_id: request_id(buf)?,
                parameters: Parameters::decode_counted(buf)?,
            },
            Kind::RequestError => Self::RequestError {
                request_id: request_id(buf)?,
                code: VarInt::decode(buf)?,
                retry_interval: VarInt::decode(buf)?,
                reason: ReasonPhrase::decode(buf)?,
            },
            Kind::Subscribe => Self::Subscribe(TrackRequest::decode(buf)?),
            Kind::TrackStatus => Self::TrackStatus(TrackRequest::decode(buf)?),
            Kind::SubscribeOk => Self::SubscribeOk {
                request_id: request_id(buf)?,
                track_alias: TrackAlias::new(VarInt::decode(buf)?),
                parameters: Parameters::decode_counted(buf)?,
                extensions: Properties::decode_to_end(buf)?,
            },
            Kind::Unsubscribe => Self::Unsubscribe {
                request_id: request_id(buf)?,
            },
            Kind::PublishNamespaceDone => Self::PublishNamespaceDone {
                request_id: request_id(buf)?,
            },
            Kind::Publish => Self::Publish {
                request_id: request_id(buf)?,
                track: FullTrackName::decode(buf)?,
                track_alias: TrackAlias::new(VarInt::decode(buf)?),
                parameters: Parameters::decode_counted(buf)?,
                extensions: Properties::decode_to_end(buf)?,
            },
            Kind::PublishDone => Self::PublishDone {
                request_id: request_id(buf)?,
                status: VarInt::decode(buf)?,
                stream_count: VarInt::decode(buf)?,
                reason: ReasonPhrase::decode(buf)?,
            },
            Kind::PublishNamespace => Self::PublishNamespace {
                request_id: request_id(buf)?,
                namespace: TrackNamespace::decode(buf)?,
                parameters: Parameters::decode_counted(buf)?,
            },
            Kind::Namespace => Self::Namespace {
                suffix: TrackNamespace::decode(buf)?,
            },
            Kind::NamespaceDone => Self::NamespaceDone {
                suffix: TrackNamespace::decode(buf)?,
            },
            Kind::SubscribeNamespace => Self::SubscribeNamespace {
                request_id: request_id(buf)?,
                prefix: TrackNamespace::decode(buf)?,
                options: VarInt::decode(buf)?,
                parameters: Parameters::decode_counted(buf)?,
            },
        })
    }
}

impl TrackRequest {
    /// A request for `track` with no parameters.
    #[must_use]
    pub const fn new(request_id: RequestId, track: FullTrackName) -> Self {
        Self {
            request_id,
            track,
            parameters: Parameters::new(),
        }
    }

    fn decode(buf: &mut &[u8]) -> Result<Self, DecodeError> {
        Ok(Self {
            request_id: RequestId::decode(buf)?,
            track: FullTrackName::decode(buf)?,
            parameters: Parameters::decode_counted(buf)?,
        })
    }
}

/// Client Request IDs (§9.1): even, from 0, each below the server's
/// `MAX_REQUEST_ID`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClientRequestIds {
    next: u64,
    limit: u64,
}

impl ClientRequestIds {
    /// Before `SERVER_SETUP`, when the limit is the default of 0.
    #[must_use]
    pub const fn new() -> Self {
        Self { next: 0, limit: 0 }
    }

    /// Raise the limit to `max`, from `SERVER_SETUP` or `MAX_REQUEST_ID`.
    ///
    /// # Errors
    /// [`DecodeError::Invalid`] if `max` is lower than the current limit,
    /// which §9.5 makes a `PROTOCOL_VIOLATION`.
    pub fn raise(&mut self, max: u64) -> Result<(), DecodeError> {
        if max < self.limit {
            return Err(DecodeError::Invalid("MAX_REQUEST_ID decreased"));
        }
        self.limit = max;
        Ok(())
    }

    /// The next ID, or `None` if the server's limit forbids it — in which
    /// case the caller sends `REQUESTS_BLOCKED` with [`Self::limit`].
    pub fn allocate(&mut self) -> Option<RequestId> {
        if self.next >= self.limit {
            return None;
        }
        let id = RequestId::new(self.next).ok()?;
        self.next += 2;
        Some(id)
    }

    /// The server's current limit.
    #[must_use]
    pub const fn limit(&self) -> u64 {
        self.limit
    }
}

impl Default for ClientRequestIds {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{GroupId, ObjectId};

    const D16: Draft = Draft::D16;

    fn hex(bytes: &[u8]) -> String {
        use std::fmt::Write as _;
        bytes.iter().fold(String::new(), |mut out, b| {
            let _ = write!(out, "{b:02x}");
            out
        })
    }

    fn rid(n: u64) -> RequestId {
        RequestId::new(n).unwrap()
    }

    fn track() -> FullTrackName {
        FullTrackName::new(
            TrackNamespace::from_parts([&b"bbb"[..]]).unwrap(),
            Bytes::from_static(b"0.mp4"),
        )
        .unwrap()
    }

    fn varint(type_value: u64, value: u32) -> Parameter {
        Parameter::varint(type_value, VarInt::from_u32(value)).unwrap()
    }

    /// Encode, compare with the hand-assembled bytes, and decode back.
    fn check(message: &Message, expected: &str) {
        let bytes = message.to_bytes(D16).unwrap();
        assert_eq!(hex(&bytes), expected, "{message:?}");
        let mut cursor = &bytes[..];
        assert_eq!(&Message::decode(D16, &mut cursor).unwrap(), message);
        assert!(cursor.is_empty());
    }

    #[test]
    fn client_setup_carries_the_path_and_a_request_limit() {
        let mut parameters = Parameters::new();
        parameters.push(Parameter::bytes(setup_param::PATH, &b"/jwt"[..]).unwrap());
        parameters.push(varint(setup_param::MAX_REQUEST_ID, 0));
        // 20 | 0009 | count 2 | delta 1, len 4, "/jwt" | delta 1, 0
        check(
            &Message::ClientSetup(parameters),
            concat!("200009", "02", "01042f6a7774", "0100"),
        );
    }

    #[test]
    fn server_setup_sets_the_request_limit() {
        let mut parameters = Parameters::new();
        parameters.push(varint(setup_param::MAX_REQUEST_ID, 100));
        // 21 | 0004 | count 1 | delta 2 | 100 as a two-byte varint
        check(&Message::ServerSetup(parameters.clone()), "21000401024064");
        let mut ids = ClientRequestIds::new();
        assert_eq!(ids.allocate(), None, "nothing before SERVER_SETUP");
        ids.raise(4).unwrap();
        assert_eq!(ids.allocate(), Some(rid(0)));
        assert_eq!(ids.allocate(), Some(rid(2)));
        assert_eq!(ids.allocate(), None, "4 is the first unusable ID");
        assert!(ids.raise(2).is_err(), "§9.5: the limit only rises");
    }

    #[test]
    fn subscribe_with_a_largest_object_filter() {
        let mut request = TrackRequest::new(rid(2), track());
        request.parameters.push(Filter::LargestObject.parameter());
        request.parameters.push(varint(param::FORWARD, 1));
        // 03 | 0012 | rid 2 | ns: 1 field "bbb" | name "0.mp4"
        // | 2 params: FORWARD (delta 0x10) = 1, FILTER (delta 0x11) len 1 = 0x02
        check(
            &Message::Subscribe(request),
            concat!(
                "030012",
                "02",
                "0103626262",
                "05302e6d7034",
                "02",
                "1001",
                "110102"
            ),
        );
    }

    #[test]
    fn subscribe_ok_reads_the_largest_object() {
        let mut parameters = Parameters::new();
        let mut location = BytesMut::new();
        Location::new(
            GroupId::new(VarInt::from_u32(7)),
            ObjectId::new(VarInt::from_u32(3)),
        )
        .encode(&mut location);
        parameters.push(Parameter::bytes(param::LARGEST_OBJECT, location.freeze()).unwrap());
        let message = Message::SubscribeOk {
            request_id: rid(2),
            track_alias: TrackAlias::new(VarInt::from_u32(5)),
            parameters,
            extensions: Properties::new(),
        };
        // 04 | 0007 | rid 2 | alias 5 | 1 param: delta 9, len 2, {7, 3}
        check(&message, concat!("040007", "02", "05", "01", "09020703"));
        let Message::SubscribeOk { parameters, .. } = message else {
            unreachable!()
        };
        assert_eq!(
            largest_object(&parameters),
            Some(Location::new(
                GroupId::new(VarInt::from_u32(7)),
                ObjectId::new(VarInt::from_u32(3))
            ))
        );
    }

    #[test]
    fn request_lifecycle_messages() {
        check(&Message::MaxRequestId(VarInt::from_u32(10)), "1500010a");
        check(&Message::RequestsBlocked(VarInt::from_u32(10)), "1a00010a");
        check(&Message::Unsubscribe { request_id: rid(4) }, "0a000104");
        check(
            &Message::RequestOk {
                request_id: rid(4),
                parameters: Parameters::new(),
            },
            "0700020400",
        );
        check(
            &Message::RequestError {
                request_id: rid(4),
                code: VarInt::from_u32(0x10),
                retry_interval: VarInt::from_u32(0),
                reason: ReasonPhrase::truncating("no"),
            },
            concat!("05000604100002", "6e6f"),
        );
        check(
            &Message::PublishDone {
                request_id: rid(4),
                status: VarInt::from_u32(2),
                stream_count: VarInt::from_u32(3),
                reason: ReasonPhrase::empty(),
            },
            concat!("0b00040402", "0300"),
        );
        check(
            &Message::TrackStatus(TrackRequest::new(rid(6), track())),
            concat!("0d000d06", "0103626262", "05302e6d7034", "00"),
        );
    }

    #[test]
    fn publishing_messages() {
        let namespace = TrackNamespace::from_parts([&b"bbb"[..]]).unwrap();
        check(
            &Message::PublishNamespace {
                request_id: rid(0),
                namespace: namespace.clone(),
                parameters: Parameters::new(),
            },
            concat!("060007", "00", "0103626262", "00"),
        );
        check(
            &Message::Publish {
                request_id: rid(2),
                track: track(),
                track_alias: TrackAlias::new(VarInt::from_u32(1)),
                parameters: Parameters::new(),
                extensions: Properties::new(),
            },
            concat!("1d000e", "02", "0103626262", "05302e6d7034", "01", "00"),
        );
        let mut accepted = Parameters::new();
        accepted.push(varint(param::FORWARD, 1));
        check(
            &Message::PublishOk {
                request_id: rid(2),
                parameters: accepted,
            },
            concat!("1e0004", "02", "01", "1001"),
        );
        check(
            &Message::PublishNamespaceDone { request_id: rid(0) },
            "09000100",
        );
    }

    #[test]
    fn namespace_discovery() {
        let prefix = TrackNamespace::from_parts([&b"bbb"[..]]).unwrap();
        check(
            &Message::SubscribeNamespace {
                request_id: rid(8),
                prefix,
                options: VarInt::new(subscribe_options::NAMESPACE).unwrap(),
                parameters: Parameters::new(),
            },
            concat!("110008", "08", "0103626262", "01", "00"),
        );
        let suffix = TrackNamespace::from_parts([&b"x"[..]]).unwrap();
        check(
            &Message::Namespace {
                suffix: suffix.clone(),
            },
            "080003010178",
        );
        check(&Message::NamespaceDone { suffix }, "0e0003010178");
    }

    #[test]
    fn out_of_subset_and_unknown_types() {
        // GOAWAY with an empty URI: defined by draft-16, not handled here.
        let mut cursor = &[0x10, 0x00, 0x01, 0x00][..];
        assert_eq!(
            Message::decode(D16, &mut cursor).unwrap(),
            Message::Unsupported {
                message_type: 0x10,
                body: Bytes::from_static(&[0x00]),
            }
        );
        // 0x40 was CLIENT_SETUP for versions <= 10, and is nothing now.
        let mut cursor = &[0x40, 0x40, 0x00, 0x00][..];
        assert!(matches!(
            Message::decode(D16, &mut cursor),
            Err(DecodeError::Invalid(_))
        ));
    }

    #[test]
    fn a_message_is_read_whole_or_not_at_all() {
        let bytes = Message::MaxRequestId(VarInt::from_u32(1000))
            .to_bytes(D16)
            .unwrap();
        for cut in 0..bytes.len() {
            let mut cursor = &bytes[..cut];
            assert!(matches!(
                Message::decode(D16, &mut cursor),
                Err(DecodeError::Short { .. })
            ));
            assert_eq!(cursor.len(), cut, "nothing consumed on a short read");
        }
        let mut padded = bytes.to_vec();
        padded.push(0);
        padded[2] += 1;
        let mut cursor = &padded[..];
        assert!(matches!(
            Message::decode(D16, &mut cursor),
            Err(DecodeError::Invalid(_))
        ));
    }

    #[test]
    fn filters_round_trip_and_reject_what_section_5_1_2_forbids() {
        let start = Location::new(
            GroupId::new(VarInt::from_u32(4)),
            ObjectId::new(VarInt::from_u32(1)),
        );
        for (filter, expected) in [
            (Filter::NextGroupStart, "01"),
            (Filter::LargestObject, "02"),
            (Filter::AbsoluteStart(start), "030401"),
            (
                Filter::AbsoluteRange {
                    start,
                    end_group: VarInt::from_u32(9),
                },
                "04040109",
            ),
        ] {
            let mut buf = Vec::new();
            filter.encode(&mut buf);
            assert_eq!(hex(&buf), expected);
            assert_eq!(Filter::decode(&buf).unwrap(), filter);
        }
        assert!(Filter::decode(&[0x05]).is_err(), "unknown type");
        assert!(
            Filter::decode(&[0x04, 0x04, 0x01, 0x03]).is_err(),
            "end before start"
        );
        assert!(Filter::decode(&[0x02, 0x00]).is_err(), "trailing bytes");
    }

    /// Publishing's data plane: a subgroup as a draft-16 publisher writes it.
    #[test]
    fn a_published_subgroup() {
        use crate::data::{SubgroupHeader, SubgroupObject, SubgroupSource, SubgroupWriter};
        let bytes = D16.scope(|| {
            let header = SubgroupHeader::new(
                TrackAlias::new(VarInt::from_u32(1)),
                GroupId::new(VarInt::from_u32(5)),
                SubgroupSource::Zero,
            );
            let mut buf = Vec::new();
            header.encode(&mut buf);
            let mut writer = SubgroupWriter::new(&header);
            for (id, payload) in [(0u32, &b"ab"[..]), (1, b"c")] {
                writer
                    .write(
                        &mut buf,
                        &SubgroupObject::new(id, Bytes::from_static(payload)),
                    )
                    .unwrap();
            }
            buf
        });
        // Type 0x30 (Subgroup ID 0, default priority, no extensions), alias
        // 1, group 5; then Object ID Delta 0, length 2, "ab"; delta 0,
        // length 1, "c".
        assert_eq!(hex(&bytes), concat!("300105", "00026162", "000163"));
    }

    #[test]
    fn the_codec_refuses_other_drafts() {
        assert!(
            Message::MaxRequestId(VarInt::from_u32(1))
                .to_bytes(Draft::D19)
                .is_err()
        );
    }
}
