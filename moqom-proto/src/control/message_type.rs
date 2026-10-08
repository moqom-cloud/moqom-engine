//! Control message types, per the registry in draft-19 §10 and draft-22 §9.

use crate::draft::Draft;
use crate::error::DecodeError;

/// Which stream a control message travels on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum StreamKind {
    /// The session-wide control stream pair.
    Control,
    /// A bidirectional request stream, one per request.
    Request,
    /// Valid on either.
    Both,
}

/// A control message type.
///
/// Draft-19 reworked this registry substantially, and the changes are the kind
/// that produce a silently wrong implementation rather than a compile error:
///
/// - `ANNOUNCE` is now [`PublishNamespace`](MessageType::PublishNamespace).
/// - Per-message `*_ERROR` and most `*_OK` responses collapsed into generic
///   [`RequestOk`](MessageType::RequestOk) and
///   [`RequestError`](MessageType::RequestError).
/// - `SUBSCRIBE_UPDATE` became [`RequestUpdate`](MessageType::RequestUpdate).
/// - **There is no `UNSUBSCRIBE`.** Requests live on their own bidirectional
///   stream, so cancellation is a stream reset rather than a message.
/// - `CLIENT_SETUP` and `SERVER_SETUP` merged into one
///   [`Setup`](MessageType::Setup) at `0x2F00`; the old codes are reserved.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u64)]
pub enum MessageType {
    /// Session setup, on the control stream.
    Setup = 0x2F00,
    /// Graceful session shutdown.
    Goaway = 0x10,

    /// Request a track.
    Subscribe = 0x3,
    /// Successful subscription response.
    SubscribeOk = 0x4,
    /// The publisher changed a subscription's state on its own account.
    /// Draft-22 only; under draft-19 the code is unknown.
    PublishStateNotify = 0x22,

    /// Offer a track to a peer.
    Publish = 0x1D,
    /// Publication has ended.
    PublishDone = 0xB,
    /// Objects were intentionally not published.
    PublishSkipped = 0xF,

    /// Retrieve a range of past objects.
    Fetch = 0x16,
    /// Successful fetch response.
    FetchOk = 0x18,

    /// Query track state without subscribing.
    TrackStatus = 0xD,

    /// Advertise a namespace.
    PublishNamespace = 0x6,
    /// Namespace advertisement from a peer.
    Namespace = 0x8,
    /// A namespace is no longer available.
    NamespaceDone = 0xE,
    /// Subscribe to namespace announcements under a prefix.
    SubscribeNamespace = 0x50,
    /// Subscribe to track announcements within a namespace.
    SubscribeTracks = 0x51,

    /// Modify an in-flight request.
    RequestUpdate = 0x2,
    /// Generic success response.
    RequestOk = 0x7,
    /// Generic error response.
    RequestError = 0x5,
}

/// Codes retired by earlier drafts. Receiving one almost always means the peer
/// is speaking a different draft, so it is worth distinguishing from an
/// entirely unknown type when reporting the failure.
const RESERVED: &[u64] = &[
    0x01, // SETUP in version 00
    0x40, // CLIENT_SETUP in <= 10
    0x41, // SERVER_SETUP in <= 10
    0x20, // CLIENT_SETUP in <= 16
    0x21, // SERVER_SETUP in <= 16
    0x1E, // PUBLISH_OK in <= 17
];

impl MessageType {
    /// The wire code.
    #[must_use]
    pub const fn as_u64(self) -> u64 {
        self as u64
    }

    /// Whether `draft` defines this message. Receiving one it does not is an
    /// unknown message type, and fatal.
    #[must_use]
    pub const fn defined_in(self, draft: Draft) -> bool {
        match self {
            Self::PublishStateNotify => matches!(draft, Draft::D22),
            _ => true,
        }
    }

    /// Which stream this message is valid on.
    #[must_use]
    pub const fn stream_kind(self) -> StreamKind {
        match self {
            Self::Setup => StreamKind::Control,
            Self::Goaway => StreamKind::Both,
            _ => StreamKind::Request,
        }
    }

    /// Whether this message must open a request stream rather than appear
    /// partway through one.
    #[must_use]
    pub const fn must_be_first(self) -> bool {
        matches!(
            self,
            Self::Subscribe
                | Self::Publish
                | Self::Fetch
                | Self::TrackStatus
                | Self::PublishNamespace
                | Self::SubscribeNamespace
                | Self::SubscribeTracks
        )
    }

    /// Whether this message carries an explicit Request ID.
    ///
    /// Only requests do. Responses travel on the same bidirectional stream as
    /// the request they answer, so the stream *is* the correlation — which is
    /// exactly the assumption a second dialect will not share, and the reason
    /// [`crate::control::RequestId`] is kept separate from stream identity.
    #[must_use]
    pub const fn carries_request_id(self) -> bool {
        matches!(
            self,
            Self::Subscribe
                | Self::Publish
                | Self::Fetch
                | Self::SubscribeNamespace
                | Self::SubscribeTracks
                | Self::PublishNamespace
                | Self::RequestUpdate
                | Self::TrackStatus
        )
    }

    /// Convert a wire code to a message type.
    ///
    /// # Errors
    /// [`DecodeError::Invalid`] for reserved or unknown codes. Draft-19 §10
    /// requires closing the session on an unknown message type — control
    /// messages carry a length to ease parsing, not to permit skipping.
    pub fn from_u64(code: u64) -> Result<Self, DecodeError> {
        Ok(match code {
            0x2F00 => Self::Setup,
            0x10 => Self::Goaway,
            0x3 => Self::Subscribe,
            0x4 => Self::SubscribeOk,
            0x22 => Self::PublishStateNotify,
            0x1D => Self::Publish,
            0xB => Self::PublishDone,
            0xF => Self::PublishSkipped,
            0x16 => Self::Fetch,
            0x18 => Self::FetchOk,
            0xD => Self::TrackStatus,
            0x6 => Self::PublishNamespace,
            0x8 => Self::Namespace,
            0xE => Self::NamespaceDone,
            0x50 => Self::SubscribeNamespace,
            0x51 => Self::SubscribeTracks,
            0x2 => Self::RequestUpdate,
            0x7 => Self::RequestOk,
            0x5 => Self::RequestError,
            other if RESERVED.contains(&other) => {
                return Err(DecodeError::Invalid(
                    "reserved control message type from an older draft",
                ));
            }
            _ => return Err(DecodeError::Invalid("unknown control message type")),
        })
    }
}

impl std::fmt::Display for MessageType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Setup => "SETUP",
            Self::Goaway => "GOAWAY",
            Self::Subscribe => "SUBSCRIBE",
            Self::SubscribeOk => "SUBSCRIBE_OK",
            Self::PublishStateNotify => "PUBLISH_STATE_NOTIFY",
            Self::Publish => "PUBLISH",
            Self::PublishDone => "PUBLISH_DONE",
            Self::PublishSkipped => "PUBLISH_SKIPPED",
            Self::Fetch => "FETCH",
            Self::FetchOk => "FETCH_OK",
            Self::TrackStatus => "TRACK_STATUS",
            Self::PublishNamespace => "PUBLISH_NAMESPACE",
            Self::Namespace => "NAMESPACE",
            Self::NamespaceDone => "NAMESPACE_DONE",
            Self::SubscribeNamespace => "SUBSCRIBE_NAMESPACE",
            Self::SubscribeTracks => "SUBSCRIBE_TRACKS",
            Self::RequestUpdate => "REQUEST_UPDATE",
            Self::RequestOk => "REQUEST_OK",
            Self::RequestError => "REQUEST_ERROR",
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALL: &[MessageType] = &[
        MessageType::Setup,
        MessageType::Goaway,
        MessageType::Subscribe,
        MessageType::SubscribeOk,
        MessageType::Publish,
        MessageType::PublishDone,
        MessageType::PublishSkipped,
        MessageType::Fetch,
        MessageType::FetchOk,
        MessageType::TrackStatus,
        MessageType::PublishNamespace,
        MessageType::Namespace,
        MessageType::NamespaceDone,
        MessageType::SubscribeNamespace,
        MessageType::SubscribeTracks,
        MessageType::RequestUpdate,
        MessageType::RequestOk,
        MessageType::RequestError,
    ];

    #[test]
    fn every_type_round_trips_through_its_code() {
        for &ty in ALL {
            assert_eq!(MessageType::from_u64(ty.as_u64()).unwrap(), ty, "{ty}");
        }
    }

    /// Codes are hand-transcribed from Table 5, so assert the exact values
    /// rather than only that they round-trip — a self-consistent typo would
    /// pass a round-trip test and fail against every other implementation.
    #[test]
    fn codes_match_the_draft19_registry() {
        assert_eq!(MessageType::Setup.as_u64(), 0x2F00);
        assert_eq!(MessageType::Goaway.as_u64(), 0x10);
        assert_eq!(MessageType::Subscribe.as_u64(), 0x3);
        assert_eq!(MessageType::SubscribeOk.as_u64(), 0x4);
        assert_eq!(MessageType::Publish.as_u64(), 0x1D);
        assert_eq!(MessageType::PublishDone.as_u64(), 0xB);
        assert_eq!(MessageType::PublishSkipped.as_u64(), 0xF);
        assert_eq!(MessageType::Fetch.as_u64(), 0x16);
        assert_eq!(MessageType::FetchOk.as_u64(), 0x18);
        assert_eq!(MessageType::TrackStatus.as_u64(), 0xD);
        assert_eq!(MessageType::PublishNamespace.as_u64(), 0x6);
        assert_eq!(MessageType::Namespace.as_u64(), 0x8);
        assert_eq!(MessageType::NamespaceDone.as_u64(), 0xE);
        assert_eq!(MessageType::SubscribeNamespace.as_u64(), 0x50);
        assert_eq!(MessageType::SubscribeTracks.as_u64(), 0x51);
        assert_eq!(MessageType::RequestUpdate.as_u64(), 0x2);
        assert_eq!(MessageType::RequestOk.as_u64(), 0x7);
        assert_eq!(MessageType::RequestError.as_u64(), 0x5);
    }

    #[test]
    fn reserved_and_unknown_codes_are_both_fatal() {
        for code in RESERVED {
            let err = MessageType::from_u64(*code).unwrap_err();
            assert!(err.is_fatal(), "reserved {code:#x}");
        }
        for code in [0x0u64, 0x99, 0x2F01, u64::MAX] {
            assert!(
                MessageType::from_u64(code).unwrap_err().is_fatal(),
                "unknown {code:#x}"
            );
        }
    }

    #[test]
    fn stream_placement_matches_table_5() {
        assert_eq!(MessageType::Setup.stream_kind(), StreamKind::Control);
        assert_eq!(MessageType::Goaway.stream_kind(), StreamKind::Both);
        assert_eq!(MessageType::Subscribe.stream_kind(), StreamKind::Request);

        // "First" messages open a request stream; responses never do.
        assert!(MessageType::Subscribe.must_be_first());
        assert!(MessageType::SubscribeNamespace.must_be_first());
        assert!(!MessageType::SubscribeOk.must_be_first());
        assert!(!MessageType::RequestOk.must_be_first());
    }

    /// Responses correlate by stream rather than by an ID in the body, so
    /// getting this set wrong means either a phantom field or a missing one.
    #[test]
    fn only_requests_carry_a_request_id() {
        for ty in [
            MessageType::Subscribe,
            MessageType::Publish,
            MessageType::Fetch,
            MessageType::TrackStatus,
            MessageType::PublishNamespace,
            MessageType::SubscribeNamespace,
            MessageType::SubscribeTracks,
            MessageType::RequestUpdate,
        ] {
            assert!(ty.carries_request_id(), "{ty} is a request");
        }
        for ty in [
            MessageType::SubscribeOk,
            MessageType::FetchOk,
            MessageType::RequestOk,
            MessageType::RequestError,
            MessageType::PublishDone,
            MessageType::Namespace,
            MessageType::Setup,
            MessageType::Goaway,
        ] {
            assert!(!ty.carries_request_id(), "{ty} is not a request");
        }
    }
}
