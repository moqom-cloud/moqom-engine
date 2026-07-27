//! The namespace messages, per draft-19 §10.15 through §10.20.
//!
//! Five messages that share three shapes, which is why they live together.
//! Discovery works in two directions and the pairing is easy to invert:
//!
//! - A publisher advertises with [`PublishNamespace`], one bidirectional stream
//!   per namespace.
//! - A subscriber asks to hear about advertisements with
//!   [`SubscribeNamespace`], and the publisher answers with [`Namespace`] and
//!   [`NamespaceDone`] on that stream.
//! - A subscriber asks to be *offered tracks* with [`SubscribeTracks`], and the
//!   publisher answers with `PUBLISH` messages on new streams, or
//!   [`PublishSkipped`] for a track it will not offer.
//!
//! The suffix rule is the trap here. [`Namespace`], [`NamespaceDone`], and
//! [`PublishSkipped`] all carry a namespace *suffix* relative to the prefix
//! from the request that caused them — never a whole namespace. Nothing in the
//! bytes distinguishes the two, so a decoder cannot catch the mistake; only the
//! session state knows the prefix to prepend. The types are named for the
//! suffix to keep that visible at every call site.

use bytes::{Buf, BufMut};

use crate::control::MessageType;
use crate::control::frame::MessageBody;
use crate::control::params::Parameters;
use crate::control::request_id::RequestId;
use crate::error::DecodeError;
use crate::model::{FullTrackName, TrackNamespace};

/// Generates a message body of `RequestId`, a namespace, and counted
/// parameters — the shape shared by the three namespace requests.
macro_rules! namespace_request {
    ($(#[$meta:meta])* $name:ident, $ty:expr, $field:ident, $field_doc:literal) => {
        $(#[$meta])*
        #[derive(Debug, Clone, PartialEq, Eq)]
        pub struct $name {
            /// Identifies this request. See [`RequestId`].
            pub request_id: RequestId,
            #[doc = $field_doc]
            pub $field: TrackNamespace,
            /// Request parameters, including authorization.
            pub parameters: Parameters,
        }

        impl $name {
            /// A request with no parameters.
            #[must_use]
            pub fn new(request_id: RequestId, $field: TrackNamespace) -> Self {
                Self { request_id, $field, parameters: Parameters::new() }
            }

            /// Encoded size of the message body.
            #[must_use]
            pub fn encoded_len(&self) -> usize {
                self.request_id.encoded_len()
                    + self.$field.encoded_len()
                    + self.parameters.encoded_len_counted()
            }

            /// Append the message body to `buf`.
            pub fn encode<B: BufMut>(&self, buf: &mut B) {
                self.request_id.encode(buf);
                self.$field.encode(buf);
                self.parameters.encode_counted(buf);
            }

            /// Read a message body.
            ///
            /// # Errors
            /// [`DecodeError::Short`] if incomplete; [`DecodeError::Invalid`]
            /// if any field violates its constraints.
            pub fn decode<B: Buf>(buf: &mut B) -> Result<Self, DecodeError> {
                Ok(Self {
                    request_id: RequestId::decode(buf)?,
                    $field: TrackNamespace::decode(buf)?,
                    parameters: Parameters::decode_counted(buf)?,
                })
            }
        }

        impl MessageBody for $name {
            const MESSAGE_TYPE: MessageType = $ty;

            fn encoded_len(&self) -> usize {
                Self::encoded_len(self)
            }

            fn encode<B: BufMut>(&self, buf: &mut B) {
                Self::encode(self, buf);
            }
        }
    };
}

namespace_request! {
    /// Advertise that tracks are available under a namespace.
    ///
    /// Opens a bidirectional stream. The advertisement lasts as long as that
    /// stream does, so withdrawing it is a stream close rather than a message —
    /// there is no `UNANNOUNCE`.
    PublishNamespace,
    MessageType::PublishNamespace,
    namespace,
    "The namespace whose tracks are on offer."
}

namespace_request! {
    /// Ask to be told about namespaces matching a prefix.
    ///
    /// The publisher answers on the same stream with [`Namespace`] for the
    /// current set and then for each change, and [`NamespaceDone`] as they go
    /// away. Two of these in one session may not share a common prefix; the
    /// publisher rejects the second with `PREFIX_OVERLAP`, since overlapping
    /// subscriptions would make the suffixes ambiguous.
    SubscribeNamespace,
    MessageType::SubscribeNamespace,
    prefix,
    "Matched against namespaces the publisher knows, with 0 to 32 fields. An \
     empty prefix matches everything."
}

namespace_request! {
    /// Ask to be *offered* the tracks in matching namespaces.
    ///
    /// The difference from [`SubscribeNamespace`] is what comes back: this
    /// produces `PUBLISH` messages for actual tracks, not namespace
    /// announcements. Parameters set here become the defaults for every
    /// resulting subscription, which is why an authorization token belongs on
    /// this message rather than being repeated per track.
    ///
    /// Overlap is tracked separately from [`SubscribeNamespace`], so one of
    /// each may use the same prefix.
    SubscribeTracks,
    MessageType::SubscribeTracks,
    prefix,
    "Matched against namespaces the publisher knows, with 0 to 32 fields."
}

/// Generates a message body that is a bare namespace suffix.
macro_rules! namespace_suffix {
    ($(#[$meta:meta])* $name:ident, $ty:expr) => {
        $(#[$meta])*
        #[derive(Debug, Clone, Default, PartialEq, Eq)]
        pub struct $name {
            /// The namespace fields *after* the prefix from the request that
            /// caused this message. Not a whole namespace.
            pub suffix: TrackNamespace,
        }

        impl $name {
            /// Wrap a suffix.
            #[must_use]
            pub const fn new(suffix: TrackNamespace) -> Self {
                Self { suffix }
            }

            /// The full namespace, given the prefix this was sent against.
            ///
            /// # Errors
            /// [`crate::model::NameError`] if joining exceeds the field count
            /// or byte budget — reachable when a peer sends a suffix that only
            /// fits under a shorter prefix than the one in play.
            pub fn resolve(
                &self,
                prefix: &TrackNamespace,
            ) -> Result<TrackNamespace, crate::model::NameError> {
                let mut full = prefix.clone();
                for field in self.suffix.fields() {
                    full.push(field.clone())?;
                }
                Ok(full)
            }

            /// Encoded size of the message body.
            #[must_use]
            pub fn encoded_len(&self) -> usize {
                self.suffix.encoded_len()
            }

            /// Append the message body to `buf`.
            pub fn encode<B: BufMut>(&self, buf: &mut B) {
                self.suffix.encode(buf);
            }

            /// Read a message body.
            ///
            /// # Errors
            /// [`DecodeError::Short`] if incomplete; [`DecodeError::Invalid`]
            /// if the namespace violates its constraints.
            pub fn decode<B: Buf>(buf: &mut B) -> Result<Self, DecodeError> {
                Ok(Self { suffix: TrackNamespace::decode(buf)? })
            }
        }

        impl MessageBody for $name {
            const MESSAGE_TYPE: MessageType = $ty;

            fn encoded_len(&self) -> usize {
                Self::encoded_len(self)
            }

            fn encode<B: BufMut>(&self, buf: &mut B) {
                Self::encode(self, buf);
            }
        }
    };
}

namespace_suffix! {
    /// A namespace matching an earlier [`SubscribeNamespace`] is available.
    Namespace,
    MessageType::Namespace
}

namespace_suffix! {
    /// A previously announced namespace is no longer being served.
    ///
    /// Ordering is normative: this must never arrive before the [`Namespace`]
    /// it retracts, and a subscriber that sees one MUST close the session. A
    /// reset or `FIN` on the response stream means the same thing for every
    /// namespace still active on it.
    NamespaceDone,
    MessageType::NamespaceDone
}

/// A track inside a subscribed namespace will not be offered.
///
/// The negative acknowledgement for [`SubscribeTracks`]: without it a
/// subscriber could not tell "not authorized for this track" from "the publisher
/// has not got to it yet", and would wait forever.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PublishSkipped {
    /// The track, whose namespace is a *suffix* relative to the
    /// [`SubscribeTracks`] prefix rather than a whole namespace.
    pub track: FullTrackName,
}

impl PublishSkipped {
    /// Name the track being skipped.
    #[must_use]
    pub const fn new(track: FullTrackName) -> Self {
        Self { track }
    }

    /// Encoded size of the message body.
    #[must_use]
    pub fn encoded_len(&self) -> usize {
        self.track.encoded_len()
    }

    /// Append the message body to `buf`.
    pub fn encode<B: BufMut>(&self, buf: &mut B) {
        self.track.encode(buf);
    }

    /// Read a message body.
    ///
    /// # Errors
    /// [`DecodeError::Short`] if incomplete; [`DecodeError::Invalid`] if the
    /// name violates its constraints.
    pub fn decode<B: Buf>(buf: &mut B) -> Result<Self, DecodeError> {
        Ok(Self {
            track: FullTrackName::decode(buf)?,
        })
    }
}

impl MessageBody for PublishSkipped {
    const MESSAGE_TYPE: MessageType = MessageType::PublishSkipped;

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
    use crate::varint::VarInt;

    fn ns(parts: &[&[u8]]) -> TrackNamespace {
        TrackNamespace::from_parts(parts.iter().copied()).unwrap()
    }

    fn params() -> Parameters {
        let mut p = Parameters::new();
        p.push(Parameter::bytes(3, &b"token"[..]).unwrap());
        p
    }

    #[test]
    fn namespace_requests_round_trip() {
        let id = Role::Client.first_request_id();

        macro_rules! check {
            ($ty:ty, $value:expr) => {{
                let value: $ty = $value;
                let mut buf = Vec::new();
                value.encode(&mut buf);
                assert_eq!(buf.len(), value.encoded_len());
                let mut cursor = buf.as_slice();
                assert_eq!(<$ty>::decode(&mut cursor).unwrap(), value);
                assert!(cursor.is_empty());
            }};
        }

        let mut publish = PublishNamespace::new(id, ns(&[b"moqom", b"room-1"]));
        publish.parameters = params();
        check!(PublishNamespace, publish);

        let mut subscribe = SubscribeNamespace::new(id, ns(&[b"moqom"]));
        subscribe.parameters = params();
        check!(SubscribeNamespace, subscribe);

        check!(
            SubscribeTracks,
            SubscribeTracks::new(id, TrackNamespace::empty())
        );
    }

    #[test]
    fn suffix_messages_round_trip() {
        for suffix in [TrackNamespace::empty(), ns(&[b"room-1", b"video"])] {
            let mut buf = Vec::new();
            let value = Namespace::new(suffix.clone());
            value.encode(&mut buf);
            assert_eq!(buf.len(), value.encoded_len());
            assert_eq!(Namespace::decode(&mut buf.as_slice()).unwrap(), value);

            let mut buf = Vec::new();
            let value = NamespaceDone::new(suffix);
            value.encode(&mut buf);
            assert_eq!(NamespaceDone::decode(&mut buf.as_slice()).unwrap(), value);
        }
    }

    /// The suffix rule is invisible on the wire, so the join is the only place
    /// it can be got right. Worth pinning both the happy path and the budget.
    #[test]
    fn resolving_a_suffix_prepends_the_prefix() {
        let prefix = ns(&[b"moqom", b"tenant-7"]);
        let message = Namespace::new(ns(&[b"room-1"]));
        assert_eq!(
            message.resolve(&prefix).unwrap(),
            ns(&[b"moqom", b"tenant-7", b"room-1"])
        );

        // An empty suffix means the prefix itself matched.
        assert_eq!(Namespace::default().resolve(&prefix).unwrap(), prefix);
    }

    #[test]
    fn resolving_past_the_field_limit_is_an_error() {
        let prefix = TrackNamespace::from_parts((0..30).map(|i| format!("p{i}"))).unwrap();
        let message =
            Namespace::new(TrackNamespace::from_parts((0..5).map(|i| format!("s{i}"))).unwrap());
        assert!(message.resolve(&prefix).is_err());
    }

    #[test]
    fn publish_skipped_round_trips() {
        let track =
            FullTrackName::new(ns(&[b"room-1"]), bytes::Bytes::from_static(b"video")).unwrap();
        let value = PublishSkipped::new(track);
        let mut buf = Vec::new();
        value.encode(&mut buf);
        assert_eq!(buf.len(), value.encoded_len());
        assert_eq!(PublishSkipped::decode(&mut buf.as_slice()).unwrap(), value);
    }

    /// Every message here must be reachable through the framed path, which is
    /// the only place the 64 KiB body cap is enforced.
    #[test]
    fn all_of_them_write_through_the_framed_path() {
        use crate::control::write_message;

        let id = Role::Server.first_request_id();
        let mut buf = Vec::new();
        write_message(&mut buf, &PublishNamespace::new(id, ns(&[b"a"]))).unwrap();
        write_message(&mut buf, &SubscribeNamespace::new(id, ns(&[b"a"]))).unwrap();
        write_message(&mut buf, &SubscribeTracks::new(id, ns(&[b"a"]))).unwrap();
        write_message(&mut buf, &Namespace::new(ns(&[b"a"]))).unwrap();
        write_message(&mut buf, &NamespaceDone::new(ns(&[b"a"]))).unwrap();
        write_message(&mut buf, &PublishSkipped::default()).unwrap();

        let mut cursor = buf.as_slice();
        let mut seen = Vec::new();
        while !cursor.is_empty() {
            seen.push(
                crate::control::ControlFrame::decode(&mut cursor)
                    .unwrap()
                    .message_type,
            );
        }
        assert_eq!(
            seen,
            vec![
                MessageType::PublishNamespace,
                MessageType::SubscribeNamespace,
                MessageType::SubscribeTracks,
                MessageType::Namespace,
                MessageType::NamespaceDone,
                MessageType::PublishSkipped,
            ]
        );
        let _ = VarInt::ZERO;
    }
}
