//! GOAWAY, per draft-19 §10.4.

use bytes::{Buf, BufMut, Bytes};

use crate::coding::{decode_bytes, encode_bytes, encoded_bytes_len};
use crate::control::request_id::Role;
use crate::error::DecodeError;
use crate::varint::VarInt;

/// Maximum length of the New Session URI.
pub const MAX_URI_LEN: usize = 8192;

/// A GOAWAY violated a rule the specification makes mandatory.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum GoawayError {
    /// The URI exceeded [`MAX_URI_LEN`].
    #[error("new session URI is {len} bytes, exceeding the {MAX_URI_LEN} byte maximum")]
    UriTooLong {
        /// The oversized length.
        len: usize,
    },
    /// A client supplied a redirect target. `PROTOCOL_VIOLATION`.
    #[error("a client may not supply a new session URI")]
    ClientSuppliedUri,
}

/// Notice that the sender intends to close the session, or to migrate a single
/// request.
///
/// On the control stream this begins a graceful shutdown; on a request stream
/// it moves just that request, which is how a relay gathers the publisher and
/// subscribers of one track onto a common node without draining everything else
/// on the connection.
///
/// A GOAWAY does not cancel anything. Subscriptions stay live and the receiver
/// is expected to wind them down itself, so treating this as a teardown loses
/// state the peer still expects to exist.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Goaway {
    /// Where to reconnect. Empty means the current URI.
    new_session_uri: Bytes,
    /// Milliseconds the sender will wait before forcing closure. Zero means no
    /// specific deadline, but asks the peer to move promptly — it does not mean
    /// "wait indefinitely".
    pub timeout_ms: VarInt,
}

impl Goaway {
    /// A GOAWAY with no redirect, which is the only form a client may send.
    #[must_use]
    pub const fn new(timeout_ms: VarInt) -> Self {
        Self {
            new_session_uri: Bytes::new(),
            timeout_ms,
        }
    }

    /// A GOAWAY redirecting the peer to another URI.
    ///
    /// # Errors
    /// [`GoawayError::UriTooLong`] beyond [`MAX_URI_LEN`].
    pub fn redirect(uri: impl Into<Bytes>, timeout_ms: VarInt) -> Result<Self, GoawayError> {
        let uri = uri.into();
        if uri.len() > MAX_URI_LEN {
            return Err(GoawayError::UriTooLong { len: uri.len() });
        }
        Ok(Self {
            new_session_uri: uri,
            timeout_ms,
        })
    }

    /// The redirect target, empty if the current URI should be reused.
    #[must_use]
    pub const fn new_session_uri(&self) -> &Bytes {
        &self.new_session_uri
    }

    /// Whether a redirect target was supplied.
    #[must_use]
    pub fn has_redirect(&self) -> bool {
        !self.new_session_uri.is_empty()
    }

    /// Check the rule that depends on who sent this.
    ///
    /// # Errors
    /// [`GoawayError::ClientSuppliedUri`] if a client supplied a URI. Clients
    /// cannot tell a server where to connect, so this is a session error rather
    /// than something to ignore.
    pub fn validate(&self, sender: Role) -> Result<(), GoawayError> {
        if sender == Role::Client && self.has_redirect() {
            return Err(GoawayError::ClientSuppliedUri);
        }
        Ok(())
    }

    /// Encoded size of the message body.
    #[must_use]
    pub fn encoded_len(&self) -> usize {
        encoded_bytes_len(&self.new_session_uri) + self.timeout_ms.size()
    }

    /// Append the message body to `buf`.
    pub fn encode<B: BufMut>(&self, buf: &mut B) {
        encode_bytes(buf, &self.new_session_uri);
        self.timeout_ms.encode(buf);
    }

    /// Read a message body.
    ///
    /// # Errors
    /// [`DecodeError::Short`] if incomplete; [`DecodeError::Invalid`] if the URI
    /// exceeds [`MAX_URI_LEN`].
    pub fn decode<B: Buf>(buf: &mut B) -> Result<Self, DecodeError> {
        let new_session_uri = Bytes::from(decode_bytes(buf, MAX_URI_LEN)?);
        let timeout_ms = VarInt::decode(buf)?;
        Ok(Self {
            new_session_uri,
            timeout_ms,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn round_trip(msg: &Goaway) {
        let mut buf = Vec::new();
        msg.encode(&mut buf);
        assert_eq!(buf.len(), msg.encoded_len());

        let mut cursor = buf.as_slice();
        assert_eq!(&Goaway::decode(&mut cursor).unwrap(), msg);
        assert!(cursor.is_empty());
    }

    #[test]
    fn round_trips_with_and_without_a_redirect() {
        round_trip(&Goaway::new(VarInt::ZERO));
        round_trip(&Goaway::new(VarInt::from_u32(30_000)));
        round_trip(
            &Goaway::redirect(
                &b"moqt://eu-west.moqom.dev/live"[..],
                VarInt::from_u32(5000),
            )
            .unwrap(),
        );
    }

    #[test]
    fn redirect_presence_is_length_based() {
        assert!(!Goaway::new(VarInt::ZERO).has_redirect());
        assert!(
            !Goaway::redirect(&b""[..], VarInt::ZERO)
                .unwrap()
                .has_redirect()
        );
        assert!(
            Goaway::redirect(&b"moqt://x/"[..], VarInt::ZERO)
                .unwrap()
                .has_redirect()
        );
    }

    /// A client cannot instruct a server where to connect, so a client GOAWAY
    /// must always carry a zero-length URI.
    #[test]
    fn only_servers_may_redirect() {
        let redirect = Goaway::redirect(&b"moqt://x/"[..], VarInt::ZERO).unwrap();
        assert_eq!(
            redirect.validate(Role::Client),
            Err(GoawayError::ClientSuppliedUri)
        );
        assert!(redirect.validate(Role::Server).is_ok());

        let plain = Goaway::new(VarInt::ZERO);
        assert!(plain.validate(Role::Client).is_ok());
        assert!(plain.validate(Role::Server).is_ok());
    }

    #[test]
    fn oversized_uris_are_rejected_both_ways() {
        assert!(Goaway::redirect(vec![b'x'; MAX_URI_LEN], VarInt::ZERO).is_ok());
        assert_eq!(
            Goaway::redirect(vec![b'x'; MAX_URI_LEN + 1], VarInt::ZERO),
            Err(GoawayError::UriTooLong {
                len: MAX_URI_LEN + 1
            })
        );

        let mut buf = Vec::new();
        VarInt::new(MAX_URI_LEN as u64 + 1)
            .unwrap()
            .encode(&mut buf);
        buf.extend_from_slice(&vec![b'x'; MAX_URI_LEN + 1]);
        VarInt::ZERO.encode(&mut buf);

        let mut cursor = buf.as_slice();
        assert!(Goaway::decode(&mut cursor).unwrap_err().is_fatal());
    }

    #[test]
    fn truncation_is_short() {
        let msg = Goaway::redirect(&b"moqt://relay/"[..], VarInt::from_u32(1000)).unwrap();
        let mut buf = Vec::new();
        msg.encode(&mut buf);

        for cut in 0..buf.len() {
            let mut cursor = &buf[..cut];
            assert!(
                !Goaway::decode(&mut cursor).unwrap_err().is_fatal(),
                "cut at {cut}"
            );
        }
    }
}
