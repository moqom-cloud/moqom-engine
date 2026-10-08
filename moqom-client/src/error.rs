//! Failures a client can observe without panicking.

use moqom_proto::control::{BodyTooLong, MessageType};
use moqom_proto::data::SubgroupError;
use moqom_proto::error::BoundsExceeded;
use moqom_proto::error::DecodeError;

/// Why a client operation failed.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// The local UDP socket could not be bound, or a name could not be resolved.
    #[error("{0}")]
    Io(#[from] std::io::Error),

    /// The TLS configuration is not usable for QUIC.
    #[error("TLS configuration is not usable for QUIC: {0}")]
    Tls(String),

    /// The QUIC handshake did not start.
    #[error("QUIC connect: {0}")]
    Connect(#[from] quinn::ConnectError),

    /// The QUIC handshake did not complete.
    #[error("QUIC handshake failed: {0}")]
    Handshake(#[from] quinn::ConnectionError),

    /// The session failed after it was established.
    #[error("{0}")]
    Session(#[from] web_transport_quinn::SessionError),

    /// A control or data stream could not be written.
    #[error("write failed: {0}")]
    Write(String),

    /// The peer closed a stream instead of answering.
    #[error("the peer closed the stream before answering")]
    Closed,

    /// The relay refused the session and said why as it closed.
    ///
    /// Distinct from [`Self::Refused`], which is one request being turned down on
    /// a session that stands. This is the session itself, and the reason phrase is
    /// the only thing that distinguishes the several ways it can happen -- an
    /// unverifiable token, a missing proof, a proof from the wrong key, and a
    /// credential that merely got old all arrive as the same error code, and the
    /// right response to each differs.
    #[error("the relay refused this session ({code}): {reason}")]
    Rejected {
        /// The MOQT session error code.
        code: u64,
        /// What the relay said as it closed.
        reason: String,
    },

    /// The peer answered SETUP with something else, or with an undecodable body.
    #[error("SETUP failed: {0}")]
    Setup(String),

    /// The peer refused a request.
    #[error("request refused ({code}): {reason}")]
    Refused {
        /// The MOQT error code.
        code: u64,
        /// Diagnostic text from the peer.
        reason: String,
    },

    /// The peer sent a message this client does not handle at this point.
    #[error("unexpected {found:?} while {during}")]
    Unexpected {
        /// The message that arrived.
        found: MessageType,
        /// What the client was doing.
        during: &'static str,
    },

    /// A control or data message could not be decoded.
    #[error("{0}")]
    Decode(#[from] DecodeError),

    /// A control message exceeded the envelope.
    #[error("{0}")]
    Frame(#[from] BodyTooLong),

    /// This session has used every legal request ID.
    #[error("request IDs exhausted")]
    RequestIdsExhausted,

    /// A group or alias is outside the varint range.
    #[error("{0}")]
    Bounds(#[from] BoundsExceeded),

    /// A subgroup could not be encoded.
    #[error("{0}")]
    Subgroup(#[from] SubgroupError),

    /// An object carried properties into a group that was opened without them.
    ///
    /// Refused rather than dropped. Whether properties are present is a flag on
    /// the subgroup header, so it is fixed before the first object and cannot be
    /// revised; encoding the object anyway would discard exactly the capture time
    /// a latency measurement is made of, and the measurement would come back
    /// empty with nothing to say why.
    #[error("this group was opened without properties, so an object cannot carry any")]
    PropertiesNotDeclared,

    /// A device key was offered, but the relay presented no certificate to bind
    /// the proof to.
    ///
    /// Not reachable over a raw QUIC handshake, which cannot complete without one.
    /// Refused rather than proven against an empty identity, since that proof
    /// would be refused by every relay for a reason nothing here would explain.
    #[error("the relay presented no certificate, so a proof cannot be bound to it")]
    NoRelayIdentity,

    /// The peer sent something the protocol does not allow at that point, and
    /// the session was closed for it.
    #[error("protocol violation: {0}")]
    Protocol(String),

    /// The handshake completed without settling on a MOQT draft this client
    /// speaks.
    #[error("the peer did not negotiate moqt-22 or moqt-19")]
    NoMoqt,

    /// The device key could not sign.
    #[error("{0}")]
    DeviceKey(#[from] crate::device::DeviceKeyError),

    /// The room does not allow a direct path. See [`crate::direct::Eligibility`].
    #[error("direct mode is not allowed here: {0}")]
    Ineligible(#[from] crate::direct::Ineligible),

    /// No direct path could be opened in time. The relay path is unaffected.
    #[error("no direct path to the peer opened within {0:?}")]
    Unreachable(std::time::Duration),

    /// A candidate offer could not be opened: wrong room secret, tampered, not
    /// addressed to us, or not an offer at all.
    #[error("candidate offer refused: {0}")]
    Offer(&'static str),

    /// The peer's credentials did not verify, so this side closed the direct
    /// session.
    #[error("the peer's credentials were refused: {0}")]
    PeerUnverified(String),

    /// The peer refused this side's credentials and said why as it closed.
    #[error("the peer refused this session ({code}): {reason}")]
    PeerRejected {
        /// The MOQT session error code.
        code: u64,
        /// What the peer said as it closed.
        reason: String,
    },
}

impl Error {
    pub(crate) fn write(error: impl std::fmt::Display) -> Self {
        Self::Write(error.to_string())
    }

    pub(crate) fn tls(error: impl std::fmt::Display) -> Self {
        Self::Tls(error.to_string())
    }

    pub(crate) fn setup(error: impl std::fmt::Display) -> Self {
        Self::Setup(error.to_string())
    }
}
