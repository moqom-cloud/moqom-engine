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
