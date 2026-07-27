//! Decode failures.

/// Why a decode did not produce a value.
///
/// The distinction between the two variants drives relay behaviour and is the
/// reason this is not a single opaque error: [`DecodeError::Short`] is an
/// ordinary condition on a streaming transport and means *wait for more bytes*,
/// while [`DecodeError::Invalid`] means the peer sent something malformed and
/// the session should be closed. Collapsing them leads either to sessions torn
/// down on a partial read or to malformed input silently retried forever.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DecodeError {
    /// The buffer holds a valid prefix but not a whole value. Not a protocol
    /// violation. `needed` is a lower bound on the additional bytes required —
    /// a lower bound rather than an exact count because nested structures
    /// cannot know their full length until the outer length prefix is read.
    #[error("incomplete: need at least {needed} more byte(s)")]
    Short {
        /// Lower bound on additional bytes required.
        needed: usize,
    },

    /// The bytes are not a valid encoding. This is a session error.
    #[error("malformed: {0}")]
    Invalid(&'static str),
}

impl DecodeError {
    /// Whether this represents a protocol violation rather than a short read.
    ///
    /// Call sites that drive a session state machine should branch on this
    /// rather than matching the variants, so new fatal variants are handled
    /// correctly by default.
    #[must_use]
    pub const fn is_fatal(&self) -> bool {
        matches!(self, Self::Invalid(_))
    }

    /// Reinterpret a short read as malformed.
    ///
    /// A [`Short`](Self::Short) means *wait for more bytes*, which is only
    /// meaningful when more bytes might arrive. Message bodies are delimited by
    /// the frame layer, so a body that runs out mid-field is not going to be
    /// completed later — it is a peer that lied about its own length, and
    /// waiting on it would hang the request stream forever.
    ///
    /// Apply this at the boundary where a complete body is handed to a body
    /// decoder:
    ///
    /// ```
    /// # use moqom_proto::{DecodeError, control::{ControlFrame, messages::Subscribe}};
    /// # fn f(frame: ControlFrame) -> Result<Subscribe, DecodeError> {
    /// let mut body = frame.body;
    /// Subscribe::decode(&mut body).map_err(DecodeError::in_complete_message)
    /// # }
    /// ```
    #[must_use]
    pub const fn in_complete_message(self) -> Self {
        match self {
            Self::Short { .. } => Self::Invalid("message body is shorter than its fields require"),
            other @ Self::Invalid(_) => other,
        }
    }
}

/// A value too large for the 62-bit variable-length integer encoding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("value exceeds the 62-bit varint maximum")]
pub struct BoundsExceeded;

impl From<BoundsExceeded> for DecodeError {
    fn from(_: BoundsExceeded) -> Self {
        Self::Invalid("varint out of range")
    }
}
