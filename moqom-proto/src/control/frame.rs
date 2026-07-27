//! The control message envelope, per draft-19 §10.
//!
//! ```text
//! MOQT Control Message {
//!   Message Type (vi64),
//!   Message Length (16),
//!   Message Body (..),
//! }
//! ```
//!
//! Message Length is a **fixed 16-bit field, not a varint**, which is a real
//! constraint rather than a formatting detail: no control message body can
//! exceed 65535 bytes. A `SUBSCRIBE_NAMESPACE` with a large authorization token,
//! or a `NAMESPACE` batch, can approach that, and the failure has to be caught
//! when the message is built rather than discovered at the socket.

use bytes::{Buf, BufMut, Bytes};

use crate::control::message_type::MessageType;
use crate::error::DecodeError;
use crate::varint::VarInt;

/// Largest control message body: `2^16 - 1` bytes.
pub const MAX_BODY_LEN: usize = (1 << 16) - 1;

/// A control message body exceeded what the envelope can describe.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("control message body is {len} bytes, exceeding the {MAX_BODY_LEN} byte maximum")]
pub struct BodyTooLong {
    /// The oversized length.
    pub len: usize,
}

/// A framed control message: a type and an opaque body.
///
/// Framing is kept separate from body parsing so that reading a message off the
/// wire and interpreting it are distinct failures. A body that does not match
/// its declared length is a framing error the session cannot recover from,
/// while a body that parses badly is specific to one message type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ControlFrame {
    /// The message type.
    pub message_type: MessageType,
    /// The body, exactly as it appeared on the wire.
    pub body: Bytes,
}

impl ControlFrame {
    /// Frame a body.
    ///
    /// # Errors
    /// [`BodyTooLong`] if the body exceeds [`MAX_BODY_LEN`].
    pub fn new(message_type: MessageType, body: impl Into<Bytes>) -> Result<Self, BodyTooLong> {
        let body = body.into();
        if body.len() > MAX_BODY_LEN {
            return Err(BodyTooLong { len: body.len() });
        }
        Ok(Self { message_type, body })
    }

    /// Total encoded size, envelope included.
    ///
    /// # Panics
    /// Cannot panic: message type codes are compile-time constants well within
    /// varint range.
    #[must_use]
    pub fn encoded_len(&self) -> usize {
        VarInt::new(self.message_type.as_u64())
            .expect("message type within varint range")
            .size()
            + 2
            + self.body.len()
    }

    /// Append the framed message to `buf`.
    ///
    /// # Panics
    /// Cannot panic: the constructor bounds the body length, and message type
    /// codes are within varint range.
    pub fn encode<B: BufMut>(&self, buf: &mut B) {
        VarInt::new(self.message_type.as_u64())
            .expect("message type within varint range")
            .encode(buf);
        buf.put_u16(u16::try_from(self.body.len()).expect("body length bounded at construction"));
        buf.put_slice(&self.body);
    }

    /// Read one framed message.
    ///
    /// # Errors
    /// - [`DecodeError::Short`] if the frame is incomplete. The buffer may have
    ///   been partially consumed; see [`crate::coding`].
    /// - [`DecodeError::Invalid`] for an unknown or reserved message type,
    ///   which draft-19 §10 requires closing the session over.
    pub fn decode<B: Buf>(buf: &mut B) -> Result<Self, DecodeError> {
        let message_type = MessageType::from_u64(VarInt::decode(buf)?.get())?;

        if buf.remaining() < 2 {
            return Err(DecodeError::Short {
                needed: 2 - buf.remaining(),
            });
        }
        let len = usize::from(buf.get_u16());

        if buf.remaining() < len {
            return Err(DecodeError::Short {
                needed: len - buf.remaining(),
            });
        }
        let body = buf.copy_to_bytes(len);

        Ok(Self { message_type, body })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips() {
        for (ty, body) in [
            (MessageType::Setup, &b""[..]),
            (MessageType::Subscribe, &b"body"[..]),
            (MessageType::RequestError, &b"\x00\x01\x02"[..]),
        ] {
            let frame = ControlFrame::new(ty, body).unwrap();
            let mut buf = Vec::new();
            frame.encode(&mut buf);
            assert_eq!(buf.len(), frame.encoded_len());

            let mut cursor = buf.as_slice();
            assert_eq!(ControlFrame::decode(&mut cursor).unwrap(), frame);
            assert!(cursor.is_empty());
        }
    }

    /// SETUP's `0x2F00` needs a two-byte varint, and the length that follows is
    /// big-endian and fixed width. Getting either wrong desynchronises the
    /// control stream on the very first message.
    #[test]
    fn envelope_layout_is_exact() {
        let frame = ControlFrame::new(MessageType::Setup, &b"ab"[..]).unwrap();
        let mut buf = Vec::new();
        frame.encode(&mut buf);
        assert_eq!(buf, vec![0x6F, 0x00, 0x00, 0x02, b'a', b'b']);

        // A single-byte type code leaves the length in the next two bytes.
        let frame = ControlFrame::new(MessageType::Subscribe, &b"x"[..]).unwrap();
        let mut buf = Vec::new();
        frame.encode(&mut buf);
        assert_eq!(buf, vec![0x03, 0x00, 0x01, b'x']);
    }

    #[test]
    fn length_is_sixteen_bits_not_a_varint() {
        // 300 bytes: a varint length would be two bytes, the real field is two
        // bytes big-endian. Distinguishable only above 255.
        let frame = ControlFrame::new(MessageType::Subscribe, vec![0u8; 300]).unwrap();
        let mut buf = Vec::new();
        frame.encode(&mut buf);
        assert_eq!(&buf[1..3], &[0x01, 0x2C]);
    }

    #[test]
    fn bodies_over_64_kib_are_rejected_when_built() {
        assert!(ControlFrame::new(MessageType::Subscribe, vec![0u8; MAX_BODY_LEN]).is_ok());
        assert_eq!(
            ControlFrame::new(MessageType::Subscribe, vec![0u8; MAX_BODY_LEN + 1]),
            Err(BodyTooLong {
                len: MAX_BODY_LEN + 1
            })
        );
    }

    #[test]
    fn max_size_body_round_trips() {
        let frame = ControlFrame::new(MessageType::Namespace, vec![0x5A; MAX_BODY_LEN]).unwrap();
        let mut buf = Vec::new();
        frame.encode(&mut buf);
        assert_eq!(&buf[1..3], &[0xFF, 0xFF]);

        let mut cursor = buf.as_slice();
        assert_eq!(ControlFrame::decode(&mut cursor).unwrap(), frame);
    }

    #[test]
    fn truncation_at_every_offset_is_short() {
        let frame = ControlFrame::new(MessageType::Setup, &b"hello"[..]).unwrap();
        let mut buf = Vec::new();
        frame.encode(&mut buf);

        for cut in 0..buf.len() {
            let mut cursor = &buf[..cut];
            let err = ControlFrame::decode(&mut cursor).unwrap_err();
            assert!(!err.is_fatal(), "cut at {cut} should be recoverable");
        }
    }

    #[test]
    fn unknown_type_is_fatal() {
        let mut buf = Vec::new();
        VarInt::from_u32(0x99).encode(&mut buf);
        buf.put_u16(0);

        let mut cursor = buf.as_slice();
        assert!(ControlFrame::decode(&mut cursor).unwrap_err().is_fatal());
    }

    #[test]
    fn framing_leaves_following_messages_intact() {
        let first = ControlFrame::new(MessageType::Subscribe, &b"one"[..]).unwrap();
        let second = ControlFrame::new(MessageType::SubscribeOk, &b"two"[..]).unwrap();

        let mut buf = Vec::new();
        first.encode(&mut buf);
        second.encode(&mut buf);

        let mut cursor = buf.as_slice();
        assert_eq!(ControlFrame::decode(&mut cursor).unwrap(), first);
        assert_eq!(ControlFrame::decode(&mut cursor).unwrap(), second);
        assert!(cursor.is_empty());
    }
}
