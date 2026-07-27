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
///
/// Worth noticing that this is the *same* number as
/// [`crate::control::MAX_VALUE_LEN`], the cap on a single parameter value. The
/// two limits are independent in the draft and they interact badly: a maximal
/// parameter value cannot fit in any message, because the type, the length
/// prefix, and every other field also have to go somewhere. An authorization
/// token approaching a few tens of kilobytes is the realistic way to hit this.
pub const MAX_BODY_LEN: usize = (1 << 16) - 1;

/// A control message body exceeded what the envelope can describe.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("control message body is {len} bytes, exceeding the {MAX_BODY_LEN} byte maximum")]
pub struct BodyTooLong {
    /// The oversized length.
    pub len: usize,
}

/// A message body that knows its own type and size.
///
/// The point of this trait is [`write_message`], which is the one place a
/// message becomes bytes. Every body already has inherent `encode` and
/// `encoded_len` methods, and a caller could reach for those and write straight
/// to a socket buffer, silently skipping the 64 KiB check. Routing through here
/// makes the check both unavoidable and free, since the size is known before
/// anything is written.
pub trait MessageBody {
    /// The registry code this body is framed with.
    const MESSAGE_TYPE: MessageType;

    /// Bytes [`MessageBody::encode`] will append.
    fn encoded_len(&self) -> usize;

    /// Append the body, without the envelope.
    fn encode<B: BufMut>(&self, buf: &mut B);
}

/// Write a complete framed control message.
///
/// Checks the length limit before writing anything, so an oversized message
/// costs nothing and leaves `buf` untouched. This is the preferred path: it
/// avoids the intermediate buffer that [`ControlFrame::new`] needs, and it is
/// the reason a body cannot quietly bypass the 64 KiB cap.
///
/// # Errors
/// [`BodyTooLong`] if the encoded body would exceed [`MAX_BODY_LEN`]. This is a
/// real possibility rather than a formality — see the note on [`MAX_BODY_LEN`].
///
/// # Panics
/// Cannot panic: message type codes are compile-time constants within varint
/// range. In debug builds it additionally asserts that the body wrote exactly
/// the number of bytes it predicted, since a disagreement there would emit a
/// frame whose declared length is wrong and desynchronise the control stream.
pub fn write_message<M: MessageBody, B: BufMut>(buf: &mut B, msg: &M) -> Result<(), BodyTooLong> {
    let len = msg.encoded_len();
    let len = u16::try_from(len).map_err(|_| BodyTooLong { len })?;

    VarInt::new(M::MESSAGE_TYPE.as_u64())
        .expect("message type within varint range")
        .encode(buf);
    buf.put_u16(len);

    let before = buf.remaining_mut();
    msg.encode(buf);
    debug_assert_eq!(
        before - buf.remaining_mut(),
        usize::from(len),
        "encoded_len disagreed with encode, so the framed length is wrong"
    );

    Ok(())
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

    /// `write_message` forwards to inherent methods of the same names, which
    /// resolves correctly only because inherent lookup wins over trait lookup.
    /// Get that wrong and it is unbounded recursion at runtime rather than a
    /// compile error, so pin it against the equivalent hand-framed bytes.
    #[test]
    fn write_message_matches_manual_framing() {
        use crate::control::messages::Goaway;
        use crate::varint::VarInt;

        let msg = Goaway::redirect(&b"moqt://eu.moqom.dev/"[..], VarInt::from_u32(3000)).unwrap();

        let mut direct = Vec::new();
        write_message(&mut direct, &msg).unwrap();

        let mut body = Vec::new();
        msg.encode(&mut body);
        let mut manual = Vec::new();
        ControlFrame::new(MessageType::Goaway, body)
            .unwrap()
            .encode(&mut manual);

        assert_eq!(direct, manual);

        let mut cursor = direct.as_slice();
        let frame = ControlFrame::decode(&mut cursor).unwrap();
        assert_eq!(frame.message_type, MessageType::Goaway);
        assert_eq!(Goaway::decode(&mut frame.body.clone()).unwrap(), msg);
    }

    /// An oversized message must be refused before anything is written, or a
    /// caller that ignores the error ships a truncated frame.
    #[test]
    fn oversized_messages_are_refused_without_touching_the_buffer() {
        use crate::control::messages::Goaway;
        use crate::control::params::Parameter;
        use crate::control::{RequestOk, params::MAX_VALUE_LEN};
        use crate::varint::VarInt;

        // The two limits are independent in the draft and collide here: a
        // maximal parameter value is exactly MAX_BODY_LEN, so it cannot fit in
        // a message alongside its own type and length prefix, let alone any
        // other field.
        let mut msg = RequestOk::new();
        msg.parameters
            .push(Parameter::bytes(1, vec![0u8; MAX_VALUE_LEN]).unwrap());
        assert!(msg.encoded_len() > MAX_BODY_LEN);

        let mut buf = Vec::new();
        assert!(matches!(
            write_message(&mut buf, &msg),
            Err(BodyTooLong { .. })
        ));
        assert!(
            buf.is_empty(),
            "a rejected message must not write a partial frame"
        );

        // And the ordinary case still writes.
        assert!(write_message(&mut buf, &Goaway::new(VarInt::ZERO)).is_ok());
        assert!(!buf.is_empty());
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
