//! Encode and decode traits, and the streaming-decode contract.
//!
//! # The contract, and the trap in it
//!
//! [`VarInt::decode`] leaves the buffer untouched on a short read. **No other
//! decoder promises that**, and assuming otherwise is the easiest way to
//! corrupt a session. A length-prefixed field has already consumed its prefix
//! by the time it discovers the body is incomplete, and unwinding that would
//! mean either buffering or a peek API at every level.
//!
//! So the discipline is: a caller accumulating bytes off a stream keeps the
//! whole buffer, notes its position, and on [`DecodeError::Short`] restores
//! that position and waits for more. [`try_decode`] packages exactly that.

use bytes::{Buf, BufMut};

use crate::error::DecodeError;
use crate::varint::VarInt;

/// A value with a defined wire representation.
pub trait Encode {
    /// Append the wire representation to `buf`.
    fn encode<B: BufMut>(&self, buf: &mut B);

    /// Bytes [`Encode::encode`] will append.
    ///
    /// Used to fill in length prefixes without encoding twice, so an
    /// implementation that disagrees with `encode` produces a corrupt frame
    /// rather than a slow one. Keep them in lockstep.
    fn encoded_len(&self) -> usize;
}

/// A value that can be read from a wire representation.
pub trait Decode: Sized {
    /// Read one value from `buf`.
    ///
    /// On [`DecodeError::Short`] the buffer may have been partially consumed;
    /// see the module documentation.
    ///
    /// # Errors
    /// [`DecodeError::Short`] if incomplete, [`DecodeError::Invalid`] if
    /// malformed.
    fn decode<B: Buf>(buf: &mut B) -> Result<Self, DecodeError>;
}

/// Attempt a decode against a slice, restoring the cursor if incomplete.
///
/// Returns `Ok(None)` when more bytes are needed, having left `input`
/// unchanged, and advances `input` past the value on success.
///
/// # Errors
/// Propagates [`DecodeError::Invalid`], which is fatal to the session.
pub fn try_decode<T: Decode>(input: &mut &[u8]) -> Result<Option<T>, DecodeError> {
    let saved = *input;
    match T::decode(input) {
        Ok(value) => Ok(Some(value)),
        Err(DecodeError::Short { .. }) => {
            *input = saved;
            Ok(None)
        }
        Err(fatal) => Err(fatal),
    }
}

impl Encode for VarInt {
    fn encode<B: BufMut>(&self, buf: &mut B) {
        (*self).encode(buf);
    }

    fn encoded_len(&self) -> usize {
        self.size()
    }
}

impl Decode for VarInt {
    fn decode<B: Buf>(buf: &mut B) -> Result<Self, DecodeError> {
        Self::decode(buf)
    }
}

/// Read a varint-length-prefixed byte string.
///
/// `limit` caps the declared length. It is not optional and has no sensible
/// default: the length is peer-supplied, so an unbounded read is a
/// single-message memory exhaustion attack, which is precisely the class of bug
/// `draft-englishm-moq-relay-dos` catalogues.
///
/// # Errors
/// [`DecodeError::Short`] if incomplete; [`DecodeError::Invalid`] if the
/// declared length exceeds `limit`.
pub fn decode_bytes<B: Buf>(buf: &mut B, limit: usize) -> Result<Vec<u8>, DecodeError> {
    let len = VarInt::decode(buf)?.get();
    let len = usize::try_from(len).map_err(|_| DecodeError::Invalid("length exceeds usize"))?;

    if len > limit {
        return Err(DecodeError::Invalid("length exceeds configured limit"));
    }
    if buf.remaining() < len {
        return Err(DecodeError::Short {
            needed: len - buf.remaining(),
        });
    }

    let mut out = vec![0u8; len];
    buf.copy_to_slice(&mut out);
    Ok(out)
}

/// Write a varint-length-prefixed byte string.
///
/// # Panics
/// Panics if `bytes` is longer than [`crate::varint::MAX`], which no real
/// message can be.
pub fn encode_bytes<B: BufMut>(buf: &mut B, bytes: &[u8]) {
    let len = VarInt::new(bytes.len() as u64).expect("byte string length within varint range");
    len.encode(buf);
    buf.put_slice(bytes);
}

/// Encoded size of a varint-length-prefixed byte string.
///
/// # Panics
/// Panics if `bytes` is longer than [`crate::varint::MAX`] — an exabyte-scale
/// slice, so unreachable in practice.
#[must_use]
pub fn encoded_bytes_len(bytes: &[u8]) -> usize {
    let len = VarInt::new(bytes.len() as u64).expect("byte string length within varint range");
    len.size() + bytes.len()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn byte_strings_round_trip() {
        for case in [b"".as_slice(), b"a", b"moqom", &[0xff; 300]] {
            let mut buf = Vec::new();
            encode_bytes(&mut buf, case);
            assert_eq!(buf.len(), encoded_bytes_len(case));

            let mut cursor = buf.as_slice();
            assert_eq!(decode_bytes(&mut cursor, 1024).unwrap(), case);
            assert!(cursor.is_empty());
        }
    }

    #[test]
    fn declared_length_over_limit_is_fatal_not_short() {
        // A 4 GiB length prefix with no body. Treating this as a short read
        // would have the relay wait for bytes that will never come while
        // holding the declared allocation in mind; it must be fatal.
        let mut buf = Vec::new();
        VarInt::new(4 * 1024 * 1024 * 1024)
            .unwrap()
            .encode(&mut buf);

        let mut cursor = buf.as_slice();
        let err = decode_bytes(&mut cursor, 64 * 1024).unwrap_err();
        assert!(err.is_fatal());
    }

    #[test]
    fn truncated_body_is_short() {
        let mut buf = Vec::new();
        encode_bytes(&mut buf, b"moqom");
        buf.truncate(3);

        let mut cursor = buf.as_slice();
        let err = decode_bytes(&mut cursor, 1024).unwrap_err();
        assert_eq!(err, DecodeError::Short { needed: 3 });
    }

    /// The blanket impls forward to `VarInt`'s inherent methods, which is only
    /// correct because inherent resolution wins over trait resolution. Get that
    /// wrong and it is unbounded recursion rather than a compile error, so it
    /// is worth pinning down.
    #[test]
    fn varint_trait_impls_do_not_recurse() {
        let value = VarInt::from_u32(15_293);

        let mut buf = Vec::new();
        Encode::encode(&value, &mut buf);
        assert_eq!(buf, vec![0x7b, 0xbd]);
        assert_eq!(Encode::encoded_len(&value), 2);

        let mut cursor = buf.as_slice();
        assert_eq!(<VarInt as Decode>::decode(&mut cursor).unwrap(), value);
    }

    #[test]
    fn try_decode_rewinds_on_short_read() {
        let bytes: &[u8] = &[0x80, 0x00];
        let mut cursor = bytes;

        assert!(try_decode::<VarInt>(&mut cursor).unwrap().is_none());
        assert_eq!(cursor.len(), bytes.len());

        let complete: &[u8] = &[0x80, 0x00, 0x00, 0x25];
        let mut cursor = complete;
        let value = try_decode::<VarInt>(&mut cursor).unwrap().unwrap();
        assert_eq!(value.get(), 37);
        assert!(cursor.is_empty());
    }
}
