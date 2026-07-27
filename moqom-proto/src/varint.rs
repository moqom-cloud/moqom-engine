//! QUIC variable-length integers, per RFC 9000 §16.
//!
//! The two most significant bits of the first byte select the encoded length;
//! the remaining 62 bits carry the value.
//!
//! | Prefix | Length | Value range         |
//! |--------|--------|---------------------|
//! | `00`   | 1      | 0 .. 63             |
//! | `01`   | 2      | 0 .. 16383          |
//! | `10`   | 4      | 0 .. 1073741823     |
//! | `11`   | 8      | 0 .. 2^62 - 1       |
//!
//! MOQT inherits this encoding wholesale, so nearly every field in every
//! control message bottoms out here.

use bytes::{Buf, BufMut};

use crate::error::{BoundsExceeded, DecodeError};

/// Largest representable value: `2^62 - 1`.
pub const MAX: u64 = (1 << 62) - 1;

/// A QUIC variable-length integer.
///
/// The inner value is guaranteed to be within [`MAX`], so encoding is
/// infallible. Construction is the only place the bound is checked.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct VarInt(u64);

impl VarInt {
    /// Zero.
    pub const ZERO: Self = Self(0);

    /// The largest representable value.
    pub const MAX: Self = Self(MAX);

    /// Construct from a `u64`, checking the 62-bit bound.
    ///
    /// # Errors
    /// Returns [`BoundsExceeded`] if `value` exceeds [`MAX`].
    pub const fn new(value: u64) -> Result<Self, BoundsExceeded> {
        if value > MAX {
            Err(BoundsExceeded)
        } else {
            Ok(Self(value))
        }
    }

    /// Construct from a `u32`, which always fits.
    #[must_use]
    pub const fn from_u32(value: u32) -> Self {
        Self(value as u64)
    }

    /// The underlying value.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }

    /// Encoded length in bytes: 1, 2, 4, or 8.
    #[must_use]
    pub const fn size(self) -> usize {
        match self.0 {
            0..=63 => 1,
            64..=16_383 => 2,
            16_384..=1_073_741_823 => 4,
            _ => 8,
        }
    }

    /// Append the minimal encoding of this value to `buf`.
    ///
    /// # Panics
    /// Panics if `buf` cannot accommodate [`Self::size`] more bytes.
    pub fn encode<B: BufMut>(self, buf: &mut B) {
        match self.size() {
            1 => buf.put_u8(self.0 as u8),
            2 => buf.put_u16(self.0 as u16 | (0b01 << 14)),
            4 => buf.put_u32(self.0 as u32 | (0b10 << 30)),
            _ => buf.put_u64(self.0 | (0b11 << 62)),
        }
    }

    /// Read one variable-length integer from `buf`.
    ///
    /// On [`DecodeError::Short`] the buffer is left **unconsumed**, so a caller
    /// accumulating bytes from a stream can simply retry once more have
    /// arrived. This guarantee is specific to `VarInt` and deliberately cheap
    /// to provide: the length is known from the first byte, so the read can be
    /// checked before anything is taken.
    ///
    /// Non-minimal encodings are accepted, as RFC 9000 §16 requires. A value of
    /// 37 may legitimately arrive as one, two, four, or eight bytes, which is
    /// why [`Self::encode`] followed by [`Self::decode`] round-trips but the
    /// reverse does not preserve bytes.
    ///
    /// # Errors
    /// Returns [`DecodeError::Short`] if fewer than the indicated number of
    /// bytes are available.
    pub fn decode<B: Buf>(buf: &mut B) -> Result<Self, DecodeError> {
        // `Buf::chunk` returns an empty slice only at end of buffer, so this
        // also covers the zero-remaining case.
        let Some(&first) = buf.chunk().first() else {
            return Err(DecodeError::Short { needed: 1 });
        };

        let len = 1usize << (first >> 6);
        let remaining = buf.remaining();
        if remaining < len {
            return Err(DecodeError::Short {
                needed: len - remaining,
            });
        }

        let value = match len {
            1 => u64::from(buf.get_u8() & 0x3f),
            2 => u64::from(buf.get_u16() & 0x3fff),
            4 => u64::from(buf.get_u32() & 0x3fff_ffff),
            _ => buf.get_u64() & 0x3fff_ffff_ffff_ffff,
        };

        Ok(Self(value))
    }
}

impl From<u8> for VarInt {
    fn from(v: u8) -> Self {
        Self(u64::from(v))
    }
}

impl From<u16> for VarInt {
    fn from(v: u16) -> Self {
        Self(u64::from(v))
    }
}

impl From<u32> for VarInt {
    fn from(v: u32) -> Self {
        Self(u64::from(v))
    }
}

impl TryFrom<u64> for VarInt {
    type Error = BoundsExceeded;

    fn try_from(v: u64) -> Result<Self, Self::Error> {
        Self::new(v)
    }
}

impl From<VarInt> for u64 {
    fn from(v: VarInt) -> Self {
        v.0
    }
}

impl std::fmt::Display for VarInt {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn encoded(value: u64) -> Vec<u8> {
        let mut buf = Vec::new();
        VarInt::new(value).unwrap().encode(&mut buf);
        buf
    }

    fn decoded(mut bytes: &[u8]) -> Result<VarInt, DecodeError> {
        VarInt::decode(&mut bytes)
    }

    /// Test vectors from RFC 9000 Appendix A.1.
    #[test]
    fn rfc9000_vectors() {
        let cases: &[(&[u8], u64)] = &[
            (
                &[0xc2, 0x19, 0x7c, 0x5e, 0xff, 0x14, 0xe8, 0x8c],
                151_288_809_941_952_652,
            ),
            (&[0x9d, 0x7f, 0x3e, 0x7d], 494_878_333),
            (&[0x7b, 0xbd], 15_293),
            (&[0x25], 37),
        ];

        for (bytes, value) in cases {
            assert_eq!(decoded(bytes).unwrap().get(), *value, "decoding {bytes:x?}");
            assert_eq!(encoded(*value), *bytes, "encoding {value}");
        }
    }

    /// RFC 9000 §16: "the encoding is not required to use the minimum number of
    /// bytes". 37 as a two-byte varint must decode, even though we never emit
    /// it that way.
    #[test]
    fn accepts_non_minimal_encoding() {
        assert_eq!(decoded(&[0x40, 0x25]).unwrap().get(), 37);
        assert_eq!(decoded(&[0x80, 0x00, 0x00, 0x25]).unwrap().get(), 37);
        assert_eq!(encoded(37), vec![0x25]);
    }

    #[test]
    fn boundaries_pick_the_expected_width() {
        for (value, width) in [
            (0u64, 1usize),
            (63, 1),
            (64, 2),
            (16_383, 2),
            (16_384, 4),
            (1_073_741_823, 4),
            (1_073_741_824, 8),
            (MAX, 8),
        ] {
            let v = VarInt::new(value).unwrap();
            assert_eq!(v.size(), width, "size of {value}");
            assert_eq!(encoded(value).len(), width, "encoded width of {value}");
        }
    }

    #[test]
    fn rejects_out_of_range() {
        assert!(VarInt::new(MAX).is_ok());
        assert!(VarInt::new(MAX + 1).is_err());
        assert!(VarInt::new(u64::MAX).is_err());
    }

    /// A short buffer must report how much more is needed and must not consume
    /// anything, so the caller can retry against the same accumulator.
    #[test]
    fn short_read_reports_need_and_consumes_nothing() {
        for (bytes, needed) in [
            (&[] as &[u8], 1usize),
            (&[0x40], 1),
            (&[0x80, 0x00], 2),
            (&[0xc0, 0x00, 0x00, 0x00], 4),
        ] {
            let mut cursor = bytes;
            let err = VarInt::decode(&mut cursor).unwrap_err();
            assert_eq!(err, DecodeError::Short { needed }, "input {bytes:x?}");
            assert!(!err.is_fatal());
            assert_eq!(cursor.len(), bytes.len(), "input {bytes:x?} was consumed");
        }
    }

    #[test]
    fn decode_consumes_exactly_one_value() {
        let mut cursor: &[u8] = &[0x25, 0x7b, 0xbd, 0x01];
        assert_eq!(VarInt::decode(&mut cursor).unwrap().get(), 37);
        assert_eq!(VarInt::decode(&mut cursor).unwrap().get(), 15_293);
        assert_eq!(VarInt::decode(&mut cursor).unwrap().get(), 1);
        assert!(cursor.is_empty());
    }

    mod properties {
        use proptest::prelude::*;

        use super::*;

        proptest! {
            /// The direction that must always hold. The reverse does not,
            /// because of non-minimal encodings.
            #[test]
            fn encode_then_decode_is_identity(value in 0u64..=MAX) {
                let bytes = encoded(value);
                prop_assert_eq!(bytes.len(), VarInt::new(value).unwrap().size());
                prop_assert_eq!(decoded(&bytes).unwrap().get(), value);
            }

            /// Decoding never panics and never over-reads, whatever the input.
            #[test]
            fn decode_is_total(bytes in prop::collection::vec(any::<u8>(), 0..32)) {
                let mut cursor = bytes.as_slice();
                let before = cursor.len();
                match VarInt::decode(&mut cursor) {
                    Ok(v) => {
                        prop_assert_eq!(before - cursor.len(), 1usize << (bytes[0] >> 6));
                        prop_assert!(v.get() <= MAX);
                    }
                    Err(e) => {
                        prop_assert!(!e.is_fatal());
                        prop_assert_eq!(cursor.len(), before);
                    }
                }
            }

            /// A stream of values decodes back in order, which is the property
            /// message framing will actually depend on.
            #[test]
            fn sequences_round_trip(values in prop::collection::vec(0u64..=MAX, 0..64)) {
                let mut buf = Vec::new();
                for &v in &values {
                    VarInt::new(v).unwrap().encode(&mut buf);
                }
                let mut cursor = buf.as_slice();
                for &expected in &values {
                    prop_assert_eq!(VarInt::decode(&mut cursor).unwrap().get(), expected);
                }
                prop_assert!(cursor.is_empty());
            }
        }
    }
}
