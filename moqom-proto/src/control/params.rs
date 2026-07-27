//! Key-Value-Pair parameters, per draft-19 §1.4.3.
//!
//! Two properties of this encoding are easy to get wrong and produce a codec
//! that interoperates with itself and nothing else:
//!
//! 1. **Types are delta-encoded.** The wire carries `Type - previous_type`,
//!    starting from zero. Types are therefore non-decreasing within a sequence,
//!    and a parameter's meaning depends on everything before it.
//! 2. **Parity selects the value format.** An even Type is followed by a bare
//!    varint. An odd Type is followed by a length and that many bytes. There is
//!    no discriminator on the wire — the type number *is* the discriminator.

use bytes::{Buf, BufMut, Bytes};

use crate::coding::{decode_bytes, encode_bytes, encoded_bytes_len};
use crate::error::DecodeError;
use crate::varint::VarInt;

/// Largest permitted byte value: `2^16 - 1`.
pub const MAX_VALUE_LEN: usize = (1 << 16) - 1;

/// A parameter could not be constructed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ParamError {
    /// A varint value was given an odd type, or bytes were given an even type.
    #[error("type {type_value} is {actual}, which requires a {required} value")]
    ParityMismatch {
        /// The offending type number.
        type_value: u64,
        /// "even" or "odd".
        actual: &'static str,
        /// The value kind that parity demands.
        required: &'static str,
    },
    /// A byte value exceeded [`MAX_VALUE_LEN`].
    #[error("value is {len} bytes, exceeding the {MAX_VALUE_LEN} byte maximum")]
    ValueTooLong {
        /// Actual length.
        len: usize,
    },
    /// A type exceeded the varint maximum.
    ///
    /// Types are only ever written as deltas, so nothing caps them at the
    /// varint bound directly. But the first type in a sequence is a delta from
    /// zero, so a constructed type above [`crate::varint::MAX`] could not be
    /// encoded if it landed first. Rejecting it here is what keeps every
    /// [`Parameters`] built through this API encodable — see the invariant
    /// documented on that type.
    #[error("type {type_value} exceeds the varint maximum")]
    TypeTooLarge {
        /// The offending type.
        type_value: u64,
    },
}

/// A parameter value. Which variant is legal is fixed by the type's parity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParamValue {
    /// A varint, carried by even-numbered types.
    VarInt(VarInt),
    /// A length-prefixed byte string, carried by odd-numbered types.
    Bytes(Bytes),
}

/// A single key-value parameter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Parameter {
    type_value: u64,
    value: ParamValue,
}

impl Parameter {
    /// Build a varint parameter.
    ///
    /// # Errors
    /// [`ParamError::ParityMismatch`] if `type_value` is odd.
    pub fn varint(type_value: u64, value: VarInt) -> Result<Self, ParamError> {
        if !type_value.is_multiple_of(2) {
            return Err(ParamError::ParityMismatch {
                type_value,
                actual: "odd",
                required: "byte",
            });
        }
        Self::check_type(type_value)?;
        Ok(Self {
            type_value,
            value: ParamValue::VarInt(value),
        })
    }

    /// Build a byte-string parameter.
    ///
    /// # Errors
    /// [`ParamError::ParityMismatch`] if `type_value` is even, or
    /// [`ParamError::ValueTooLong`] beyond [`MAX_VALUE_LEN`].
    pub fn bytes(type_value: u64, value: impl Into<Bytes>) -> Result<Self, ParamError> {
        if type_value.is_multiple_of(2) {
            return Err(ParamError::ParityMismatch {
                type_value,
                actual: "even",
                required: "varint",
            });
        }
        Self::check_type(type_value)?;
        let value = value.into();
        if value.len() > MAX_VALUE_LEN {
            return Err(ParamError::ValueTooLong { len: value.len() });
        }
        Ok(Self {
            type_value,
            value: ParamValue::Bytes(value),
        })
    }

    fn check_type(type_value: u64) -> Result<(), ParamError> {
        if type_value > crate::varint::MAX {
            return Err(ParamError::TypeTooLarge { type_value });
        }
        Ok(())
    }

    /// The parameter type.
    #[must_use]
    pub const fn type_value(&self) -> u64 {
        self.type_value
    }

    /// The parameter value.
    #[must_use]
    pub const fn value(&self) -> &ParamValue {
        &self.value
    }

    /// The value as a varint, if this is a varint parameter.
    #[must_use]
    pub const fn as_varint(&self) -> Option<VarInt> {
        match self.value {
            ParamValue::VarInt(v) => Some(v),
            ParamValue::Bytes(_) => None,
        }
    }

    /// The value as bytes, if this is a byte parameter.
    #[must_use]
    pub const fn as_bytes(&self) -> Option<&Bytes> {
        match &self.value {
            ParamValue::Bytes(b) => Some(b),
            ParamValue::VarInt(_) => None,
        }
    }

    /// The delta this parameter encodes as, given its predecessor's type.
    ///
    /// Both the sizing and the writing path go through here so they cannot
    /// disagree. They previously did: one returned a guess of 8 for an
    /// unrepresentable delta while the other panicked, which would have written
    /// a frame whose declared length did not match its contents.
    ///
    /// # Panics
    /// If the [`Parameters`] ordering invariant is broken, or if the delta
    /// exceeds varint range. Neither is reachable through the public API; see
    /// the invariant on [`Parameters`].
    fn delta_from(&self, previous_type: u64) -> VarInt {
        let delta = self
            .type_value
            .checked_sub(previous_type)
            .expect("parameters are held in ascending type order");
        VarInt::new(delta).expect("parameter type deltas are varint-representable")
    }

    fn encoded_len_after(&self, previous_type: u64) -> usize {
        self.delta_from(previous_type).size()
            + match &self.value {
                ParamValue::VarInt(v) => v.size(),
                ParamValue::Bytes(b) => encoded_bytes_len(b.as_ref()),
            }
    }

    fn encode_after<B: BufMut>(&self, buf: &mut B, previous_type: u64) {
        self.delta_from(previous_type).encode(buf);
        match &self.value {
            ParamValue::VarInt(v) => v.encode(buf),
            ParamValue::Bytes(b) => encode_bytes(buf, b.as_ref()),
        }
    }

    fn decode_after<B: Buf>(buf: &mut B, previous_type: u64) -> Result<Self, DecodeError> {
        let delta = VarInt::decode(buf)?.get();
        let type_value = previous_type
            .checked_add(delta)
            .ok_or(DecodeError::Invalid(
                "parameter type delta overflows 64 bits",
            ))?;

        // Deliberately stricter than draft-19, which permits types up to
        // 2^64-1 by accumulating deltas. We cap them at the varint maximum.
        //
        // A type above 2^62 is encodable only in the position it arrived in:
        // insert a smaller type ahead of one and the resulting delta no longer
        // fits a varint. That is a live hazard for relays, which decode
        // parameters they do not understand, add their own, and forward. The
        // alternatives were a fallible API on every insertion, or a panic
        // reachable from hostile input. A clean protocol error at a threshold
        // no registered code point comes within 2^62 of is the better trade.
        if type_value > crate::varint::MAX {
            return Err(DecodeError::Invalid(
                "parameter type exceeds the varint maximum",
            ));
        }

        let value = if type_value.is_multiple_of(2) {
            ParamValue::VarInt(VarInt::decode(buf)?)
        } else {
            ParamValue::Bytes(Bytes::from(decode_bytes(buf, MAX_VALUE_LEN)?))
        };

        Ok(Self { type_value, value })
    }
}

/// An ordered sequence of parameters.
///
/// # Invariant
///
/// Held sorted by type, with every type at most [`crate::varint::MAX`]. Those
/// two facts together are what make encoding infallible: sorting means no delta
/// is negative, and the bound means no delta is too large to write, including
/// the first one, which is measured from zero.
///
/// Both are enforced at the only two entry points. The constructors on
/// [`Parameter`] reject an out-of-range type, and every insertion here places
/// the parameter in sorted position. The vector is private, so there is no
/// third way in.
///
/// Decoding upholds it too: types are read as unsigned deltas so they can only
/// ascend, and the decoder rejects any that accumulate past the bound. That
/// last check is a deliberate tightening of the draft, explained where it is
/// applied, and it is what lets a relay decode parameters it does not
/// understand, insert its own, and re-encode without a fallible path.
///
/// Order carries no meaning in MOQT, so sorting loses nothing; the sort is
/// stable, which preserves the relative order of repeated types.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Parameters(Vec<Parameter>);

impl Parameters {
    /// An empty parameter list.
    #[must_use]
    pub const fn new() -> Self {
        Self(Vec::new())
    }

    /// Build from a list, sorting into encodable order.
    #[must_use]
    pub fn from_vec(mut params: Vec<Parameter>) -> Self {
        params.sort_by_key(Parameter::type_value);
        Self(params)
    }

    /// Add a parameter, keeping the list sorted.
    pub fn push(&mut self, param: Parameter) {
        let at = self.0.partition_point(|p| p.type_value <= param.type_value);
        self.0.insert(at, param);
    }

    /// The parameters, in ascending type order.
    #[must_use]
    pub fn as_slice(&self) -> &[Parameter] {
        &self.0
    }

    /// Number of parameters.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether the list is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// The first parameter with the given type.
    #[must_use]
    pub fn get(&self, type_value: u64) -> Option<&Parameter> {
        self.0.iter().find(|p| p.type_value == type_value)
    }

    /// Whether any type appears more than once.
    ///
    /// Most parameters are defined as at-most-once, but not all, so this is
    /// offered as a check for message decoders to apply rather than enforced
    /// here.
    #[must_use]
    pub fn has_duplicates(&self) -> bool {
        self.0
            .windows(2)
            .any(|w| w[0].type_value == w[1].type_value)
    }

    /// Total encoded size in bytes.
    #[must_use]
    pub fn encoded_len(&self) -> usize {
        let mut previous = 0u64;
        let mut total = 0;
        for param in &self.0 {
            total += param.encoded_len_after(previous);
            previous = param.type_value;
        }
        total
    }

    /// Append the encoded sequence to `buf`.
    ///
    /// Emits no length prefix. Every use site in draft-19 already bounds the
    /// sequence by some enclosing length, and adding a second one here would
    /// put an extra field on the wire.
    pub fn encode<B: BufMut>(&self, buf: &mut B) {
        let mut previous = 0u64;
        for param in &self.0 {
            param.encode_after(buf, previous);
            previous = param.type_value;
        }
    }

    /// Total encoded size including the leading count.
    #[must_use]
    pub fn encoded_len_counted(&self) -> usize {
        VarInt::new(self.0.len() as u64).map_or(8, VarInt::size) + self.encoded_len()
    }

    /// Append the sequence prefixed by a parameter count.
    ///
    /// This is the form used by request and response messages, where a byte
    /// length would not do: several of them place Track Properties immediately
    /// after the parameters, and only a count says where one ends and the other
    /// begins. SETUP uses [`Self::encode`] instead, since its options run to the
    /// end of the message.
    ///
    /// # Panics
    /// Cannot panic: a parameter count is bounded by the 64 KiB message limit.
    pub fn encode_counted<B: BufMut>(&self, buf: &mut B) {
        VarInt::new(self.0.len() as u64)
            .expect("parameter count within varint range")
            .encode(buf);
        self.encode(buf);
    }

    /// Decode a count-prefixed sequence.
    ///
    /// A count the buffer cannot possibly satisfy is reported as
    /// [`DecodeError::Short`], not as malformed, because this decoder cannot
    /// tell a truncated read from a lying peer. The caller can: a body handed
    /// over by the frame layer is complete, so it converts with
    /// [`DecodeError::in_complete_message`]. Either way no allocation happens
    /// until the count is known to be satisfiable.
    ///
    /// # Errors
    /// - [`DecodeError::Short`] if incomplete.
    /// - [`DecodeError::Invalid`] if a parameter is malformed.
    pub fn decode_counted<B: Buf>(buf: &mut B) -> Result<Self, DecodeError> {
        let count = VarInt::decode(buf)?.get();

        // The smallest parameter is two bytes: a one-byte delta plus either a
        // one-byte varint or a one-byte zero length. Checking that before
        // reserving keeps a two-byte header from requesting a huge allocation.
        let minimum_bytes = count.saturating_mul(2);
        if minimum_bytes > buf.remaining() as u64 {
            return Err(DecodeError::Short {
                needed: usize::try_from(minimum_bytes - buf.remaining() as u64)
                    .unwrap_or(usize::MAX),
            });
        }
        let count =
            usize::try_from(count).map_err(|_| DecodeError::Invalid("count exceeds usize"))?;

        let mut params = Vec::with_capacity(count);
        let mut previous = 0u64;
        for _ in 0..count {
            let param = Parameter::decode_after(buf, previous)?;
            previous = param.type_value;
            params.push(param);
        }

        Ok(Self(params))
    }

    /// Decode exactly `byte_len` bytes worth of parameters.
    ///
    /// The length is required rather than inferred: the sequence has no
    /// terminator and no count, so only the enclosing message knows where it
    /// ends.
    ///
    /// # Errors
    /// - [`DecodeError::Short`] if fewer than `byte_len` bytes are available.
    /// - [`DecodeError::Invalid`] if a parameter straddles the end of the
    ///   region, if a type delta overflows, or if a value is oversized.
    pub fn decode<B: Buf>(buf: &mut B, byte_len: usize) -> Result<Self, DecodeError> {
        if buf.remaining() < byte_len {
            return Err(DecodeError::Short {
                needed: byte_len - buf.remaining(),
            });
        }

        let start = buf.remaining();
        let mut params = Vec::new();
        let mut previous = 0u64;

        while start - buf.remaining() < byte_len {
            let param = Parameter::decode_after(buf, previous)?;
            previous = param.type_value;
            params.push(param);
        }

        // A parameter that reads past the region did not belong to it. The
        // bytes it consumed came from whatever follows, so the message is
        // malformed rather than merely truncated.
        if start - buf.remaining() != byte_len {
            return Err(DecodeError::Invalid(
                "parameter overruns its enclosing length",
            ));
        }

        Ok(Self(params))
    }
}

impl FromIterator<Parameter> for Parameters {
    fn from_iter<I: IntoIterator<Item = Parameter>>(iter: I) -> Self {
        Self::from_vec(iter.into_iter().collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn round_trip(params: &Parameters) {
        let mut buf = Vec::new();
        params.encode(&mut buf);
        assert_eq!(
            buf.len(),
            params.encoded_len(),
            "encoded_len disagrees with encode"
        );

        let mut cursor = buf.as_slice();
        let decoded = Parameters::decode(&mut cursor, buf.len()).unwrap();
        assert_eq!(&decoded, params);
        assert!(cursor.is_empty());
    }

    #[test]
    fn empty_encodes_to_nothing() {
        let params = Parameters::new();
        assert_eq!(params.encoded_len(), 0);
        round_trip(&params);
    }

    #[test]
    fn varint_and_byte_parameters_round_trip() {
        let params = Parameters::from_vec(vec![
            Parameter::varint(0, VarInt::new(42).unwrap()).unwrap(),
            Parameter::bytes(1, &b"hello"[..]).unwrap(),
            Parameter::varint(100, VarInt::new(1_000_000).unwrap()).unwrap(),
            Parameter::bytes(1001, &b""[..]).unwrap(),
        ]);
        round_trip(&params);
    }

    /// The saving that motivates delta encoding: a run of nearby high-numbered
    /// types costs one byte each instead of the four an absolute type would.
    #[test]
    fn deltas_are_written_not_absolute_types() {
        let params = Parameters::from_vec(vec![
            Parameter::varint(1000, VarInt::ZERO).unwrap(),
            Parameter::varint(1002, VarInt::ZERO).unwrap(),
            Parameter::varint(1004, VarInt::ZERO).unwrap(),
        ]);
        let mut buf = Vec::new();
        params.encode(&mut buf);

        // 1000 needs two bytes; the deltas of 2 need one each.
        assert_eq!(buf.len(), (2 + 1) + (1 + 1) + (1 + 1));
        assert_eq!(buf[2 + 1], 2, "second type is written as a delta of 2");
        round_trip(&params);
    }

    #[test]
    fn unsorted_input_is_ordered_so_deltas_stay_representable() {
        let params = Parameters::from_vec(vec![
            Parameter::varint(50, VarInt::ZERO).unwrap(),
            Parameter::varint(10, VarInt::ZERO).unwrap(),
            Parameter::varint(30, VarInt::ZERO).unwrap(),
        ]);
        let types: Vec<_> = params
            .as_slice()
            .iter()
            .map(Parameter::type_value)
            .collect();
        assert_eq!(types, vec![10, 30, 50]);
        round_trip(&params);
    }

    #[test]
    fn push_maintains_order() {
        let mut params = Parameters::new();
        params.push(Parameter::varint(20, VarInt::ZERO).unwrap());
        params.push(Parameter::varint(4, VarInt::ZERO).unwrap());
        params.push(Parameter::varint(12, VarInt::ZERO).unwrap());

        let types: Vec<_> = params
            .as_slice()
            .iter()
            .map(Parameter::type_value)
            .collect();
        assert_eq!(types, vec![4, 12, 20]);
        round_trip(&params);
    }

    /// Parity is the only signal for how to read a value, so a mismatch would
    /// silently desynchronise the whole rest of the sequence.
    #[test]
    fn parity_mismatches_are_rejected_at_construction() {
        assert!(matches!(
            Parameter::varint(1, VarInt::ZERO),
            Err(ParamError::ParityMismatch { type_value: 1, .. })
        ));
        assert!(matches!(
            Parameter::bytes(2, &b"x"[..]),
            Err(ParamError::ParityMismatch { type_value: 2, .. })
        ));
    }

    /// Types above the varint bound are only encodable in the position they
    /// arrived in, so they are refused at both entry points rather than
    /// allowed in and panicked on later.
    #[test]
    fn types_above_the_varint_bound_are_refused() {
        let max = crate::varint::MAX; // odd, so it takes a byte value
        assert!(Parameter::bytes(max, &b"x"[..]).is_ok());
        assert!(matches!(
            Parameter::varint(max + 1, VarInt::ZERO),
            Err(ParamError::TypeTooLarge { .. })
        ));

        // On the wire the same limit is reached by accumulating deltas, since
        // no single delta can express it.
        let mut buf = Vec::new();
        VarInt::MAX.encode(&mut buf);
        encode_bytes(&mut buf, b"x");
        VarInt::new(1).unwrap().encode(&mut buf); // pushes the type past MAX
        VarInt::ZERO.encode(&mut buf);

        let mut cursor = buf.as_slice();
        let err = Parameters::decode(&mut cursor, buf.len()).unwrap_err();
        assert!(err.is_fatal());
    }

    /// A relay decodes parameters it does not understand, adds its own, and
    /// forwards. That used to be able to panic when a hostile peer sent a type
    /// near the top of the range.
    #[test]
    fn inserting_into_a_decoded_set_cannot_panic() {
        let hostile = Parameters::from_vec(vec![
            Parameter::bytes(crate::varint::MAX, &b"far"[..]).unwrap(),
        ]);
        let mut buf = Vec::new();
        hostile.encode(&mut buf);

        let mut cursor = buf.as_slice();
        let mut decoded = Parameters::decode(&mut cursor, buf.len()).unwrap();
        decoded.push(Parameter::varint(0, VarInt::ZERO).unwrap());

        round_trip(&decoded);
    }

    #[test]
    fn oversized_values_are_rejected() {
        let too_long = vec![0u8; MAX_VALUE_LEN + 1];
        assert!(matches!(
            Parameter::bytes(1, too_long),
            Err(ParamError::ValueTooLong { len }) if len == MAX_VALUE_LEN + 1
        ));
        assert!(Parameter::bytes(1, vec![0u8; MAX_VALUE_LEN]).is_ok());
    }

    #[test]
    fn max_length_value_round_trips() {
        let params = Parameters::from_vec(vec![
            Parameter::bytes(1, vec![0xAB; MAX_VALUE_LEN]).unwrap(),
        ]);
        round_trip(&params);
    }

    /// A type is only reachable by accumulating deltas, and each delta is
    /// capped at the varint maximum of `2^62 - 1`, so it takes five of them to
    /// push a type past `u64::MAX`.
    #[test]
    fn a_delta_that_overflows_64_bits_is_invalid() {
        let mut buf = Vec::new();
        let mut type_value = 0u64;

        for _ in 0..4 {
            VarInt::MAX.encode(&mut buf);
            type_value += crate::varint::MAX;
            if type_value.is_multiple_of(2) {
                VarInt::ZERO.encode(&mut buf);
            } else {
                encode_bytes(&mut buf, &[]);
            }
        }
        VarInt::MAX.encode(&mut buf);

        let mut cursor = buf.as_slice();
        let err = Parameters::decode(&mut cursor, buf.len()).unwrap_err();
        assert!(
            err.is_fatal(),
            "overflow is a protocol violation, not truncation"
        );
    }

    #[test]
    fn truncation_is_short_not_invalid() {
        let params = Parameters::from_vec(vec![Parameter::bytes(1, &b"abcdef"[..]).unwrap()]);
        let mut buf = Vec::new();
        params.encode(&mut buf);

        for cut in 1..buf.len() {
            let mut cursor = &buf[..cut];
            let err = Parameters::decode(&mut cursor, buf.len()).unwrap_err();
            assert!(!err.is_fatal(), "cut at {cut} should be recoverable");
        }
    }

    /// A parameter reading past its region has consumed bytes belonging to the
    /// next field, which is corruption rather than a short read.
    #[test]
    fn a_parameter_overrunning_its_region_is_invalid() {
        let params = Parameters::from_vec(vec![Parameter::bytes(1, &b"abcdef"[..]).unwrap()]);
        let mut buf = Vec::new();
        params.encode(&mut buf);
        buf.extend_from_slice(b"trailing bytes");

        let mut cursor = buf.as_slice();
        let err = Parameters::decode(&mut cursor, 3).unwrap_err();
        assert!(err.is_fatal());
    }

    #[test]
    fn decode_stops_at_the_region_boundary() {
        let params =
            Parameters::from_vec(vec![Parameter::varint(0, VarInt::new(7).unwrap()).unwrap()]);
        let mut buf = Vec::new();
        params.encode(&mut buf);
        let region = buf.len();
        buf.extend_from_slice(b"\xff\xff\xff\xff");

        let mut cursor = buf.as_slice();
        let decoded = Parameters::decode(&mut cursor, region).unwrap();
        assert_eq!(decoded, params);
        assert_eq!(cursor.len(), 4, "trailing bytes are left for the caller");
    }

    #[test]
    fn accessors_respect_parity() {
        let v = Parameter::varint(0, VarInt::new(9).unwrap()).unwrap();
        assert_eq!(v.as_varint().unwrap().get(), 9);
        assert!(v.as_bytes().is_none());

        let b = Parameter::bytes(1, &b"xy"[..]).unwrap();
        assert_eq!(b.as_bytes().unwrap().as_ref(), b"xy");
        assert!(b.as_varint().is_none());
    }

    #[test]
    fn duplicate_detection_finds_repeated_types() {
        let params = Parameters::from_vec(vec![
            Parameter::varint(2, VarInt::ZERO).unwrap(),
            Parameter::varint(2, VarInt::new(1).unwrap()).unwrap(),
        ]);
        assert!(params.has_duplicates());
        round_trip(&params); // a repeat is a delta of zero, which is legal

        let unique = Parameters::from_vec(vec![
            Parameter::varint(2, VarInt::ZERO).unwrap(),
            Parameter::varint(4, VarInt::ZERO).unwrap(),
        ]);
        assert!(!unique.has_duplicates());
    }

    fn round_trip_counted(params: &Parameters) {
        let mut buf = Vec::new();
        params.encode_counted(&mut buf);
        assert_eq!(buf.len(), params.encoded_len_counted());

        let mut cursor = buf.as_slice();
        assert_eq!(&Parameters::decode_counted(&mut cursor).unwrap(), params);
        assert!(cursor.is_empty());
    }

    #[test]
    fn counted_form_round_trips() {
        round_trip_counted(&Parameters::new());
        round_trip_counted(&Parameters::from_vec(vec![
            Parameter::varint(0, VarInt::new(5).unwrap()).unwrap(),
            Parameter::bytes(3, &b"token"[..]).unwrap(),
            Parameter::varint(400, VarInt::new(9).unwrap()).unwrap(),
        ]));
    }

    /// The count is what separates parameters from the Track Properties that
    /// follow them, so decoding must stop exactly on the boundary.
    #[test]
    fn counted_decode_leaves_trailing_fields_alone() {
        let params =
            Parameters::from_vec(vec![Parameter::varint(2, VarInt::new(1).unwrap()).unwrap()]);
        let mut buf = Vec::new();
        params.encode_counted(&mut buf);
        buf.extend_from_slice(b"properties");

        let mut cursor = buf.as_slice();
        assert_eq!(Parameters::decode_counted(&mut cursor).unwrap(), params);
        assert_eq!(cursor, b"properties");
    }

    /// A large count with no bytes behind it must not cause a large allocation.
    /// Reported as short here, because only the caller knows whether the body
    /// was complete; a complete body makes it fatal.
    #[test]
    fn an_impossible_count_is_rejected_before_allocating() {
        for count in [1_000_000u64, crate::varint::MAX] {
            let mut buf = Vec::new();
            VarInt::new(count).unwrap().encode(&mut buf);

            let mut cursor = buf.as_slice();
            let err = Parameters::decode_counted(&mut cursor).unwrap_err();
            assert!(
                matches!(err, DecodeError::Short { .. }),
                "count {count}: {err:?}"
            );
            assert!(err.in_complete_message().is_fatal());
        }
    }

    #[test]
    fn a_truncated_counted_sequence_is_short() {
        let params = Parameters::from_vec(vec![
            Parameter::bytes(1, &b"aaaa"[..]).unwrap(),
            Parameter::bytes(3, &b"bbbb"[..]).unwrap(),
        ]);
        let mut buf = Vec::new();
        params.encode_counted(&mut buf);
        buf.truncate(buf.len() - 2);

        let mut cursor = buf.as_slice();
        let err = Parameters::decode_counted(&mut cursor).unwrap_err();
        assert!(!err.is_fatal(), "truncation is recoverable, got {err:?}");
    }

    mod properties {
        use proptest::prelude::*;

        use super::*;

        /// Parameters built the way callers build them: arbitrary types across
        /// the full range, with the value shape forced to match parity.
        fn any_parameter() -> impl Strategy<Value = Parameter> {
            (
                0..=crate::varint::MAX,
                prop::collection::vec(any::<u8>(), 0..32),
            )
                .prop_map(|(type_value, bytes)| {
                    if type_value.is_multiple_of(2) {
                        let v = VarInt::new(u64::from(bytes.len() as u32)).unwrap();
                        Parameter::varint(type_value, v).unwrap()
                    } else {
                        Parameter::bytes(type_value, bytes).unwrap()
                    }
                })
        }

        fn any_parameters() -> impl Strategy<Value = Parameters> {
            prop::collection::vec(any_parameter(), 0..12).prop_map(Parameters::from_vec)
        }

        proptest! {
            /// `encoded_len` fills in the frame's length field while `encode`
            /// writes the bytes. If they can ever disagree, the frame declares
            /// a length that does not match its contents and the peer's control
            /// stream desynchronises — so this is the single most important
            /// property in the module.
            #[test]
            fn sizing_always_matches_writing(params in any_parameters()) {
                let mut buf = Vec::new();
                params.encode(&mut buf);
                prop_assert_eq!(buf.len(), params.encoded_len());

                let mut counted = Vec::new();
                params.encode_counted(&mut counted);
                prop_assert_eq!(counted.len(), params.encoded_len_counted());
            }

            #[test]
            fn round_trips_in_both_framings(params in any_parameters()) {
                let mut buf = Vec::new();
                params.encode(&mut buf);
                let mut cursor = buf.as_slice();
                prop_assert_eq!(Parameters::decode(&mut cursor, buf.len()).unwrap(), params.clone());

                let mut buf = Vec::new();
                params.encode_counted(&mut buf);
                let mut cursor = buf.as_slice();
                prop_assert_eq!(Parameters::decode_counted(&mut cursor).unwrap(), params);
            }

            /// Whatever a peer sends, decoding must either fail or produce a
            /// set that satisfies the invariant — otherwise re-encoding it,
            /// which every relay does, could panic.
            #[test]
            fn decoded_sets_are_always_re_encodable(bytes in prop::collection::vec(any::<u8>(), 0..256)) {
                let mut cursor = bytes.as_slice();
                if let Ok(params) = Parameters::decode(&mut cursor, bytes.len()) {
                    let types: Vec<u64> = params.as_slice().iter().map(Parameter::type_value).collect();
                    prop_assert!(types.windows(2).all(|w| w[0] <= w[1]), "not ascending");
                    prop_assert!(types.iter().all(|&t| t <= crate::varint::MAX), "type out of range");

                    let mut buf = Vec::new();
                    params.encode(&mut buf);
                    prop_assert_eq!(buf.len(), params.encoded_len());
                }
            }
        }
    }

    #[test]
    fn get_finds_by_type() {
        let params = Parameters::from_vec(vec![
            Parameter::varint(0, VarInt::new(1).unwrap()).unwrap(),
            Parameter::bytes(3, &b"v"[..]).unwrap(),
        ]);
        assert_eq!(params.get(3).unwrap().as_bytes().unwrap().as_ref(), b"v");
        assert!(params.get(5).is_none());
        assert_eq!(params.len(), 2);
        assert!(!params.is_empty());
    }
}
