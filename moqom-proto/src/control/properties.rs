//! Track Properties, per draft-19 §2.5.
//!
//! Properties are relay-visible metadata on a track or object. They need no
//! negotiation, which is what makes the mandatory range below matter: an
//! unnegotiated field that changes how a track must be handled can only be made
//! safe by refusing tracks that carry one you do not understand.
//!
//! Track Properties are always the last field of the message that carries them,
//! so their extent is whatever is left after every preceding field. Object
//! Properties, by contrast, carry an explicit length.

use bytes::{Buf, BufMut};

use crate::control::params::{Parameter, Parameters};
use crate::error::DecodeError;

/// Inclusive bounds of the Mandatory Track Property range.
pub const MANDATORY_RANGE: std::ops::RangeInclusive<u64> = 0x4000..=0x7FFF;

/// One-byte application-specific range, for tight space budgets.
pub const APP_RANGE_SMALL: std::ops::RangeInclusive<u64> = 0x78..=0x7F;

/// Two-byte application-specific range.
pub const APP_RANGE_LARGE: std::ops::RangeInclusive<u64> = 0x3800..=0x3FFF;

/// Whether a property type is a Mandatory Track Property.
///
/// Receiving one of these that you do not understand is not ignorable: the
/// track must be refused with `UNSUPPORTED_EXTENSION`, or cancelled if it has
/// already been accepted. This is the opposite of the default rule for unknown
/// properties, which is to forward and cache them untouched.
#[must_use]
pub const fn is_mandatory(type_value: u64) -> bool {
    type_value >= *MANDATORY_RANGE.start() && type_value <= *MANDATORY_RANGE.end()
}

/// Whether a property type is reserved for application use.
///
/// IANA will never allocate in these ranges, so two applications may use the
/// same code point for different things. A relay must forward them unchanged
/// and must not try to interpret them.
#[must_use]
pub const fn is_application_specific(type_value: u64) -> bool {
    (type_value >= *APP_RANGE_SMALL.start() && type_value <= *APP_RANGE_SMALL.end())
        || (type_value >= *APP_RANGE_LARGE.start() && type_value <= *APP_RANGE_LARGE.end())
}

/// A sequence of Track Properties.
///
/// Wraps [`Parameters`] rather than aliasing it because this is a third
/// independent numbering, alongside message parameters and Setup Options. The
/// encoding is shared; the meaning of any given number is not.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Properties(Parameters);

impl Properties {
    /// An empty property set.
    #[must_use]
    pub const fn new() -> Self {
        Self(Parameters::new())
    }

    /// Wrap an existing parameter list.
    #[must_use]
    pub const fn from_parameters(params: Parameters) -> Self {
        Self(params)
    }

    /// The underlying parameters.
    #[must_use]
    pub const fn as_parameters(&self) -> &Parameters {
        &self.0
    }

    /// Add a property.
    pub fn push(&mut self, property: Parameter) {
        self.0.push(property);
    }

    /// The property with the given type, if present.
    #[must_use]
    pub fn get(&self, type_value: u64) -> Option<&Parameter> {
        self.0.get(type_value)
    }

    /// Number of properties.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether the set is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Mandatory property types not accepted by `understood`.
    ///
    /// The caller supplies the predicate because what an endpoint understands
    /// depends on its build and configuration, not on the protocol. A non-empty
    /// result means the track must be refused or cancelled — see draft-19
    /// §2.5.1 for which applies to each message.
    pub fn unsupported_mandatory<F>(&self, understood: F) -> Vec<u64>
    where
        F: Fn(u64) -> bool,
    {
        self.0
            .as_slice()
            .iter()
            .map(Parameter::type_value)
            .filter(|&t| is_mandatory(t) && !understood(t))
            .collect()
    }

    /// Encoded size in bytes.
    #[must_use]
    pub fn encoded_len(&self) -> usize {
        self.0.encoded_len()
    }

    /// Append the properties to `buf`, with no length prefix.
    pub fn encode<B: BufMut>(&self, buf: &mut B) {
        self.0.encode(buf);
    }

    /// Decode properties occupying exactly `byte_len` bytes.
    ///
    /// # Errors
    /// Propagates [`DecodeError`] from the underlying sequence.
    pub fn decode<B: Buf>(buf: &mut B, byte_len: usize) -> Result<Self, DecodeError> {
        Ok(Self(Parameters::decode(buf, byte_len)?))
    }

    /// Encoded size including the length prefix Object Properties carry.
    #[must_use]
    pub fn encoded_len_prefixed(&self) -> usize {
        let body = self.encoded_len();
        crate::varint::VarInt::try_from(body as u64)
            .map_or(8, crate::varint::VarInt::size)
            .saturating_add(body)
    }

    /// Append the properties with the `vi64` length prefix, as Object
    /// Properties are framed on the data plane (draft-19 §11.2.1.2).
    ///
    /// # Panics
    /// If the encoded body exceeds the varint maximum, which cannot happen for
    /// a set built through the public API.
    pub fn encode_prefixed<B: BufMut>(&self, buf: &mut B) {
        let body = self.encoded_len();
        let len = crate::varint::VarInt::try_from(body as u64)
            .expect("property sets built through the API always fit a varint");
        len.encode(buf);
        self.encode(buf);
    }

    /// Decode length-prefixed Object Properties.
    ///
    /// The prefix is peer-supplied, so it is checked against what is actually
    /// buffered before being used as a length. Trusting it would let a peer
    /// name a region larger than the datagram it arrived in.
    ///
    /// # Errors
    /// [`DecodeError::Short`] if fewer bytes are buffered than the prefix
    /// claims, or [`DecodeError::Invalid`] if the prefix cannot be a length.
    pub fn decode_prefixed<B: Buf>(buf: &mut B) -> Result<Self, DecodeError> {
        let len = crate::varint::VarInt::decode(buf)?.get();
        let len = usize::try_from(len)
            .map_err(|_| DecodeError::Invalid("property length exceeds addressable memory"))?;
        if buf.remaining() < len {
            return Err(DecodeError::Short {
                needed: len - buf.remaining(),
            });
        }
        Self::decode(buf, len)
    }

    /// Decode properties filling the remainder of a message body.
    ///
    /// Track Properties are defined as "the remaining length of the message",
    /// so this is the form nearly every caller wants. It is correct only when
    /// `buf` holds exactly one message body, which the frame layer guarantees.
    ///
    /// # Errors
    /// Propagates [`DecodeError`] from the underlying sequence.
    pub fn decode_to_end<B: Buf>(buf: &mut B) -> Result<Self, DecodeError> {
        let remaining = buf.remaining();
        Self::decode(buf, remaining)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::varint::VarInt;

    #[test]
    fn mandatory_range_boundaries() {
        assert!(!is_mandatory(0x3FFF));
        assert!(is_mandatory(0x4000));
        assert!(is_mandatory(0x5ABC));
        assert!(is_mandatory(0x7FFF));
        assert!(!is_mandatory(0x8000));
    }

    #[test]
    fn application_ranges_are_recognised() {
        assert!(!is_application_specific(0x77));
        assert!(is_application_specific(0x78));
        assert!(is_application_specific(0x7F));
        assert!(!is_application_specific(0x80));

        assert!(!is_application_specific(0x37FF));
        assert!(is_application_specific(0x3800));
        assert!(is_application_specific(0x3FFF));
        assert!(!is_application_specific(0x4000));
    }

    /// The two ranges must not overlap, or a property would be both
    /// application-defined and mandatory, which has no coherent handling rule.
    #[test]
    fn application_and_mandatory_ranges_are_disjoint() {
        for t in [0x78u64, 0x7F, 0x3800, 0x3FFF] {
            assert!(!is_mandatory(t), "{t:#x}");
        }
        for t in [0x4000u64, 0x7FFF] {
            assert!(!is_application_specific(t), "{t:#x}");
        }
    }

    #[test]
    fn round_trips_to_end_of_body() {
        let mut props = Properties::new();
        props.push(Parameter::varint(0x10, VarInt::new(3).unwrap()).unwrap());
        props.push(Parameter::bytes(0x4001, &b"codec-config"[..]).unwrap());

        let mut buf = Vec::new();
        props.encode(&mut buf);
        assert_eq!(buf.len(), props.encoded_len());

        let mut cursor = buf.as_slice();
        assert_eq!(Properties::decode_to_end(&mut cursor).unwrap(), props);
        assert!(cursor.is_empty());
    }

    #[test]
    fn empty_properties_encode_to_nothing() {
        let props = Properties::new();
        assert_eq!(props.encoded_len(), 0);
        assert!(props.is_empty());

        let mut cursor = &[][..];
        assert_eq!(Properties::decode_to_end(&mut cursor).unwrap(), props);
    }

    /// Unknown mandatory properties are the whole point of the range, so the
    /// check has to find them while leaving ordinary unknowns alone.
    #[test]
    fn unsupported_mandatory_finds_only_unknown_mandatory_types() {
        let mut props = Properties::new();
        props.push(Parameter::varint(0x10, VarInt::ZERO).unwrap()); // ordinary
        props.push(Parameter::varint(0x4000, VarInt::ZERO).unwrap()); // known
        props.push(Parameter::varint(0x4002, VarInt::ZERO).unwrap()); // unknown
        props.push(Parameter::varint(0x9000, VarInt::ZERO).unwrap()); // ordinary

        let unsupported = props.unsupported_mandatory(|t| t == 0x4000);
        assert_eq!(unsupported, vec![0x4002]);

        assert!(props.unsupported_mandatory(|_| true).is_empty());
        assert_eq!(props.unsupported_mandatory(|_| false), vec![0x4000, 0x4002]);
    }

    #[test]
    fn accessors_work() {
        let mut props = Properties::new();
        props.push(Parameter::bytes(0x4001, &b"v"[..]).unwrap());
        assert_eq!(props.len(), 1);
        assert!(!props.is_empty());
        assert!(props.get(0x4001).is_some());
        assert!(props.get(0x4003).is_none());
        assert_eq!(props.as_parameters().len(), 1);
    }
}
