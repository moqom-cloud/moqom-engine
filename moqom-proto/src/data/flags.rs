//! The bit-packed type fields that open a datagram or a subgroup stream.
//!
//! Both the datagram type (draft-19 §11.3.1) and the subgroup header type
//! (§11.4.2) encode which optional fields follow into the type code itself.
//! Getting a bit wrong here does not produce a slightly wrong value; it makes
//! the decoder read the next field from the wrong offset and mis-frame
//! everything after it, on a stream that may carry thousands of objects.
//!
//! Both layouts reserve combinations that the draft calls protocol violations.
//! Those are rejected here on decode, and made unrepresentable in the types
//! that wrap these, so the encoder cannot emit one even by mistake.

use crate::error::DecodeError;

/// Where the Subgroup ID comes from, per the two-bit `SUBGROUP_ID_MODE` field.
///
/// The draft reserves mode `0b11`, so there is deliberately no variant for it:
/// the reserved encoding is rejected on decode and cannot be constructed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum SubgroupIdMode {
    /// `0b00`: the field is absent and the Subgroup ID is zero.
    #[default]
    Zero,
    /// `0b01`: the field is absent and the Subgroup ID is the Object ID of the
    /// first object on the stream.
    ///
    /// Which means the Subgroup ID is not known from the header alone. A reader
    /// has to carry it forward from the first object.
    FirstObjectId,
    /// `0b10`: the Subgroup ID is present in the header.
    Explicit,
}

impl SubgroupIdMode {
    const fn as_bits(self) -> u8 {
        match self {
            Self::Zero => 0b00,
            Self::FirstObjectId => 0b01,
            Self::Explicit => 0b10,
        }
    }

    const fn from_bits(bits: u8) -> Result<Self, DecodeError> {
        match bits {
            0b00 => Ok(Self::Zero),
            0b01 => Ok(Self::FirstObjectId),
            0b10 => Ok(Self::Explicit),
            _ => Err(DecodeError::Invalid("subgroup ID mode 0b11 is reserved")),
        }
    }
}

/// The type code of an `OBJECT_DATAGRAM`.
///
/// Valid codes have the form `0b00X0XXXX`, i.e. only the bits in [`Self::MASK`]
/// may be set.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct DatagramType(u8);

impl DatagramType {
    /// Object Properties follow the fixed fields.
    pub const PROPERTIES: u8 = 0x01;
    /// No object in this group has a larger Object ID.
    pub const END_OF_GROUP: u8 = 0x02;
    /// The Object ID field is omitted and the Object ID is zero.
    pub const ZERO_OBJECT_ID: u8 = 0x04;
    /// The Priority field is omitted; inherit it from the subscription.
    pub const DEFAULT_PRIORITY: u8 = 0x08;
    /// Carries an Object Status instead of a payload.
    pub const STATUS: u8 = 0x20;

    /// Every bit the layout defines. Any other bit set is malformed.
    pub const MASK: u8 = Self::PROPERTIES
        | Self::END_OF_GROUP
        | Self::ZERO_OBJECT_ID
        | Self::DEFAULT_PRIORITY
        | Self::STATUS;

    /// Build a type code from the fields that will be present.
    ///
    /// `status` and `end_of_group` are mutually exclusive — a status message
    /// cannot signal end of group — so this takes them as one argument rather
    /// than two booleans that could disagree.
    // The bools mirror the wire's flag bits one for one. A parameter struct
    // would just restate the header type that already calls this.
    #[allow(clippy::fn_params_excessive_bools)]
    #[must_use]
    pub const fn new(
        properties: bool,
        zero_object_id: bool,
        default_priority: bool,
        carries_status: bool,
        end_of_group: bool,
    ) -> Self {
        let mut bits = 0u8;
        if properties {
            bits |= Self::PROPERTIES;
        }
        if zero_object_id {
            bits |= Self::ZERO_OBJECT_ID;
        }
        if default_priority {
            bits |= Self::DEFAULT_PRIORITY;
        }
        if carries_status {
            bits |= Self::STATUS;
        } else if end_of_group {
            bits |= Self::END_OF_GROUP;
        }
        Self(bits)
    }

    /// The wire value.
    #[must_use]
    pub const fn as_u8(self) -> u8 {
        self.0
    }

    /// Whether Object Properties are present.
    #[must_use]
    pub const fn has_properties(self) -> bool {
        self.0 & Self::PROPERTIES != 0
    }

    /// Whether this object is the last in its group.
    #[must_use]
    pub const fn is_end_of_group(self) -> bool {
        self.0 & Self::END_OF_GROUP != 0
    }

    /// Whether the Object ID field is omitted.
    #[must_use]
    pub const fn has_zero_object_id(self) -> bool {
        self.0 & Self::ZERO_OBJECT_ID != 0
    }

    /// Whether the Priority field is omitted.
    #[must_use]
    pub const fn has_default_priority(self) -> bool {
        self.0 & Self::DEFAULT_PRIORITY != 0
    }

    /// Whether a status replaces the payload.
    #[must_use]
    pub const fn carries_status(self) -> bool {
        self.0 & Self::STATUS != 0
    }

    /// Validate a type code read off the wire.
    ///
    /// # Errors
    /// [`DecodeError::Invalid`] for a code outside the defined form, or for the
    /// `STATUS` and `END_OF_GROUP` combination the draft forbids.
    pub const fn from_u64(code: u64) -> Result<Self, DecodeError> {
        if code > Self::MASK as u64 || (code as u8) & !Self::MASK != 0 {
            return Err(DecodeError::Invalid(
                "datagram type is outside the form 0b00X0XXXX",
            ));
        }
        let bits = code as u8;
        if bits & Self::STATUS != 0 && bits & Self::END_OF_GROUP != 0 {
            return Err(DecodeError::Invalid(
                "datagram cannot be both a status and end of group",
            ));
        }
        Ok(Self(bits))
    }
}

/// The type code of a `SUBGROUP_HEADER`.
///
/// Valid codes have the form `0b0XX1XXXX`: bit 4 is always set, and only the
/// bits in [`Self::MASK`] may be.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SubgroupType(u8);

impl SubgroupType {
    /// Object Properties are present on *every* object on this stream.
    pub const PROPERTIES: u8 = 0x01;
    /// Two-bit Subgroup ID mode.
    pub const SUBGROUP_ID_MODE: u8 = 0x06;
    /// This subgroup contains the largest Object in the group.
    pub const END_OF_GROUP: u8 = 0x08;
    /// Always set; distinguishes a subgroup header from a datagram.
    pub const MARKER: u8 = 0x10;
    /// The Priority field is omitted; inherit it from the subscription.
    pub const DEFAULT_PRIORITY: u8 = 0x20;
    /// The first object here is the first the original publisher sent.
    pub const FIRST_OBJECT: u8 = 0x40;

    /// Every bit the layout defines.
    pub const MASK: u8 = Self::PROPERTIES
        | Self::SUBGROUP_ID_MODE
        | Self::END_OF_GROUP
        | Self::MARKER
        | Self::DEFAULT_PRIORITY
        | Self::FIRST_OBJECT;

    /// Build a type code from the fields that will be present.
    // The bools mirror the wire's flag bits one for one. A parameter struct
    // would just restate the header type that already calls this.
    #[allow(clippy::fn_params_excessive_bools)]
    #[must_use]
    pub const fn new(
        properties: bool,
        mode: SubgroupIdMode,
        end_of_group: bool,
        default_priority: bool,
        first_object: bool,
    ) -> Self {
        let mut bits = Self::MARKER | (mode.as_bits() << 1);
        if properties {
            bits |= Self::PROPERTIES;
        }
        if end_of_group {
            bits |= Self::END_OF_GROUP;
        }
        if default_priority {
            bits |= Self::DEFAULT_PRIORITY;
        }
        if first_object {
            bits |= Self::FIRST_OBJECT;
        }
        Self(bits)
    }

    /// The wire value.
    #[must_use]
    pub const fn as_u8(self) -> u8 {
        self.0
    }

    /// Whether every object on this stream carries a Properties field.
    #[must_use]
    pub const fn has_properties(self) -> bool {
        self.0 & Self::PROPERTIES != 0
    }

    /// How the Subgroup ID is conveyed.
    ///
    /// # Errors
    /// Never in practice: [`Self::from_u64`] rejects the reserved mode, so any
    /// value of this type holds a valid one. Returns a result only so the two
    /// paths share one table.
    pub const fn subgroup_id_mode(self) -> Result<SubgroupIdMode, DecodeError> {
        SubgroupIdMode::from_bits((self.0 & Self::SUBGROUP_ID_MODE) >> 1)
    }

    /// Whether this subgroup holds the largest Object in its group.
    #[must_use]
    pub const fn is_end_of_group(self) -> bool {
        self.0 & Self::END_OF_GROUP != 0
    }

    /// Whether the Priority field is omitted.
    #[must_use]
    pub const fn has_default_priority(self) -> bool {
        self.0 & Self::DEFAULT_PRIORITY != 0
    }

    /// Whether the first object here is the publisher's first in the subgroup.
    #[must_use]
    pub const fn is_first_object(self) -> bool {
        self.0 & Self::FIRST_OBJECT != 0
    }

    /// Validate a type code read off the wire.
    ///
    /// # Errors
    /// [`DecodeError::Invalid`] for a code outside the defined form, or one
    /// using the reserved Subgroup ID mode.
    pub const fn from_u64(code: u64) -> Result<Self, DecodeError> {
        if code > Self::MASK as u64 || (code as u8) & !Self::MASK != 0 {
            return Err(DecodeError::Invalid(
                "subgroup type is outside the form 0b0XX1XXXX",
            ));
        }
        let bits = code as u8;
        if bits & Self::MARKER == 0 {
            return Err(DecodeError::Invalid("subgroup type must have bit 4 set"));
        }
        // Surface the reserved mode as an error rather than storing it.
        match SubgroupIdMode::from_bits((bits & Self::SUBGROUP_ID_MODE) >> 1) {
            Ok(_) => Ok(Self(bits)),
            Err(e) => Err(e),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The draft enumerates exactly which codes are valid. Rather than trust a
    /// reading of the bit rules, walk every byte and compare against the
    /// enumerated ranges, which are stated independently in the same section.
    #[test]
    fn datagram_validity_matches_the_enumerated_ranges() {
        // §11.3.1: "0x00..0x0F / 0x20..0x21 / 0x24..0x25 / 0x28..0x29 / 0x2C..0x2D"
        let enumerated: Vec<u64> = (0x00..=0x0F)
            .chain(0x20..=0x21)
            .chain(0x24..=0x25)
            .chain(0x28..=0x29)
            .chain(0x2C..=0x2D)
            .collect();

        for code in 0u64..=0x3FF {
            let ours = DatagramType::from_u64(code).is_ok();
            assert_eq!(
                ours,
                enumerated.contains(&code),
                "disagreement at {code:#04x}"
            );
        }
    }

    /// The invalid list is stated separately, so check it separately.
    #[test]
    fn status_with_end_of_group_is_rejected() {
        for code in [0x22u64, 0x23, 0x26, 0x27, 0x2A, 0x2B, 0x2E, 0x2F] {
            assert!(
                DatagramType::from_u64(code).is_err(),
                "{code:#04x} should be invalid"
            );
        }
    }

    #[test]
    fn subgroup_validity_matches_the_enumerated_ranges() {
        // §11.4.2: "0x10..0x15 / 0x18..0x1D / 0x30..0x35 / 0x38..0x3D /
        //           0x50..0x55 / 0x58..0x5D / 0x70..0x75 / 0x78..0x7D"
        let enumerated: Vec<u64> = (0x10..=0x15)
            .chain(0x18..=0x1D)
            .chain(0x30..=0x35)
            .chain(0x38..=0x3D)
            .chain(0x50..=0x55)
            .chain(0x58..=0x5D)
            .chain(0x70..=0x75)
            .chain(0x78..=0x7D)
            .collect();

        for code in 0u64..=0x3FF {
            let ours = SubgroupType::from_u64(code).is_ok();
            assert_eq!(
                ours,
                enumerated.contains(&code),
                "disagreement at {code:#04x}"
            );
        }
    }

    #[test]
    fn reserved_subgroup_mode_is_rejected() {
        for code in [
            0x16u64, 0x17, 0x1E, 0x1F, 0x36, 0x37, 0x3E, 0x3F, 0x56, 0x57, 0x5E, 0x5F, 0x76, 0x77,
            0x7E, 0x7F,
        ] {
            assert!(
                SubgroupType::from_u64(code).is_err(),
                "{code:#04x} should be invalid"
            );
        }
    }

    /// Building a code and reading it back must agree, or the encoder and
    /// decoder disagree about which fields are on the wire.
    #[test]
    fn datagram_accessors_invert_construction() {
        for properties in [false, true] {
            for zero_object_id in [false, true] {
                for default_priority in [false, true] {
                    for (carries_status, end_of_group) in
                        [(false, false), (false, true), (true, false)]
                    {
                        let ty = DatagramType::new(
                            properties,
                            zero_object_id,
                            default_priority,
                            carries_status,
                            end_of_group,
                        );
                        let parsed = DatagramType::from_u64(u64::from(ty.as_u8()))
                            .expect("constructed types are always valid");
                        assert_eq!(parsed, ty);
                        assert_eq!(parsed.has_properties(), properties);
                        assert_eq!(parsed.has_zero_object_id(), zero_object_id);
                        assert_eq!(parsed.has_default_priority(), default_priority);
                        assert_eq!(parsed.carries_status(), carries_status);
                        assert_eq!(parsed.is_end_of_group(), end_of_group && !carries_status);
                    }
                }
            }
        }
    }

    #[test]
    fn subgroup_accessors_invert_construction() {
        let modes = [
            SubgroupIdMode::Zero,
            SubgroupIdMode::FirstObjectId,
            SubgroupIdMode::Explicit,
        ];
        for properties in [false, true] {
            for mode in modes {
                for end_of_group in [false, true] {
                    for default_priority in [false, true] {
                        for first_object in [false, true] {
                            let ty = SubgroupType::new(
                                properties,
                                mode,
                                end_of_group,
                                default_priority,
                                first_object,
                            );
                            let parsed = SubgroupType::from_u64(u64::from(ty.as_u8()))
                                .expect("constructed types are always valid");
                            assert_eq!(parsed, ty);
                            assert_eq!(parsed.has_properties(), properties);
                            assert_eq!(parsed.subgroup_id_mode().unwrap(), mode);
                            assert_eq!(parsed.is_end_of_group(), end_of_group);
                            assert_eq!(parsed.has_default_priority(), default_priority);
                            assert_eq!(parsed.is_first_object(), first_object);
                        }
                    }
                }
            }
        }
    }

    /// The two spaces must not overlap: a receiver picks the parser from the
    /// stream or datagram type alone, so an ambiguous code would be read two
    /// different ways by two implementations.
    #[test]
    fn datagram_and_subgroup_type_spaces_are_disjoint() {
        for code in 0u64..=0xFF {
            assert!(
                !(DatagramType::from_u64(code).is_ok() && SubgroupType::from_u64(code).is_ok()),
                "{code:#04x} parses as both"
            );
        }
    }
}
