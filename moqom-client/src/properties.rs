//! MOQOM's object properties: what a publisher says about each object.
//!
//! The codes live in the draft's application range, which exists so a deployment
//! can define its own object metadata without waiting for a registry entry. Even
//! codes carry a varint and odd codes carry bytes — the parity *is* the
//! discriminator, there is no type tag — so everything defined here is even
//! except the one thing that has to be bytes.
//!
//! A relay that does not know these forwards them untouched, which is the
//! property that makes them safe to add: an old relay in the path costs the
//! receiver nothing.
//!
//! The Swift SDK has defined and set these for some time
//! (`MoqomKit/Transport/ObjectProperties+Wire.swift`); this is the other half, so
//! that a publisher written against this crate produces objects a MOQOM viewer
//! can read, and a subscriber written against it can read what a phone sent. The
//! codes are duplicated rather than shared, there being no way to share a
//! constant across two languages, so they are pinned by a test that would fail
//! if either side moved.

use bytes::Bytes;
use moqom_proto::control::params::Parameter;
use moqom_proto::control::properties::Properties;
use moqom_proto::varint::VarInt;

/// Capture time in microseconds.
///
/// Microseconds rather than nanoseconds because a varint of a nanosecond
/// timestamp is eight bytes for anything past a few seconds of uptime, and no
/// display pipeline resolves better than a microsecond anyway.
pub const CAPTURE_TIME_MICROSECONDS: u64 = 0x78;

/// Decoder configuration for the group this object opens.
///
/// Odd, so it carries bytes: the length-prefixed parameter sets. Only ever on a
/// keyframe, so the hundred-odd bytes it costs are not per-frame overhead. It
/// does not replace the catalog — what it adds is that a group is decodable from
/// itself, which matters because a relay caches by track name and a joiner
/// served an older group would otherwise decode it against whichever parameter
/// sets the catalog is advertising now.
pub const CONFIGURATION: u64 = 0x79;

/// Temporal layer index, `0` being the base.
pub const TEMPORAL_LAYER: u64 = 0x7A;

/// Non-zero when an audio packet is silence.
///
/// A property rather than a flag inside the payload, so a receiver can tell
/// silence from loss without decoding and a relay can tell it without
/// decrypting.
pub const SILENCE: u64 = 0x7C;

/// What a sealed `.catalog` object discloses.
///
/// Odd, so it carries bytes: JSON in the shape of a catalog, holding the
/// version, the `SFrame` key ID, the locale, and each track's name, kind and
/// video geometry. The catalog itself is end-to-end encrypted; this is what a
/// relay tiers usage on and a recorder files tracks by. `SFrame` authenticates
/// it with the ciphertext, so it can be read on the way through and not changed.
pub const CATALOG_DISCLOSURE: u64 = 0x7D;

/// The room authority's ML-DSA-87 signature over a `.control` entry.
///
/// One byte of key ID length, the key ID, then the signature over
/// `"moqom room log v1" ‖ 0 ‖ tenant ‖ 0 ‖ room ‖ 0 ‖ entry`. Clients apply
/// only entries that verify against the control plane's keys; it is carried
/// here so that an archived control track still verifies on playback.
pub const AUTHORITY_SIGNATURE: u64 = 0x7F;

/// What a publisher said about one object.
///
/// Every field is optional and absent means "not stated" rather than a default,
/// which is the distinction that matters for [`Self::is_silence`]: a video object
/// says nothing about audibility, and reading that as "not silence" would have it
/// claiming to be audio that happens to have sound in it.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct ObjectProperties {
    /// When the frame in this object was captured, in microseconds on the
    /// publisher's clock.
    pub capture_time_micros: Option<u64>,
    /// Parameter sets for the group this object opens.
    pub configuration: Option<Bytes>,
    /// Temporal layer index, `0` being the base.
    pub temporal_layer: Option<u64>,
    /// Whether this audio packet is silence.
    pub is_silence: Option<bool>,
    /// On a sealed catalog, the part of it that is not secret from the relay.
    pub disclosure: Option<Bytes>,
    /// On a control-log entry, the room authority's signature over it.
    pub authority_signature: Option<Bytes>,
}

impl ObjectProperties {
    /// Nothing stated, which is what a publisher that only sends bytes produces.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        *self == Self::default()
    }

    /// Tag an object with a capture time.
    #[must_use]
    pub const fn captured_at_micros(mut self, micros: u64) -> Self {
        self.capture_time_micros = Some(micros);
        self
    }

    /// Carry the parameter sets that open a group.
    #[must_use]
    pub fn opening(mut self, configuration: impl Into<Bytes>) -> Self {
        self.configuration = Some(configuration.into());
        self
    }

    /// As wire properties, omitting anything absent.
    ///
    /// Anything that will not fit is dropped rather than raising, because these
    /// are metadata: a capture time too large to be a varint is worth losing, and
    /// is not worth failing a frame of video over.
    #[must_use]
    pub fn to_wire(&self) -> Properties {
        let mut properties = Properties::new();
        if let Some(micros) = self.capture_time_micros {
            push_varint(&mut properties, CAPTURE_TIME_MICROSECONDS, micros);
        }
        if let Some(configuration) = &self.configuration
            && !configuration.is_empty()
            && let Ok(parameter) = Parameter::bytes(CONFIGURATION, configuration.clone())
        {
            properties.push(parameter);
        }
        if let Some(layer) = self.temporal_layer {
            push_varint(&mut properties, TEMPORAL_LAYER, layer);
        }
        // Only when true. A property saying "not silence" on every packet of a
        // conversation spends a byte per packet to state the default.
        if self.is_silence == Some(true) {
            push_varint(&mut properties, SILENCE, 1);
        }
        if let Some(disclosure) = &self.disclosure
            && !disclosure.is_empty()
            && let Ok(parameter) = Parameter::bytes(CATALOG_DISCLOSURE, disclosure.clone())
        {
            properties.push(parameter);
        }
        if let Some(signature) = &self.authority_signature
            && !signature.is_empty()
            && let Ok(parameter) = Parameter::bytes(AUTHORITY_SIGNATURE, signature.clone())
        {
            properties.push(parameter);
        }
        properties
    }

    /// From wire properties, ignoring anything unrecognised.
    ///
    /// Ignoring rather than rejecting: the draft requires unknown properties to
    /// be forwarded and tolerated, and a receiver that refused an object because
    /// a newer publisher tagged it with something extra would break on every
    /// upgrade.
    #[must_use]
    pub fn from_wire(properties: &Properties) -> Self {
        let varint = |code| {
            properties
                .get(code)
                .and_then(Parameter::as_varint)
                .map(VarInt::get)
        };
        Self {
            capture_time_micros: varint(CAPTURE_TIME_MICROSECONDS),
            configuration: properties
                .get(CONFIGURATION)
                .and_then(Parameter::as_bytes)
                .cloned(),
            temporal_layer: varint(TEMPORAL_LAYER),
            is_silence: varint(SILENCE).map(|value| value != 0),
            disclosure: properties
                .get(CATALOG_DISCLOSURE)
                .and_then(Parameter::as_bytes)
                .cloned(),
            authority_signature: properties
                .get(AUTHORITY_SIGNATURE)
                .and_then(Parameter::as_bytes)
                .cloned(),
        }
    }
}

fn push_varint(properties: &mut Properties, code: u64, value: u64) {
    if let Ok(value) = VarInt::new(value)
        && let Ok(parameter) = Parameter::varint(code, value)
    {
        properties.push(parameter);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn everything_stated_survives_the_wire() {
        let properties = ObjectProperties {
            capture_time_micros: Some(1_234_567),
            configuration: Some(Bytes::from_static(b"sps/pps")),
            temporal_layer: Some(2),
            is_silence: Some(true),
            disclosure: Some(Bytes::from_static(br#"{"tracks":[],"version":1}"#)),
            authority_signature: Some(Bytes::from(vec![0xAB; 3321])),
        };
        assert_eq!(
            ObjectProperties::from_wire(&properties.to_wire()),
            properties
        );
    }

    /// Absent has to survive as absent, since "not stated" and "stated as zero"
    /// are different answers for a temporal layer, where zero is the base rung.
    #[test]
    fn nothing_stated_stays_nothing() {
        let empty = ObjectProperties::default();
        assert!(empty.is_empty());
        assert_eq!(empty.to_wire().len(), 0);
        assert_eq!(ObjectProperties::from_wire(&empty.to_wire()), empty);

        let base = ObjectProperties {
            temporal_layer: Some(0),
            ..ObjectProperties::default()
        };
        assert_eq!(base.to_wire().len(), 1);
        assert_eq!(ObjectProperties::from_wire(&base.to_wire()), base);
    }

    /// Silence is only sent when true, so `false` and absent are the same bytes.
    /// Worth pinning: the alternative reading, that every packet declares itself,
    /// is a byte per packet for the default.
    #[test]
    fn silence_is_only_stated_when_there_is_some() {
        let audible = ObjectProperties {
            is_silence: Some(false),
            ..ObjectProperties::default()
        };
        assert_eq!(audible.to_wire().len(), 0);
        assert_eq!(
            ObjectProperties::from_wire(&audible.to_wire()).is_silence,
            None
        );
    }

    /// The codes the Swift SDK sets, written out here rather than referenced, so
    /// that changing one in this file fails instead of silently ending
    /// interoperability with every phone already running.
    #[test]
    fn the_codes_are_the_ones_the_sdks_agreed_on() {
        assert_eq!(CAPTURE_TIME_MICROSECONDS, 0x78);
        assert_eq!(CONFIGURATION, 0x79);
        assert_eq!(TEMPORAL_LAYER, 0x7A);
        assert_eq!(SILENCE, 0x7C);
    }

    /// Parity is the discriminator, and getting it wrong is silent: a varint
    /// pushed under an odd code is refused by the builder rather than encoded as
    /// bytes, and this is the assertion that the codes above are on the right
    /// side of that.
    #[test]
    fn each_code_is_the_parity_its_value_needs() {
        assert!(Parameter::varint(CAPTURE_TIME_MICROSECONDS, VarInt::new(1).unwrap()).is_ok());
        assert!(Parameter::varint(TEMPORAL_LAYER, VarInt::new(1).unwrap()).is_ok());
        assert!(Parameter::varint(SILENCE, VarInt::new(1).unwrap()).is_ok());
        assert!(Parameter::bytes(CONFIGURATION, Bytes::from_static(b"x")).is_ok());
    }
}
