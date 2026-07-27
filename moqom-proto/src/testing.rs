//! The codec contract, and machinery to hold every wire type to it.
//!
//! # Why this exists
//!
//! Writing this crate turned up a recurring class of bug that hand-written
//! tests kept missing, and that a careful reading of the draft only catches
//! when you happen to be looking:
//!
//! - `encoded_len` disagreeing with `encode`, which corrupts the enclosing
//!   frame's length field rather than failing locally.
//! - A decoder consuming more than it was given, or reading into the next
//!   field.
//! - A peer-supplied count or length driving an allocation before it is
//!   bounded.
//! - A decoder that panics rather than erroring on hostile bytes.
//! - A field silently dropped on decode, invisible because the round-trip test
//!   only ever exercises values the encoder produced.
//!
//! Each of those recurs for every new message, and there are far more messages
//! left than are written. So the contract is stated once here and enforced
//! uniformly, and adding a wire type means adding one line to the conformance
//! list rather than remembering five separate hazards.
//!
//! # The two halves
//!
//! [`assert_value_contract`] checks a value the encoder produced. It is the
//! cheap half and catches sizing and framing mistakes.
//!
//! [`assert_decoder_contract`] checks a decoder against *arbitrary bytes*, and
//! is the half that matters. It needs no generator for the type, so it applies
//! uniformly to everything, and its idempotence check is the only test here
//! capable of noticing a dropped field: a value the encoder never produces is
//! precisely what a round-trip test cannot reach.

use bytes::Bytes;

use crate::control::params::Parameters;
use crate::error::DecodeError;

/// A type with a wire representation that can be checked against the contract.
///
/// Implementations are adapters over each type's inherent `encode`/`decode`,
/// deliberately rather than a blanket impl: the signatures genuinely differ
/// (some decoders need an explicit length) and flattening that difference is
/// how a length-bounded field ends up being decoded unbounded.
pub trait Codec: Sized + PartialEq + std::fmt::Debug {
    /// Name used in assertion messages.
    const NAME: &'static str;

    /// Whether decoding is *defined* to consume its entire input.
    ///
    /// True for fields specified as "the remainder of the message", such as
    /// Track Properties and Setup Options. These behave differently under the
    /// contract: truncating one can yield a smaller valid value rather than an
    /// error, and they legitimately consume trailing bytes.
    const CONSUMES_TO_END: bool = false;

    /// Append the wire representation.
    fn encode_to(&self, buf: &mut Vec<u8>);

    /// Bytes [`Codec::encode_to`] will append.
    fn encoded_size(&self) -> usize;

    /// Read one value, advancing `input`.
    ///
    /// # Errors
    /// Whatever the underlying decoder reports.
    fn decode_from(input: &mut &[u8]) -> Result<Self, DecodeError>;
}

/// Check every property required of a value the encoder produced.
///
/// # Panics
/// On any contract violation, with the offending type named.
pub fn assert_value_contract<T: Codec>(value: &T) {
    let mut buf = Vec::new();
    value.encode_to(&mut buf);

    assert_eq!(
        buf.len(),
        value.encoded_size(),
        "{}: encoded_size disagrees with encode, which corrupts the enclosing length field",
        T::NAME
    );

    let mut cursor = buf.as_slice();
    let decoded = match T::decode_from(&mut cursor) {
        Ok(v) => v,
        Err(e) => panic!("{}: own output failed to decode: {e}", T::NAME),
    };
    assert_eq!(&decoded, value, "{}: round trip changed the value", T::NAME);
    assert!(
        cursor.is_empty(),
        "{}: decode left {} byte(s) unread",
        T::NAME,
        cursor.len()
    );

    // Truncation must never be fatal and never panic. A short read means "wait
    // for more bytes"; reporting a violation instead would tear down a session
    // over a partial read.
    for cut in 0..buf.len() {
        let mut cursor = &buf[..cut];
        match T::decode_from(&mut cursor) {
            Err(e) => assert!(
                !e.is_fatal(),
                "{}: truncation at {cut} reported a protocol violation: {e}",
                T::NAME
            ),
            // A prefix of a to-end field is a legitimate smaller value.
            Ok(_) => assert!(
                T::CONSUMES_TO_END,
                "{}: truncation at {cut} decoded as a complete value",
                T::NAME
            ),
        }
    }

    if !T::CONSUMES_TO_END {
        let mut extended = buf.clone();
        extended.extend_from_slice(b"\xde\xad\xbe\xef");
        let mut cursor = extended.as_slice();
        let decoded = T::decode_from(&mut cursor).expect("decoding with trailing bytes");
        assert_eq!(
            &decoded,
            value,
            "{}: trailing bytes changed the value",
            T::NAME
        );
        assert_eq!(
            cursor.len(),
            4,
            "{}: consumed bytes past its own encoding",
            T::NAME
        );
    }
}

/// Check every property required of a decoder, against bytes it did not write.
///
/// This is the important half. Feed it anything — truncated frames, hostile
/// lengths, random noise — and it holds the decoder to:
///
/// 1. Never panicking, which for a relay is the difference between rejecting a
///    connection and losing the process.
/// 2. Never consuming more than it was given.
/// 3. Agreeing with itself about size, on values the encoder would never emit.
/// 4. **Idempotence.** If bytes decode, re-encoding and decoding again must
///    produce an equal value. This is the only check here that can notice a
///    dropped field, because it reaches values no generator of ours would
///    think to produce.
///
/// Byte-for-byte equality is deliberately *not* asserted: varints have
/// non-minimal encodings that decode correctly but re-encode shorter, so
/// requiring identical bytes would fail on input that is perfectly legal.
///
/// # Panics
/// On any contract violation, with the offending type named.
pub fn assert_decoder_contract<T: Codec>(bytes: &[u8]) {
    let mut cursor = bytes;
    let Ok(value) = T::decode_from(&mut cursor) else {
        return;
    };

    assert!(
        cursor.len() <= bytes.len(),
        "{}: decoder produced more input than it was given",
        T::NAME
    );

    let mut reencoded = Vec::new();
    value.encode_to(&mut reencoded);
    assert_eq!(
        reencoded.len(),
        value.encoded_size(),
        "{}: encoded_size disagrees with encode on a decoded value",
        T::NAME
    );

    let mut cursor = reencoded.as_slice();
    match T::decode_from(&mut cursor) {
        Ok(again) => assert_eq!(
            again,
            value,
            "{}: decode is not idempotent, so a field is being dropped or mangled",
            T::NAME
        ),
        Err(e) => panic!("{}: re-encoded value failed to decode: {e}", T::NAME),
    }
}

/// Parameters in their count-prefixed framing.
///
/// A distinct type because [`Parameters`] has two wire forms and only one can
/// be the [`Codec`] impl. The counted form is the one request messages use, so
/// leaving it outside the contract would exempt the framing that carries most
/// of the protocol.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CountedParameters(pub Parameters);

macro_rules! impl_codec {
    (
        $ty:ty, $name:literal, $to_end:literal,
        encode: |$s:ident, $buf:ident| $enc:expr,
        size: |$s2:ident| $size:expr,
        decode: |$input:ident| $dec:expr $(,)?
    ) => {
        impl Codec for $ty {
            const NAME: &'static str = $name;
            const CONSUMES_TO_END: bool = $to_end;

            fn encode_to(&self, buf: &mut Vec<u8>) {
                let $s = self;
                let $buf = buf;
                $enc
            }

            fn encoded_size(&self) -> usize {
                let $s2 = self;
                $size
            }

            fn decode_from(input: &mut &[u8]) -> Result<Self, DecodeError> {
                let $input = input;
                $dec
            }
        }
    };
}

impl_codec!(crate::varint::VarInt, "VarInt", false,
    encode: |s, buf| (*s).encode(buf),
    size: |s| s.size(),
    decode: |i| Self::decode(i));

impl_codec!(crate::model::TrackNamespace, "TrackNamespace", false,
    encode: |s, buf| s.encode(buf),
    size: |s| s.encoded_len(),
    decode: |i| Self::decode(i));

impl_codec!(crate::model::FullTrackName, "FullTrackName", false,
    encode: |s, buf| s.encode(buf),
    size: |s| s.encoded_len(),
    decode: |i| Self::decode(i));

impl_codec!(crate::model::Location, "Location", false,
    encode: |s, buf| s.encode(buf),
    size: |s| s.encoded_len(),
    decode: |i| Self::decode(i));

impl_codec!(crate::model::ObjectStatus, "ObjectStatus", false,
    encode: |s, buf| s.encode(buf),
    size: |s| s.encoded_len(),
    decode: |i| Self::decode(i));

impl_codec!(crate::control::ReasonPhrase, "ReasonPhrase", false,
    encode: |s, buf| s.encode(buf),
    size: |s| s.encoded_len(),
    decode: |i| Self::decode(i));

impl_codec!(crate::control::ControlFrame, "ControlFrame", false,
    encode: |s, buf| s.encode(buf),
    size: |s| s.encoded_len(),
    decode: |i| Self::decode(i));

impl_codec!(Parameters, "Parameters", true,
    encode: |s, buf| s.encode(buf),
    size: |s| s.encoded_len(),
    decode: |i| { let n = i.len(); Self::decode(i, n) });

impl_codec!(CountedParameters, "CountedParameters", false,
    encode: |s, buf| s.0.encode_counted(buf),
    size: |s| s.0.encoded_len_counted(),
    decode: |i| Parameters::decode_counted(i).map(Self));

impl_codec!(crate::control::Properties, "Properties", true,
    encode: |s, buf| s.encode(buf),
    size: |s| s.encoded_len(),
    decode: |i| Self::decode_to_end(i));

impl_codec!(crate::control::Setup, "Setup", true,
    encode: |s, buf| s.encode(buf),
    size: |s| s.encoded_len(),
    decode: |i| { let n = i.len(); Self::decode(i, n) });

impl_codec!(crate::control::Goaway, "Goaway", false,
    encode: |s, buf| s.encode(buf),
    size: |s| s.encoded_len(),
    decode: |i| Self::decode(i));

impl_codec!(crate::control::Subscribe, "Subscribe", false,
    encode: |s, buf| s.encode(buf),
    size: |s| s.encoded_len(),
    decode: |i| Self::decode(i));

impl_codec!(crate::control::SubscribeOk, "SubscribeOk", true,
    encode: |s, buf| s.encode(buf),
    size: |s| s.encoded_len(),
    decode: |i| Self::decode(i));

impl_codec!(crate::control::RequestOk, "RequestOk", true,
    encode: |s, buf| s.encode(buf),
    size: |s| s.encoded_len(),
    decode: |i| Self::decode(i));

impl_codec!(crate::control::RequestError, "RequestError", true,
    encode: |s, buf| s.encode(buf),
    size: |s| s.encoded_len(),
    decode: |i| Self::decode(i));

impl_codec!(crate::control::Redirect, "Redirect", false,
    encode: |s, buf| s.encode(buf),
    size: |s| s.encoded_len(),
    decode: |i| Self::decode(i));

/// Run the decoder contract over every wire type in the crate.
///
/// One call site for all of them, so a new type is one line here and cannot be
/// quietly left uncovered. Shared by the property tests and the fuzz targets so
/// both hold the same standard.
///
/// # Panics
/// On any contract violation.
pub fn assert_all_decoder_contracts(bytes: &[u8]) {
    use crate::control::{
        ControlFrame, Goaway, Properties, ReasonPhrase, Redirect, RequestError, RequestOk, Setup,
        Subscribe, SubscribeOk,
    };
    use crate::model::{FullTrackName, Location, ObjectStatus, TrackNamespace};
    use crate::varint::VarInt;

    assert_decoder_contract::<VarInt>(bytes);
    assert_decoder_contract::<TrackNamespace>(bytes);
    assert_decoder_contract::<FullTrackName>(bytes);
    assert_decoder_contract::<Location>(bytes);
    assert_decoder_contract::<ObjectStatus>(bytes);
    assert_decoder_contract::<ReasonPhrase>(bytes);
    assert_decoder_contract::<Parameters>(bytes);
    assert_decoder_contract::<CountedParameters>(bytes);
    assert_decoder_contract::<Properties>(bytes);
    assert_decoder_contract::<ControlFrame>(bytes);
    assert_decoder_contract::<Setup>(bytes);
    assert_decoder_contract::<Goaway>(bytes);
    assert_decoder_contract::<Subscribe>(bytes);
    assert_decoder_contract::<SubscribeOk>(bytes);
    assert_decoder_contract::<RequestOk>(bytes);
    assert_decoder_contract::<RequestError>(bytes);
    assert_decoder_contract::<Redirect>(bytes);
}

/// Valid encodings of every wire type, for seeding mutation.
///
/// Random bytes are close to useless against a structured format, and it is
/// worth being concrete about how useless: measured on this crate, 20,000
/// random inputs produced **zero** successful `SUBSCRIBE` decodes and one
/// successful frame decode. Since the idempotence check only runs on input that
/// decodes, it was never running for the message types — a suite that looked
/// thorough and tested almost nothing.
///
/// Mutating a valid encoding keeps input near the boundary where decoders
/// accept, which is both where the interesting bugs are and the only place the
/// expensive checks can fire. The same corpus seeds the fuzzer, which is why it
/// is built here rather than inline in a test.
/// # Panics
/// If any representative value fails to build, which would mean a constructor
/// rejected input the type is documented to accept.
#[must_use]
#[allow(clippy::vec_init_then_push, clippy::too_many_lines)] // one push per type, read as a checklist
pub fn seed_corpus() -> Vec<Vec<u8>> {
    use crate::control::params::Parameter;
    use crate::control::properties::Properties;
    use crate::control::{
        ControlFrame, Goaway, MessageType, ReasonPhrase, Redirect, RequestError, RequestErrorCode,
        RequestId, RequestOk, Setup, Subscribe, SubscribeOk,
    };
    use crate::model::{FullTrackName, GroupId, Location, ObjectId, ObjectStatus, TrackAlias};
    use crate::model::{TrackNamespace, name::MAX_FIELDS};
    use crate::varint::VarInt;

    fn enc<T: Codec>(value: &T) -> Vec<u8> {
        let mut buf = Vec::new();
        value.encode_to(&mut buf);
        buf
    }

    let namespace = TrackNamespace::from_parts([&b"moqom"[..], &b"room-42"[..]]).unwrap();
    let track = FullTrackName::new(namespace.clone(), bytes(b"video/hd")).unwrap();

    let mut params = Parameters::new();
    params.push(Parameter::bytes(3, bytes(b"auth-token")).unwrap());
    params.push(Parameter::varint(6, VarInt::from_u32(2)).unwrap());
    params.push(Parameter::varint(1000, VarInt::from_u32(1)).unwrap());

    let mut props = Properties::new();
    props.push(Parameter::varint(0x10, VarInt::from_u32(3)).unwrap());
    props.push(Parameter::bytes(0x4001, bytes(b"codec-config")).unwrap());

    let mut corpus = Vec::new();

    // Every varint width, since width selection is a common off-by-one.
    for v in [
        0u64,
        63,
        64,
        16_383,
        16_384,
        1_073_741_823,
        1_073_741_824,
        crate::varint::MAX,
    ] {
        corpus.push(enc(&VarInt::new(v).unwrap()));
    }

    corpus.push(enc(&TrackNamespace::empty()));
    corpus.push(enc(&namespace));
    corpus.push(enc(&TrackNamespace::from_parts(
        (0..MAX_FIELDS).map(|i| format!("f{i}")),
    )
    .unwrap()));
    corpus.push(enc(&track));
    corpus.push(enc(&FullTrackName::default()));
    corpus.push(enc(&Location::new(
        GroupId::from(7u32),
        ObjectId::from(3u32),
    )));
    corpus.push(enc(&ObjectStatus::Normal));
    corpus.push(enc(&ObjectStatus::EndOfGroup));
    corpus.push(enc(&ObjectStatus::EndOfTrack));
    corpus.push(enc(&ReasonPhrase::empty()));
    corpus.push(enc(&ReasonPhrase::truncating("subscription refused")));

    corpus.push(enc(&Parameters::new()));
    corpus.push(enc(&params));
    corpus.push(enc(&CountedParameters(params.clone())));
    corpus.push(enc(&CountedParameters(Parameters::new())));
    corpus.push(enc(&props));

    let mut setup = Setup::new();
    setup.options.set_bytes(0x01, bytes(b"/live")).unwrap();
    setup.options.set_varint(0x04, 8192).unwrap();
    setup
        .options
        .set_bytes(0x07, bytes(b"moqom/0.0.0"))
        .unwrap();
    corpus.push(enc(&setup));
    corpus.push(enc(&Setup::new()));

    corpus.push(enc(&Goaway::new(VarInt::from_u32(30_000))));
    corpus.push(enc(&Goaway::redirect(
        bytes(b"moqt://eu.moqom.dev/"),
        VarInt::ZERO,
    )
    .unwrap()));

    let mut subscribe = Subscribe::new(RequestId::new(4).unwrap(), track.clone());
    subscribe.parameters = params.clone();
    corpus.push(enc(&subscribe));
    corpus.push(enc(&Subscribe::new(
        RequestId::new(0).unwrap(),
        track.clone(),
    )));

    let mut subscribe_ok = SubscribeOk::new(TrackAlias::from(7u32));
    subscribe_ok.parameters = params.clone();
    subscribe_ok.properties = props.clone();
    corpus.push(enc(&subscribe_ok));
    corpus.push(enc(&SubscribeOk::new(TrackAlias::ZERO)));

    let mut request_ok = RequestOk::new();
    request_ok.parameters = params;
    request_ok.properties = props;
    corpus.push(enc(&request_ok));
    corpus.push(enc(&RequestOk::new()));

    let reason = ReasonPhrase::truncating("no such track");
    corpus.push(enc(&RequestError::new(
        RequestErrorCode::DOES_NOT_EXIST,
        reason.clone(),
    )));
    corpus.push(enc(&RequestError::retryable(
        RequestErrorCode::EXCESSIVE_LOAD,
        reason.clone(),
        2500,
    )
    .unwrap()));
    corpus.push(enc(&RequestError::redirect(
        reason,
        Redirect::to_track(track.clone()),
    )));
    corpus.push(enc(&Redirect::to_track(track)));
    corpus.push(enc(
        &Redirect::to_uri(bytes(b"moqt://eu.moqom.dev/")).unwrap()
    ));
    corpus.push(enc(&Redirect::default()));

    for ty in [
        MessageType::Setup,
        MessageType::Subscribe,
        MessageType::RequestError,
    ] {
        corpus.push(enc(
            &ControlFrame::new(ty, bytes(b"\x00\x01\x02\x03")).unwrap()
        ));
    }

    corpus
}

/// Apply a byte-level mutation, the way a fuzzer would.
///
/// Kept deliberately crude. The value is not in the cleverness of the mutation
/// but in starting from something that already parses, so the decoder gets far
/// enough in to be interesting.
#[must_use]
pub fn mutate(base: &[u8], seed: u64) -> Vec<u8> {
    let mut out = base.to_vec();
    let mut state = seed | 1;
    let mut next = || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state
    };

    match next() % 5 {
        0 if !out.is_empty() => {
            let at = (next() as usize) % out.len();
            out[at] ^= 1 << (next() % 8);
        }
        1 if !out.is_empty() => {
            let at = (next() as usize) % out.len();
            out[at] = (next() & 0xFF) as u8;
        }
        2 if !out.is_empty() => out.truncate((next() as usize) % out.len()),
        3 => {
            for _ in 0..=(next() % 8) {
                out.push((next() & 0xFF) as u8);
            }
        }
        _ if !out.is_empty() => {
            // Length fields are the highest-value target: saturating one is how
            // you find an unbounded allocation or a decoder reading past its
            // region.
            let at = (next() as usize) % out.len();
            out[at] = 0xFF;
        }
        _ => {}
    }

    out
}

/// Bytes that once broke something, replayed on every run.
///
/// A fuzzer finding a crash is only half the value; the other half is that the
/// input never works again. Anything a fuzz run turns up gets added here, which
/// keeps the regression in the stable test suite rather than depending on
/// someone re-running the fuzzer.
pub const REGRESSION_CORPUS: &[&[u8]] = &[
    // A parameter count of 1,000,000 with no parameters behind it. Must not
    // allocate on the count before checking the bytes are there.
    &[0x80, 0x0F, 0x42, 0x40],
    // A namespace claiming 2^30 fields.
    &[0xC0, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00],
    // A control frame declaring a 65535-byte body it does not have.
    &[0x03, 0xFF, 0xFF],
    // Setup options whose type deltas accumulate past the varint maximum.
    &[
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x40, 0x01, 0x00,
    ],
    // A reason phrase declaring a length beyond its 1024-byte maximum.
    &[0x44, 0x01, 0x61],
];

/// Convenience for building a [`Bytes`] in tests.
#[must_use]
pub fn bytes(slice: &[u8]) -> Bytes {
    Bytes::copy_from_slice(slice)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::control::params::Parameter;
    use crate::control::{ControlFrame, MessageType, ReasonPhrase, Setup, Subscribe};
    use crate::control::{RequestId, Role};
    use crate::model::{FullTrackName, TrackNamespace};
    use crate::varint::VarInt;

    #[test]
    fn regression_corpus_is_clean() {
        for case in REGRESSION_CORPUS {
            assert_all_decoder_contracts(case);
        }
    }

    #[test]
    fn value_contract_holds_for_representative_values() {
        assert_value_contract(&VarInt::from_u32(16_384));
        assert_value_contract(&ReasonPhrase::truncating("something went wrong"));
        assert_value_contract(&TrackNamespace::from_parts([&b"moqom"[..], &b"room"[..]]).unwrap());

        let track = FullTrackName::new(
            TrackNamespace::from_parts([&b"moqom"[..]]).unwrap(),
            bytes(b"video"),
        )
        .unwrap();
        assert_value_contract(&Subscribe::new(
            Role::Client.first_request_id(),
            track.clone(),
        ));

        let mut setup = Setup::new();
        setup.options.set_varint(0x08, 4).unwrap();
        assert_value_contract(&setup);

        assert_value_contract(&ControlFrame::new(MessageType::Subscribe, bytes(b"body")).unwrap());

        let mut params = Parameters::new();
        params.push(Parameter::bytes(3, bytes(b"tok")).unwrap());
        params.push(Parameter::varint(4, VarInt::from_u32(9)).unwrap());
        assert_value_contract(&params);
        assert_value_contract(&CountedParameters(params));

        let _ = RequestId::new(0).unwrap();
    }

    /// The harness has to be able to fail, or a green suite means nothing.
    #[test]
    #[should_panic(expected = "encoded_size disagrees")]
    fn the_harness_catches_a_sizing_mismatch() {
        #[derive(Debug, PartialEq)]
        struct Wrong;

        impl Codec for Wrong {
            const NAME: &'static str = "Wrong";
            fn encode_to(&self, buf: &mut Vec<u8>) {
                buf.extend_from_slice(&[0, 0]);
            }
            fn encoded_size(&self) -> usize {
                1 // deliberately wrong
            }
            fn decode_from(_: &mut &[u8]) -> Result<Self, DecodeError> {
                Ok(Self)
            }
        }

        assert_value_contract(&Wrong);
    }

    #[test]
    #[should_panic(expected = "not idempotent")]
    fn the_harness_catches_a_dropped_field() {
        /// Decodes two bytes but only remembers one, so the second is lost.
        #[derive(Debug, PartialEq)]
        struct Lossy(u8);

        impl Codec for Lossy {
            const NAME: &'static str = "Lossy";
            fn encode_to(&self, buf: &mut Vec<u8>) {
                buf.extend_from_slice(&[self.0, 0xFF]);
            }
            fn encoded_size(&self) -> usize {
                2
            }
            fn decode_from(input: &mut &[u8]) -> Result<Self, DecodeError> {
                if input.len() < 2 {
                    return Err(DecodeError::Short {
                        needed: 2 - input.len(),
                    });
                }
                let v = input[0];
                *input = &input[2..];
                Ok(Self(v.wrapping_add(1)))
            }
        }

        assert_decoder_contract::<Lossy>(&[0x01, 0x02]);
    }

    mod properties {
        use proptest::prelude::*;

        use super::*;

        proptest! {
            #![proptest_config(ProptestConfig::with_cases(2048))]

            /// Random bytes, which catch panics on obviously bad input but
            /// almost never reach a successful decode. Cheap, so kept, but it
            /// is not the test that earns its place.
            #[test]
            fn every_decoder_survives_arbitrary_input(
                bytes in prop::collection::vec(any::<u8>(), 0..512)
            ) {
                assert_all_decoder_contracts(&bytes);
            }

            /// Mutations of valid encodings. This is the one that matters: it
            /// reaches inputs that decode successfully but that our encoder
            /// would never emit, which is the only place the idempotence check
            /// can catch a dropped field.
            #[test]
            fn every_decoder_survives_mutated_valid_input(
                index in any::<prop::sample::Index>(),
                seed in any::<u64>(),
                rounds in 1u8..4,
            ) {
                let corpus = seed_corpus();
                let mut input = index.get(&corpus).clone();
                for round in 0..rounds {
                    input = mutate(&input, seed.wrapping_add(u64::from(round)));
                }
                assert_all_decoder_contracts(&input);
            }

            /// Two valid encodings spliced together, which is how a decoder
            /// that reads past its own region gets caught.
            #[test]
            fn spliced_encodings_do_not_bleed_across(
                a in any::<prop::sample::Index>(),
                b in any::<prop::sample::Index>(),
            ) {
                let corpus = seed_corpus();
                let mut input = a.get(&corpus).clone();
                input.extend_from_slice(b.get(&corpus));
                assert_all_decoder_contracts(&input);
            }
        }

        /// The corpus only helps if mutating it actually reaches successful
        /// decodes of the structured types. Random bytes did not: measured at
        /// zero `SUBSCRIBE` decodes in 20,000 attempts. Assert a floor so this
        /// cannot silently rot back into a suite that tests nothing.
        #[test]
        fn mutation_actually_reaches_the_interesting_decoders() {
            use crate::control::{ControlFrame, RequestError, Subscribe, SubscribeOk};

            let corpus = seed_corpus();
            let (mut subscribe, mut subscribe_ok, mut request_error, mut frame) = (0, 0, 0, 0);

            for seed in 0..20_000u64 {
                let base = &corpus[(seed as usize) % corpus.len()];
                let input = mutate(base, seed.wrapping_mul(0x9E37_79B9_7F4A_7C15));

                if Subscribe::decode(&mut input.as_slice()).is_ok() {
                    subscribe += 1;
                }
                if SubscribeOk::decode(&mut input.as_slice()).is_ok() {
                    subscribe_ok += 1;
                }
                if RequestError::decode(&mut input.as_slice()).is_ok() {
                    request_error += 1;
                }
                if ControlFrame::decode(&mut input.as_slice()).is_ok() {
                    frame += 1;
                }
            }

            let report = format!(
                "Subscribe={subscribe} SubscribeOk={subscribe_ok} \
                         RequestError={request_error} ControlFrame={frame}"
            );
            assert!(subscribe >= 100, "too few Subscribe decodes: {report}");
            assert!(subscribe_ok >= 100, "too few SubscribeOk decodes: {report}");
            assert!(
                request_error >= 100,
                "too few RequestError decodes: {report}"
            );
            assert!(frame >= 100, "too few ControlFrame decodes: {report}");
        }
    }
}
