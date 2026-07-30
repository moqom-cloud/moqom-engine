//! Byte-exactness against Microsoft's own recorded bitstreams.
//!
//! This is the test that decides whether the port was a good idea. Everything in
//! the unit tests proves the coder is self-consistent, which is necessary and
//! nowhere near sufficient: a coder that is wrong in the same way in both
//! directions round-trips perfectly and cannot decode anything a real encoder
//! produced.
//!
//! What makes these vectors worth more than fixtures generated here is their
//! provenance. They are `packages/msrtc_rans/python/test/*.zip` from
//! microsoft/mlvc, unmodified — real probability tables from a trained model,
//! real latents, and a bitstream recorded in 2024 by a build of the C++ nobody
//! here has touched. Reproducing those bytes proves interoperability with the
//! reference as shipped, not with a copy of it built alongside this crate.
//!
//! See `tests/fixtures/README.md` for the source digests.

// As the crate itself: reading a fixture is deliberate numeric conversion, and
// every index cast here is guarded by the `index < 0` test above it.
#![allow(clippy::cast_possible_wrap, clippy::cast_sign_loss)]
// `decoder` and `decoded` — the coder and its output. Both names are right.
#![allow(clippy::similar_names)]

use moqom_rans::{Decoder, Encoder};
use std::path::PathBuf;

/// One recorded case: the tables, the inputs, and the bytes to match.
struct Vector {
    name: &'static str,
    /// `symbolBits`, `bypassBits` as the reference's Python was called with.
    symbol_bits: i32,
    bypass_bits: i32,

    pmf_lengths: Vec<i32>,
    pmf_offsets: Vec<i32>,
    pmf_table: Vec<i32>,
    indices: Vec<i32>,
    values: Vec<i32>,
    bitstream: Vec<u8>,
}

impl Vector {
    fn load(name: &'static str, symbol_bits: i32, bypass_bits: i32) -> Self {
        let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures")
            .join(name);
        let read = |file: &str| {
            std::fs::read(dir.join(file))
                .unwrap_or_else(|e| panic!("fixture {name}/{file} should be readable: {e}"))
        };

        Self {
            name,
            symbol_bits,
            bypass_bits,
            pmf_lengths: i32s(&read("pmf_lengths.np")),
            pmf_offsets: i32s(&read("pmf_offsets.np")),
            pmf_table: i32s(&read("pmf_table.np")),
            indices: i32s(&read("indices.np")),
            values: i32s(&read("values.np")),
            bitstream: read("bitstream.bin"),
        }
    }

    fn encoder(&self) -> Encoder {
        Encoder::new(
            &self.pmf_lengths,
            &self.pmf_offsets,
            &self.pmf_table,
            self.symbol_bits,
            self.bypass_bits,
        )
        .expect("the reference's own tables should be accepted")
    }

    fn decoder(&self) -> Decoder {
        Decoder::new(
            &self.pmf_lengths,
            &self.pmf_offsets,
            &self.pmf_table,
            self.symbol_bits,
            self.bypass_bits,
        )
        .expect("the reference's own tables should be accepted")
    }
}

/// Reinterpret a little-endian `int32` dump, which is how numpy wrote these.
///
/// Read a byte at a time rather than cast, because a fixture on disk carries no
/// alignment guarantee — the same reason this crate's decoder takes bytes.
fn i32s(bytes: &[u8]) -> Vec<i32> {
    assert!(
        bytes.len().is_multiple_of(4),
        "an int32 dump should be a whole number of int32s"
    );
    bytes
        .chunks_exact(4)
        .map(|c| i32::from_le_bytes([c[0], c[1], c[2], c[3]]))
        .collect()
}

fn vectors() -> Vec<Vector> {
    vec![
        // The configuration MLVC's models actually construct: bypassBits = 2.
        Vector::load("bit_estimator_z0", 16, 2),
        // The reference's default bypassBits = 4, which nothing in MLVC uses but
        // which the coder supports — worth covering, since a different bypass
        // width changes both the digit split and the count encoding.
        Vector::load("gaussian_encoder0", 16, 4),
    ]
}

/// The headline claim: identical bytes, not merely a working round trip.
#[test]
fn encoding_reproduces_the_reference_bitstream_exactly() {
    for vector in vectors() {
        let produced = vector
            .encoder()
            .encode(&vector.indices, &vector.values)
            .expect("the reference's own inputs should encode");

        assert_eq!(
            produced.len(),
            vector.bitstream.len(),
            "{}: length differs — {} bytes against the recorded {}",
            vector.name,
            produced.len(),
            vector.bitstream.len()
        );

        if produced != vector.bitstream {
            let at = produced
                .iter()
                .zip(&vector.bitstream)
                .position(|(a, b)| a != b)
                .expect("lengths matched, so a difference must be in the contents");
            panic!(
                "{}: first differing byte at {at}: produced {:#04x}, recorded {:#04x}",
                vector.name, produced[at], vector.bitstream[at]
            );
        }
    }
}

/// And the other direction: their bytes, our values.
///
/// Decoding the *recorded* stream rather than one just produced is the half that
/// matters for a viewer, who never sees a stream this process wrote.
#[test]
fn decoding_the_reference_bitstream_recovers_the_reference_values() {
    for vector in vectors() {
        let mut decoded = vec![0i32; vector.values.len()];
        vector
            .decoder()
            .decode(&mut decoded, &vector.indices, &vector.bitstream)
            .unwrap_or_else(|e| panic!("{}: recorded stream should decode: {e}", vector.name));

        if decoded != vector.values {
            let at = decoded
                .iter()
                .zip(&vector.values)
                .position(|(a, b)| a != b)
                .expect("a difference must exist");
            panic!(
                "{}: first differing value at {at}: decoded {}, expected {} (index {})",
                vector.name, decoded[at], vector.values[at], vector.indices[at]
            );
        }
    }
}

/// What these two vectors do and do not reach.
///
/// Worth stating explicitly, because the answer is less than you would assume
/// and it is the reason `differential_corpus.rs` exists. Between them they cover
/// real model tables of varying length, both bypass widths, and — in
/// `bit_estimator_z0` — the bypass path. Neither masks a position out, and
/// `gaussian_encoder0` never bypasses at all: 58,880 latents in 108 bytes is a
/// distribution so skewed that almost everything is the same symbol.
///
/// The assertions are on the union rather than on each vector, so this records
/// the coverage honestly instead of demanding something the fixtures do not have.
#[test]
fn the_vectors_cover_real_tables_and_the_bypass_path() {
    let mut total_bypassed = 0usize;
    let mut bypass_widths = std::collections::BTreeSet::new();

    for vector in vectors() {
        let distributions = vector.pmf_lengths.len();
        assert!(
            distributions > 1,
            "{}: should have several distributions",
            vector.name
        );

        // Variable-length distributions, which is what makes the table walk
        // non-trivial: equal lengths would let an indexing bug go unnoticed.
        let lengths: std::collections::BTreeSet<_> = vector.pmf_lengths.iter().collect();
        assert!(
            lengths.len() > 1,
            "{}: distributions should not all be the same length",
            vector.name
        );

        let masked = vector.indices.iter().filter(|&&i| i < 0).count();
        let coded = vector.indices.len() - masked;
        assert!(coded > 0, "{}: should code something", vector.name);

        // A value is bypassed when it falls outside its distribution's explicit
        // range, which needs the offsets to work out.
        let mut bypassed = 0usize;
        for (&index, &value) in vector.indices.iter().zip(&vector.values) {
            if index < 0 {
                continue;
            }
            let d = (index as usize).min(distributions - 1);
            let shifted = i64::from(value) + i64::from(vector.pmf_offsets[d]);
            let sentinel = i64::from(vector.pmf_lengths[d] - 1);
            if !(0..sentinel).contains(&shifted) {
                bypassed += 1;
            }
        }

        println!(
            "{}: {distributions} distributions, lengths {}..={}, {coded} coded, \
             {masked} masked, {bypassed} bypassed, {} bytes",
            vector.name,
            vector.pmf_lengths.iter().min().expect("non-empty"),
            vector.pmf_lengths.iter().max().expect("non-empty"),
            vector.bitstream.len()
        );

        total_bypassed += bypassed;
        bypass_widths.insert(vector.bypass_bits);
    }

    assert!(
        total_bypassed > 0,
        "at least one vector should reach the bypass path"
    );
    assert!(
        bypass_widths.len() > 1,
        "the two vectors should use different bypass widths, got {bypass_widths:?}"
    );
}

/// Re-encoding what was decoded returns the same bytes.
///
/// Weaker than the exactness test on its own, but it catches a class the others
/// cannot: a value that decodes correctly yet re-encodes down a different path,
/// which is how an off-by-one at the sentinel boundary would show up.
#[test]
fn a_decode_then_encode_of_the_reference_stream_is_stable() {
    for vector in vectors() {
        let mut decoded = vec![0i32; vector.values.len()];
        vector
            .decoder()
            .decode(&mut decoded, &vector.indices, &vector.bitstream)
            .expect("recorded stream should decode");

        let reencoded = vector
            .encoder()
            .encode(&vector.indices, &decoded)
            .expect("decoded values should re-encode");

        assert_eq!(
            reencoded, vector.bitstream,
            "{}: re-encoding should return the same bytes",
            vector.name
        );
    }
}

/// Every byte of a real stream matters.
///
/// Flipping any single bit should change the decoded values or be rejected —
/// never leave the output identical. A coder that ignored part of its input
/// would pass every test above.
#[test]
fn flipping_any_bit_of_a_real_stream_is_detected() {
    let vector = &vectors()[0];
    let decoder = vector.decoder();

    let mut reference = vec![0i32; vector.values.len()];
    decoder
        .decode(&mut reference, &vector.indices, &vector.bitstream)
        .expect("recorded stream should decode");

    let mut ignored = 0usize;
    // Every bit of the first sixteen bytes, then a sample deeper in. Exhaustive
    // over the whole stream would be 7,864 decodes of 7,680 values each, which
    // is slower than this test is worth.
    let positions: Vec<usize> = (0..16)
        .chain((16..vector.bitstream.len()).step_by(37))
        .collect();

    for byte in positions {
        for bit in 0..8 {
            let mut corrupted = vector.bitstream.clone();
            corrupted[byte] ^= 1 << bit;

            let mut decoded = vec![0i32; vector.values.len()];
            match decoder.decode(&mut decoded, &vector.indices, &corrupted) {
                Err(_) => {}
                Ok(()) => {
                    if decoded == reference {
                        ignored += 1;
                    }
                }
            }
        }
    }

    assert_eq!(
        ignored, 0,
        "{ignored} single-bit changes left the decoded values untouched, \
         so those bits are not being read"
    );
}
