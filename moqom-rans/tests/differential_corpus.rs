//! Byte-exactness against the reference over a randomised corpus.
//!
//! Complements `reference_vectors.rs`. Those two vectors are the more
//! trustworthy evidence — recorded in 2024 by a build of the C++ nobody here has
//! touched — but between them they never mask a position out and, in the
//! `gaussian_encoder0` case, never reach bypass at all. This corpus covers what
//! they miss: masked positions, bypass values needing up to twenty-six bits,
//! three different bypass widths, symbol scales from 8 to the usable maximum of
//! 23, and distributions from two to sixty-four symbols.
//!
//! Every stream in it was produced by the reference C++ and round-tripped by the
//! reference before being written, so a mismatch here is this crate's.
//!
//! Regenerate with `tests/fixtures/generate.py`, which needs the reference
//! package; the corpus is checked in so that neither Python nor the C++
//! extension is required to run these tests.

// As the crate itself; see the note there.
#![allow(clippy::cast_possible_wrap, clippy::cast_sign_loss)]
#![allow(clippy::similar_names)]

use moqom_rans::{Decoder, Encoder};

const MAGIC: &[u8; 16] = b"MOQOM-RANS-CORP1";

/// One generated case.
struct Case {
    name: String,
    symbol_bits: i32,
    bypass_bits: i32,
    pmf_lengths: Vec<i32>,
    pmf_offsets: Vec<i32>,
    pmf_table: Vec<i32>,
    indices: Vec<i32>,
    values: Vec<i32>,
    stream: Vec<u8>,
}

/// A cursor over the corpus file.
///
/// Hand-rolled rather than pulling in a deserialiser, for the same reason the
/// crate has no dependencies: this is a fixed layout written by one script and
/// read by one test, and a schema library would be more code than the format.
struct Reader<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl Reader<'_> {
    fn u32(&mut self) -> u32 {
        let value = u32::from_le_bytes(
            self.bytes[self.at..self.at + 4]
                .try_into()
                .expect("four bytes"),
        );
        self.at += 4;
        value
    }

    fn i32(&mut self) -> i32 {
        self.u32() as i32
    }

    fn i32s(&mut self, count: usize) -> Vec<i32> {
        (0..count).map(|_| self.i32()).collect()
    }

    fn bytes(&mut self, count: usize) -> Vec<u8> {
        let taken = self.bytes[self.at..self.at + count].to_vec();
        self.at += count;
        taken
    }
}

fn corpus() -> Vec<Case> {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/corpus.bin");
    let bytes = std::fs::read(path).expect("the checked-in corpus should be readable");

    assert!(
        bytes.starts_with(MAGIC),
        "corpus should start with its magic; regenerate it with generate.py"
    );

    let mut reader = Reader {
        bytes: &bytes,
        at: MAGIC.len(),
    };
    let count = reader.u32() as usize;

    let mut cases = Vec::with_capacity(count);
    for _ in 0..count {
        let name_len = reader.u32() as usize;
        let symbol_bits = reader.i32();
        let bypass_bits = reader.i32();
        let distributions = reader.u32() as usize;
        let table_len = reader.u32() as usize;
        let data_len = reader.u32() as usize;
        let stream_len = reader.u32() as usize;

        let name = String::from_utf8(reader.bytes(name_len)).expect("a utf-8 case name");
        cases.push(Case {
            name,
            symbol_bits,
            bypass_bits,
            pmf_lengths: reader.i32s(distributions),
            pmf_offsets: reader.i32s(distributions),
            pmf_table: reader.i32s(table_len),
            indices: reader.i32s(data_len),
            values: reader.i32s(data_len),
            stream: reader.bytes(stream_len),
        });
    }

    assert_eq!(reader.at, bytes.len(), "corpus should be exactly consumed");
    assert!(!cases.is_empty(), "corpus should contain cases");
    cases
}

impl Case {
    fn encoder(&self) -> Encoder {
        Encoder::new(
            &self.pmf_lengths,
            &self.pmf_offsets,
            &self.pmf_table,
            self.symbol_bits,
            self.bypass_bits,
        )
        .unwrap_or_else(|e| panic!("{}: tables should be accepted: {e}", self.name))
    }

    fn decoder(&self) -> Decoder {
        Decoder::new(
            &self.pmf_lengths,
            &self.pmf_offsets,
            &self.pmf_table,
            self.symbol_bits,
            self.bypass_bits,
        )
        .unwrap_or_else(|e| panic!("{}: tables should be accepted: {e}", self.name))
    }
}

#[test]
fn every_case_encodes_to_the_reference_bytes() {
    for case in corpus() {
        let produced = case
            .encoder()
            .encode(&case.indices, &case.values)
            .unwrap_or_else(|e| panic!("{}: should encode: {e}", case.name));

        assert_eq!(
            produced.len(),
            case.stream.len(),
            "{}: length differs, {} against {}",
            case.name,
            produced.len(),
            case.stream.len()
        );
        if produced != case.stream {
            let at = produced
                .iter()
                .zip(&case.stream)
                .position(|(a, b)| a != b)
                .expect("a difference must exist");
            panic!(
                "{}: byte {at} differs: produced {:#04x}, reference {:#04x}",
                case.name, produced[at], case.stream[at]
            );
        }
    }
}

#[test]
fn every_case_decodes_the_reference_bytes() {
    for case in corpus() {
        let mut decoded = vec![0i32; case.values.len()];
        case.decoder()
            .decode(&mut decoded, &case.indices, &case.stream)
            .unwrap_or_else(|e| panic!("{}: reference stream should decode: {e}", case.name));

        if decoded != case.values {
            let at = decoded
                .iter()
                .zip(&case.values)
                .position(|(a, b)| a != b)
                .expect("a difference must exist");
            panic!(
                "{}: value {at} differs: decoded {}, expected {} (index {}, offset {})",
                case.name,
                decoded[at],
                case.values[at],
                case.indices[at],
                case.pmf_offsets
                    [(case.indices[at].max(0) as usize).min(case.pmf_offsets.len() - 1)]
            );
        }
    }
}

/// The corpus should still be covering what it was built to cover.
///
/// A regenerated corpus that quietly lost its bypass or masked cases would leave
/// the two tests above passing while testing much less, and the failure would be
/// invisible. So state the coverage as a requirement.
#[test]
fn the_corpus_covers_masking_bypass_and_a_range_of_widths() {
    let cases = corpus();

    let mut masked_total = 0usize;
    let mut bypassed_total = 0usize;
    let mut symbol_widths = std::collections::BTreeSet::new();
    let mut bypass_widths = std::collections::BTreeSet::new();
    let mut longest_bypass_bits = 0u32;

    for case in &cases {
        symbol_widths.insert(case.symbol_bits);
        bypass_widths.insert(case.bypass_bits);

        let mut masked = 0usize;
        let mut bypassed = 0usize;
        for (&index, &value) in case.indices.iter().zip(&case.values) {
            if index < 0 {
                masked += 1;
                continue;
            }
            let d = (index as usize).min(case.pmf_lengths.len() - 1);
            let shifted = i64::from(value) + i64::from(case.pmf_offsets[d]);
            let sentinel = i64::from(case.pmf_lengths[d] - 1);
            if !(0..sentinel).contains(&shifted) {
                bypassed += 1;
                // How wide the bypass value itself was, which is what decides
                // how many digits it splits into.
                let bypass = if shifted < 0 {
                    2 * -shifted - 1
                } else {
                    2 * (shifted - sentinel)
                };
                longest_bypass_bits = longest_bypass_bits.max(64 - (bypass as u64).leading_zeros());
            }
        }
        masked_total += masked;
        bypassed_total += bypassed;

        println!(
            "{:26} sym {:2} byp {}  {:5} values  {:5} masked  {:5} bypassed  {:6} bytes",
            case.name,
            case.symbol_bits,
            case.bypass_bits,
            case.indices.len(),
            masked,
            bypassed,
            case.stream.len()
        );
    }

    assert!(masked_total > 1000, "masking is barely covered");
    assert!(bypassed_total > 1000, "bypass is barely covered");
    assert!(
        symbol_widths.len() >= 3,
        "should cover several symbol widths, got {symbol_widths:?}"
    );
    assert!(
        bypass_widths.len() >= 3,
        "should cover several bypass widths, got {bypass_widths:?}"
    );
    // A bypass value this wide needs thirteen digits at two bits each, which is
    // the multi-digit path the reference mishandles on the way back.
    assert!(
        longest_bypass_bits >= 24,
        "widest bypass value was only {longest_bypass_bits} bits"
    );
    println!(
        "\n{} cases, {masked_total} masked, {bypassed_total} bypassed, \
         widest bypass value {longest_bypass_bits} bits",
        cases.len()
    );
}

/// Corrupting a case's stream must not corrupt this process.
///
/// The corpus doubles as a seed set for hostile input: real streams with one
/// byte changed are far more likely to reach deep into the decoder than random
/// bytes are, because the header and the early symbols stay valid.
#[test]
fn corrupted_variants_of_real_streams_never_panic() {
    for case in corpus() {
        let decoder = case.decoder();
        let mut state = 0x9e37_79b9u32;

        for _ in 0..64 {
            let mut corrupted = case.stream.clone();
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            let at = (state as usize) % corrupted.len();
            corrupted[at] ^= (state >> 11) as u8 | 1;

            let mut decoded = vec![0i32; case.values.len()];
            // Any outcome is acceptable except a crash.
            let _ = decoder.decode(&mut decoded, &case.indices, &corrupted);
        }

        // And truncation at every plausible boundary.
        for cut in [0, 1, 3, 4, 5, case.stream.len() / 3, case.stream.len() - 1] {
            if cut > case.stream.len() {
                continue;
            }
            let mut decoded = vec![0i32; case.values.len()];
            let _ = decoder.decode(&mut decoded, &case.indices, &case.stream[..cut]);
        }
    }
}
