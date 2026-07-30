//! What the coder costs, on the reference's own data.
//!
//! Exists to settle a claim rather than to tune anything. Choosing Rust over C++
//! for this crate was argued on safety and portability, with performance asserted
//! to be a wash — both compilers are LLVM and the hot loop is scalar integer work
//! with a table lookup. An assertion like that should be checked, and the C++
//! side of the comparison is `throughput.py`, which drives the reference through
//! the same Python API the models use.
//!
//! It also answers a question the device benchmark needs: the `CoreML` export
//! measures the neural half only, and the reference pipeline leaves about a third
//! of its frame time in neither model. Some of that is Python and numpy, and some
//! is this. Knowing which matters, because a phone that can run the network in
//! time can still miss the frame if the entropy coder is slow.
//!
//! ```text
//! cargo run --release --example throughput -p moqom-rans
//! ```
//!
//! Release matters more than usual: a debug build reports roughly an order of
//! magnitude less and would make the comparison meaningless.
//!
//! # Measure the shipped tables, not the fixtures
//!
//! The checked-in fixtures are a bad guide to cost, and taking them at face value
//! gave the wrong answer for a while. `gaussian_encoder0` is 99.7% zeros and codes
//! 58,880 symbols into 108 bytes, so it hardly ever renormalises and runs about
//! twice as fast per symbol as a real frame; `bit_estimator_z0` is 75% zeros. They
//! are golden vectors, chosen to pin down behaviour, and nobody promised they were
//! representative.
//!
//! What a client is actually handed comes out of `convert.py export`, which writes
//! `gaussian_pmf.json` and `bit_estimator_pmf.json` beside the `CoreML` packages.
//! `deployment-tables.py` converts those into this layout, along with latents of
//! the right shape and every case a frame contains, so:
//!
//! ```text
//! uv run python deployment-tables.py <export>/640x368
//! cargo run --release --example throughput -p moqom-rans -- --tables /tmp/mlvc-tables
//! ```
//!
//! It checks byte-for-byte against a reference-produced stream when the converter
//! found the reference installed, so this doubles as a differential test on the
//! tables that will really be deployed rather than only on 2024's.
//!
//! # What it measured, on an M1 Pro
//!
//! On the shipped tables at 640x368, one frame — two y halves of 58,880 symbols
//! and 6,400 of z — costs 0.75ms to encode and 2.22ms to decode. The C++ takes
//! 0.76ms and 2.48ms, so encode is a wash and decode is about 11% in this crate's
//! favour. The "performance is a wash" claim holds.
//!
//! It did not look that way on the fixtures, where decode measured 13% and 24%
//! *slower* than the C++. That gap was an artefact of the degenerate bitrate: with
//! almost every symbol the most probable one, the reference's tighter renormalise
//! loop is all that is being timed. At a realistic bitrate the per-symbol table
//! work dominates and the ordering reverses. Worth remembering as a general point
//! about this coder — its cost tracks bits emitted, not symbols coded.
//!
//! Two changes were made while chasing the apparent gap and both were kept:
//! taking each distribution's frequencies as one slice to hoist the per-symbol
//! bounds checks, and moving the per-symbol overflow check to table construction.
//! Neither is worth much, but the second belongs there regardless.
//!
//! Either way it is not the number that decides anything. 2.2ms of decode sits
//! against 13.7ms for the neural decoder at this resolution, so the coder is
//! roughly a seventh of the decode path — enough to matter in a 33.3ms frame
//! budget, not enough for the language choice to.

// A benchmark's arithmetic is reporting, not correctness: symbol counts become
// floats to divide by a duration, and paths are printed for a human who is about to
// go and look at them.
#![allow(clippy::cast_precision_loss, clippy::unnecessary_debug_formatting)]

use moqom_rans::{Decoder, Encoder};
use std::path::{Path, PathBuf};
use std::time::Instant;

fn i32s(bytes: &[u8]) -> Vec<i32> {
    bytes
        .chunks_exact(4)
        .map(|c| i32::from_le_bytes([c[0], c[1], c[2], c[3]]))
        .collect()
}

struct Case {
    name: String,
    symbol_bits: i32,
    bypass_bits: i32,
    lengths: Vec<i32>,
    offsets: Vec<i32>,
    table: Vec<i32>,
    indices: Vec<i32>,
    values: Vec<i32>,
    /// The reference's bytes, when they are available. Absent means the converter
    /// ran without the reference installed, and the only check left is a round
    /// trip through this crate.
    stream: Option<Vec<u8>>,
}

fn load(dir: &Path, bits: Option<(i32, i32)>) -> Case {
    let read = |file: &str| std::fs::read(dir.join(file)).expect("a readable fixture");
    let (symbol_bits, bypass_bits) = bits.unwrap_or_else(|| {
        let text = std::fs::read_to_string(dir.join("bits.txt")).expect("bits.txt");
        let mut parts = text.split_whitespace();
        let mut next = || parts.next().expect("two integers").parse().expect("integer");
        (next(), next())
    });
    Case {
        name: dir
            .file_name()
            .expect("a named directory")
            .to_string_lossy()
            .into_owned(),
        symbol_bits,
        bypass_bits,
        lengths: i32s(&read("pmf_lengths.np")),
        offsets: i32s(&read("pmf_offsets.np")),
        table: i32s(&read("pmf_table.np")),
        indices: i32s(&read("indices.np")),
        values: i32s(&read("values.np")),
        stream: std::fs::read(dir.join("bitstream.bin")).ok(),
    }
}

/// Median of repeated runs, rather than a mean or a best-of.
///
/// A mean is dragged around by the occasional scheduler interruption, and a
/// best-of reports a number the code will not reproduce in a real pipeline. The
/// median of enough runs is the one a caller will actually see.
fn median_micros(runs: usize, mut body: impl FnMut()) -> f64 {
    let mut samples = Vec::with_capacity(runs);
    for _ in 0..runs {
        let start = Instant::now();
        body();
        samples.push(start.elapsed().as_secs_f64() * 1e6);
    }
    samples.sort_by(f64::total_cmp);
    samples[samples.len() / 2]
}

/// Time one case, printing its row and returning its encode and decode medians.
fn measure(case: &Case) -> (f64, f64) {
    let build_encoder = || {
        Encoder::new(
            &case.lengths,
            &case.offsets,
            &case.table,
            case.symbol_bits,
            case.bypass_bits,
        )
        .expect("valid tables")
    };
    let build_decoder = || {
        Decoder::new(
            &case.lengths,
            &case.offsets,
            &case.table,
            case.symbol_bits,
            case.bypass_bits,
        )
        .expect("valid tables")
    };

    let build = median_micros(5, || {
        std::hint::black_box((build_encoder(), build_decoder()));
    });

    let encoder = build_encoder();
    let decoder = build_decoder();

    // Establish the numbers mean something before reporting how fast they were
    // produced. With the reference's bytes on hand this is the differential check;
    // without them it is a round trip, which still catches a table this crate
    // mishandles.
    let produced = encoder
        .encode(&case.indices, &case.values)
        .expect("encodable");
    if let Some(expected) = &case.stream {
        assert!(
            &produced == expected,
            "{}: produced {} bytes, reference produced {}",
            case.name,
            produced.len(),
            expected.len()
        );
    }
    let mut recovered = vec![0i32; case.values.len()];
    decoder
        .decode(&mut recovered, &case.indices, &produced)
        .expect("decodable");
    assert!(recovered == case.values, "{}: did not round-trip", case.name);

    // Warm up, so the first sample is not paying for page faults on the tables —
    // which for a real model are hundreds of kilobytes and would be resident.
    for _ in 0..20 {
        let _ = encoder.encode(&case.indices, &case.values);
    }

    let encode = median_micros(200, || {
        let out = encoder
            .encode(&case.indices, &case.values)
            .expect("encodable");
        // Consumed so the optimiser cannot delete the work. Cheap next to the
        // encode itself.
        std::hint::black_box(out);
    });

    let mut scratch = vec![0i32; case.values.len()];
    let decode = median_micros(200, || {
        decoder
            .decode(&mut scratch, &case.indices, &produced)
            .expect("decodable");
        std::hint::black_box(&scratch);
    });

    println!(
        "{:<18} {:>8} {:>8} {:>11.2} {:>11.1} {:>11.1} {:>11.1}",
        case.name,
        case.values.len(),
        produced.len(),
        build / 1000.0,
        encode,
        decode,
        case.values.len() as f64 / decode
    );

    (encode, decode)
}

fn collect_cases(tables: Option<&PathBuf>) -> Vec<Case> {
    let Some(root) = tables else {
        let fixtures = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
        return vec![
            load(&fixtures.join("bit_estimator_z0"), Some((16, 2))),
            load(&fixtures.join("gaussian_encoder0"), Some((16, 4))),
        ];
    };

    let mut dirs: Vec<PathBuf> = std::fs::read_dir(root)
        .expect("a readable directory")
        .filter_map(|e| {
            let path = e.expect("a readable entry").path();
            path.is_dir().then_some(path)
        })
        .collect();
    dirs.sort();
    assert!(!dirs.is_empty(), "no table directories under {root:?}");
    dirs.iter().map(|d| load(d, None)).collect()
}

fn main() {
    let mut args = std::env::args().skip(1);
    let tables = match args.next().as_deref() {
        Some("--tables") => Some(PathBuf::from(args.next().expect("a directory"))),
        Some(other) => {
            eprintln!("unexpected argument {other}, expected --tables <dir>");
            std::process::exit(2);
        }
        None => None,
    };

    let cases = collect_cases(tables.as_ref());

    println!(
        "{:<18} {:>8} {:>8} {:>11} {:>11} {:>11} {:>11}",
        "case", "symbols", "bytes", "build ms", "enc us", "dec us", "Msym/s dec"
    );

    let mut encode_total = 0.0;
    let mut decode_total = 0.0;
    for case in &cases {
        let (encode, decode) = measure(case);
        encode_total += encode;
        decode_total += decode;
    }

    println!();
    if tables.is_some() {
        // The converter emits every case a frame contains, so the totals are one
        // frame — but its values are drawn uniformly rather than from a real encode,
        // which escapes to the bypass path more often than a trained model would.
        // Treat this as a ceiling.
        println!(
            "One frame over all cases: {:.2}ms encode, {:.2}ms decode.",
            encode_total / 1000.0,
            decode_total / 1000.0
        );
        println!(
            "Values are synthetic and escape to bypass more than a real encode \
             would, so this is an upper bound."
        );
    } else {
        println!("Compare with the reference: uv run python throughput.py");
    }
    println!(
        "A frame budget at 30fps is 33333 us, and a cohost pays both columns \
         plus the network."
    );
}
