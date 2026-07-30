//! The entropy decoder against arbitrary bytes.
//!
//! This is the most exposed parser MOQOM has. A viewer decodes a bitstream
//! produced by whoever is broadcasting, and under end-to-end encryption no relay
//! has been able to look at it first — so every byte reaching this code is
//! attacker-controlled by construction, on the device of someone who only joined
//! to watch.
//!
//! The C++ this was ported from has undefined behaviour reachable from here: a
//! bypass length claiming more digits than a `u32` holds makes it shift a `u32`
//! by up to 62 bits. The port rejects that, and this target is what keeps it
//! rejected.
//!
//! The property is simply that nothing panics and nothing hangs. Correctness for
//! well-formed streams is settled elsewhere, byte-for-byte against the
//! reference's own recorded vectors; there is no oracle for garbage, and inventing
//! one would only test this crate against itself.
//!
//! ```text
//! cargo +nightly fuzz run rans_decoder
//! ```
//!
//! Seeding is worth the trouble here, because a random stream usually dies at the
//! four-byte state check and never reaches the table walk. The corpus in
//! `moqom-rans/tests/fixtures` holds real streams:
//!
//! ```text
//! mkdir -p fuzz/corpus/rans_decoder
//! cp ../moqom-rans/tests/fixtures/*/bitstream.bin fuzz/corpus/rans_decoder/
//! ```

#![no_main]

use libfuzzer_sys::fuzz_target;
use moqom_rans::Decoder;

/// Tables shaped like the ones MLVC builds, so the fuzzer spends its budget on
/// the stream rather than on discovering that a table was rejected.
///
/// Built once per process. Several distributions of differing length, a sentinel
/// in each, and totals that sometimes fall short of the scale — all the shapes
/// the decoder has to walk.
fn decoder() -> Decoder {
    let scale = 1 << 16;
    let mut lengths = Vec::new();
    let mut offsets = Vec::new();
    let mut table = Vec::new();

    for i in 0..16u32 {
        let length = 2 + (i % 7) as usize;
        lengths.push(length as i32);
        // Zero sometimes sits outside the range, which makes a distribution
        // reachable only through bypass.
        offsets.push((i % 5) as i32 - 1);

        // Skewed, and deliberately not always summing to the scale: a total
        // below it leaves part of the code space mapping to no symbol, which is
        // permitted and is the case where the interval search runs off its end.
        let mut remaining = scale - length as i32;
        for j in 0..length {
            let freq = if j + 1 == length {
                1 + remaining / 2
            } else {
                1 + remaining / 3
            };
            remaining -= freq - 1;
            table.push(freq);
        }
    }

    Decoder::new(&lengths, &offsets, &table, 16, 2).expect("hand-built tables should be valid")
}

fuzz_target!(|data: &[u8]| {
    // One decoder for the whole run. Rebuilding it per input would spend most of
    // the CPU budget on table construction, which has its own tests.
    use std::sync::OnceLock;
    static DECODER: OnceLock<Decoder> = OnceLock::new();
    let decoder = DECODER.get_or_init(decoder);

    // The first byte picks how many values to ask for and which distributions to
    // draw them from, so that one corpus entry can exercise different shapes of
    // request against the same bytes. Taken from the input rather than fixed
    // because the number of symbols requested is what decides how deep into the
    // stream the decoder walks.
    let (control, stream) = data.split_first().unwrap_or((&0, &[]));
    let count = 1 + (*control as usize % 512);

    let indices: Vec<i32> = (0..count)
        .map(|i| {
            // A quarter masked, and some indices past the end so the clamp is
            // exercised too.
            match (i + *control as usize) % 4 {
                0 => -1,
                _ => ((i * 7 + *control as usize) % 20) as i32,
            }
        })
        .collect();

    let mut values = vec![0i32; count];
    let _ = decoder.decode(&mut values, &indices, stream);
});
