//! Every decoder in the crate, against the shared codec contract.
//!
//! Deliberately the same assertions the stable property tests run, so there is
//! one definition of correct rather than two that drift. What fuzzing adds is
//! coverage guidance: it finds the byte sequences that reach deep into a
//! decoder, which random generation does not.
//!
//! Seed the corpus first, or this spends its budget rediscovering the shape of
//! a varint:
//!
//! ```text
//! cargo run --example seed-corpus --features testing -p moqom-proto -- fuzz/corpus/decoders
//! cargo +nightly fuzz run decoders
//! ```

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    moqom_proto::testing::assert_all_decoder_contracts(data);
});
