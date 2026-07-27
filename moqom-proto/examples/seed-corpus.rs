//! Write valid encodings of every wire type to a directory, to seed a fuzzer.
//!
//! Seeding is not optional for a structured format. Measured on this crate,
//! 20,000 random inputs produced zero successful `SUBSCRIBE` decodes — an
//! unseeded fuzzer spends its entire budget failing at the first field, and
//! reports clean because it never reached anything.
//!
//! ```text
//! cargo run --example seed-corpus --features testing -- fuzz/corpus/decoders
//! ```

use std::path::PathBuf;

fn main() -> std::io::Result<()> {
    let dir: PathBuf = std::env::args_os()
        .nth(1)
        .map_or_else(|| PathBuf::from("fuzz/corpus/decoders"), PathBuf::from);

    std::fs::create_dir_all(&dir)?;

    let corpus = moqom_proto::testing::seed_corpus();
    for (i, case) in corpus.iter().enumerate() {
        std::fs::write(dir.join(format!("seed-{i:04}")), case)?;
    }

    // Known-bad inputs belong in the corpus too, so a fuzz run starts from the
    // edges already known to be sharp rather than rediscovering them.
    for (i, case) in moqom_proto::testing::REGRESSION_CORPUS.iter().enumerate() {
        std::fs::write(dir.join(format!("regression-{i:04}")), case)?;
    }

    println!(
        "wrote {} seeds and {} regressions to {}",
        corpus.len(),
        moqom_proto::testing::REGRESSION_CORPUS.len(),
        dir.display()
    );
    Ok(())
}
