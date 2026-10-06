//! Regenerates the recorder-link bindings, on request only.
//!
//! The output is checked in and this does nothing unless `MOQOM_REGENERATE_PROTO`
//! is set, for the reason the relay gives: `protoc` should not stand between this
//! crate and `cargo build`. Both halves are generated because the tests answer
//! the link with a fake control plane on a loopback port.

fn main() {
    println!("cargo:rerun-if-env-changed=MOQOM_REGENERATE_PROTO");

    if std::env::var_os("MOQOM_REGENERATE_PROTO").is_none() {
        return;
    }

    let root = match std::env::var_os("MOQOM_PROTO_ROOT") {
        Some(given) => std::path::PathBuf::from(given),
        None => std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../moqom/proto"),
    }
    .canonicalize()
    .expect(
        "the proto directory is where it is expected: set MOQOM_PROTO_ROOT, \
         or check out moqom-cloud/moqom beside this repository",
    );
    let out = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/generated");
    std::fs::create_dir_all(&out).expect("creating the generated directory");

    let files = [root.join("moqom/recorder/v1/recorder.proto")];
    for file in &files {
        println!("cargo:rerun-if-changed={}", file.display());
    }
    tonic_prost_build::configure()
        .build_server(true)
        .build_client(true)
        .out_dir(&out)
        .compile_protos(&files, &[root])
        .expect("compiling the recorder link's proto");
}
