//! Regenerates the control-plane bindings, on request only.
//!
//! The generated files are checked in and this does nothing unless
//! `MOQOM_REGENERATE_PROTO` is set. Generating on every build would put `protoc`
//! between this crate and `cargo build`, which is a poor thing to demand of a
//! relay that anybody has to be able to compile in a hurry — and the contract
//! changes when the control plane's API does, which is not often and never
//! silently.
//!
//! Both halves are built although a relay only ever dials out. The server half
//! is what the link's tests implement: a fake control plane on a loopback port,
//! which is the only way to test this code against a real gRPC stream rather
//! than against a mock of one — and the failures worth catching here (a stream
//! that breaks, a peer that stops reading, a reattach) are all properties of the
//! stream.

fn main() {
    println!("cargo:rerun-if-env-changed=MOQOM_REGENERATE_PROTO");

    if std::env::var_os("MOQOM_REGENERATE_PROTO").is_none() {
        return;
    }

    // The contract lives in the platform repository, which is a different
    // repository to this one. `MOQOM_PROTO_ROOT` says where it is; the fallback
    // assumes the two are siblings, which is where they land if you cloned both
    // into the same directory.
    let root = match std::env::var_os("MOQOM_PROTO_ROOT") {
        Some(given) => std::path::PathBuf::from(given),
        None => std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../moqom/proto"),
    }
    .canonicalize()
    .expect(
        "the proto directory is where it is expected: set MOQOM_PROTO_ROOT, \
         or check out moqom-cloud/moqom beside this repository",
    );
    let manifest = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));

    let link = [
        root.join("moqom/admin/v1/common.proto"),
        root.join("moqom/admin/v1/tokens.proto"),
        root.join("moqom/relay/v1/relay.proto"),
    ];
    generate(&link, &root, &manifest.join("src/generated"), Serves::Both);

    // The admin API, for the tests only. `tests/interop_link.rs` has to be the
    // customer's backend as well as the relay -- create a room, mint a token,
    // issue a ban -- and there is no other way to check that a moderator's call
    // ends in somebody's connection closing. It is generated apart from the
    // bindings above and included from the test, so a relay binary carries no
    // client for an API it must never call.
    let admin = [
        root.join("moqom/admin/v1/common.proto"),
        root.join("moqom/admin/v1/tokens.proto"),
        root.join("moqom/admin/v1/rooms.proto"),
        root.join("moqom/admin/v1/moderation.proto"),
    ];
    generate(
        &admin,
        &root,
        &manifest.join("tests/generated"),
        Serves::Client,
    );
}

/// Which halves of a service are worth generating.
#[derive(Clone, Copy)]
enum Serves {
    /// Both, for the link: the relay dials out and its tests answer.
    Both,
    /// The calling half only. Nothing here ever implements the admin API.
    Client,
}

fn generate(
    files: &[std::path::PathBuf],
    root: &std::path::Path,
    out: &std::path::Path,
    serves: Serves,
) {
    std::fs::create_dir_all(out).expect("creating the generated directory");
    for file in files {
        println!("cargo:rerun-if-changed={}", file.display());
    }

    tonic_prost_build::configure()
        .build_server(matches!(serves, Serves::Both))
        .build_client(true)
        .out_dir(out)
        .compile_protos(files, &[root.to_path_buf()])
        .expect("compiling the control plane's protos");
}
