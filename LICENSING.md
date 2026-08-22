# Licensing

This repository spans both of MOQOM's licence halves, and the line between them
is the same one drawn in the [platform
repository](https://github.com/moqom-cloud/moqom/blob/main/LICENSING.md): the
pieces you build *against* are permissive, and the server that constitutes the
product is source-available.

| Crate | License | Why |
|---|---|---|
| `moqom-proto` | Apache-2.0 | An implementation of an IETF draft. Nobody should need permission to speak a standard. |
| `moqom-transport` | Apache-2.0 | QUIC and WebTransport session establishment — the other half of being able to speak it. |
| `moqom-client` | Apache-2.0 | A MOQT subscriber and publisher. Receiving frames is this crate, not the admin SDK. |
| `moqom-media` | Apache-2.0 | Reading coded video into objects. Framing, not decoding, and shared by the binary that publishes a file and the harness that measures with one. |
| `moqom-cli` | Apache-2.0 | The `moqom` binary. It uses only `moqom-client`'s public API. |
| `moqom-loadgen` | Apache-2.0 | A load harness. It measures the relay from outside, over a socket, and links none of it — so it sits with `fuzz` rather than with the product, and a customer sizing their own deployment can use it. |
| `moqom-relay` | BUSL-1.1 → Apache-2.0 | The server. This is the product. |
| `fuzz` | Apache-2.0 | Test harness for the Apache half. |
| `vendor/quinn` | MIT OR Apache-2.0 | Upstream's, unmodified. See `vendor/quinn-rationale.md`. |

Full texts are in [`LICENSES/`](LICENSES/). **Every crate declares its own
`license` field, and a crate without one is a bug** — this workspace spans both
halves, so there is no safe default to fall back on and no workspace-level
`license` to inherit.

## Why both halves share a workspace

Keeping a BUSL crate beside Apache ones is a deliberate trade, made once and
worth restating because it looks like an oversight.

`moqom-relay` depends on `moqom-proto` by path. While
[draft-ietf-moq-transport](https://datatracker.ietf.org/doc/draft-ietf-moq-transport/)
is still moving, the codec and its principal consumer change together, often in
the same commit. Splitting them across repositories would turn every protocol
correction into a version bump, a release, and a lag during which the two are
provably out of step — for a codec whose entire job is that two implementations
agree byte for byte.

The cost of keeping them together is that a licence scanner sees one repository
with two answers. That cost is paid by the per-crate `license` fields, which are
what any scanner actually reads, and by this file. The cost of separating them
would be paid on every protocol change.

If the draft reaches RFC and `moqom-proto` stops moving weekly, this reasoning
expires and the Apache crates should be split out.

## Consuming only the permissive half

`moqom-proto`, `moqom-transport`, and `moqom-client` carry no dependency on `moqom-relay` —
the arrow points the other way. Depending on either of them pulls in no
BUSL code, and `cargo tree` is the check rather than this sentence.

What they *do* pull in is the `[patch.crates-io]` at the workspace root, which
redirects `quinn` to the vendored tree. That is a property of building inside
this workspace, not of the crates themselves, but it is the reason the backend
SDKs live in [`moqom-rust`](https://github.com/moqom-cloud/moqom-rust) and
[`moqom-go`](https://github.com/moqom-cloud/moqom-go) instead of here: a
customer's backend should not acquire a QUIC stack for the sake of kicking
somebody out of a room.
