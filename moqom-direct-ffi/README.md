# moqom-direct-ffi

A C ABI for the socket half of MOQOM's direct (peer-to-peer) path, for the
Swift SDK's `MoqomDirectRust` backend. The contract is
[`include/moqom_direct.h`](include/moqom_direct.h); the Rust side is
`moqom_client::direct::socket`.

## Why it exists

Network.framework cannot share one UDP port between a [QUIC](https://www.rfc-editor.org/rfc/rfc9000) listener and plain
UDP flows: a flow to the peer's address takes the listener's packets. The
Swift SDK's own backend can therefore probe a NAT only in a short burst before
it starts listening. This library does [STUN](https://www.rfc-editor.org/rfc/rfc8489), NAT probes and QUIC on one std
socket, the way `moqom-client` does, and probes for as long as an
establishment takes.

It hands across exactly that layer: bind with STUN, probing, pinned mutual-TLS
dial and accept, streams, and datagrams. MOQT SETUP, peer verification,
admission and path merging stay in Swift.

## Building for Apple platforms

```sh
./build-apple.sh            # iOS device, iOS simulator, macOS (all arm64)
./build-apple.sh --device   # device only
```

Output: `target/MoqomDirectFFI.xcframework`, module `MoqomDirectFFI`. It builds
with `panic = "unwind"` so a panic reaches the boundary as
`MOQOM_DIRECT_PANIC`, and it pins `IPHONEOS_DEPLOYMENT_TARGET` and
`MACOSX_DEPLOYMENT_TARGET` to 26.0, the Swift package's floor, so rustc and the
C in aws-lc and ring agree.

A target linking the static library also needs `Security.framework` and
`CoreFoundation.framework`, which rustls's platform verifier and the standard
library use. Nothing else is required.

visionOS and tvOS are not built: their Rust targets are tier 3, with no
prebuilt standard library.

## Behaviour the header leaves open

The crate documentation (`src/lib.rs`) lists these, in short:

- Successful binds, dials and accepts pass a null `message`.
- Freeing an endpoint leaves its connections working.
- Freeing a send stream with writes pending cancels them and resets the stream
  with code 0; freeing one with nothing pending finishes it.
- Writes and reads on one stream complete in the order they were issued.
- A dial may return a connection that closes at once if the peer refuses this
  side's certificate, because [TLS 1.3](https://www.rfc-editor.org/rfc/rfc8446) clients finish before servers judge them.
- With datagrams off, none are sent or received, and the maximum datagram size
  reads zero.
- An endpoint binds `[::]` on the requested port, dual-stack, or falls back to
  IPv4 alone on a host without IPv6. Probe targets and dial addresses can be
  either family. The reflexive address reported is the IPv4 one when [STUN](https://www.rfc-editor.org/rfc/rfc8489)
  returned both.
- TLS prefers the hybrid [X25519MLKEM768](https://datatracker.ietf.org/doc/draft-ietf-tls-ecdhe-mlkem/) key exchange, with X25519 as the
  fallback.

## Testing

```sh
cargo test -p moqom-direct-ffi
```

The tests drive the library only through its `extern "C"` functions, with two
endpoints on loopback, a local [STUN](https://www.rfc-editor.org/rfc/rfc8489) responder, and a plain UDP socket watching
for probes.
