# MOQOM Engine

The media path of the **Media Over QUIC Orchestration Mesh**: the protocol
codec, the transport, and the relay. Pure Rust, and everything here sits between
a publisher and a subscriber.

Targets [`draft-ietf-moq-transport`](https://datatracker.ietf.org/doc/draft-ietf-moq-transport/)
drafts 22 and 19, chosen per session by ALPN. The relay accepts `moqt-22` and
`moqt-19` and prefers 22. The client offers both, and also speaks a draft-16
subset (`moqom_client::cloudflare`, `moqom cloudflare sub`) for subscribing
through Cloudflare's relay. Direct links and WebTransport sessions are draft-19.
The implementation is our own rather than a fork, because owning the wire format
is what makes the congestion controller, the object-to-transport mapping, and
end-to-end encryption our decisions instead of someone else's.

| Crate | License | What |
| --- | --- | --- |
| `moqom-proto` | Apache-2.0 | The object model, control messages, and data plane, per draft (`Draft::{D16, D19, D22}`) |
| `moqom-transport` | Apache-2.0 | QUIC and WebTransport sessions on one UDP port |
| `moqom-client` | Apache-2.0 | A MOQT subscriber and publisher for recorders, classifiers, and the CLI; direct (peer-to-peer) sessions in `direct` |
| `moqom-direct-ffi` | Apache-2.0 | C ABI for the direct path's socket (STUN, NAT probes, pinned QUIC on one port), built into `MoqomDirectFFI.xcframework` for the Swift SDK |
| `moqom-cli` | Apache-2.0 | The `moqom` binary: `subscribe`, `publish` and `cloudflare sub`, using only `moqom-client` |
| `moqom-media` | Apache-2.0 | Framing coded video into MOQOM objects, shared by the CLI and the load generator |
| `moqom-loadgen` | Apache-2.0 | Load generation and relay measurement |
| `moqom-relay` | Proprietary | The relay: announcement, subscription, fan-out, retention, authorisation, usage metering, direct tickets |
| `moqom-recorder` | Proprietary | The hosted recorder: joins as a subscribe-only viewer and writes what it receives |
| `fuzz` | Apache-2.0 | Coverage-guided harnesses for the decoders |

Two licences in one workspace is deliberate and [LICENSING.md](LICENSING.md)
explains the trade. The short version: the relay depends on the codec by path,
and while the draft is still moving they change in the same commit.

## Status

Media moves. `moqom-proto` covers the object model, every control message in
draft-19, and the whole data plane: object datagrams, subgroup streams, and
fetch streams with the gap markers a partial cache needs. `moqom-transport`
accepts sessions over both QUIC and WebTransport on one UDP port, and
`moqom-relay` speaks MOQT over them: setup, namespace announcement and
withdrawal, prefix watching, subscription, and subgroup fan-out with alias
rewriting.

Two iPhones on a home network, through a relay in Los Angeles, measure 56–57ms
glass to glass at the median and 70ms at the 95th percentile: 720p at thirty
frames a second, both directions at once, every frame delivered.

History is retained and fetchable, which is what makes a reconnection
survivable. A client that dropped its connection asks for the range it missed; a
client joining a live track asks for the group already in progress rather than
waiting out a keyframe interval of black. Retention is bounded by group count
and by byte budget, evicting whole groups because half a group is undecodable,
and can be turned off entirely for operators who must not store media. Caching
is a tee off the forward path rather than a stage in it — forwarding still never
parses an object, so end-to-end encryption and retention stay compatible.

One track is pulled once. However many people watch a broadcast the publisher is
asked for it a single time, and every copy after the first is made here — the
arithmetic a relay is bought for, and `moqom_relay_subscriptions_total` reports
it directly, `established` counting the copies the publisher paid for and
`shared` the ones it did not. Each copy is then written by its own task behind a
short bounded queue, so a viewer that cannot keep up has that subgroup abandoned
— its stream reset, and the shed counted — instead of holding up the room or
backing pressure up into the publisher's phone. What the relay will not do is
pick a smaller rung on that viewer's behalf: the layers belong to the publisher
and the choice to the subscriber, and shedding is what turns the condition into
something the subscriber can see and act on.

Subscriptions end at both ends, which sounds like bookkeeping and is not.
Closing a request stream is how MOQT spells unsubscribe, and when the last
viewer of a track does it the relay stops pulling that track — the publisher is
usually a phone, and a room that empties should stop costing the person who
left it. In the other direction a publisher that stops is announced to every
viewer with `PUBLISH_DONE`, because objects merely ceasing is also what a bad
network looks like, and a player is right to wait a bad network out.

Sessions are authenticated and authorised. A token's tenant, room and grants are
checked against the namespace every request names, so a holder may publish only
as themselves, in the room they were admitted to, and may read only what that
room contains; refusals are counted by reason. A token's lifetime bounds the
session and not merely the joining of it: the relay closes a session whose
credential has lapsed, and a client that wants to outlast its token presents a
fresh one on a stream it already has — draft-19's `REQUEST_UPDATE` carries an
authorization token, so this costs no reconnection. A renewal may move the
deadline and nothing else; a token naming a different holder or a different scope
is refused, and the session carries on under the credential it had.

A token also names the device it was issued to, in `cnf.jkt`, and the relay
makes that name mean something. By default (`MOQOM_RELAY_POSSESSION=required`) every
place a token is checked — SETUP and each renewal — also demands an ES256
signature from the key the thumbprint identifies, over the token it accompanies
and over this relay's certificate, usable once. So a token read off a log or out
of a capture is worth nothing to anybody without the Secure Enclave it was bound
to, and one taken from a session here cannot be spent at another relay.
`observed` verifies a proof when one is offered and admits a session that offers
none, for upgrading a fleet that still has old clients; `bearer` turns it off.
Both log a warning at startup and on every session admitted without a proof. Note the shape of the other default: with no
keys configured there is no verified tenant to compare anything against, and such
a relay authorises nothing at all — nor holds anybody to an expiry, nor asks
anybody to prove anything. That is the mode the benchmarks and the two-phone rig
run in.

The relay can be watched. An admin surface on its own port — off unless
`MOQOM_RELAY_ADMIN_ADDR` says otherwise — exposes Prometheus metrics for
sessions, subscriptions, fetches, fan-out and bytes, plus JSON snapshots of live
sessions, occupied rooms and forwarded tracks, and separate liveness and
readiness so draining stops new connections without killing the ones in flight.
Round-trip time, congestion window and loss are sampled from the QUIC connection
itself rather than estimated a second time. Metric labels are fixed and
low-cardinality; anything per-room or per-participant lives in the JSON, because
a label whose values grow with traffic is how a metrics backend becomes an
outage.

Track silence is reported alongside all that, because it is the one failure no
transport signal reaches: a publisher whose camera freezes keeps a healthy
connection and an unbroken announcement while its viewers watch a still picture.
`/tracks` names which track stopped and how long ago; `/metrics` carries only the
population, bucketed.

Revoking access during a session does work, and against the connection already
open rather than at the next token: `tests/interop_link.rs` bans a joined client
through the real Go control plane's admin API and asserts the phone's connection
closes. Unbanning and ending a room travel the same link. Those need a Go
toolchain, so they are `#[ignore]`d and run by `moqom/tools/interop.sh`.

The admin surface is guarded. A listener on anything but loopback refuses to
start unless it has a bearer token (`MOQOM_RELAY_ADMIN_TOKEN_FILE`), mutual TLS
against an operator authority (`MOQOM_RELAY_ADMIN_CLIENT_CA`), or
`MOQOM_RELAY_ADMIN_AUTH=probes-only`, which serves only liveness and readiness
for a load balancer's health check. `MOQOM_RELAY_ADMIN_LOCAL_ADDR` adds a second,
loopback-only listener with the whole surface, for an OpenZiti tunneler on the
same machine to host as a dark service. That is how MOQOM's own relays run: probes
on the network, metrics and sessions only to enrolled operator identities. The
overlay itself is in `moqom/docs/OPENZITI-AND-P2P.md`.

Usage is metered here (`src/usage`). Every session's connected seconds, role,
tier and bytes are written as records every `MOQOM_RELAY_USAGE_INTERVAL` seconds
and posted to the control plane's `/v1/usage`, queued while it is unreachable. A
self-hosted relay reports against its own `mqk_` key (`MOQOM_RELAY_USAGE_KEY_FILE`)
and stops admitting new sessions when that account says it is not admitting.

Direct calls are metered by ticket (`src/ticket.rs`), because their media never
reaches a relay. A participant on a direct path subscribes to its own
`.direct/{peerUser}/{peerDevice}` track; the relay answers with an ML-DSA-65-signed
ticket about once a minute and counts those seconds as `direct_seconds`. Each
peer holds the other to its tickets (`moqom-client`'s `direct` module, and the
Swift SDK), so an app that drops the relay session loses the direct path. Keys
come from `MOQOM_RELAY_TICKET_KEYS`; unset, no tickets are issued and nobody on
that relay goes direct. The relay also honours `FORWARD=0` on `REQUEST_UPDATE`,
which pauses a subscriber's relay copy while its direct path carries the media.
The design, including the two-modified-apps limitation, is in
`moqom/docs/OPENZITI-AND-P2P.md` under "Direct tickets and billing".

Key exchange prefers post-quantum. The workspace enables rustls's
`prefer-post-quantum`, so every TLS configuration here offers the hybrid
X25519MLKEM768 first and plain X25519 second. That covers the relay listener,
the client, relay links, direct paths, and gRPC. `moqom-client/tests/post_quantum.rs`
completes real handshakes and asserts the negotiated group, for both the
listener and both ends of a direct path. A classical peer still connects:
X25519 costs no extra round trip, and only a peer with neither group pays for a
HelloRetryRequest. Certificates are still classical.

Direct paths are dual-stack. The socket binds `[::]` with IPv4 mapped onto it,
or IPv4 alone where the host has no IPv6. It gathers a host candidate and a
STUN reflexive address for each family it can reach, and probes and dials
either. `moqom-client/tests/ipv6.rs` runs on `::1`.

The relay answers STUN Binding requests on its own UDP socket, 3478 by default
(`MOQOM_RELAY_STUN_ADDR`, or `off`), so a device behind NAT can learn its
public address without a third-party server. Only well-formed Binding requests
get an answer: XOR-MAPPED-ADDRESS and FINGERPRINT, smaller than the request.
Anything else is dropped. Each source address, or IPv6 /64, has a token bucket
(`MOQOM_RELAY_STUN_RATE`, `MOQOM_RELAY_STUN_BURST`). The reply leaves from the
address the request was sent to, so it works behind a passthrough load
balancer. The control plane names this server in a room's direct grant, and
`DirectPolicy::AUTOMATIC` asks it unless the application named its own.
`moqom-relay/tests/stun.rs` runs the client against the relay.

Draft-22 authorization tokens parse in all four Alias Types (§8.9), and
`moqom_proto::control::tokens::TokenCache` keeps the alias state with the
accounting of §9.1.3. The relay advertises no token cache, so a registration or
an alias reference in a `REQUEST_UPDATE` closes the session with the error
code §8.9 gives it. A draft-22 `TRACK_STATUS` is answered from what the relay
holds: the `LARGEST_OBJECT` a `SUBSCRIBE_OK` would carry, behind the same
checks. The relay neither forwards the query nor subscribes to answer it.

**What the relay is not yet:** scheduling between the rungs of one broadcast
under pressure, which is `moqom-cc`'s job, or forwarding datagrams; only subgroup
streams are carried. `moqom-relay/src/lib.rs` lists the remaining gaps and says
which matter.

## Development

Requires the toolchain pinned in `rust-toolchain.toml`, which rustup installs
automatically.

```sh
cargo fmt --all --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-features
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --all-features
```

All four, in that order, are what CI runs — the last one included, since a
broken intra-doc link fails the build and nothing about it fails a test.

**On a Mac, that is not the whole check.** The relay reads the kernel's clock
health through `adjtimex`, which is behind `cfg(target_os = "linux")`, so a
local run compiles the other branch and never sees that code. CI is the only
thing that builds it.

`quinn` is vendored under `vendor/` and patched in at the workspace root, so a
build here links our copy rather than the registry's. Both halves of that claim
decay silently, so both are checked rather than trusted:

```sh
./vendor/verify-quinn.sh    # unmodified, and actually the copy being linked
```

## Testing the codec

A wire codec fails in a small number of ways, and they recur for every message
type. `encoded_len` disagreeing with `encode` corrupts the enclosing frame's
length field rather than failing locally. A peer-supplied count drives an
allocation before anything bounds it. A decoder reads past its own region and
desynchronises everything after it. A field is silently dropped on decode, which
a round-trip test can never see because it only ever replays values the encoder
produced.

Eighteen control messages and two data-plane mappings share the same handful of
failure modes, so the contract is stated once, in `moqom-proto/src/testing.rs`,
and enforced uniformly. Adding a wire type means implementing `Codec` and adding
one line to `assert_all_decoder_contracts`; it then inherits every check, and an
omission is visible in one place instead of being a hazard you had to remember.

One measurement shaped the design. Against 20,000 uniformly random inputs, the
`SUBSCRIBE` decoder succeeded **zero** times and the frame decoder once — so the
idempotence check, the only one that can catch a dropped field, was never
running. Random bytes are close to worthless against a structured format. The
suite instead mutates valid encodings from `seed_corpus()`, which lifts those
counts into the thousands, and
`mutation_actually_reaches_the_interesting_decoders` asserts a floor so it
cannot quietly regress to testing nothing.

Fuzzing runs the same assertions with coverage guidance:

```sh
cargo run --example seed-corpus --features testing -- fuzz/corpus/decoders
cargo +nightly fuzz run decoders
```

Seeding is not optional, for the same reason. CI runs a 60-second smoke pass per
target on every change and deeper scheduled runs in `fuzz.yml`. Crashes get
transcribed into `REGRESSION_CORPUS`, so they run on stable forever rather than
living in an artifact nobody opens again.

**What none of this catches: misreading the draft.** A rule misread the same way
in both the encoder and the decoder is self-consistent, and every check here
passes. Only differential testing against an independent implementation closes
that gap. The first of it exists:
[`MoqomKit`](https://github.com/moqom-cloud/moqom-swift)'s codec was written
separately from this one, and its interop suite runs a Swift publisher and a
Swift subscriber through `moqom-relay` over a real socket. Two implementations
that agree is a weaker claim than two written from the draft by different
people, so interop against `moq-rs` and `moxygen` remains a milestone rather
than a nice-to-have.

## Cross-repository seams

Two things here are checked against code that lives elsewhere.

**Token verification.** `moqom-relay/tests/testdata/tokens.json` is minted by
the Go control plane and verified here. It is committed rather than generated on
demand so that `cargo test` needs no Go toolchain — which is the whole point,
since it means the check runs on every build instead of only where a harness is
set up. Regenerate it from the platform repository with `MOQOM_WRITE_FIXTURES=1
go test ./internal/token/`.

**The protocol.** `MoqomKit` carries a second implementation of the same draft,
and its interop tests run against a relay built from this repository. A change
to the wire format here that is not mirrored there will fail over there, not
here.

**The direct-path ABI.** `moqom-direct-ffi/include/moqom_direct.h` is written by
hand and is what the Swift SDK's `MoqomDirectRust` codes against. Change it
together with that SDK, and bump `MOQOM_DIRECT_ABI_VERSION` on any incompatible
change.

## Design notes

Two documents are worth reading before changing protocol code:

- `moqom-proto/src/coding.rs` — the streaming-decode contract. Only
  `VarInt::decode` leaves the buffer intact on a short read; assuming that of
  other decoders will corrupt a session.
- `moqom-proto/src/error.rs` — why "incomplete" and "malformed" are different
  types. One means wait, the other means close the connection.

## The rest of MOQOM

| Repository | License | What |
| --- | --- | --- |
| [`moqom`](https://github.com/moqom-cloud/moqom) | Mixed | The platform: control plane, the gRPC contract, deployment, and the plan |
| [`moqom-swift`](https://github.com/moqom-cloud/moqom-swift) | Apache-2.0 | `MoqomKit`, the Apple-platform client SDK |
| [`moqom-go`](https://github.com/moqom-cloud/moqom-go) | Apache-2.0 | Server-side SDK for backends |
| [`moqom-rust`](https://github.com/moqom-cloud/moqom-rust) | Apache-2.0 | Server-side SDK for backends |

The backend SDKs are deliberately not here. Neither speaks MOQT: administering a
room and carrying media are different jobs, and making every backend link a QUIC
stack to change somebody's grants would be a poor trade. Since the
`[patch.crates-io]` at this workspace root applies to everything inside it,
"not in this workspace" is what enforces that rather than good intentions.

## Contributing

Contributions require signing the [CLA](https://github.com/moqom-cloud/moqom/blob/main/.github/CLA.md).
MOQOM is dual-licensed and the CLA permits relicensing — Section 4 spells out
exactly what that means, because it is the term most worth reading before you
agree to it.
