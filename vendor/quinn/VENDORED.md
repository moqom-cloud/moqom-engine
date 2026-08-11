# Vendored quinn

**Do not edit anything in this directory.** It is a copy of
[quinn-rs/quinn](https://github.com/quinn-rs/quinn) plus the patches recorded
below, and the whole point of it is that `vendor/verify-quinn.sh` reports an
empty diff once those patches are applied to the upstream tag. An edit made
here rather than in `vendor/patches` fails that check.

| | |
|---|---|
| Upstream | https://github.com/quinn-rs/quinn |
| Tag | `quinn-0.11.11` |
| Commit | `a7499b8439e393a6299330111d9c8564cd96c464` |
| Crates | `quinn` 0.11.11, `quinn-proto` 0.11.15, `quinn-udp` 0.5.14 |
| Licence | Apache-2.0 OR MIT (see `LICENSE-APACHE`, `LICENSE-MIT`) |

## Why vendor something we do not modify

The transport is the one dependency where being blocked matters. A QUIC bug
that reaches production cannot wait on an upstream release cycle, and a CVE in
`quinn-proto` is a same-day problem. Vendoring means the fix is a local patch
applied in minutes, reviewed against a diff we can read, and reverted just as
fast when upstream ships the real one.

It also pins the build. Cargo's lockfile pins versions, not availability; a
yanked crate or a registry outage stops a release. This does not.

The earlier plan was to fork and modify `quinn` outright, to own stream
prioritisation and the congestion controller. That was the wrong shape. Both
are already extension points — `quinn` takes a `Controller` implementation, and
stream priority is a public API — so a fork would have bought the same
capability at the cost of a permanent merge burden and a growing distance from
upstream's fuzzing and security review. `moqom-cc` plugs into the interface
instead. This directory stays byte-identical, and `verify-quinn.sh` in CI is
what keeps that claim honest rather than aspirational.

The consequence worth stating: **if we ever do patch, the diff must be small,
temporary, and accompanied by an upstream PR link in this file.** A permanent
local patch means the decision above was reversed, and it should be reversed
deliberately rather than by accretion.

## Patches

Held as files in `vendor/patches` and applied to the upstream tag by
`verify-quinn.sh`, so the tree here is still fully described by "the tag, plus
this list". Delete a patch when upstream carries it, and the diff returns to
empty on its own.

### `0001-preserve-socket-dscp.patch`

| | |
|---|---|
| Upstream PR | *not yet opened — see below* |
| Issue | https://github.com/quinn-rs/quinn/issues/1749 |
| Files | `quinn-udp/src/unix.rs` |
| Delete when | `quinn-udp` reads or preserves DSCP itself |

Every send attaches an `IP_TOS` control message carrying the ECN codepoint, and
a control message sets the *whole* byte — so the six differentiated-services
bits above ECN are written as zero on every datagram, and a socket configured
with `IP_TOS` or `IPV6_TCLASS` has that configuration silently discarded. It is
invisible from the sending side, because the option reads back exactly as it was
set; only the receiver can see that it did nothing. The patch reads the socket's
codepoint once at construction and includes it in the control message, so ECN
keeps the two bits it owns and the caller keeps the six it set.

We wanted it because marking is the cheapest latency win measured so far:
asking the radio for an interactive queue on the client's uplink was worth
15.6ms at the 95th percentile of link latency and 8.2ms of glass-to-glass. Each
frame crosses the same access point twice, and the relay's egress — the other
crossing — is queued by the access point from the bits on arriving packets,
which were zero. `moqom-transport`'s `Server::bind_marked` binds the socket and
sets them; `moqom-transport/tests/marking.rs` asserts they reach the wire and
fails without this patch.

**It does not currently buy anything, and is kept anyway.** Deployed to dev with
AF41 and measured from the far end, the codepoint does not arrive: replies read
off the wire came back with a type-of-service byte of zero on ten consecutive
sockets, each hashing to its own backend. The relay's side is not in doubt — the
instances ran the marking build with the value set and stayed healthy, which a
failed socket option would not have allowed — so a hop between Google and a home
network clears it. Whether that is the fabric on egress or the ISP was not
established.

Kept because it is correct, tested, costs nothing while the setting is off, and
is the part that would be tedious to reconstruct on the day a path honours the
bits. Delete it along with `Server::bind_marked` if that day is decided against.

Upstream has discussed exposing DSCP (issue 1749) and has not; `Transmit` still
carries only ECN as of `quinn-udp` 0.6.1. The patch here is deliberately the
smaller shape — respect a socket option the caller already set, rather than add
API — because that is defensible as a bug fix, and a fix upstream in any shape
lets this be deleted.

## Updating

```sh
vendor/update-quinn.sh quinn-0.11.12
cd rs && cargo test --all-features
```

The script refuses to overwrite a tree with local modifications, so an
accidental edit surfaces as a failed update rather than being silently
discarded.

## Verifying

```sh
vendor/verify-quinn.sh
```

Fetches the recorded tag and diffs it against this directory. Runs in CI.
