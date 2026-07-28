# Vendored quinn

**Do not edit anything in this directory.** It is an unmodified copy of
[quinn-rs/quinn](https://github.com/quinn-rs/quinn), and the whole point of it
is that `vendor/verify-quinn.sh` reports an empty diff.

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
