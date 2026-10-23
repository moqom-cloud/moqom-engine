#!/usr/bin/env bash
# Build the relay and the generator from the source tarball this host was given.
#
# Built once, on one host, and copied to the others. Building on each host separately
# would be faster to write and would leave the lab unable to answer the first question
# asked of a surprising result: whether every machine was running the same binary.
#
# Not built on the relay's host. A cargo build leaves page cache and CPU history
# behind it, and the relay is the one machine whose behaviour is the measurement.
set -euo pipefail

# Under the login user's home rather than /opt, which is root-owned so that the
# binaries every host runs cannot be rewritten by an unprivileged process. Only the
# installed artifacts go there, and they go by way of sudo below.
src="$HOME/moqom-src"
tarball="${1:-/tmp/moqom-engine.tar.gz}"

rm -rf "$src"
mkdir -p "$src"
tar -xzf "$tarball" -C "$src"

# The toolchain the tree pins, so the lab's binaries are comparable with CI's and
# with a developer's. rustup reads rust-toolchain.toml and fetches 1.97.1 itself.
if [[ ! -x "$HOME/.cargo/bin/cargo" ]]; then
  curl -sSf https://sh.rustup.rs | sh -s -- -y --no-modify-path --default-toolchain none
fi
export PATH="$HOME/.cargo/bin:$PATH"

cd "$src"
cargo build --release -p moqom-relay -p moqom-loadgen

sudo install -m 0755 target/release/moqom-relay /opt/moqom/bin/moqom-relay
sudo install -m 0755 target/release/moqom-load /opt/moqom/bin/moqom-load

# The key set the relay is told to trust, and the tokens the generator mints, both
# come from a constant seed in moqom-loadgen -- so this file is reproducible and the
# signing half is public. That is stated loudly in `moqom-load jwks` output and is
# only safe because these relays are reachable from nothing but this lab.
/opt/moqom/bin/moqom-load jwks > /tmp/jwks.json 2>/dev/null
sudo install -m 0644 /tmp/jwks.json /opt/moqom/jwks.json

# The relay's admin token. Its admin port listens across the lab's VPC, and the
# relay refuses to do that without a credential. Random per build rather than a
# constant like the seed above, and readable by every account on these hosts,
# which only matters to somebody who already has a shell on one.
# `head` closing the pipe kills `tr` with SIGPIPE, which pipefail would treat as failure.
{ LC_ALL=C tr -dc 'A-Za-z0-9' < /dev/urandom || true; } | head -c 48 > /tmp/admin-token
sudo install -m 0644 /tmp/admin-token /opt/moqom/admin-token
rm -f /tmp/admin-token

# The binaries' hashes rather than a version string. The relay takes its whole
# configuration from the environment and ignores its arguments, so asking it for a
# version would start a relay and never return -- and a hash is the thing worth
# comparing across hosts anyway.
sha256sum "$tarball" /opt/moqom/bin/moqom-relay /opt/moqom/bin/moqom-load
