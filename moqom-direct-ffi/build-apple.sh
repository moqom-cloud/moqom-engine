#!/usr/bin/env bash
#
# Build moqom-direct-ffi as an xcframework for Apple platforms.
#
# An xcframework rather than a bare static library because Xcode will otherwise
# happily link the device slice into a simulator build and fail at the last step
# with an architecture error that names no cause. The framework carries the
# platform metadata, so the wrong slice is a build error with a sentence in it.
#
# Unwinding rather than aborting, deliberately. The workspace release profile sets
# `panic = "abort"`, which is right for a relay — a panic there is a bug and the
# process should die where it can be seen. On a client it is wrong: this library
# parses packets from the network and from another participant, and terminating
# someone's call because of a bug in a path the relay could have carried is the
# worst available outcome. With unwinding, the catch at the FFI boundary can turn
# it into MOQOM_DIRECT_PANIC instead.
#
#   ./build-apple.sh              # device, simulator, and Mac
#   ./build-apple.sh --device     # device only, which is faster
#
# The Mac slice is not there for shipping a Mac app. The Swift package's tests run
# on the host, and two endpoints on loopback is exactly the kind of test that wants
# a fast loop rather than a device and an install cycle.
#
# visionOS and tvOS are not built: their Rust targets are tier 3, with no
# prebuilt standard library, and nothing ships there yet.
#
# Output: target/MoqomDirectFFI.xcframework

set -euo pipefail

cd "$(dirname "$0")"
ROOT="$(cd ../ && pwd)"
OUT="$ROOT/target/apple-direct"
FRAMEWORK="$ROOT/target/MoqomDirectFFI.xcframework"
LIB=libmoqom_direct_ffi.a

TARGETS=(aarch64-apple-ios aarch64-apple-ios-sim aarch64-apple-darwin)
if [[ "${1:-}" == "--device" ]]; then
    TARGETS=(aarch64-apple-ios)
fi

# See the note above. Overriding the profile from the environment rather than
# adding a profile to Cargo.toml keeps the relay's abort-on-panic untouched.
export CARGO_PROFILE_RELEASE_PANIC=unwind

# One deployment target for rustc and for the C that aws-lc and ring compile.
# Unset, rustc links for iOS 10 while cc builds for the SDK's own version, and
# the link fails on `___chkstk_darwin`, which iOS 10's stubs do not have. The
# value is the Swift package's own floor; lower both together.
export IPHONEOS_DEPLOYMENT_TARGET="${IPHONEOS_DEPLOYMENT_TARGET:-26.0}"
export MACOSX_DEPLOYMENT_TARGET="${MACOSX_DEPLOYMENT_TARGET:-26.0}"

for target in "${TARGETS[@]}"; do
    echo "==> $target"
    rustup target add "$target" >/dev/null 2>&1 || true
    cargo build --release --target "$target" -p moqom-direct-ffi
done

rm -rf "$OUT" "$FRAMEWORK"
mkdir -p "$OUT"

ARGS=()
for target in "${TARGETS[@]}"; do
    # Headers are staged per slice. xcodebuild wants a directory it owns, and
    # pointing it at include/ directly makes it copy in whatever else is there.
    staging="$OUT/$target"
    mkdir -p "$staging/Headers"
    cp include/moqom_direct.h "$staging/Headers/"
    cp "$ROOT/target/$target/release/$LIB" "$staging/"

    # A module map, so Swift can `import MoqomDirectFFI` instead of needing a
    # bridging header. Without it the framework links but the symbols are
    # invisible to Swift, which is a confusing way to fail.
    cat >"$staging/Headers/module.modulemap" <<'EOF'
module MoqomDirectFFI {
    header "moqom_direct.h"
    export *
}
EOF

    ARGS+=(-library "$staging/$LIB" -headers "$staging/Headers")
done

xcodebuild -create-xcframework "${ARGS[@]}" -output "$FRAMEWORK"

echo
echo "==> $FRAMEWORK"
for target in "${TARGETS[@]}"; do
    printf '    %-24s %s\n' "$target" \
        "$(du -h "$ROOT/target/$target/release/$LIB" | cut -f1)"
done
echo
echo "Add it to a sample with XcodeGen:"
echo "    dependencies:"
echo "      - framework: ../../../moqom-engine/target/MoqomDirectFFI.xcframework"
echo "        embed: false"
