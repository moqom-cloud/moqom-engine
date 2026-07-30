#!/usr/bin/env bash
#
# Build moqom-rans-ffi as an xcframework for Apple platforms.
#
# An xcframework rather than a bare static library because Xcode will otherwise
# happily link the device slice into a simulator build and fail at the last step
# with an architecture error that names no cause. The framework carries the
# platform metadata, so the wrong slice is a build error with a sentence in it.
#
# Unwinding rather than aborting, deliberately. The workspace release profile sets
# `panic = "abort"`, which is right for a relay — a panic there is a bug and the
# process should die where it can be seen. On a client it is wrong: the decoder
# parses bytes from another participant, and terminating someone's app because a
# stranger sent a bad frame is the worst available outcome. With unwinding, the
# catch at the FFI boundary can turn it into an error code instead.
#
#   ./build-apple.sh              # device and simulator
#   ./build-apple.sh --device     # device only, which is faster
#
# Output: target/MoqomRans.xcframework

set -euo pipefail

cd "$(dirname "$0")"
ROOT="$(cd ../ && pwd)"
OUT="$ROOT/target/apple"
FRAMEWORK="$ROOT/target/MoqomRans.xcframework"
LIB=libmoqom_rans_ffi.a

TARGETS=(aarch64-apple-ios aarch64-apple-ios-sim)
if [[ "${1:-}" == "--device" ]]; then
    TARGETS=(aarch64-apple-ios)
fi

# See the note above. Overriding the profile from the environment rather than
# adding a profile to Cargo.toml keeps the relay's abort-on-panic untouched.
export CARGO_PROFILE_RELEASE_PANIC=unwind

for target in "${TARGETS[@]}"; do
    echo "==> $target"
    rustup target add "$target" >/dev/null 2>&1 || true
    cargo build --release --target "$target" -p moqom-rans-ffi
done

rm -rf "$OUT" "$FRAMEWORK"
mkdir -p "$OUT"

ARGS=()
for target in "${TARGETS[@]}"; do
    # Headers are staged per slice. xcodebuild wants a directory it owns, and
    # pointing it at include/ directly makes it copy in whatever else is there.
    staging="$OUT/$target"
    mkdir -p "$staging/Headers"
    cp include/moqom_rans.h "$staging/Headers/"
    cp "$ROOT/target/$target/release/$LIB" "$staging/"

    # A module map, so Swift can `import MoqomRans` instead of needing a bridging
    # header. Without it the framework links but the symbols are invisible to
    # Swift, which is a confusing way to fail.
    cat >"$staging/Headers/module.modulemap" <<'EOF'
module MoqomRans {
    header "moqom_rans.h"
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
echo "      - framework: ../../../moqom-engine/target/MoqomRans.xcframework"
echo "        embed: false"
