#!/usr/bin/env bash
# Assert that vendor/quinn is byte-identical to the upstream tag it records.
#
# The vendoring only buys anything if the claim "unmodified" is checkable, so
# this runs in CI rather than living in a contributor's memory.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
vendored="$here/quinn"
manifest="$vendored/VENDORED.md"

[[ -f "$manifest" ]] || { echo "no VENDORED.md; is vendor/quinn populated?" >&2; exit 1; }

tag="$(grep -oE '`quinn-[0-9]+\.[0-9]+\.[0-9]+`' "$manifest" | head -1 | tr -d '`')"
commit="$(grep -oE '`[0-9a-f]{40}`' "$manifest" | head -1 | tr -d '`')"
[[ -n "$tag" && -n "$commit" ]] || { echo "could not read tag/commit from VENDORED.md" >&2; exit 1; }

scratch="$(mktemp -d)"
trap 'rm -rf "$scratch"' EXIT

echo "checking vendor/quinn against $tag ($commit)"
git -c advice.detachedHead=false clone -q --depth 1 --branch "$tag" \
  https://github.com/quinn-rs/quinn "$scratch/upstream"

actual="$(git -C "$scratch/upstream" rev-parse HEAD)"
if [[ "$actual" != "$commit" ]]; then
  echo "tag $tag now points at $actual, not the recorded $commit." >&2
  echo "Upstream retagged. Re-vendor deliberately rather than trusting the tag." >&2
  exit 1
fi

rm -rf "$scratch/upstream/.git"

# VENDORED.md is ours and is the one file expected to differ.
if diff -ru --exclude=VENDORED.md "$scratch/upstream" "$vendored"; then
  echo "vendor/quinn matches $tag exactly"
else
  cat >&2 <<'EOF'

vendor/quinn has diverged from upstream.

If this was deliberate, VENDORED.md must say so and link the upstream PR --
see the note there about local patches being small and temporary. If it was
not, run vendor/update-quinn.sh to restore it.
EOF
  exit 1
fi

# An unmodified tree proves nothing if the build ignores it. A [patch.crates-io]
# entry can silently stop applying -- most easily when a version requirement
# drifts past what the vendored copy provides -- and cargo reports that as a
# warning nobody reads while quietly linking the registry crate instead.
echo
echo "checking that the build actually uses it"
metadata="$(cd "$here/.." && cargo metadata --format-version 1 --quiet)"
for crate in quinn quinn-proto quinn-udp; do
  path="$(printf '%s' "$metadata" | python3 -c "
import json, sys
name = sys.argv[1]
for pkg in json.load(sys.stdin)['packages']:
    if pkg['name'] == name:
        print(pkg['manifest_path'])
        break
" "$crate")"

  if [[ -z "$path" ]]; then
    echo "  $crate: not in the dependency graph (nothing depends on it yet)"
  elif [[ "$path" == *"/vendor/quinn/"* ]]; then
    echo "  $crate: vendored"
  else
    echo "  $crate: resolved to $path, NOT the vendored copy" >&2
    echo "The [patch.crates-io] entry in Cargo.toml is not taking effect." >&2
    exit 1
  fi
done
