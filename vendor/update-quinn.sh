#!/usr/bin/env bash
# Re-vendor quinn at a given upstream tag.
#
# Usage: vendor/update-quinn.sh quinn-0.11.12
set -euo pipefail

tag="${1:-}"
[[ -n "$tag" ]] || { echo "usage: $0 <upstream-tag>   e.g. quinn-0.11.12" >&2; exit 1; }

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
vendored="$here/quinn"

# Refuse to discard local edits. If someone patched the vendored tree, that is
# a decision worth surfacing rather than steamrolling -- the patch may be the
# only thing holding production together.
if [[ -d "$vendored" ]] && ! git -C "$here" diff --quiet -- quinn; then
  echo "vendor/quinn has uncommitted changes. Commit or discard them first." >&2
  exit 1
fi

scratch="$(mktemp -d)"
trap 'rm -rf "$scratch"' EXIT

git clone -q --depth 1 --branch "$tag" https://github.com/quinn-rs/quinn "$scratch/upstream"
commit="$(git -C "$scratch/upstream" rev-parse HEAD)"
rm -rf "$scratch/upstream/.git"

version() { grep -m1 '^version' "$scratch/upstream/$1/Cargo.toml" | cut -d'"' -f2; }
quinn_v="$(version quinn)"
proto_v="$(version quinn-proto)"
udp_v="$(version quinn-udp)"

rm -rf "$vendored"
mkdir -p "$vendored"
(cd "$scratch/upstream" && tar -cf - .) | (cd "$vendored" && tar -xf -)

cat > "$vendored/VENDORED.md" <<EOF
# Vendored quinn

**Do not edit anything in this directory.** It is an unmodified copy of
[quinn-rs/quinn](https://github.com/quinn-rs/quinn), and the whole point of it
is that \`vendor/verify-quinn.sh\` reports an empty diff.

| | |
|---|---|
| Upstream | https://github.com/quinn-rs/quinn |
| Tag | \`$tag\` |
| Commit | \`$commit\` |
| Crates | \`quinn\` $quinn_v, \`quinn-proto\` $proto_v, \`quinn-udp\` $udp_v |
| Licence | Apache-2.0 OR MIT (see \`LICENSE-APACHE\`, \`LICENSE-MIT\`) |
EOF

# Keep the prose from the previous manifest: it explains why this exists, and
# regenerating it from the script would lose that on every bump.
if [[ -f "$here/quinn-rationale.md" ]]; then
  cat "$here/quinn-rationale.md" >> "$vendored/VENDORED.md"
fi

echo "vendored $tag ($commit)"
echo "  quinn $quinn_v, quinn-proto $proto_v, quinn-udp $udp_v"
echo
echo "next: cd rs && cargo test --all-features"
