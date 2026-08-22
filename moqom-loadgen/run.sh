#!/usr/bin/env bash
# Start a relay that trusts the harness's tokens, run one fan-out measurement
# against it, and stop it again.
#
# Exists because a run has four preconditions that are easy to get individually
# wrong and produce failures that name none of them: the relay has to trust the
# key set, expect the matching issuer, expose an admin listener for the metrics
# half of the report, and the shell has to raise a file-descriptor limit that
# macOS sets far below one socket per subscriber.
#
#   ./run.sh 200 20          # 200 subscribers for 20 seconds
#   ./run.sh 1200 15 2048    # the same bitrate in twice as many, smaller frames
#
# Real video instead of synthetic frames, which is the shape a capacity figure
# should be quoted against -- lumpy, with keyframes an order of magnitude larger
# than the frames after them, and groups where the encoder put them:
#
#   ffmpeg -i clip.mp4 -c:v copy -bsf:v h264_mp4toannexb /tmp/clip.h264
#   CLIP=/tmp/clip.h264 FPS=24 ./run.sh 200 20
set -euo pipefail

subscribers="${1:-50}"
seconds="${2:-10}"
frame_bytes="${3:-4096}"

# How many sockets the relay shares its port across. One is the shipped default.
# More than one is a Linux measurement -- macOS permits the bind without spreading
# load across it -- so locally this checks that a sharded relay still serves, not
# what sharding is worth.
: "${SHARDS:=1}"

# An Annex B elementary stream to publish, instead of frames of one size.
: "${CLIP:=}"
# What to play it at. An elementary stream carries no timing of its own, so this
# is a claim about the file; the generator prints the bitrate it implies, which is
# what shows the claim to be wrong.
: "${FPS:=30}"
: "${CODEC:=h264}"

if [[ -n "$CLIP" ]]; then
  traffic=(--file "$CLIP" --codec "$CODEC" --fps "$FPS")
else
  traffic=(--frame-bytes "$frame_bytes" --fps "$FPS")
fi

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
root="$(cd "$here/.." && pwd)"
# shellcheck source=probe.sh
. "$here/probe.sh"
relay="$root/target/release/moqom-relay"
load="$root/target/release/moqom-load"

for binary in "$relay" "$load"; do
  if [[ ! -x "$binary" ]]; then
    echo "missing $binary -- run: cargo build --release -p moqom-relay -p moqom-loadgen" >&2
    exit 1
  fi
done

work="$(mktemp -d)"
# Waited for rather than just signalled, so the port is released before this
# script returns. Without the wait, two runs back to back fail on the second with
# an address already in use, which reads as a bug in the harness.
cleanup() {
  if [[ -n "${relay_pid:-}" ]]; then
    kill "$relay_pid" 2>/dev/null || true
    wait "$relay_pid" 2>/dev/null || true
  fi
  rm -rf "$work"
}
trap cleanup EXIT

"$load" jwks > "$work/jwks.json" 2>/dev/null

# One UDP socket per subscriber, plus the relay's own. macOS defaults to 256.
wanted="$(( subscribers * 4 + 512 ))"
ulimit -n "$wanted" 2>/dev/null || true
check_host_limits "$wanted"

MOQOM_RELAY_ADDR=127.0.0.1:4433 \
MOQOM_RELAY_ADMIN_ADDR=127.0.0.1:9091 \
MOQOM_RELAY_JWKS="$work/jwks.json" \
MOQOM_RELAY_ISSUER=https://loadgen.moqom.invalid \
MOQOM_RELAY_SHARDS="$SHARDS" \
  "$relay" > "$work/relay.log" 2>"$work/relay.err" &
relay_pid=$!

for _ in $(seq 1 100); do
  grep -q "listening:" "$work/relay.log" 2>/dev/null && break
  sleep 0.1
done
if ! grep -q "listening:" "$work/relay.log" 2>/dev/null; then
  echo "the relay did not start:" >&2
  cat "$work/relay.err" >&2
  exit 1
fi

drops_before="$(udp_drops)"
cpu_before="$(cpu_seconds "$relay_pid")"
began="$(date +%s)"

# The generator's own CPU is reported beside the relay's, because both are on
# this machine and the question a capacity number has to answer first is which of
# the two ran out. A relay measured while a heavier generator crowds it is a floor
# and not a capacity.
set +e
/usr/bin/time -p "$load" fanout \
  --relay 127.0.0.1:4433 \
  --metrics 127.0.0.1:9091 \
  --subscribers "$subscribers" \
  --seconds "$seconds" \
  "${traffic[@]}" \
  --insecure
status=$?
set -e

cpu_after="$(cpu_seconds "$relay_pid")"
drops_after="$(udp_drops)"
wall="$(( $(date +%s) - began ))"
echo
report_host "$(( ${drops_after:-0} - ${drops_before:-0} ))" \
  "${cpu_before:-0}" "${cpu_after:-0}" "$wall" "$subscribers"
exit "$status"
