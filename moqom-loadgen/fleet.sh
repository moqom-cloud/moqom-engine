#!/usr/bin/env bash
# Drive one relay from separate publisher and subscriber processes.
#
# The point is the separation, not the count. `run.sh` puts the whole load in one
# process beside the relay, which is convenient and caps out where the generator
# starts competing with what it is measuring; this runs the same load as several
# processes, so the same invocations work unchanged when the processes are on
# different machines and the relay has the host to itself.
#
#   ./fleet.sh 4 250 20      # four hosts' worth of 250 subscribers, 20 seconds
#
# To spread it over real machines, run the relay somewhere, then on the publisher
# host:
#
#   moqom-load publish --relay RELAY:4433 --seconds 60 --insecure
#
# and on the Nth subscriber host, counting from zero:
#
#   moqom-load watch --relay RELAY:4433 --subscribers 500 \
#     --first-viewer $((N * 500)) --seconds 60 --insecure
#
# The viewer ranges must not overlap. Two hosts using the same range charge the
# same identities twice, and the relay's per-identity allowance — not the relay's
# capacity — becomes what the run measures.
set -euo pipefail

hosts="${1:-2}"
per_host="${2:-100}"
seconds="${3:-15}"
frame_bytes="${4:-4096}"

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
root="$(cd "$here/.." && pwd)"
relay="$root/target/release/moqom-relay"
load="$root/target/release/moqom-load"
# shellcheck source=probe.sh
. "$here/probe.sh"

for binary in "$relay" "$load"; do
  if [[ ! -x "$binary" ]]; then
    echo "missing $binary -- run: cargo build --release -p moqom-relay -p moqom-loadgen" >&2
    exit 1
  fi
done

subscribers="$(( hosts * per_host ))"
work="$(mktemp -d)"
pids=()

cleanup() {
  for pid in "${pids[@]:-}"; do
    [[ -n "$pid" ]] && kill "$pid" 2>/dev/null || true
  done
  if [[ -n "${relay_pid:-}" ]]; then
    kill "$relay_pid" 2>/dev/null || true
    wait "$relay_pid" 2>/dev/null || true
  fi
  rm -rf "$work"
}
trap cleanup EXIT

"$load" jwks > "$work/jwks.json" 2>/dev/null

wanted="$(( subscribers * 4 + 512 ))"
ulimit -n "$wanted" 2>/dev/null || true
check_host_limits "$wanted"

MOQOM_RELAY_ADDR=127.0.0.1:4433 \
MOQOM_RELAY_ADMIN_ADDR=127.0.0.1:9091 \
MOQOM_RELAY_JWKS="$work/jwks.json" \
MOQOM_RELAY_ISSUER=https://loadgen.moqom.invalid \
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

# Subscribers first. Each retries a track that does not exist yet, so starting
# them ahead of the publisher is the safe order: the publisher refuses to send
# until somebody is watching, and objects sent before the relay pulls the track
# would be lost with nothing to show it.
echo "starting $hosts subscriber process(es) of $per_host each"
for (( n = 0; n < hosts; n++ )); do
  "$load" watch \
    --relay 127.0.0.1:4433 \
    --subscribers "$per_host" \
    --first-viewer "$(( n * per_host ))" \
    --seconds "$seconds" \
    --frame-bytes "$frame_bytes" \
    --insecure \
    > "$work/watch-$n.out" 2>"$work/watch-$n.err" &
  pids+=($!)
done

# Only the publisher scrapes. Every scrape competes with the load for the relay's
# CPU, and several processes reading the same counters would each compute growth
# over a window that includes the others' subscriptions.
"$load" publish \
  --relay 127.0.0.1:4433 \
  --metrics 127.0.0.1:9091 \
  --seconds "$seconds" \
  --frame-bytes "$frame_bytes" \
  --linger 20 \
  --insecure \
  > "$work/publish.out" 2>"$work/publish.err" &
publisher=$!
pids+=("$publisher")

status=0
wait "$publisher" || status=$?
for (( n = 0; n < hosts; n++ )); do
  wait "${pids[$n]}" || status=$?
done

cpu_after="$(cpu_seconds "$relay_pid")"
drops_after="$(udp_drops)"
wall="$(( $(date +%s) - began ))"

echo
cat "$work/publish.out"
for (( n = 0; n < hosts; n++ )); do
  echo
  echo "--- subscriber process $n ---"
  cat "$work/watch-$n.out"
done

echo
report_host "$(( ${drops_after:-0} - ${drops_before:-0} ))" \
  "${cpu_before:-0}" "${cpu_after:-0}" "$wall" "$subscribers"

if (( status != 0 )); then
  echo
  echo "at least one process reported a problem; the errors it printed:" >&2
  tail -n 5 "$work"/*.err 2>/dev/null >&2 || true
fi
exit "$status"
