#!/usr/bin/env bash
# Run a two-tier tree: one origin, N edges, and viewers on the edges only.
#
# This is the arrangement the scaling arithmetic is about, and the number it exists
# to produce is the interior overhead — what the origin pays to feed the edges,
# against what the edges deliver to viewers. The prediction is that it is small, and
# that depth is therefore nearly free; this measures it instead of asserting it.
#
#   ./tier.sh 3 200 20      # three edges, 200 viewers each, 20 seconds
#
# Certificates are generated here because the upstream link verifies them and offers
# no way not to. That is deliberate in the relay, and it means a tier needs a
# certificate authority even on one laptop — so this makes a throwaway one, which is
# also what a real fleet on internal names has to do.
set -euo pipefail

edges="${1:-2}"
per_edge="${2:-100}"
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
if ! command -v openssl >/dev/null; then
  echo "openssl is needed to generate the fleet's certificates" >&2
  exit 1
fi

viewers="$(( edges * per_edge ))"
work="$(mktemp -d)"
pids=()

cleanup() {
  for pid in "${pids[@]:-}"; do
    [[ -n "$pid" ]] && kill "$pid" 2>/dev/null || true
  done
  wait 2>/dev/null || true
  rm -rf "$work"
}
trap cleanup EXIT

# A throwaway authority, and one certificate for "localhost" that the origin
# presents and the edges verify against.
openssl req -x509 -newkey rsa:2048 -nodes -keyout "$work/ca.key" -out "$work/ca.pem" \
  -days 1 -subj "/CN=moqom-loadgen-ca" 2>/dev/null
openssl req -newkey rsa:2048 -nodes -keyout "$work/origin.key" -out "$work/origin.csr" \
  -subj "/CN=localhost" 2>/dev/null
printf 'subjectAltName=DNS:localhost,IP:127.0.0.1\n' > "$work/ext"
openssl x509 -req -in "$work/origin.csr" -CA "$work/ca.pem" -CAkey "$work/ca.key" \
  -CAcreateserial -out "$work/origin.pem" -days 1 -extfile "$work/ext" 2>/dev/null

"$load" jwks > "$work/jwks.json" 2>/dev/null
# The edges need a credential of their own: the origin verifies tokens, and an
# anonymous edge is refused the room exactly as an anonymous client would be.
edge_token="$("$load" token)"

wanted="$(( viewers * 4 + 1024 ))"
ulimit -n "$wanted" 2>/dev/null || true
check_host_limits "$wanted"

start_relay() {
  local name="$1" port="$2" admin="$3"
  shift 3
  env MOQOM_RELAY_ADDR="127.0.0.1:$port" \
      MOQOM_RELAY_ADMIN_ADDR="127.0.0.1:$admin" \
      MOQOM_RELAY_JWKS="$work/jwks.json" \
      MOQOM_RELAY_ISSUER=https://loadgen.moqom.invalid \
      "$@" \
      "$relay" > "$work/$name.log" 2>&1 &
  pids+=($!)
  for _ in $(seq 1 100); do
    grep -q "listening:" "$work/$name.log" 2>/dev/null && return 0
    sleep 0.1
  done
  echo "$name did not start:" >&2
  tail -5 "$work/$name.log" >&2
  return 1
}

# The origin holds the publisher and presents the generated certificate.
start_relay origin 4433 9091 \
  MOQOM_RELAY_CERT="$work/origin.pem" MOQOM_RELAY_KEY="$work/origin.key"
origin_pid="${pids[-1]}"

# The edges hold nothing, and fetch from the origin by name so the certificate
# verifies.
watchers=()
edge_pids=()
for (( n = 0; n < edges; n++ )); do
  start_relay "edge-$n" "$(( 4500 + n ))" "$(( 9500 + n ))" \
    MOQOM_RELAY_UPSTREAM="localhost:4433" \
    MOQOM_RELAY_UPSTREAM_CA="$work/ca.pem" \
    MOQOM_RELAY_UPSTREAM_TOKEN="$edge_token"
  edge_pids+=("${pids[-1]}")
done

# Wait for the link the relay says it has, rather than for the absence of a failure
# within some interval. The first version of this check did the latter and reported
# three attached edges while all three were timing out against an address nothing
# listened on, which sent the investigation to the subscribe path for an afternoon.
for (( n = 0; n < edges; n++ )); do
  attached=false
  for _ in $(seq 1 100); do
    if grep -q "attached to upstream relay" "$work/edge-$n.log"; then
      attached=true
      break
    fi
    sleep 0.1
  done
  if [[ "$attached" != true ]]; then
    echo "edge-$n never attached to the origin:" >&2
    grep -E "upstream" "$work/edge-$n.log" | tail -3 >&2
    exit 1
  fi
done
echo "$edges edge(s) attached to the origin"

drops_before="$(udp_drops)"
origin_cpu_before="$(cpu_seconds "$origin_pid")"
edge_cpu_before=0
for pid in "${edge_pids[@]}"; do
  this="$(cpu_seconds "$pid")"
  edge_cpu_before="$(awk -v a="$edge_cpu_before" -v b="${this:-0}" 'BEGIN { print a + b }')"
done
began="$(date +%s)"

# Viewers on the edges only. Nobody subscribes to the origin, which is the point:
# the origin's egress should be one copy per edge rather than one per viewer.
for (( n = 0; n < edges; n++ )); do
  "$load" watch \
    --relay "127.0.0.1:$(( 4500 + n ))" \
    --subscribers "$per_edge" \
    --first-viewer "$(( n * per_edge ))" \
    --seconds "$seconds" \
    --frame-bytes "$frame_bytes" \
    --insecure \
    > "$work/watch-$n.out" 2>&1 &
  pids+=($!)
  watchers+=("${pids[-1]}")
done

"$load" publish \
  --relay 127.0.0.1:4433 \
  --metrics 127.0.0.1:9091 \
  --seconds "$seconds" \
  --frame-bytes "$frame_bytes" \
  --linger 20 \
  --insecure \
  > "$work/publish.out" 2>&1 &
publisher=$!
pids+=("$publisher")

status=0
wait "$publisher" || status=$?
for pid in "${watchers[@]}"; do
  wait "$pid" || status=$?
done

origin_cpu_after="$(cpu_seconds "$origin_pid")"
edge_cpu_after=0
for pid in "${edge_pids[@]}"; do
  this="$(cpu_seconds "$pid")"
  edge_cpu_after="$(awk -v a="$edge_cpu_after" -v b="${this:-0}" 'BEGIN { print a + b }')"
done
drops_after="$(udp_drops)"
wall="$(( $(date +%s) - began ))"

echo
cat "$work/publish.out"
for (( n = 0; n < edges; n++ )); do
  echo
  echo "--- edge $n ---"
  cat "$work/watch-$n.out"
done

# The measurement this script exists for. The origin's egress is what feeding the
# tier costs; the edges' egress is what the audience received. Their ratio is the
# interior overhead, and the prediction is that it shrinks as the fan-out grows.
origin_egress="$(curl -s "http://127.0.0.1:9091/metrics" |
  awk '/^moqom_relay_egress_bytes_total/ { print $2 }')"
edge_egress=0
for (( n = 0; n < edges; n++ )); do
  this="$(curl -s "http://127.0.0.1:$(( 9500 + n ))/metrics" |
    awk '/^moqom_relay_egress_bytes_total/ { print $2 }')"
  edge_egress="$(awk -v a="$edge_egress" -v b="${this:-0}" 'BEGIN { print a + b }')"
done

echo
awk -v origin="${origin_egress:-0}" -v edge="$edge_egress" -v edges="$edges" \
    -v viewers="$viewers" '
  BEGIN {
    printf "tier         origin wrote %.1f MiB to feed %d edge(s)\n",
           origin / 1048576, edges;
    printf "             edges wrote %.1f MiB to %d viewer(s)\n", edge / 1048576, viewers;
    if (edge > 0)
      printf "             interior overhead %.2f%% of what the audience received\n",
             100 * origin / edge;
  }'
# The edges' CPU rather than the origin's, because in a tier the edges do the
# fan-out and the per-core figure is about them. The origin's is reported beside it:
# an interior relay that is barely working is the claim the tier rests on, and a
# number for it is the way to notice when it stops being true.
report_host "$(( ${drops_after:-0} - ${drops_before:-0} ))" \
  "${edge_cpu_before:-0}" "${edge_cpu_after:-0}" "$wall" "$viewers"
awk -v before="${origin_cpu_before:-0}" -v after="${origin_cpu_after:-0}" -v wall="$wall" '
  BEGIN {
    if (wall <= 0) wall = 1;
    printf "origin       %.1fs of CPU over %ds, so %.2f core(s) busy feeding the tier\n",
           after - before, wall, (after - before) / wall;
  }'
exit "$status"
