#!/usr/bin/env bash
# Drive the lab at one or more audience sizes and report what the relay did.
#
#   ./measure.sh 2000                  # one size
#   ./measure.sh 1000 2000 4000 8000   # a sweep, which is what finds the ceiling
#   ./measure.sh --seconds 60 4000     # a longer look at one size
#   ./measure.sh --live 5 4000         # print sessions/shed/Gbit/s every 5s
#   ./live.sh                          # same numbers from another terminal
#
# Sizes are total subscribers, split evenly across the generator hosts. Total rather
# than per-host because the total is what gets published, and splitting it here is the
# one arithmetic mistake that produces a plausible wrong answer: two hosts given the
# same viewer numbers present the same identities twice, and the relay's per-identity
# allowance -- not its capacity -- becomes what the run measures.
#
# The relay is restarted between sizes. Its quota state and its counters are both
# per-process, so a size measured against a relay still holding the previous size's
# principals is measuring a warmed-up limiter, and the growth deltas would span two
# runs.
#
# A sweep is the point. One size tells you whether that size works; a sweep tells you
# where the knee is, and the knee is the number. Read the three lines under each size
# together: subscribers per core is only meaningful when the kernel dropped little and
# the NIC was not at its cap.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
loadgen="$(cd "$here/.." && pwd)"
# shellcheck source=lab.sh
. "$here/lab.sh"
# report_host, shared with the local runs so a cloud result and a laptop result are
# the same arithmetic over the same readings.
# shellcheck source=../probe.sh
. "$loadgen/probe.sh"
require_lab

seconds=30
frame_bytes=4096
fps=30
# An Annex B elementary stream on the lab hosts, published instead of frames of one
# size. Distributed by up.sh --clip, which puts it at the same path everywhere --
# subscribers included, since that is where they learn how long each group is.
#
# Worth preferring for any number that gets quoted. Synthetic frames are all the same
# size, which makes every group the same shape and never asks the relay to absorb a
# burst; real video puts a keyframe an order of magnitude larger than its neighbours
# at the head of every group, which is where fan-out costs are.
clip=
codec=h264
# How many sockets the relay shares its port across. One is the shipped default.
shards=1
# Sample the relay mid-run for this many seconds. Zero does not profile.
profile=0
# Publishing starts after the subscribers have had a chance to connect. The publisher
# sends nothing until the relay asks for the track, and the relay asks when the first
# subscriber arrives -- so without this the earliest host would be watching a live
# track while the last was still opening sockets, and the two would report different
# object counts for reasons that have nothing to do with the relay.
stagger=15
# The publisher holds the track open after it stops sending. The last group is still
# in flight when the frames run out, and a publisher that exits immediately withdraws
# the track and takes its own tail with it, which every subscriber then reports as
# loss.
linger=30
# How often to print a live line while a size is running. Zero is silent until
# the size ends, which is how this used to behave. Two seconds is frequent
# enough to watch a join ramp and rare enough that an IAP scrape is not the load.
live=2
sizes=()

while (( $# > 0 )); do
  case "$1" in
    --seconds) seconds="$2"; shift 2 ;;
    --frame-bytes) frame_bytes="$2"; shift 2 ;;
    --fps) fps="$2"; shift 2 ;;
    --clip) clip="$2"; shift 2 ;;
    --codec) codec="$2"; shift 2 ;;
    --shards) shards="$2"; shift 2 ;;
    --profile) profile="$2"; shift 2 ;;
    --stagger) stagger="$2"; shift 2 ;;
    --linger) linger="$2"; shift 2 ;;
    --live) live="$2"; shift 2 ;;
    -h|--help) sed -n '2,26p' "${BASH_SOURCE[0]}"; exit 0 ;;
    -*) echo "unknown option $1" >&2; exit 64 ;;
    *) sizes+=("$1"); shift ;;
  esac
done
if (( ${#sizes[@]} == 0 )); then
  sizes=(2000)
fi

# The traffic flags, identical for both roles. A subscriber is given them because it
# checks what arrived against the shape it was told to expect rather than against
# anything the publisher reports -- which is what lets the roles run on separate hosts
# with no channel between them.
if [[ -n "$clip" ]]; then
  traffic=(--file "$clip" --codec "$codec" --fps "$fps")
  describe="$clip at ${fps}fps"
else
  traffic=(--frame-bytes "$frame_bytes" --fps "$fps")
  describe="${fps}fps of ${frame_bytes}-byte frames"
fi

relay_ip="$(internal_ip "$RELAY_HOST")"
if [[ -z "$relay_ip" ]]; then
  echo "no relay in lab $LAB: run ./up.sh first" >&2
  exit 1
fi

results="$here/results/$(date +%Y%m%dT%H%M%S)"
mkdir -p "$results"

# This tree's relay.sh, so a lab stood up before live ticks existed still
# prints them. One SCP, not a rebuild.
push "$RELAY_HOST" "$here/remote/relay.sh" /tmp/relay.sh
on "$RELAY_HOST" "sudo install -m 0755 /tmp/relay.sh $REMOTE_ROOT/relay.sh"

# An interrupted sweep must not leave a relay running. The next size restarts it
# anyway, but a relay left behind by a Ctrl-C serves the following run with the
# previous run's principals already charged against its limiter, and the number that
# comes out looks like capacity rather than like a mistake.
watchers=()
publisher=
ticker=
cleanup() {
  local pid
  for pid in "${watchers[@]:-}" "$publisher" "$ticker"; do
    # `|| true` matters: this runs on EXIT, and killing a process that has already
    # finished fails, which would otherwise turn a successful sweep's exit status
    # into a failure.
    [[ -n "$pid" ]] && { kill "$pid" 2>/dev/null || true; }
  done
  on "$RELAY_HOST" "$REMOTE_ROOT/relay.sh stop" >/dev/null 2>&1 || true
}
trap cleanup EXIT

# What a reader of these numbers in six months needs in order to believe them. Written
# before the first run, so a sweep that dies half way still leaves an interpretable
# directory behind.
{
  echo "lab          $LAB in $ZONE of $PROJECT"
  echo "relay        $RELAY_HOST ($RELAY_MACHINE) at $relay_ip:$PORT"
  echo "generators   $GENERATORS x $GEN_MACHINE"
  echo "publisher    $PUB_HOST ($PUB_MACHINE)"
  echo "network      MTU $MTU, gVNIC, one zone"
  echo "traffic      $describe, ${seconds}s per size"
  echo "relay        $shards socket(s) sharing the port"
  echo "sizes        ${sizes[*]}"
  echo
  on "$RELAY_HOST" "nproc && sha256sum $REMOTE_ROOT/bin/moqom-relay && \
    sysctl net.core.rmem_max net.core.wmem_max && ulimit -n" 2>/dev/null || true
} > "$results/context.txt"
cat "$results/context.txt"

# Pull one reading out of the probe line relay.sh prints.
#
# Split into lines and anchored rather than matched with a word boundary, because
# \b is a GNU extension and this half of the harness runs on whichever machine the
# operator is sitting at. On BSD sed it matches nothing at all, which cost a sweep:
# every reading came back empty and the arithmetic below failed on the first size.
field() {
  tr ' ' '\n' <<<"$1" | sed -n "s/^$2=//p" | head -1
}

# The same, for the readings that go into arithmetic.
#
# A missing reading becomes zero rather than an error: a relay that died mid-run
# should produce a visibly wrong line in the summary, not abandon the sizes that had
# not been measured yet.
number() {
  local value
  value="$(field "$1" "$2")"
  if [[ "$value" =~ ^[0-9]+$ ]]; then echo "$value"; else echo 0; fi
}

# Datagrams one host's kernel discarded for full receive buffers.
#
# The same reading probe.sh takes locally, so a generator and the relay are compared
# by the same counter. Zero on failure rather than an error: this is diagnosis, and it
# must not be able to end a sweep.
host_drops() {
  local value
  value="$(on "$1" ". $REMOTE_ROOT/probe.sh && udp_drops" 2>/dev/null | tr -dc '0-9')"
  echo "${value:-0}"
}

# The nth whitespace-separated word of a reading, since the pairs above are collected
# as one string per host: bash 3.2 has no arrays of arrays and stock macOS still ships
# it, and this half of the harness runs wherever the operator is sitting.
word() { awk -v n="$2" '{ print $n }' <<<"$1"; }

# How many cores a generator has, for reporting how much of one was left.
GEN_CORES="${GEN_MACHINE##*-}"
case "$GEN_CORES" in ''|*[!0-9]*) GEN_CORES=0 ;; esac

# Busy jiffies across every core of one host: everything except idle and iowait.
#
# For the generators, where the question is not how much CPU one process used but
# whether the machine had any left. A generator at its ceiling produces loss that
# looks exactly like a relay at its ceiling, and this is what separates them.
host_busy() {
  local value
  # shellcheck disable=SC2016 # deliberately unexpanded: the remote shell evaluates it
  value="$(on "$1" 'read -r _ u n s d w q x t r < /proc/stat; echo $((u+n+s+q+x+t))' \
    2>/dev/null | tr -dc '0-9')"
  echo "${value:-0}"
}

printf '%-8s %-7s %-12s %-14s %-10s %s\n' \
  size clean relay-cores subs-per-core Gbit/s kernel-drops > "$results/summary.txt"

for size in "${sizes[@]}"; do
  echo
  echo "=== $size subscriber(s) across $GENERATORS host(s) ==="
  run="$results/size-$size"
  mkdir -p "$run"

  base=$(( size / GENERATORS ))
  extra=$(( size % GENERATORS ))
  if (( base == 0 )); then
    echo "  $size across $GENERATORS hosts leaves a host with nobody; skipping" >&2
    continue
  fi
  if (( base > 1500 )); then
    # Not a hard limit, but the place where a run stops being about the relay: a host
    # opening this many QUIC sessions is doing real work, and the harness gives up if
    # no subscriber becomes ready for a whole minute. More hosts is the right lever.
    echo "  note: $base subscribers on one host is a lot; consider GENERATORS=$(( GENERATORS * 2 ))"
  fi

  on "$RELAY_HOST" "MOQOM_LAB_PORT=$PORT MOQOM_LAB_ADMIN_PORT=$ADMIN_PORT \
    MOQOM_LAB_SHARDS=$shards $REMOTE_ROOT/relay.sh start" > "$run/relay-start.txt" 2>&1 || {
    echo "  the relay would not start:" >&2
    cat "$run/relay-start.txt" >&2
    exit 1
  }


  # Subscribers first, each retrying a track that does not exist yet. The reverse
  # order loses the beginning of the stream: objects published before the relay has
  # pulled the track go nowhere, and nothing records that they did.
  watchers=()
  first=0
  for (( n = 0; n < GENERATORS; n++ )); do
    mine=$base
    (( n < extra )) && mine=$(( base + 1 ))
    host="$(generator "$n")"
    on "$host" "ulimit -n 1048576; $REMOTE_ROOT/bin/moqom-load watch \
      --relay $relay_ip:$PORT \
      --subscribers $mine \
      --first-viewer $first \
      --seconds $seconds \
      ${traffic[*]} \
      --wait 120 \
      --insecure" > "$run/watch-$n.txt" 2>&1 &
    watchers+=($!)
    first=$(( first + mine ))
  done

  sleep "$stagger"

  # Readings bracket the load rather than the whole orchestration. Taken around the
  # outside they would span the stagger, the linger and the drain -- three times the
  # window, most of it with the relay nearly idle -- and every figure derived from
  # them would come out about a third of the truth. That is not a conservative error:
  # it reads as a relay with plenty of headroom at a size that was in fact losing
  # data, which is the one wrong conclusion this whole lab exists to avoid.
  before="$(on "$RELAY_HOST" "$REMOTE_ROOT/relay.sh probe")"
  gen_before=()
  for (( n = 0; n < GENERATORS; n++ )); do
    gen_before+=("$(host_drops "$(generator "$n")") $(host_busy "$(generator "$n")")")
  done
  began="$(date +%s)"

  # Only this host scrapes the relay's counters. Several scrapers would each compute
  # growth over a window containing the others' subscriptions, and every scrape
  # competes with the load for the relay's CPU.
  on "$PUB_HOST" "MOQOM_RELAY_ADMIN_TOKEN_FILE=$REMOTE_ROOT/admin-token $REMOTE_ROOT/bin/moqom-load publish \
    --relay $relay_ip:$PORT \
    --metrics $relay_ip:$ADMIN_PORT \
    --seconds $seconds \
    ${traffic[*]} \
    --linger $linger \
    --insecure" > "$run/publish.txt" 2>&1 &
  publisher=$!

  # Sampled while the run is at its busiest, which is the only time the profile says
  # anything. Backgrounded so it overlaps the run rather than extending it.
  if (( profile > 0 )); then
    ( sleep $(( stagger + 5 ))
      on "$RELAY_HOST" "$REMOTE_ROOT/relay.sh profile $profile" ) \
      > "$run/profile.txt" 2>&1 &
  fi

  # The load lasts `seconds`; the publisher lives for `linger` beyond it. Read the
  # counters at the end of the load, then let the tail finish.
  #
  # Live ticks are backgrounded so this sleep is still the clock: a tick that
  # waits on IAP must not push the after-probe past the load window, or every
  # derived rate would include the linger.
  ticker=
  if (( live > 0 )); then
    on "$RELAY_HOST" "rm -f /tmp/moqom-relay.tick" >/dev/null 2>&1 || true
    echo
    echo "  live         every ${live}s  (also $run/live.txt)"
    (
      t=0
      while :; do
        line="$(on "$RELAY_HOST" \
          "MOQOM_LAB_ADMIN_PORT=$ADMIN_PORT $REMOTE_ROOT/relay.sh tick $t" \
          2>/dev/null || true)"
        if [[ -n "$line" ]]; then
          printf '  %s\n' "$line"
          printf '%s\n' "$line" >> "$run/live.txt"
        fi
        t=$(( t + live ))
        (( t > seconds )) && break
        sleep "$live"
      done
    ) &
    ticker=$!
  fi
  sleep "$seconds"
  if [[ -n "$ticker" ]]; then
    kill "$ticker" 2>/dev/null || true
    wait "$ticker" 2>/dev/null || true
    ticker=
  fi
  after="$(on "$RELAY_HOST" "$REMOTE_ROOT/relay.sh probe" || true)"
  wall=$(( $(date +%s) - began ))
  gen_after=()
  for (( n = 0; n < GENERATORS; n++ )); do
    gen_after+=("$(host_drops "$(generator "$n")") $(host_busy "$(generator "$n")")")
  done

  status=0
  wait "$publisher" || status=$?
  for pid in "${watchers[@]}"; do
    wait "$pid" || status=$?
  done

  # Tolerated rather than trusted. A relay that died mid-run is a result -- arguably
  # the most interesting one a capacity sweep can produce -- so it has to be recorded
  # and reported, not allowed to end the sweep before the remaining sizes are tried.
  if [[ "$after" != *alive=yes* ]]; then
    echo "  the relay was not running when the run ended" >&2
    status=1
  fi
  on "$RELAY_HOST" "$REMOTE_ROOT/relay.sh log 60" > "$run/relay.log" 2>&1 || true
  on "$RELAY_HOST" "$REMOTE_ROOT/relay.sh stop" >/dev/null 2>&1 || true

  echo
  cat "$run/publish.txt"
  for (( n = 0; n < GENERATORS; n++ )); do
    echo
    echo "--- generator $n ---"
    cat "$run/watch-$n.txt"
  done

  drops=$(( $(number "$after" drops) - $(number "$before" drops) ))
  cpu_before="$(number "$before" cpu)"
  cpu_after="$(number "$after" cpu)"
  echo
  report_host "$drops" "$cpu_before" "$cpu_after" "$wall" "$size"

  # Whose buffers overflowed, and whether the machines that generated the load had
  # anything left. Loss at a subscriber is evidence about the relay only once the host
  # holding that subscriber is ruled out, and a saturated generator reports exactly
  # what a saturated relay does.
  gen_drops=0
  for (( n = 0; n < GENERATORS; n++ )); do
    mine=$(( $(word "${gen_after[$n]}" 1) - $(word "${gen_before[$n]}" 1) ))
    (( mine < 0 )) && mine=0
    gen_drops=$(( gen_drops + mine ))
    busy="$(awk -v b="$(word "${gen_before[$n]}" 2)" -v a="$(word "${gen_after[$n]}" 2)" \
      -v w="$wall" -v c="$GEN_CORES" \
      'BEGIN { if (w <= 0) w = 1; printf "%.1f of %d core(s)", (a - b) / 100 / w, c }')"
    printf 'generator %-2s %s busy, %s datagram(s) dropped\n' "$n" "$busy" "$mine"
  done
  if (( gen_drops > drops * 2 && gen_drops > 1000 )); then
    echo "             the generators dropped more than the relay did: read the loss"
    echo "             above as this lab running out of hosts, not as capacity"
  fi

  # What left the virtual NIC, against what the relay believes it wrote. When a
  # ceiling appears this is the line that says whether it was the software or the
  # machine, and it is the reason the local figures could not be trusted.
  tx=$(( $(number "$after" tx) - $(number "$before" tx) ))
  awk -v tx="$tx" -v wall="$wall" -v nic="$(field "$after" nic)" '
    BEGIN {
      if (wall <= 0) wall = 1;
      printf "egress       %.2f Gbit/s off %s over %ds\n", tx * 8 / wall / 1e9, nic, wall;
    }'

  clean=yes
  grep -qh "PROBLEM" "$run"/watch-*.txt 2>/dev/null && clean=no
  (( status != 0 )) && clean=no

  # The sweep's own line, so the knee is readable without re-reading every run.
  cores="$(awk -v b="$cpu_before" -v a="$cpu_after" -v w="$wall" \
    'BEGIN { if (w <= 0) w = 1; printf "%.2f", (a - b) / w }')"
  per_core="$(awk -v s="$size" -v c="$cores" \
    'BEGIN { if (c > 0.01) printf "%.0f", s / c; else printf "n/a" }')"
  gbit="$(awk -v tx="$tx" -v w="$wall" \
    'BEGIN { if (w <= 0) w = 1; printf "%.2f", tx * 8 / w / 1e9 }')"
  printf '%-8s %-7s %-12s %-14s %-10s %s\n' \
    "$size" "$clean" "$cores" "$per_core" "$gbit" "$drops" >> "$results/summary.txt"

  # Sockets from the last size are still closing, and TIME_WAIT on thousands of them
  # is not a state the next size should start from.
  sleep 10
done

echo
echo "=== sweep ==="
cat "$results/summary.txt"
echo
echo "saved to $results"
