#!/usr/bin/env bash
# Start, stop and read the relay on the host it runs on.
#
# Kept here rather than embedded in ssh invocations so that the environment the relay
# is given is legible in one place. The configuration is the interesting part of a
# capacity measurement: a relay with limits disabled or a cache sized differently is a
# different subject, and a reader of a surprising number needs to see what it was.
#
#   relay.sh start        bring one up, wait for it to bind, print where
#   relay.sh stop         take it down
#   relay.sh probe        one line of readings, for either side of a run
#   relay.sh tick [t]     one live line: sessions, shed, Gbit/s, drops, cores
#   relay.sh live [s] [i] tick every i seconds for s seconds
#   relay.sh log          what it has said
set -euo pipefail

root=/opt/moqom
log=/tmp/moqom-relay.log
port="${MOQOM_LAB_PORT:-4433}"
admin_port="${MOQOM_LAB_ADMIN_PORT:-9091}"

# The interface packets actually leave by, which is ens4 on gVNIC and eth0 on virtio.
# Read from the routing table rather than assumed, because the counters below are the
# check on whether a ceiling was the relay or the virtual NIC.
primary_nic() {
  ip -o route get 8.8.8.8 2>/dev/null | sed -n 's/.*dev \([^ ]*\).*/\1/p' | head -1
}

# One Prometheus series from a /metrics body. Labels stay on the name, so a
# caller that wants `outcome="established"` asks for the whole series.
metric() {
  local body="$1" name="$2"
  awk -v name="$name" '
    $0 ~ /^#/ { next }
    $1 == name { print $2; exit }
    index($1, name "{") == 1 { print $2; exit }
  ' <<<"$body"
}

# One live line against the running relay. Rates are since the previous tick
# (or zero on the first), so a sweep that prints these every couple of seconds
# is watching the same counters the end-of-size report will subtract.
#
# Written to the relay host rather than scraped over IAP each time, because a
# scrape is a GET against localhost and an IAP round-trip is not. The optional
# argument is elapsed seconds for the printed `t+`, so a caller that already
# knows the clock does not have to parse the state file.
emit_tick() {
  local elapsed="${1:-}"
  # shellcheck disable=SC1091
  . "$root/probe.sh"
  local pid
  pid="$(pgrep -f "$root/bin/moqom-relay" | head -1 || true)"
  local nic tx drops jiffies metrics sess shed clk
  nic="$(primary_nic)"
  tx="$(awk -v nic="$nic:" '$1 == nic { print $10 }' /proc/net/dev)"
  drops="$(udp_drops)"
  jiffies=0
  if [[ -n "$pid" && -r /proc/$pid/stat ]]; then
    jiffies="$(awk '{ print $14 + $15 }' "/proc/$pid/stat")"
  fi
  metrics="$(curl -sf --max-time 2 -H "Authorization: Bearer $(cat "$root/admin-token")" \
    "http://127.0.0.1:$admin_port/metrics" || true)"
  sess="$(metric "$metrics" moqom_relay_sessions)"
  shed="$(metric "$metrics" moqom_relay_subgroups_shed_total)"
  # Whole numbers for the shell arithmetic below. Prometheus may print a
  # trailing `.0`; a gauge that is actually fractional is not one of these.
  sess="${sess%%.*}"
  shed="${shed%%.*}"
  : "${tx:=0}" "${drops:=0}" "${jiffies:=0}"
  : "${sess:=0}" "${shed:=0}"
  clk="$(getconf CLK_TCK 2>/dev/null || echo 100)"

  local state=/tmp/moqom-relay.tick
  local now start prev_ts prev_j prev_tx prev_drops prev_shed
  now="$(date +%s)"
  if [[ -f "$state" ]]; then
    # shellcheck disable=SC1090
    . "$state"
  fi
  start="${start:-$now}"
  prev_ts="${ts:-$now}"
  prev_j="${cpu_jiffies:-$jiffies}"
  prev_tx="${tx_bytes:-$tx}"
  prev_drops="${udp_drops:-$drops}"
  prev_shed="${shed_total:-$shed}"

  local dt gbit cores shed_delta drops_delta
  dt=$(( now - prev_ts ))
  (( dt < 1 )) && dt=1
  gbit="$(awk -v a="$prev_tx" -v b="$tx" -v d="$dt" \
    'BEGIN { printf "%.2f", (b - a) * 8 / d / 1e9 }')"
  cores="$(awk -v a="$prev_j" -v b="$jiffies" -v d="$dt" -v c="$clk" \
    'BEGIN { if (c < 1) c = 100; printf "%.2f", (b - a) / c / d }')"
  shed_delta=$(( shed - prev_shed ))
  (( shed_delta < 0 )) && shed_delta=0
  drops_delta=$(( drops - prev_drops ))
  (( drops_delta < 0 )) && drops_delta=0
  [[ -z "$elapsed" ]] && elapsed=$(( now - start ))

  printf 't+%3ds   sess %6s   shed %6s   %5s Gbit/s   drops %6s   %5s cores\n' \
    "$elapsed" "$sess" "$shed_delta" "$gbit" "$drops_delta" "$cores"

  cat > "$state" <<EOF
start=$start
ts=$now
cpu_jiffies=$jiffies
tx_bytes=$tx
udp_drops=$drops
shed_total=$shed
EOF
}

case "${1:-}" in
  start)
    pkill -f "$root/bin/moqom-relay" 2>/dev/null || true
    # Waited for rather than slept past: the port has to be free before the next
    # relay binds it, and a sweep restarts the relay between sizes.
    for _ in $(seq 1 50); do
      pgrep -f "$root/bin/moqom-relay" >/dev/null || break
      sleep 0.1
    done
    : > "$log"

    # Every subscriber is a connection, and the relay holds a socket per subscriber
    # plus its own. The hard limit was raised in host-setup.sh; this is the soft one.
    ulimit -n 1048576

    # Bound to every address because the generators reach it across the VPC, which the
    # firewall restricts to this lab's own instances. No certificate is configured, so
    # the relay generates a self-signed one and prints its hash -- the generators pass
    # --insecure, which is honest here: the question is fan-out, and a lab measuring
    # certificate verification would be measuring rustls.
    #
    # Keys are configured because an authenticated session is charged against its own
    # device and user, where the allowance is per identity. An unauthenticated one is
    # charged by address, and every subscriber on one generator host shares an address
    # -- so without these the run would measure the rate limiter.
    # How many sockets share the port. One is the shipped default and the thing a
    # before-and-after pair of runs compares against; more gives each shard its own
    # endpoint driver and its own send lock, which is what lets one relay use more
    # than one core's worth of packet handling. Set per run rather than baked in,
    # because the whole question is what it is worth.
    MOQOM_RELAY_ADDR="0.0.0.0:$port" \
    MOQOM_RELAY_ADMIN_ADDR="0.0.0.0:$admin_port" \
    MOQOM_RELAY_ADMIN_TOKEN_FILE="$root/admin-token" \
    MOQOM_RELAY_JWKS="$root/jwks.json" \
    MOQOM_RELAY_ISSUER=https://loadgen.moqom.invalid \
    MOQOM_RELAY_SHARDS="${MOQOM_LAB_SHARDS:-1}" \
    RUST_LOG="${MOQOM_LAB_LOG:-moqom_relay=info}" \
      setsid nohup "$root/bin/moqom-relay" >>"$log" 2>&1 </dev/null &

    for _ in $(seq 1 100); do
      grep -q "listening:" "$log" 2>/dev/null && break
      sleep 0.1
    done
    if ! grep -q "listening:" "$log" 2>/dev/null; then
      echo "the relay did not start:" >&2
      tail -20 "$log" >&2
      exit 1
    fi
    grep -m1 "listening:" "$log"
    ;;

  stop)
    pkill -f "$root/bin/moqom-relay" 2>/dev/null || true
    ;;

  probe)
    # Installed by up.sh; it exists on a lab host and nowhere a linter can reach.
    # shellcheck disable=SC1091
    . "$root/probe.sh"
    # Tolerant of the relay being gone, because this is what a sweep calls to find out
    # how a run went and pgrep failing under pipefail would take the whole sweep down
    # with it -- losing every remaining size to report that one of them died.
    pid="$(pgrep -f "$root/bin/moqom-relay" | head -1 || true)"
    alive=yes
    [[ -z "$pid" ]] && alive=no
    nic="$(primary_nic)"
    # Bytes off the wire as well as the relay's own account of what it wrote. When a
    # ceiling turns up, the first question is whether it was the software or the
    # virtual NIC, and only one of those two numbers can answer it.
    tx="$(awk -v nic="$nic:" '$1 == nic { print $10 }' /proc/net/dev)"
    rx="$(awk -v nic="$nic:" '$1 == nic { print $2 }' /proc/net/dev)"
    echo "drops=$(udp_drops) cpu=$(cpu_seconds "${pid:-0}") tx=${tx:-0} rx=${rx:-0}" \
      "nic=${nic:-unknown} alive=$alive"
    ;;

  log)
    tail -"${2:-40}" "$log"
    ;;

  tick)
    emit_tick "${2:-}"
    ;;

  live)
    # One SSH, many lines. measure.sh backgrounds this so the after-probe still
    # happens at the end of the load window rather than after the last tick.
    seconds="${2:-30}"
    interval="${3:-2}"
    rm -f /tmp/moqom-relay.tick
    elapsed=0
    while :; do
      emit_tick "$elapsed"
      (( elapsed >= seconds )) && break
      sleep "$interval"
      elapsed=$(( elapsed + interval ))
    done
    ;;

  profile)
    # Where the CPU went, which is the difference between fixing a ceiling and
    # guessing at it. Sampled from a running relay for a few seconds mid-run.
    pid="$(pgrep -f "$root/bin/moqom-relay" | head -1 || true)"
    if [[ -z "$pid" ]]; then
      echo "no relay is running to profile" >&2
      exit 1
    fi
    if ! command -v perf >/dev/null 2>&1; then
      echo "perf is not installed on this host; skipping the profile" >&2
      exit 0
    fi
    out=/tmp/moqom-relay.perf
    # Frame pointers are not guaranteed in a release build, so dwarf unwinding --
    # slower to record and the only way the call graph means anything.
    perf record --call-graph dwarf -F 99 -p "$pid" -o "$out" -- sleep "${2:-10}" \
      >/dev/null 2>&1 || true
    perf report -i "$out" --stdio --no-children --percent-limit 0.5 2>/dev/null |
      head -60
    ;;

  *)
    echo "usage: relay.sh start|stop|probe|tick|live|log|profile" >&2
    exit 64
    ;;
esac
