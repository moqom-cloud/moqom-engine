#!/usr/bin/env bash
# Fan-out through Cloudflare's MoQ relay, measured from a lab of our own hosts.
#
#   ./cloudflare.sh up                 # build the lab: a publisher and N generators
#   ./cloudflare.sh run 1000 6000      # one run per size, results in cloud/results
#   ./cloudflare.sh down               # delete everything and stop the charges
#
# Needs MOQOM_CF_PUBLISH_TOKEN and MOQOM_CF_SUBSCRIBE_TOKEN from a Cloudflare MoQ relay,
# read from $CF_ENV (~/.config/moqom/cloudflare.env by default) and copied to each host.
#
# Not the same lab as up.sh. There is no relay host, since Cloudflare is the relay, and
# no Cloud NAT: a generator holds one UDP socket per subscriber, NAT allows 64 ports
# per VM by default, and it bills for every gigabyte it carries. So every host has a
# public address instead, and only IAP may reach its SSH port.
#
# Cloudflare exposes no relay counters, so a run reports what the subscribers received
# and how busy the generators were. Loss while a generator was near its core count is
# a statement about this lab, not about Cloudflare.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
loadgen="$(cd "$here/.." && pwd)"
engine="$(cd "$loadgen/.." && pwd)"

: "${LAB:=moqom-cf}"
: "${ZONE:=us-west2-a}"
: "${GENERATORS:=3}"
: "${GEN_MACHINE:=n2-standard-4}"
: "${PUB_MACHINE:=n2-standard-2}"
: "${SUBNET_RANGE:=10.130.0.0/20}"
: "${TTL_MINUTES:=180}"
: "${CF_ENV:=$HOME/.config/moqom/cloudflare.env}"
: "${CF_RELAY:=draft-16.cloudflare.mediaoverquic.com:443}"
# How long subscribers get to connect before the publisher offers the track.
: "${STAGGER:=45}"
: "${SECONDS_PER_RUN:=90}"
# Sessions each generator opens per second, so a run is not one handshake burst.
: "${RAMP:=100}"
: "${LINGER:=15}"
: "${FRAME_BYTES:=4096}"
: "${FPS:=30}"
# shellcheck source=lab.sh
. "$here/lab.sh"
require_lab

# The publisher is too small to build on, so the first generator builds.
BUILD="$(generator 0)"

cf_hosts() {
  echo "$PUB_HOST"
  generators
}

each_host() {
  local label="$1" pids=() names=() host i failed=0
  shift
  for host in $(cf_hosts); do
    ( "$@" "$host" ) > "$work/$label-$host.log" 2>&1 &
    pids+=("$!")
    names+=("$host")
  done
  for i in "${!pids[@]}"; do
    if wait "${pids[$i]}"; then
      echo "  ${names[$i]}"
    else
      echo "  ${names[$i]} FAILED" >&2
      tail -20 "$work/$label-${names[$i]}.log" >&2
      failed=1
    fi
  done
  return "$failed"
}

up() {
  [[ -s "$CF_ENV" ]] || { echo "no Cloudflare tokens at $CF_ENV" >&2; exit 1; }
  echo "lab      $LAB in $ZONE of $PROJECT"
  echo "hosts    1 publisher ($PUB_MACHINE), $GENERATORS generator(s) ($GEN_MACHINE)"
  echo "relay    Cloudflare, $CF_RELAY"
  echo "lifetime each host shuts itself down after $TTL_MINUTES minutes"
  confirm "create this lab?" || { echo "nothing created"; exit 0; }

  present networks "$NETWORK" ||
    gc compute networks create "$NETWORK" --subnet-mode=custom --mtu="$MTU"
  present "networks subnets" "$SUBNET" --region "$REGION" ||
    gc compute networks subnets create "$SUBNET" \
      --network="$NETWORK" --region="$REGION" --range="$SUBNET_RANGE"
  present firewall-rules "${LAB}-ssh-iap" ||
    gc compute firewall-rules create "${LAB}-ssh-iap" \
      --network="$NETWORK" --allow=tcp:22 \
      --source-ranges=35.235.240.0/20 --target-tags="$LAB" \
      --description="SSH to the $LAB load lab, through IAP only"

  cat > "$work/startup.sh" <<STARTUP
#!/bin/bash
shutdown -h +$TTL_MINUTES "moqom load lab lifetime reached" || true
STARTUP

  local missing=() host
  for host in $(cf_hosts); do
    present instances "$host" --zone "$ZONE" || missing+=("$host")
  done
  create() {
    local machine="$1" role="$2"
    shift 2
    gcz compute instances create "$@" \
      --machine-type="$machine" \
      --image-family="$IMAGE_FAMILY" --image-project="$IMAGE_PROJECT" \
      --boot-disk-size="$BOOT_DISK_SIZE" --boot-disk-type=pd-balanced \
      --network-interface="subnet=$SUBNET,nic-type=GVNIC" \
      --tags="$LAB" \
      --labels="moqom-lab=$LAB,moqom-role=$role" \
      --metadata-from-file=startup-script="$work/startup.sh" \
      --shielded-secure-boot --shielded-vtpm --shielded-integrity-monitoring
  }
  local gens=()
  for host in "${missing[@]+"${missing[@]}"}"; do
    if [[ "$host" == "$PUB_HOST" ]]; then
      create "$PUB_MACHINE" pub "$host"
    else
      gens+=("$host")
    fi
  done
  (( ${#gens[@]} > 0 )) && create "$GEN_MACHINE" gen "${gens[@]}"

  await_ssh() {
    local host="$1"
    for _ in $(seq 1 60); do
      on "$host" true >/dev/null 2>&1 && return 0
      sleep 5
    done
    return 1
  }
  echo "waiting for ssh"
  each_host ssh await_ssh

  prepare() {
    local host="$1"
    push "$host" "$loadgen/probe.sh" /tmp/probe.sh
    push "$host" "$here/remote/host-setup.sh" /tmp/host-setup.sh
    push "$host" "$CF_ENV" cloudflare.env
    on "$host" "chmod 600 ~/cloudflare.env \
      && sudo install -d -m 0755 $REMOTE_ROOT/bin \
      && sudo install -m 0644 /tmp/probe.sh $REMOTE_ROOT/probe.sh \
      && chmod +x /tmp/host-setup.sh && /tmp/host-setup.sh"
  }
  echo "preparing hosts"
  each_host prepare prepare

  echo "building on $BUILD"
  tar --exclude=./target --exclude=./.git --exclude=./moqom-loadgen/cloud/results \
    -czf "$work/moqom-engine.tar.gz" -C "$engine" .
  # The workspace takes moqom-token, moqom-proof, moqom-sframe and moqom-mls from
  # ../moqom-security, and build.sh unpacks the engine at ~/moqom-src.
  tar --exclude=./rust/target -czf "$work/moqom-security.tar.gz" \
    -C "$engine/../moqom-security" ./rust
  push "$BUILD" "$work/moqom-engine.tar.gz" /tmp/moqom-engine.tar.gz
  push "$BUILD" "$work/moqom-security.tar.gz" /tmp/moqom-security.tar.gz
  push "$BUILD" "$here/remote/build.sh" /tmp/build.sh
  on "$BUILD" "rm -rf ~/moqom-security && mkdir -p ~/moqom-security \
    && tar -xzf /tmp/moqom-security.tar.gz -C ~/moqom-security \
    && chmod +x /tmp/build.sh && /tmp/build.sh /tmp/moqom-engine.tar.gz"

  echo "distributing the generator"
  pull "$BUILD" "$REMOTE_ROOT/bin/moqom-load" "$work/moqom-load"
  install_load() {
    local host="$1"
    [[ "$host" == "$BUILD" ]] && return 0
    push "$host" "$work/moqom-load" /tmp/moqom-load
    on "$host" "sudo install -m 0755 /tmp/moqom-load $REMOTE_ROOT/bin/moqom-load"
  }
  each_host install install_load
  echo
  echo "lab ready; next: $0 run 1000 6000 10000"
}

# Busy jiffies across every core of one host.
busy() {
  local value
  # shellcheck disable=SC2016 # evaluated by the remote shell
  value="$(on "$1" 'read -r _ u n s d w q x t r < /proc/stat; echo $((u+n+s+q+x+t))' \
    2>/dev/null | tr -dc '0-9')"
  echo "${value:-0}"
}

run() {
  (( $# > 0 )) || { echo "which sizes? e.g. $0 run 1000 6000" >&2; exit 64; }
  local results stamp
  stamp="$(date -u +%Y%m%dT%H%MZ)"
  results="$here/results/cloudflare-$stamp"
  mkdir -p "$results"
  local traffic="--frame-bytes $FRAME_BYTES --fps $FPS"
  local cores="${GEN_MACHINE##*-}"
  {
    echo "date        $stamp"
    echo "relay       Cloudflare MoQ beta, $CF_RELAY"
    echo "zone        $ZONE"
    echo "publisher   $PUB_HOST ($PUB_MACHINE)"
    echo "generators  $GENERATORS x $GEN_MACHINE"
    echo "traffic     $FPS fps of $FRAME_BYTES-byte frames, ${SECONDS_PER_RUN}s per run"
    echo "ramp        $RAMP sessions per second per generator; counting starts once all are in"
  } | tee "$results/context.txt"
  printf '%-7s %-9s %-7s %-14s %-30s %-10s %s\n' \
    size watching lossy setup-retries latency-p50/p95/p99 Gbit/s generator-cores-busy > "$results/summary.txt"

  local size
  for size in "$@"; do
    echo
    echo "=== $size subscribers across $GENERATORS host(s) ==="
    local dir="$results/size-$size"
    mkdir -p "$dir"
    local base=$(( size / GENERATORS )) extra=$(( size % GENERATORS ))
    local watchers=() first=0 n mine host before=()

    for (( n = 0; n < GENERATORS; n++ )); do
      before+=("$(busy "$(generator "$n")")")
    done
    local began
    began="$(date +%s)"
    for (( n = 0; n < GENERATORS; n++ )); do
      mine=$base
      (( n < extra )) && mine=$(( base + 1 ))
      host="$(generator "$n")"
      on "$host" "set -a; . ~/cloudflare.env; set +a; ulimit -n 1048576; \
        $REMOTE_ROOT/bin/moqom-load watch --cloudflare --relay $CF_RELAY \
        --subscribers $mine --first-viewer $first --seconds $SECONDS_PER_RUN \
        --ramp $RAMP $traffic --wait 240 --live 0" > "$dir/watch-$n.txt" 2>&1 &
      watchers+=($!)
      first=$(( first + mine ))
    done

    # The publisher starts with the first subscriber (Cloudflare refuses a PUBLISH
    # nobody wants), while each generator starts its window once all of its own
    # subscribers are in, and counts nothing before then. So it publishes for
    # longer than any window can last and is stopped once they have all closed.
    sleep "$STAGGER"
    on "$PUB_HOST" "set -a; . ~/cloudflare.env; set +a; \
      $REMOTE_ROOT/bin/moqom-load publish --cloudflare --relay $CF_RELAY \
      --seconds $(( SECONDS_PER_RUN + 60 )) $traffic --linger $LINGER --live 10" \
      > "$dir/publish.txt" 2>&1 &
    local publisher=$!

    local status=0 pid
    for pid in "${watchers[@]}"; do
      wait "$pid" || status=$?
    done
    on "$PUB_HOST" "pkill -f 'bin/[m]oqom-load publish'" >/dev/null 2>&1 || true
    local wall=$(( $(date +%s) - began ))
    local load=""
    for (( n = 0; n < GENERATORS; n++ )); do
      load+="$(awk -v b="${before[$n]}" -v a="$(busy "$(generator "$n")")" -v w="$wall" \
        'BEGIN { if (w <= 0) w = 1; printf "%.1f ", (a - b) / 100 / w }')"
    done
    wait "$publisher" || true

    cat "$dir"/watch-*.txt
    local watching lossy gbit lat retried
    retried="$(sed -n 's/^setup  *\([0-9]*\) session.*/\1/p' "$dir"/watch-*.txt | awk '{ s += $1 } END { print s + 0 }')"
    watching="$(sed -n 's/^subscribers  *\([0-9]*\) of.*/\1/p' "$dir"/watch-*.txt | awk '{ s += $1 } END { print s + 0 }')"
    lossy="$(sed -n 's/^loss  *\([0-9]*\) subscriber.*/\1/p' "$dir"/watch-*.txt | awk '{ s += $1 } END { print s + 0 }')"
    gbit="$(sed -n 's/^throughput  *\([0-9]*\) Mbit.*/\1/p' "$dir"/watch-*.txt | awk '{ s += $1 } END { printf "%.2f", s / 1000 }')"
    lat="$(sed -n 's/^latency  *p50 \([0-9.]*\)ms  p95 \([0-9.]*\)ms  p99 \([0-9.]*\)ms.*/\1\/\2\/\3/p' "$dir"/watch-*.txt | paste -sd ' ' -)"
    (( status != 0 )) && echo "  a generator reported a problem (exit $status)"
    printf '%-7s %-9s %-7s %-14s %-30s %-10s %s(of %s each)\n' \
      "$size" "$watching" "$lossy" "$retried" "${lat:-none}" "$gbit" "$load" "$cores" | tee -a "$results/summary.txt"
  done
  echo
  cat "$results/summary.txt"
  echo "results in $results"
}

down() {
  local doomed=() host
  for host in $(cf_hosts); do
    present instances "$host" --zone "$ZONE" && doomed+=("$host")
  done
  echo "deleting ${doomed[*]:-no instances}, ${LAB}-ssh-iap, $SUBNET, $NETWORK in $PROJECT"
  confirm "type the lab's name to delete it:" "$LAB" || { echo "nothing deleted"; exit 0; }
  (( ${#doomed[@]} > 0 )) && gcz compute instances delete "${doomed[@]}"
  present firewall-rules "${LAB}-ssh-iap" && gc compute firewall-rules delete "${LAB}-ssh-iap"
  present "networks subnets" "$SUBNET" --region "$REGION" &&
    gc compute networks subnets delete "$SUBNET" --region="$REGION"
  present networks "$NETWORK" && gc compute networks delete "$NETWORK"
  echo "lab $LAB removed"
}

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

case "${1:-}" in
  up) up ;;
  run) shift; run "$@" ;;
  down) down ;;
  *) sed -n '2,10p' "${BASH_SOURCE[0]}"; exit 64 ;;
esac
