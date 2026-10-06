#!/usr/bin/env bash
# Build the lab: a network, a relay host, a publisher host and N generator hosts.
#
#   ./up.sh                    # four generators, the defaults in lab.sh
#   GENERATORS=8 ./up.sh       # eight
#   CLIP=/tmp/clip.h264 ./up.sh   # and a real video for the runs to publish
#
# Run once. `measure.sh` then runs as many sweeps as you like against it, and
# `down.sh` removes everything. Provisioning is separate from measuring because
# creating a dozen VMs takes minutes and a sweep takes seconds, and because a lab that
# has to be rebuilt for every run is a lab nobody re-runs.
#
# Everything is self-contained: its own VPC, its own subnet, its own NAT. That is more
# resources than reusing the project's default network, and it is worth it -- the
# instances need no public addresses, nothing in the project can reach the relay's
# port, and teardown is a list of names rather than a judgement call about what was
# here before.
#
# What this lab cannot answer, so that nobody reads it as more than it is: every host
# is in one zone, so it says nothing about a tier of relays in different places. That
# is the next measurement, and it reuses these helpers.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
loadgen="$(cd "$here/.." && pwd)"
engine="$(cd "$loadgen/.." && pwd)"
# shellcheck source=lab.sh
. "$here/lab.sh"
require_lab

total_vms=$(( GENERATORS + 2 ))

# --- quota preflight ---------------------------------------------------------
#
# Checked before anything is created, because the failure it prevents is the
# expensive kind: creation stops part way through, leaving a network, a NAT and two
# of three generators. Not a measurement, and not free either.
#
# Three separate ceilings have to be cleared, and each one was found the hard way:
# a per-family regional quota (24 C3 vCPUs in a fresh project), a global cap across
# all regions that no regional quota mentions (32), and whatever the project is
# already spending -- two unrelated dev relays here, which is 4 vCPUs this lab may
# not have. So what is compared is what remains, not what the limit says.
#
# Summed by awk rather than in an associative array, because stock macOS still ships
# bash 3.2 and this half of the harness runs wherever the operator is sitting.
family_need() {
  local machine="$1" family cores
  family="$(printf '%s' "${machine%%-*}" | tr '[:lower:]' '[:upper:]')"
  cores="${machine##*-}"
  # Shared-core types have no numeric suffix and no per-family quota worth checking.
  case "$cores" in ''|*[!0-9]*) return 0 ;; esac
  echo "${family}_CPUS $cores"
}

# Only hosts that do not exist yet count, so that re-running against a lab already
# half built is not refused for the vCPUs it is already holding.
absent_machines() {
  local machine="$1" host
  shift
  for host in "$@"; do
    present instances "$host" --zone "$ZONE" || echo "$machine"
  done
}

pending="$( {
  absent_machines "$RELAY_MACHINE" "$RELAY_HOST"
  absent_machines "$PUB_MACHINE" "$PUB_HOST"
  while read -r host; do absent_machines "$GEN_MACHINE" "$host"; done < <(generators)
} )"

# An `if` rather than a short-circuit, deliberately: a here-string of an empty
# variable still presents one empty line, so a trailing `[[ -n ... ]] &&` would leave
# the loop's status at 1, pipefail would carry it out of the substitution and set -e
# would end the script here without printing anything at all.
wanted="$(while read -r machine; do
  if [[ -n "$machine" ]]; then family_need "$machine"; fi
done <<<"$pending" \
  | awk '{ total[$1] += $2 } END { for (metric in total) print metric, total[metric] }')"

new_vms="$(grep -c . <<<"$pending" || true)"

if [[ -n "$wanted" ]]; then
  # Both limit and usage, because the headroom is the difference and the usage is
  # what a bare limit hides.
  quotas="$(gc compute regions describe "$REGION" --flatten='quotas[]' \
    --format='value(quotas.metric,quotas.limit,quotas.usage)' 2>/dev/null)"
  if [[ -z "$quotas" ]]; then
    echo "could not read quotas for $REGION: check the project and that Compute is on" >&2
    exit 1
  fi
  global="$(gc compute project-info describe --flatten='quotas[]' \
    --format='value(quotas.metric,quotas.limit,quotas.usage)' 2>/dev/null)"

  short=0
  check() {
    local metric="$1" need="$2" table="$3" limit usage spare
    limit="$(awk -v m="$metric" '$1 == m { print $2; exit }' <<<"$table")"
    # A family with no quota entry of its own is bounded only by the totals, which
    # are checked in their own right.
    [[ -z "$limit" ]] && return 0
    usage="$(awk -v m="$metric" '$1 == m { print $3 + 0; exit }' <<<"$table")"
    spare="$(awk -v l="$limit" -v u="$usage" 'BEGIN { print l - u }')"
    if awk -v s="$spare" -v n="$need" 'BEGIN { exit !(n > s) }'; then
      echo "quota: $metric has $spare of $limit free, this lab needs $need" >&2
      short=1
    fi
  }

  while read -r metric need; do
    [[ -n "$metric" ]] && check "$metric" "$need" "$quotas"
  done <<<"$wanted
INSTANCES $new_vms"

  check CPUS_ALL_REGIONS "$(awk '{ n += $2 } END { print n + 0 }' <<<"$wanted")" "$global"

  if (( short )); then
    cat >&2 <<ADVICE

Lower GENERATORS, choose a smaller GEN_MACHINE, or raise the quota:
  https://console.cloud.google.com/iam-admin/quotas?project=$PROJECT
ADVICE
    exit 1
  fi
fi

cat <<SUMMARY
lab          $LAB in $ZONE of $PROJECT
hosts        1 relay ($RELAY_MACHINE), 1 publisher ($PUB_MACHINE),
             $GENERATORS generator(s) ($GEN_MACHINE) -- $total_vms VMs
lifetime     each host shuts itself down after $TTL_MINUTES minutes;
             ./down.sh deletes the lab and stops all charges
SUMMARY
if ! confirm "create this lab?"; then
  echo "nothing created"
  exit 0
fi

# --- network -----------------------------------------------------------------
#
# Custom subnet mode so the lab gets exactly one subnet in one region, rather than one
# in every region for a measurement that uses a single zone.
if ! present networks "$NETWORK"; then
  echo "creating network $NETWORK"
  gc compute networks create "$NETWORK" --subnet-mode=custom --mtu="$MTU"
fi
if ! present "networks subnets" "$SUBNET" --region "$REGION"; then
  echo "creating subnet $SUBNET"
  gc compute networks subnets create "$SUBNET" \
    --network="$NETWORK" --region="$REGION" --range="$SUBNET_RANGE"
fi

# Outbound only, and only so the hosts can fetch apt packages and the Rust toolchain.
# Nothing dials in: that is what makes it safe for the instances to have no addresses.
if ! present routers "$ROUTER" --region "$REGION"; then
  echo "creating router and NAT for outbound package fetches"
  gc compute routers create "$ROUTER" --network="$NETWORK" --region="$REGION"
  gc compute routers nats create "$NAT" \
    --router="$ROUTER" --region="$REGION" \
    --auto-allocate-nat-external-ips --nat-all-subnet-ip-ranges
fi

# SSH arrives through Identity-Aware Proxy from a fixed Google-owned range, so port 22
# is never open to the internet and access is an IAM decision rather than a firewall
# one.
if ! present firewall-rules "${LAB}-ssh-iap"; then
  gc compute firewall-rules create "${LAB}-ssh-iap" \
    --network="$NETWORK" --allow=tcp:22 \
    --source-ranges=35.235.240.0/20 --target-tags="$LAB" \
    --description="SSH to the $LAB load lab, through IAP only"
fi
# The relay's QUIC port, reachable from this lab's own instances and from nowhere
# else. Scoped by tag rather than by address range so it stays correct if the subnet
# changes.
if ! present firewall-rules "${LAB}-moqt"; then
  gc compute firewall-rules create "${LAB}-moqt" \
    --network="$NETWORK" --allow="udp:$PORT" \
    --source-tags="${LAB}-gen,${LAB}-pub" --target-tags="${LAB}-relay" \
    --description="MOQT from the $LAB generators to its relay"
fi
# The admin port carries the relay's own counters, which is half of every result: what
# arrived is one account, and what the relay decided to shed is the other. Only the
# publisher host scrapes it, because every scrape competes with the load.
if ! present firewall-rules "${LAB}-admin"; then
  gc compute firewall-rules create "${LAB}-admin" \
    --network="$NETWORK" --allow="tcp:$ADMIN_PORT" \
    --source-tags="${LAB}-pub" --target-tags="${LAB}-relay" \
    --description="Metrics scraping of the $LAB relay, from its publisher host only"
fi

# --- instances ---------------------------------------------------------------

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

# The one thing that must happen even if provisioning fails half way: a host that
# nobody remembers should stop costing money. Scheduled at boot rather than by a
# later ssh, so it applies to an instance whose setup never completed.
cat > "$work/startup.sh" <<STARTUP
#!/bin/bash
# Stop this host after the lab's lifetime, whatever else has or has not happened.
shutdown -h +$TTL_MINUTES "moqom load lab lifetime reached" || true
STARTUP

create_host() {
  local name="$1" machine="$2" role="$3"
  if present instances "$name" --zone "$ZONE"; then
    echo "$name exists"
    return 0
  fi
  echo "creating $name ($machine)"
  gcz compute instances create "$name" \
    --machine-type="$machine" \
    --image-family="$IMAGE_FAMILY" --image-project="$IMAGE_PROJECT" \
    --boot-disk-size="$BOOT_DISK_SIZE" --boot-disk-type=pd-balanced \
    --network-interface="subnet=$SUBNET,nic-type=GVNIC,no-address" \
    --tags="$LAB,${LAB}-${role}" \
    --labels="moqom-lab=$LAB,moqom-role=$role" \
    --metadata-from-file=startup-script="$work/startup.sh" \
    --shielded-secure-boot --shielded-vtpm --shielded-integrity-monitoring
}

create_host "$RELAY_HOST" "$RELAY_MACHINE" relay
create_host "$PUB_HOST" "$PUB_MACHINE" pub

# The generators are identical, so they go up in one call rather than one at a time.
# Ten sequential creates is two and a half minutes of waiting for nothing.
missing=()
for host in $(generators); do
  present instances "$host" --zone "$ZONE" || missing+=("$host")
done
if (( ${#missing[@]} > 0 )); then
  echo "creating ${#missing[@]} generator(s) ($GEN_MACHINE)"
  gcz compute instances create "${missing[@]}" \
    --machine-type="$GEN_MACHINE" \
    --image-family="$IMAGE_FAMILY" --image-project="$IMAGE_PROJECT" \
    --boot-disk-size="$BOOT_DISK_SIZE" --boot-disk-type=pd-balanced \
    --network-interface="subnet=$SUBNET,nic-type=GVNIC,no-address" \
    --tags="$LAB,${LAB}-gen" \
    --labels="moqom-lab=$LAB,moqom-role=gen" \
    --metadata-from-file=startup-script="$work/startup.sh" \
    --shielded-secure-boot --shielded-vtpm --shielded-integrity-monitoring
fi

# Everything from here is done to every host at once. Serially it is twenty-five
# minutes of apt, rustup and file copying with all ten machines already billing, and
# the hosts have nothing to do with each other -- so the only thing serial ordering
# buys is a tidier log, at a price.
#
# Each host's output goes to its own file so a failure is still diagnosable, and the
# names are carried alongside the pids because a pid on its own cannot say which
# machine went wrong.
run_on_every_host() {
  local label="$1" pids=() names=() host i failed=0
  shift
  for host in $(hosts); do
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

# SSH is not available the moment an instance is RUNNING: sshd and the guest
# environment start after it, and IAP needs a moment more. Polled rather than slept
# past, because the wait is a minute on a good day and five on a bad one.
await_ssh() {
  local host="$1"
  for _ in $(seq 1 60); do
    on "$host" true >/dev/null 2>&1 && return 0
    sleep 5
  done
  echo "never accepted ssh; check IAP permissions and the NAT" >&2
  return 1
}

echo "waiting for ssh"
run_on_every_host ssh await_ssh

# --- the harness -------------------------------------------------------------

prepare_host() {
  local host="$1"
  push "$host" "$loadgen/probe.sh" /tmp/probe.sh
  push "$host" "$here/remote/host-setup.sh" /tmp/host-setup.sh
  push "$host" "$here/remote/relay.sh" /tmp/relay.sh
  on "$host" "sudo install -d -m 0755 $REMOTE_ROOT/bin \
    && sudo install -m 0644 /tmp/probe.sh $REMOTE_ROOT/probe.sh \
    && sudo install -m 0755 /tmp/relay.sh $REMOTE_ROOT/relay.sh \
    && chmod +x /tmp/host-setup.sh && /tmp/host-setup.sh"
}

echo "preparing hosts"
run_on_every_host prepare prepare_host

# The working tree rather than a git archive, so uncommitted work is measured. A lab
# built from HEAD while the change under test sat unstaged would be the most
# expensive way to learn nothing.
echo "packaging the source tree"
tar --exclude=./target --exclude=./.git --exclude=./cloud/results \
  -czf "$work/moqom-engine.tar.gz" -C "$engine" .

echo "building on $BUILD_HOST"
push "$BUILD_HOST" "$work/moqom-engine.tar.gz" /tmp/moqom-engine.tar.gz
push "$BUILD_HOST" "$here/remote/build.sh" /tmp/build.sh
on "$BUILD_HOST" "chmod +x /tmp/build.sh && /tmp/build.sh /tmp/moqom-engine.tar.gz"

# One build, copied everywhere, so no result can be explained by version skew.
echo "distributing the binaries"
pull "$BUILD_HOST" "$REMOTE_ROOT/bin/moqom-relay" "$work/moqom-relay"
pull "$BUILD_HOST" "$REMOTE_ROOT/bin/moqom-load" "$work/moqom-load"
pull "$BUILD_HOST" "$REMOTE_ROOT/jwks.json" "$work/jwks.json"
pull "$BUILD_HOST" "$REMOTE_ROOT/admin-token" "$work/admin-token"
install_binaries() {
  local host="$1"
  # The build host already has them, and they are the originals rather than copies.
  [[ "$host" == "$BUILD_HOST" ]] && return 0
  push "$host" "$work/moqom-relay" /tmp/moqom-relay
  push "$host" "$work/moqom-load" /tmp/moqom-load
  push "$host" "$work/jwks.json" /tmp/jwks.json
  push "$host" "$work/admin-token" /tmp/admin-token
  on "$host" "sudo install -m 0755 /tmp/moqom-relay $REMOTE_ROOT/bin/moqom-relay \
    && sudo install -m 0755 /tmp/moqom-load $REMOTE_ROOT/bin/moqom-load \
    && sudo install -m 0644 /tmp/jwks.json $REMOTE_ROOT/jwks.json \
    && sudo install -m 0644 /tmp/admin-token $REMOTE_ROOT/admin-token && rm -f /tmp/admin-token"
}

run_on_every_host install install_binaries

# The clip, to every host including the subscribers: a subscriber reads it to learn
# how long each group should be, which is how it reports loss without being told
# anything by the publisher. Same path everywhere, so one --clip serves the whole run.
if [[ -n "$CLIP" ]]; then
  echo "distributing $(basename "$CLIP")"
  install_clip() {
    local host="$1"
    push "$host" "$CLIP" /tmp/clip.h264
    on "$host" "sudo install -m 0644 /tmp/clip.h264 $REMOTE_CLIP"
  }
  run_on_every_host clip install_clip
fi

relay_ip="$(internal_ip "$RELAY_HOST")"
cat <<DONE

lab ready
relay        $RELAY_HOST at $relay_ip:$PORT
publisher    $PUB_HOST (the only host that scrapes the relay's metrics)
generators   $(generators | tr '\n' ' ')
built on     $BUILD_HOST

next         ./measure.sh 2000 4000 8000
then         ./down.sh
DONE

if [[ -n "$CLIP" ]]; then
  echo "clip         $REMOTE_CLIP on every host"
fi
