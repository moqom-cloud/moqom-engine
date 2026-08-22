#!/usr/bin/env bash
# Names and settings below are read by the scripts that source this one rather than by
# this one, which is what a configuration file is for.
# shellcheck disable=SC2034
#
# Where the cloud lab lives and how to talk to it. Sourced by the others, not run.
#
# The measurement this exists for cannot be done on one machine. The local figures
# stalled at roughly 160 subscribers per core with the relay never exceeding a third
# of the host's CPU, because what actually ran out was a loopback shared by the
# generator and the thing it was measuring: datagrams the kernel discarded rose from
# about 1,300 at 500 subscribers to 108,000 at 1,000. Past that the run stops being
# about the relay. Separate hosts are the fix, and they are the only fix.
#
# Linux rather than macOS for a second reason: it is where the relay ships, and it is
# where quinn's GSO and GRO both apply. Enabling Apple's batched-send path moved the
# local ceiling only from about 570 to 650 Mbit/s, so send batching was a tax rather
# than the wall — but the number worth publishing has to come from the kernel the
# relay runs on in production.
#
# Everything is named from $LAB and labelled with it, so teardown is exact and two
# people can run labs in one project without colliding.

# Fail loudly if this is executed rather than sourced. Every path below assumes the
# caller's shell, and a stray `./lab.sh` that silently did nothing would be read as
# a lab that had been configured.
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
  echo "lab.sh is sourced by up.sh, measure.sh and down.sh rather than run" >&2
  exit 64
fi

# A lab that exists has a shape, and every script has to agree on it: measure.sh
# asking six generators for load when up.sh built three does not fail cleanly, it
# hangs on ssh to hosts that were never created. So the shape is written down once,
# here, rather than retyped into each invocation.
#
# Untracked, because it describes one person's project and quota rather than the
# design. Use the same `: "${VAR:=value}"` form as below, so that a variable given on
# the command line still wins over the file.
# shellcheck source=/dev/null
[[ -f "${BASH_SOURCE[0]%/*}/lab.local" ]] && source "${BASH_SOURCE[0]%/*}/lab.local"

: "${LAB:=moqom-lab}"
: "${ZONE:=us-central1-a}"

# N2 rather than the newer C3, for a dull reason worth writing down: a fresh project
# gets 24 C3 vCPUs in a region and 200 N2, and this lab wants well over a hundred. C3
# would measure slightly better per core, so a figure from here is the conservative
# one -- which is the right direction for a number that gets published. Raise the C3
# quota and set RELAY_MACHINE to compare.
#
# Eight cores for the relay leaves it below its own egress cap: GCP allows roughly
# 2 Gbit/s per vCPU, so 16 Gbit/s here, against the 650 Mbit/s the laptop managed.
: "${RELAY_MACHINE:=n2-standard-8}"

# The generators are deliberately much larger in aggregate than the relay. A
# subscriber costs its own host more than it costs the relay -- each one is a whole
# QUIC client with its own socket and its own decryption -- so generation capacity
# has to exceed serving capacity or the run measures the generators, which is the
# entire failure the local numbers suffered from.
: "${GEN_MACHINE:=n2-standard-16}"

# The publisher sends one copy of one track and scrapes the relay's counters, which
# is close to no work at all -- but it is also the build host, and it is sized for
# that. A clean release build of the workspace on four cores is fifteen minutes with
# the whole lab already billing, which costs more than the larger machine does.
: "${PUB_MACHINE:=n2-standard-16}"

# How many hosts generate load. Eight of them against a relay with eight cores is
# roughly sixteen generator cores per relay core, which should leave the relay as the
# first thing to run out.
: "${GENERATORS:=8}"

: "${IMAGE_FAMILY:=ubuntu-2404-lts-amd64}"
: "${IMAGE_PROJECT:=ubuntu-os-cloud}"
: "${BOOT_DISK_SIZE:=50GB}"

# A lab that stops billing on its own if it is forgotten. This is a shutdown rather
# than a delete, so the results and logs on disk survive it; `down.sh` is what
# actually removes anything. Four hours is long enough for a sweep and short enough
# that a laptop closed at the wrong moment does not become a monthly line item.
: "${TTL_MINUTES:=240}"

: "${SUBNET_RANGE:=10.128.0.0/20}"

# The default GCP MTU, deliberately, although the VPC would carry 8896. A relay's
# ceiling measured over jumbo frames is not a number that describes the internet, and
# this measurement exists to be published. Raise it only to answer a separate
# question, and say so beside the answer.
: "${MTU:=1460}"

readonly PORT=4433
readonly ADMIN_PORT=9091

# Where the harness lands on every host.
readonly REMOTE_ROOT=/opt/moqom

# An Annex B elementary stream to publish instead of frames of one size, given to
# `up.sh` so that it reaches every host:
#
#   ffmpeg -i clip.mp4 -c:v copy -bsf:v h264_mp4toannexb /tmp/clip.h264
#   CLIP=/tmp/clip.h264 ./up.sh
#   ./measure.sh --clip "$REMOTE_CLIP" --fps 24 2000 4000
#
# Subscribers get it too, and need to: a subscriber reads the clip to learn how many
# frames each group should hold, which is how it reports loss without being told
# anything by the publisher. One path on every host is what makes that work.
: "${CLIP:=}"
readonly REMOTE_CLIP="$REMOTE_ROOT/clip.h264"

REGION="${ZONE%-*}"

: "${PROJECT:=$(gcloud config get-value project 2>/dev/null)}"

readonly NETWORK="${LAB}-net"
readonly SUBNET="${LAB}-subnet"
readonly ROUTER="${LAB}-router"
readonly NAT="${LAB}-nat"
readonly RELAY_HOST="${LAB}-relay"
readonly PUB_HOST="${LAB}-pub"

# The publisher host doubles as the builder by default. Anything but the relay will
# do, which is why this can be overridden: the relay has to be a machine nothing else
# has touched, because a cargo build leaves half a gigabyte of page cache and several
# minutes of scheduler history behind it and the relay's CPU and memory behaviour is
# the whole exercise. A generator is a fine builder, and worth choosing when vCPU
# quota is tight enough that the publisher has to be small -- building the workspace
# on two cores costs more in billed waiting than the larger machine ever would.
: "${BUILD_HOST:=$PUB_HOST}"
readonly BUILD_HOST

# Generator host N, counting from zero.
generator() { echo "${LAB}-gen-$1"; }

# Every generator host, in order.
generators() {
  local n
  for (( n = 0; n < GENERATORS; n++ )); do generator "$n"; done
}

# Every host in the lab.
hosts() {
  echo "$RELAY_HOST"
  echo "$PUB_HOST"
  generators
}

# gcloud with the lab's project and zone already applied.
#
# Wrapped rather than repeated so that no call can accidentally run against
# whatever project happened to be configured, which for a script that creates and
# deletes instances is worth more than the brevity.
# Which account to act as.
#
# Pinned rather than left to whichever account gcloud has active, because the failure
# otherwise is misleading in an expensive way: a stale token on some unrelated signed-in
# account fails every call here with a message about reauthentication that names no
# project, while the account that can actually reach the lab is signed in and working.
# Set it in lab.local.
: "${ACCOUNT:=}"
gc() {
  if [[ -n "$ACCOUNT" ]]; then
    gcloud --project "$PROJECT" --account "$ACCOUNT" --quiet "$@"
  else
    gcloud --project "$PROJECT" --quiet "$@"
  fi
}
gcz() { gc "$@" --zone "$ZONE"; }

# Which private key to authenticate with.
#
# Named explicitly rather than left to gcloud's default, because the default key is
# often passphrase-protected and everything here runs unattended: ssh answers a
# passphrase prompt it cannot show by failing, which surfaces as every host refusing
# to accept ssh and reads exactly like a firewall or IAP fault. Point this at a key
# with no passphrase, or add the usual one to an agent before starting.
: "${SSH_KEY_FILE:=}"
ssh_key_flags() {
  [[ -n "$SSH_KEY_FILE" ]] && echo "--ssh-key-file=$SSH_KEY_FILE"
}

# Run a command on a lab host.
#
# Over IAP, because the instances have no public addresses: an open SSH port is the
# one thing in here that would outlive the measurement if teardown were forgotten.
# The keepalives matter — a measurement holds the session open for the length of the
# run, and a dropped channel would look like a generator failing.
on() {
  local host="$1"
  shift
  # shellcheck disable=SC2046 # deliberately unquoted: absent means no flag at all
  gcz compute ssh "$host" \
    --tunnel-through-iap $(ssh_key_flags) \
    --ssh-flag=-oServerAliveInterval=30 \
    --ssh-flag=-oServerAliveCountMax=10 \
    --ssh-flag=-oLogLevel=ERROR \
    --command "$*"
}

# Copy into a lab host.
push() {
  local host="$1" local_path="$2" remote_path="$3"
  # shellcheck disable=SC2046
  gcz compute scp --tunnel-through-iap $(ssh_key_flags) "$local_path" "$host:$remote_path"
}

# Copy out of a lab host.
pull() {
  local host="$1" remote_path="$2" local_path="$3"
  # shellcheck disable=SC2046
  gcz compute scp --tunnel-through-iap $(ssh_key_flags) "$host:$remote_path" "$local_path"
}

# A host's address inside the VPC, which is the only address it has.
internal_ip() {
  gcz compute instances describe "$1" \
    --format='value(networkInterfaces[0].networkIP)' 2>/dev/null
}

# Whether a resource is already there, so provisioning can be run twice.
#
# The kind is one argument even when gcloud spells it as two words, as
# "networks subnets" is, and is split here on purpose. Passing it as two arguments
# would make the subnet's own name the third, so the check would ask about a network
# called "subnets", always find nothing, and quietly turn every run into a first run.
present() {
  local kind="$1" name="$2"
  shift 2
  local words
  read -ra words <<<"$kind"
  gc compute "${words[@]}" describe "$name" "$@" --format='value(name)' >/dev/null 2>&1
}

# Ask before doing something that costs money or destroys a lab.
#
# Typed confirmation rather than y/n for the destructive one, because these scripts
# name their resources predictably and the cost of a reflexive "y" against the wrong
# lab is somebody else's measurement.
confirm() {
  local prompt="$1" expected="${2:-yes}"
  if [[ "${ASSUME_YES:-}" == "1" ]]; then
    return 0
  fi
  local answer
  read -r -p "$prompt [$expected] " answer
  [[ "$answer" == "$expected" ]]
}

# Refuse to start without the things every path here needs.
require_lab() {
  if ! command -v gcloud >/dev/null; then
    echo "the Google Cloud CLI is not installed" >&2
    return 1
  fi
  if [[ -z "$PROJECT" ]]; then
    echo "no project set: gcloud config set project PROJECT, or PROJECT=... $0" >&2
    return 1
  fi
  return 0
}
