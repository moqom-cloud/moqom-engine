#!/usr/bin/env bash
# Prepare one lab host. Runs on the host, once, before anything is measured.
#
# Two of the settings in here are the reason the lab exists. The local runs were
# limited by datagrams the kernel discarded for full socket buffers rather than by
# anything the relay did, so a cloud host left at its defaults would reproduce the
# same wall in a more expensive place and the result would again say nothing about
# the software. Raising the buffers is not tuning for a flattering number: it is
# removing a constraint that has already been shown to dominate.
#
# Everything here is idempotent, because provisioning gets run twice.
set -euo pipefail

sudo install -d -m 0755 /opt/moqom /opt/moqom/bin

# Build dependencies. cmake, a C toolchain and perl are for aws-lc-rs, which builds
# its own crypto rather than linking the system's; the relay's protobuf bindings are
# checked in, so protoc is deliberately not needed.
export DEBIAN_FRONTEND=noninteractive
sudo apt-get update -qq
sudo apt-get install -y -qq \
  build-essential cmake pkg-config perl curl ca-certificates jq >/dev/null

# A profiler, because a ceiling is worth attributing rather than guessing at. Not
# fatal if the kernel's matching package is missing -- a lab that cannot profile can
# still measure, and `relay.sh profile` says so rather than failing a sweep.
sudo apt-get install -y -qq linux-perf >/dev/null 2>&1 ||
  sudo apt-get install -y -qq "linux-tools-$(uname -r)" >/dev/null 2>&1 || true
# Sampling a process this user owns, which is otherwise refused at the default
# setting. Confined to this lab: the hosts have no public address and exist for the
# length of a measurement.
sudo sysctl --quiet -w kernel.perf_event_paranoid=1 || true

# Socket buffers, which is the constraint the local measurement actually hit.
#
# 128 MiB of headroom rather than a carefully chosen figure: the aim is to move the
# kernel far enough out of the way that a drop means something, not to find the
# smallest value that works. udp_mem is in pages, and the defaults on a machine with
# plenty of memory are low enough to matter under fan-out.
#
# netdev_max_backlog is here for the receive side of a host holding thousands of
# sockets: the default drops packets between the NIC and the stack, which is invisible
# in a relay's own counters and appears only as loss at a subscriber.
sudo tee /etc/sysctl.d/99-moqom-lab.conf >/dev/null <<'CONF'
net.core.rmem_max = 134217728
net.core.wmem_max = 134217728
net.core.rmem_default = 33554432
net.core.wmem_default = 33554432
net.core.netdev_max_backlog = 250000
net.ipv4.udp_mem = 786432 1048576 26777216
net.ipv4.udp_rmem_min = 16384
net.ipv4.udp_wmem_min = 16384
# Each subscriber is its own socket, so a generator host holding thousands of them
# runs out of ephemeral ports long before it runs out of anything else.
net.ipv4.ip_local_port_range = 1024 65535
CONF
sudo sysctl --quiet --system

# File descriptors, the first ceiling a large run meets. Written to limits.d rather
# than raised with ulimit in the run command, because a login shell can only raise a
# soft limit as far as the hard one and the hard one is what needs moving. A session
# opened after this picks it up through pam_limits.
sudo tee /etc/security/limits.d/99-moqom-lab.conf >/dev/null <<'CONF'
* soft nofile 1048576
* hard nofile 1048576
root soft nofile 1048576
root hard nofile 1048576
CONF
sudo sysctl --quiet -w fs.nr_open=2097152

# The harness's own probes, so the numbers that decide whether a result is about the
# relay come from the same code the local runs used rather than from a second
# implementation written against Linux by hand.
if [[ -f /opt/moqom/probe.sh ]]; then
  # Installed by up.sh; it exists on a lab host and nowhere a linter can reach.
  # shellcheck disable=SC1091
  . /opt/moqom/probe.sh
  echo "probe.sh loads; udp drops so far: $(udp_drops)"
fi

echo "host ready: $(hostname), $(nproc) cores, $(free -g | awk '/^Mem:/ { print $2 }')GiB"
