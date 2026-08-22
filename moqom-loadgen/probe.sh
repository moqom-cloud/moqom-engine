#!/usr/bin/env bash
# What the machine did, on either of the two operating systems this runs on.
#
# Sourced by run.sh and fleet.sh rather than duplicated, because the two numbers
# in here are the ones that decide whether a result is about the relay at all, and
# a measurement that silently reports zero on Linux because it was written against
# BSD netstat is worse than one that reports nothing.

# Datagrams the kernel threw away because a receive buffer was full.
#
# This is the first number to read after a disappointing run. A relay sheds a
# subscriber that has stopped reading, and a subscriber whose datagrams the kernel
# discarded has stopped reading through no fault of its own — so a run with many
# drops is a run measuring the host, and the relay's behaviour is correct however
# bad the report looks.
udp_drops() {
  case "$(uname -s)" in
    Darwin)
      netstat -s -p udp 2>/dev/null |
        sed -n 's/.*[^0-9]\([0-9]\{1,\}\) dropped due to full socket buffers.*/\1/p' |
        head -1
      ;;
    Linux)
      # RcvbufErrors from /proc/net/snmp, which is the same quantity under a
      # different name. Read positionally from the header rather than by a fixed
      # column, because the set of counters has grown between kernel versions.
      awk '
        /^Udp:/ {
          if (header == "") { for (i = 2; i <= NF; i++) column[$i] = i; header = "seen"; next }
          if ("RcvbufErrors" in column) print $column["RcvbufErrors"]
        }' /proc/net/snmp 2>/dev/null | head -1
      ;;
    *) ;;
  esac
}

# Cumulative CPU seconds a process has spent.
#
# Cumulative rather than instantaneous on purpose: by the time a percentage can be
# read the load has stopped, so `%cpu` reports the relay doing nothing and invites
# the conclusion that it was never busy.
cpu_seconds() {
  # Linux gives whole seconds directly. macOS has no such field, so fall through
  # to parsing the clock format, which is [DD-]HH:MM:SS.
  local seconds
  seconds="$(ps -p "$1" -o cputimes= 2>/dev/null | tr -d ' ')"
  if [[ "$seconds" =~ ^[0-9]+$ ]]; then
    echo "$seconds"
    return
  fi
  ps -p "$1" -o cputime= 2>/dev/null | tr -d ' ' | tr '-' ':' |
    awk -F: '{ s = 0; for (i = 1; i <= NF; i++) s = s * 60 + $i; print s }'
}

# Warn about the host limits a large run meets before the relay does.
#
# Advisory rather than enforced, because raising them needs privileges this script
# should not assume and the run is still worth doing without them.
check_host_limits() {
  local wanted="$1"
  local limit
  limit="$(ulimit -n)"
  if [[ "$limit" != "unlimited" ]] && (( limit < wanted )); then
    echo "file descriptors capped at $limit but this run wants about $wanted;" >&2
    echo "  subscribers past that will fail to connect" >&2
  fi

  if [[ "$(uname -s)" == "Linux" ]]; then
    local rmem
    rmem="$(sysctl -n net.core.rmem_max 2>/dev/null || echo 0)"
    # Below a couple of megabytes the kernel discards datagrams long before the
    # relay is busy, and the run measures sysctl rather than software.
    if (( rmem < 2097152 )); then
      echo "net.core.rmem_max is $rmem, which will drop datagrams before the relay is busy;" >&2
      echo "  consider: sudo sysctl -w net.core.rmem_max=16777216 net.core.wmem_max=16777216" >&2
    fi
  fi
}

# Print what the machine spent, given readings taken either side of a run.
report_host() {
  local dropped="$1" cpu_before="$2" cpu_after="$3" wall="$4" subscribers="$5"

  echo "kernel       $dropped datagram(s) dropped for full socket buffers"
  # A clean run on a ten-core Mac loses on the order of a thousand and QUIC
  # recovers every one, so the threshold sits well above that: it is here to catch
  # the regime where drops stop being noise, not to comment on a healthy run.
  if (( dropped > 5000 )); then
    echo "             enough to matter: this machine, not the relay, may be the limit,"
    echo "             and subscribers the relay shed may genuinely have stopped reading"
  fi

  awk -v before="${cpu_before:-0}" -v after="${cpu_after:-0}" -v wall="$wall" \
      -v subscribers="$subscribers" '
    BEGIN {
      spent = after - before;
      if (wall <= 0) wall = 1;
      cores = spent / wall;
      printf "relay        %.1fs of CPU over %ds, so %.2f core(s) busy\n", spent, wall, cores;
      if (cores > 0.01)
        printf "             %.0f subscribers per core at this frame rate and size\n",
               subscribers / cores;
    }'
}
