#!/usr/bin/env bash
# Watch the lab's numbers in this terminal until you stop it.
#
#   ./live.sh           # every 2s
#   ./live.sh 5         # every 5s
#
# Open this in a Cursor terminal and leave it running. It waits for the relay
# if the lab is down, then prints a line every interval once a run is on.
# measure.sh prints the same line; this is the second-terminal view.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lab.sh
. "$here/lab.sh"
require_lab

interval="${1:-2}"
if ! [[ "$interval" =~ ^[0-9]+$ ]] || (( interval < 1 )); then
  echo "usage: $0 [seconds-between-lines]" >&2
  exit 64
fi

installed=
waiting=
echo "watching $RELAY_HOST in $ZONE  (Ctrl-C to stop)"
echo "waiting for the lab — start a run with ./measure.sh in another terminal"
while :; do
  if [[ -z "$installed" ]]; then
    if push "$RELAY_HOST" "$here/remote/relay.sh" /tmp/relay.sh >/dev/null 2>&1 \
      && on "$RELAY_HOST" "sudo install -m 0755 /tmp/relay.sh $REMOTE_ROOT/relay.sh && rm -f /tmp/moqom-relay.tick" >/dev/null 2>&1; then
      installed=yes
      waiting=
      echo
      echo "live from $RELAY_HOST every ${interval}s"
    else
      if [[ -z "$waiting" ]]; then
        echo "  still waiting for $RELAY_HOST to accept ssh"
        waiting=yes
      fi
      sleep "$interval"
      continue
    fi
  fi

  line="$(on "$RELAY_HOST" \
    "MOQOM_LAB_ADMIN_PORT=$ADMIN_PORT $REMOTE_ROOT/relay.sh tick" \
    2>/dev/null || true)"
  if [[ -n "$line" ]]; then
    printf '%s\n' "$line"
  else
    # The host went away mid-run (sweep restart, teardown). Re-install next pass.
    echo "  relay did not answer — waiting"
    installed=
  fi
  sleep "$interval"
done
