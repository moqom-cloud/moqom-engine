#!/usr/bin/env bash
# Delete the lab and stop the charges.
#
#   ./down.sh              # asks first, listing exactly what it will remove
#   ASSUME_YES=1 ./down.sh # for a wrapper that has already asked
#
# Deletion is by exact name, every name derived from $LAB, and nothing here filters on
# anything looser. A teardown script for a load lab is the most likely thing in this
# directory to be pointed at the wrong project by accident, and a filter like "every
# instance with a load-ish label" would make that mistake expensive rather than
# annoying.
#
# Order matters: instances hold the subnet, the NAT holds the router, and the router
# and firewall rules hold the network. Deleting outside in fails on dependencies and
# leaves half a lab behind, which then bills for the parts nobody can see.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lab.sh
. "$here/lab.sh"
require_lab

# Arguments are checked rather than ignored. `--yes` is the obvious thing to reach for
# on a script that asks for confirmation, and silently disregarding it on the one
# script here that destroys things means watching a teardown you thought was
# unattended stop and wait, or worse, assuming it ran.
while (( $# > 0 )); do
  # shellcheck disable=SC2034 # ASSUME_YES is read by confirm() over in lab.sh
  case "$1" in
    -y|--yes) ASSUME_YES=1; shift ;;
    -h|--help) sed -n '2,15p' "${BASH_SOURCE[0]}"; exit 0 ;;
    *) echo "unknown argument $1; this script takes --yes or nothing" >&2; exit 64 ;;
  esac
done

# Only what is actually there, so the confirmation reflects reality rather than the
# configuration -- a half-created lab and a fully created one need different lists.
doomed=()
for host in $(hosts); do
  present instances "$host" --zone "$ZONE" && doomed+=("$host")
done

echo "project      $PROJECT"
echo "lab          $LAB in $ZONE"
if (( ${#doomed[@]} > 0 )); then
  echo "instances    ${doomed[*]}"
else
  echo "instances    none found"
fi
echo "network      $NETWORK, $SUBNET, $ROUTER, $NAT,"
echo "             firewall rules ${LAB}-ssh-iap, ${LAB}-moqt, ${LAB}-admin"
echo
echo "Anything on these hosts is destroyed, including relay logs. Results already"
echo "pulled into cloud/results are local and are not touched."
if ! confirm "type the lab's name to delete it:" "$LAB"; then
  echo "nothing deleted"
  exit 0
fi

if (( ${#doomed[@]} > 0 )); then
  echo "deleting instances"
  # One call, so the deletes proceed together rather than a minute each in series.
  gcz compute instances delete "${doomed[@]}"
fi

for rule in "${LAB}-ssh-iap" "${LAB}-moqt" "${LAB}-admin"; do
  if present firewall-rules "$rule"; then
    echo "deleting firewall rule $rule"
    gc compute firewall-rules delete "$rule"
  fi
done

if present routers "$ROUTER" --region "$REGION"; then
  echo "deleting NAT and router"
  gc compute routers nats delete "$NAT" --router="$ROUTER" --region="$REGION" 2>/dev/null || true
  gc compute routers delete "$ROUTER" --region="$REGION"
fi

if present "networks subnets" "$SUBNET" --region "$REGION"; then
  echo "deleting subnet $SUBNET"
  gc compute networks subnets delete "$SUBNET" --region="$REGION"
fi

if present networks "$NETWORK"; then
  echo "deleting network $NETWORK"
  gc compute networks delete "$NETWORK"
fi

echo
echo "lab $LAB removed"
# Worth saying rather than assuming: a lab is not the only thing a measurement can
# leave running, and the check costs one command.
echo "if a sweep was interrupted, confirm nothing survives:"
echo "  gcloud compute instances list --project $PROJECT --filter='labels.moqom-lab=$LAB'"
