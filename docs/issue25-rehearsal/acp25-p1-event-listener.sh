#!/usr/bin/env bash
# acp25-p1-event-listener — issue #25 P1. Event-driven delegation: on every
# Docker `start` event for the production `hermes` container, run the pinned
# delegation helper (idempotent; converges against the settling s6 tree).
# If the helper fails, the seam gate stays UNKNOWN (fail-closed) — we log and
# keep listening; never retry-spam the same event.
set -eu
CONTAINER="${1:-hermes}"
HELPER=/usr/local/bin/acp25-p1-helper.sh
docker events --filter "container=$CONTAINER" --filter event=start |
while read -r _line; do
  # start event fires once PID1 exists; helper's re-pass loop absorbs the rest.
  if "$HELPER" "$CONTAINER"; then
    logger -t acp-delegate "delegation OK for $CONTAINER"
  else
    logger -t acp-delegate "WARN: helper failed for $CONTAINER (exit $?) — gate stays UNKNOWN"
  fi
done
