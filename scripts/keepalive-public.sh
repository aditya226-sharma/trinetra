#!/usr/bin/env bash
# Public tunnel keepalive: probe the ngrok endpoint and restore the stack
# whenever it goes offline. Run periodically by the com.trinetra.public
# LaunchAgent (ThrottleInterval 30).
#
# Hardenings vs the ngrok free tier's flaky edges:
#   - single transient probe resets are retried (no knee-jerk recreate)
#   - a lockfile prevents concurrent launchd invocations from fighting
#   - credentials come from compose's env_file, so recreate always works
set -uo pipefail

TUNNEL_URL="${TRINETRA_TUNNEL_URL:-https://unease-chummy-outburst.ngrok-free.dev}"
COMPOSE="${TRINETRA_COMPOSE:-/Users/adityasharma/trinetra/compose.public.yml}"
PROJECT="${TRINETRA_PROJECT:-trinetra-deploy}"
LOG="/tmp/trinetra-deploy/public-keepalive.log"
LOCK="/tmp/trinetra-deploy/public-keepalive.lock"

DOCKER="${TRINETRA_DOCKER:-/usr/local/bin/docker}"

log() { printf '%s %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$*" >> "$LOG"; }

probe() { curl -sf --max-time 10 -o /dev/null "$TUNNEL_URL/api/health" 2>/dev/null; }

# A single probe reset can be a momentary hiccup that recovers on its own,
# so only treat the tunnel as down when N consecutive probes fail.
down_after_retries() {
  local n=0
  for _ in 1 2 3; do
    probe && return 1     # up -> healthy, no restart needed
    n=$((n + 1))
    sleep 4
  done
  return 0                # all 3 failed -> genuinely offline
}

# Ensure the API stack is running before probing (cheap no-op when healthy).
"$DOCKER" compose -f "$COMPOSE" -p "$PROJECT" up -d >>"$LOG" 2>&1

if probe; then
  exit 0
fi

# Claim the lock so two launchd runs never restack simultaneously.
if /usr/bin/shlock -f "$LOCK" -p $$ 2>/dev/null; then
  if down_after_retries; then
    log "tunnel offline for consecutive probes — restoring stack"
    "$DOCKER" compose -f "$COMPOSE" -p "$PROJECT" up -d --force-recreate trinetra-ngrok >>"$LOG" 2>&1
    sleep 12
    if probe; then
      log "tunnel recovered"
    else
      log "tunnel still down after ngrok recreate (will retry next round)"
    fi
  else
    log "transient ok (recovered within retries) — no restart"
  fi
  rm -f "$LOCK"
else
  log "skipping: another keepalive instance holds the lock"
fi
exit 0