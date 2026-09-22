#!/usr/bin/env bash
# Public tunnel keepalive: probe the live edge and restore the stack whenever
# it goes offline. Run periodically by the com.trinetra.public LaunchAgent
# (ThrottleInterval 30).
#
# Replaced the ngrok-based watchdog (which hit the free-tier bandwidth cap):
# the edge is now a Cloudflare quick tunnel (`trinetra-tunnel`, cloudflared)
# with no data-transfer quota. Because quick-tunnel hostnames rotate on
# recreate, this script re-registers the CURRENT URL in
# frontend/public/live.html + live-url.txt so the dashboard banner and the
# live.html redirect never point at a stale host.
#
# Hardening:
#   - single transient probe resets are retried (no knee-jerk recreate)
#   - a lockfile prevents concurrent launchd invocations from fighting
#   - recreate targets trinetra-public / trinetra-tunnel only (ngrok is gone)
set -uo pipefail

PUBLIC_REPO="/Users/adityasharma/trinetra"
COMPOSE="${TRINETRA_COMPOSE:-$PUBLIC_REPO/compose.public.yml}"
PROJECT="${TRINETRA_PROJECT:-trinetra-deploy}"
LOG="/tmp/trinetra-deploy/public-keepalive.log"
LOCK="/tmp/trinetra-deploy/public-keepalive.lock"
LIVE_HTML="$PUBLIC_REPO/frontend/public/live.html"
LIVE_URL_TXT="$PUBLIC_REPO/frontend/public/live-url.txt"

DOCKER="${TRINETRA_DOCKER:-/usr/local/bin/docker}"

# URL is dynamic (cloudflared quick tunnel) — derive it from the container's
# own logs so we always probe the CURRENT edge, never a hardcoded one.
# Docker Desktop's log reader can return truncated output over a pipe, so
# spill to a temp file first (deterministic) before grepping.
TUNNEL_DIR="${TUNNEL_DIR:-$(mktemp -d)}"
docker logs trinetra-tunnel > "$TUNNEL_DIR/tunnel.log" 2>&1 || true
TUNNEL_URL="$(grep -oE 'https://[a-zA-Z0-9.-]+\.trycloudflare\.com' "$TUNNEL_DIR/tunnel.log" | tail -1)"
TUNNEL_URL="${TUNNEL_URL:-}"

log() { printf '%s %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$*" >> "$LOG"; }

probe() {
  if [ -n "$TUNNEL_URL" ] && curl -sf --max-time 10 -o /dev/null "$TUNNEL_URL/api/health" 2>/dev/null; then
    return 0
  fi
  # Fall back to the local API when we can't resolve a tunnel URL yet.
  curl -sf --max-time 10 -o /dev/null "http://127.0.0.1:8001/api/health" 2>/dev/null
}

# (Re)write live.html + live-url.txt with the tunnel's current URL so the
# dashboard banner and the "bookmark" page stay correct across rotations.
refresh_live_refs() {
  local url="$1"
  [ -n "$url" ] || return 0
  log "registering live URL $url"
  printf '%s\n' "$url" > "$LIVE_URL_TXT"
  cat > "$LIVE_HTML.tmp" <<EOF
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>TriNetra — Live instance</title>
<!--
  Regenerated automatically by the watchdog (keepalive-public.sh): this page
  always redirects to the CURRENT live tunnel URL, even after cloudflared
  rotates the quick-tunnel hostname. Bookmark this page: it never breaks.
-->
<meta http-equiv="refresh" content="0; url=$url">
<style>
  html,body{margin:0;min-height:100vh;display:grid;place-items:center;background:#0a0f1a;color:#cbd5e1;
    font:14px/1.6 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;text-align:center}
  a{color:#34d399;text-decoration:none;font-weight:600}
  a:hover{text-decoration:underline}
  .card{max-width:560px;padding:40px;border:1px solid #1e293b;border-radius:16px;background:#0f172a}
  .badge{display:inline-block;margin-bottom:12px;padding:3px 10px;border-radius:99px;font-size:12px;
    letter-spacing:.04em;color:#34d399;background:rgba(52,211,153,.12);border:1px solid rgba(52,211,153,.35)}
  p.mono{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:12px;color:#64748b;word-break:break-all}
</style>
</head>
<body>
  <div class="card">
    <span class="badge">TRINETRA · LIVE</span>
    <h1 style="margin:0 0 8px;font-size:20px;color:#f1f5f9">TriNetra live instance</h1>
    <p>Redirecting to the current live tunnel&hellip;</p>
    <p class="mono"><a href="$url">$url</a></p>
  </div>
</body>
</html>
EOF
  mv "$LIVE_HTML.tmp" "$LIVE_HTML"
}

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
  refresh_live_refs "$TUNNEL_URL"
  exit 0
fi

# Claim the lock so two launchd runs never restack simultaneously.
if /usr/bin/shlock -f "$LOCK" -p $$ 2>/dev/null; then
  if down_after_retries; then
    log "tunnel offline for consecutive probes — restoring stack"
    "$DOCKER" compose -f "$COMPOSE" -p "$PROJECT" up -d --force-recreate trinetra-public trinetra-tunnel >>"$LOG" 2>&1
    sleep 12
    docker logs trinetra-tunnel > "$TUNNEL_DIR/tunnel.log" 2>&1 || true
    TUNNEL_URL="$(grep -oE 'https://[a-zA-Z0-9.-]+\.trycloudflare\.com' "$TUNNEL_DIR/tunnel.log" | tail -1)"
    refresh_live_refs "$TUNNEL_URL"
    if probe; then
      log "tunnel recovered"
    else
      log "tunnel still down after recreate (will retry next round)"
    fi
  else
    log "transient ok (recovered within retries) — no restart"
  fi
  rm -f "$LOCK"
else
  log "skipping: another keepalive instance holds the lock"
fi
exit 0