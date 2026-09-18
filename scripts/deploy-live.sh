#!/usr/bin/env bash
# Refresh the live edge deployment from GHCR.
#
# Pulls the latest published image and recreates trinetra-public / trinetra-ngrok
# without touching the persistent `trinetra-public-data` volume (cases, events,
# users, JWT secret all survive).
#
# Requires: ADMIN_PASSWORD, AGENT_TOKEN, NGROK_AUTHTOKEN in the environment.
# Look at .env.example for the full variable list.
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PROJECT_NAME="${TRINETRA_PROJECT:-trinetra-deploy}"

require_env() {
  for v in "$@"; do
    if [ -z "${!v:-}" ]; then
      echo "error: $v is not set (see .env.example)" >&2
      exit 1
    fi
  done
}

main() {
  require_env ADMIN_PASSWORD AGENT_TOKEN NGROK_AUTHTOKEN

  echo "==> pulling ghcr.io/aditya226-sharma/trinetra:latest"
  docker compose -f "$REPO/compose.public.yml" \
    -p "$PROJECT_NAME" pull trinetra-public

  echo "==> recreating containers (data volume untouched)"
  docker compose -f "$REPO/compose.public.yml" \
    -p "$PROJECT_NAME" up -d

  echo "==> waiting for health..."
  for _ in $(seq 1 30); do
    curl -sf http://127.0.0.1:8001/api/health >/dev/null && {
      echo "    healthy at http://127.0.0.1:8001/api/health"
      return 0
    }
    sleep 2
  done
  echo "error: container did not become healthy" >&2
  docker compose -f "$REPO/compose.public.yml" -p "$PROJECT_NAME" ps
  return 1
}

main "$@"