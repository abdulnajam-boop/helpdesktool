#!/usr/bin/env bash
# Stands up the real production API + frontend Docker images (not dev
# servers) against a real, throwaway Postgres, seeds one tenant/device/
# incident through the real HTTP API, then runs browser_e2e.mjs inside the
# official Playwright image against it. Everything is torn down on exit,
# success or failure. Requires Docker; nothing else.
#
# Usage: bash tests/e2e/run.sh
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
NET="helpdesk-e2e-net-$$"
PG="helpdesk-e2e-pg-$$"
API="helpdesk-e2e-api-$$"
FRONTEND="helpdesk-e2e-frontend-$$"
OUT_DIR="${REPO_ROOT}/tests/e2e/out"
BOOTSTRAP_TOKEN="e2e-bootstrap-token"

cleanup() {
  docker rm -f "$FRONTEND" "$API" "$PG" >/dev/null 2>&1 || true
  docker network rm "$NET" >/dev/null 2>&1 || true
}
trap cleanup EXIT

echo "==> Building images"
docker build -t helpdesktool-api:e2e "$REPO_ROOT" >/dev/null

echo "==> Starting network + Postgres"
docker network create "$NET" >/dev/null
docker run -d --name "$PG" --network "$NET" \
  -e POSTGRES_USER=helpdesk -e POSTGRES_PASSWORD=helpdesk -e POSTGRES_DB=helpdesk \
  postgres:17 >/dev/null
for _ in $(seq 1 30); do
  docker exec "$PG" pg_isready -U helpdesk >/dev/null 2>&1 && break
  sleep 1
done

echo "==> Running migrations"
docker run --rm --network "$NET" \
  -e HELPDESK_DATABASE_URL="postgresql+psycopg://helpdesk:helpdesk@${PG}:5432/helpdesk" \
  helpdesktool-api:e2e alembic upgrade head

echo "==> Starting the API"
docker run -d --name "$API" --network "$NET" -p 18100:8000 \
  -e HELPDESK_DATABASE_URL="postgresql+psycopg://helpdesk:helpdesk@${PG}:5432/helpdesk" \
  -e HELPDESK_APP_ROLE_PASSWORD="change-me-before-use" \
  -e HELPDESK_ENVIRONMENT="development" \
  -e HELPDESK_CORS_ORIGINS="http://${FRONTEND}" \
  -e HELPDESK_BOOTSTRAP_TOKEN="$BOOTSTRAP_TOKEN" \
  -e HELPDESK_SERVICE_ALLOWLIST="demo.service" \
  helpdesktool-api:e2e >/dev/null
for _ in $(seq 1 30); do
  curl -fs http://localhost:18100/health/live >/dev/null 2>&1 && break
  sleep 1
done

echo "==> Seeding a tenant, device, and incident through the real API"
IDENTITY=$(curl -sf -X POST http://localhost:18100/v1/tenants \
  -H "X-Bootstrap-Token: $BOOTSTRAP_TOKEN" -H "Content-Type: application/json" \
  -d '{"name":"Acme E2E","admin_email":"owner@e2e.example"}')
TENANT_ID=$(echo "$IDENTITY" | python -c "import json,sys; print(json.load(sys.stdin)['tenant_id'])")
ADMIN_ID=$(echo "$IDENTITY" | python -c "import json,sys; print(json.load(sys.stdin)['admin_user_id'])")
DEVICE=$(curl -sf -X POST http://localhost:18100/v1/devices/enroll \
  -H "X-Tenant-ID: $TENANT_ID" -H "X-User-ID: $ADMIN_ID" -H "Content-Type: application/json" \
  -d '{"external_id":"e2e-server-1","hostname":"e2e-server-1","os":"linux"}')
DEVICE_ID=$(echo "$DEVICE" | python -c "import json,sys; print(json.load(sys.stdin)['device_id'])")
AGENT_TOKEN=$(echo "$DEVICE" | python -c "import json,sys; print(json.load(sys.stdin)['agent_token'])")
curl -sf -X POST "http://localhost:18100/v1/devices/${DEVICE_ID}/inventory" \
  -H "Authorization: Bearer $AGENT_TOKEN" -H "Idempotency-Key: inv-1" -H "Content-Type: application/json" \
  -d '{"collected_at":"2026-08-20T12:00:00Z","payload":{"filesystems":[{"mountpoint":"/","total_bytes":1000,"free_bytes":30}]}}' >/dev/null

echo "==> Building the frontend image against the API container's internal address"
docker build -t helpdesktool-frontend:e2e \
  --build-arg "VITE_API_URL=http://${API}:8000" \
  "$REPO_ROOT/frontend" >/dev/null

echo "==> Starting the frontend"
docker run -d --name "$FRONTEND" --network "$NET" helpdesktool-frontend:e2e >/dev/null
sleep 2

echo "==> Running the browser E2E suite"
mkdir -p "$OUT_DIR"
# MSYS_NO_PATHCONV avoids Git Bash on Windows silently rewriting the
# container-side halves of -v/-w/-e below into host paths; a leading //
# on those same container-side paths is belt-and-suspenders for the same
# reason (harmless, and ignored, on real Linux/macOS bash).
MSYS_NO_PATHCONV=1 docker run --rm --network "$NET" \
  -e "E2E_BASE_URL=http://${FRONTEND}" \
  -e "E2E_OUT_DIR=//out" \
  -v "$OUT_DIR://out" \
  -v "$REPO_ROOT/tests/e2e/browser_e2e.mjs://work/browser_e2e.mjs:ro" \
  -w //work \
  mcr.microsoft.com/playwright:v1.48.0-noble \
  bash -c "npm init -y >/dev/null 2>&1 && npm install playwright@1.48.0 >/dev/null 2>&1 && node browser_e2e.mjs"
