# Helpdesktool

Helpdesktool is a deterministic, safety-first IT operations SaaS MVP. It combines a FastAPI/PostgreSQL control plane, an unprivileged Linux endpoint agent, and a React operator console.

The executable trust boundary is:

```text
Observe -> Detect -> Correlate -> Ticket -> Structured action proposal
-> Policy -> Independent approval when required -> Device-bound job
-> Authenticated allowlisted agent executor -> Verify -> Roll back/escalate
-> Audit and domain events
```

The product is **not** a remote shell. Neither browser input nor future AI output can become an arbitrary shell or PowerShell command. The control plane queues structured work; only an authenticated endpoint agent can execute a locally allowlisted deterministic skill.

## What the MVP includes

- Multi-tenant tenants, users, roles, devices, inventory, heartbeats, tickets, incidents, actions, approvals, execution results, audit events, and webhook integrations.
- Development-only browser sessions for Owner, Admin, Operator, and Viewer demo users. Non-development environments fail closed if development authentication is enabled.
- Dashboard and searchable browser pages for Devices, Tickets, Incidents, Actions, Approvals, Audit, Integrations, and Settings.
- Deterministic low-disk detection, correlation, automatic ticket creation, recovery detection, incident reopening, and domain events.
- A browser-accessible low-disk simulator which writes structured development telemetry without filling a real disk.
- Risk-based policy and separation-of-duties approval before mutating endpoint work is queued.
- Device-bound job leases, claim-token validation, idempotent reporting, verification and rollback outcomes.
- Hash-chained tenant audit history and a transactional signed-webhook outbox.
- An unprivileged Linux agent with inventory collectors and one allowlisted `service.restart` executor using fixed `systemctl` argument vectors and no shell.

## Architecture

```text
React/Vite operator console (:3000)
              |
              v
FastAPI control plane (:8000) ----> PostgreSQL
  |       |       |                      |
  |       |       +--> audit + events --> webhook outbox worker
  |       +----------> incident correlation + tickets
  +------------------> policy + approvals + persistent jobs
                                      |
                                      v
                         authenticated Linux agent
                                      |
                                      v
                    allowlisted deterministic executor
```

Core backend modules live in `helpdesktool/`, the agent in `linux_agent/`, the browser application in `frontend/`, and additive Alembic migrations in `migrations/versions/`.

## Quick start: one command

Requirements: Docker Engine with the Compose plugin.

```bash
cp .env.example .env
```

Replace every `replace-with-...` value in `.env`, then run:

```bash
docker compose up --build
```

Compose starts PostgreSQL, applies all migrations, idempotently seeds the Acme demo tenant, starts the API and webhook worker, then starts the frontend after the API health check passes. The named PostgreSQL volume preserves development data across `docker compose down` and restarts.

Open:

- Operator console: <http://localhost:3000>
- API: <http://localhost:8000>
- OpenAPI documentation: <http://localhost:8000/docs>
- Liveness: <http://localhost:8000/health/live>
- Database readiness: <http://localhost:8000/health/ready>

Select `admin@acme.local` on the development login page.

### Seeded development data

`helpdesk-seed` is development-only and safe to run repeatedly. It creates or reconciles:

- Tenant: **Acme IT**
- Users: `owner@acme.local`, `admin@acme.local`, `operator@acme.local`, and `viewer@acme.local`
- Devices: `web-prod-01`, `db-prod-01`, and `employee-laptop-01`
- Realistic heartbeats and inventories
- A correlated low-disk incident and linked ticket on `web-prod-01`
- A database-backup ticket
- A pending, ticket-linked controlled action requested by the Operator
- Device, incident, ticket, approval, audit, and domain-event history

## First browser test

1. Log in as `admin@acme.local`.
2. Confirm the Dashboard shows three devices and a pending approval.
3. Open **Devices -> web-prod-01**.
4. In **Simulated disk use**, submit `96`. The existing low-disk incident is correlated and its occurrence count increases.
5. Submit `40`. Recovery telemetry resolves the incident and linked ticket.
6. Submit `96` again. The same incident reopens rather than creating an unlimited duplicate.
7. Open **Approvals**, inspect the allowlisted skill parameters, and approve or deny the seeded request.
8. Inspect the linked Action and Audit timeline. Approval only queues work; it does not execute an OS command in the browser or control plane.

The complete browser and live-agent checklist is in [docs/MVP_TESTING.md](docs/MVP_TESTING.md).

## Role behavior

- **Owner:** tenant administration and all operational capabilities.
- **Admin:** device, ticket, action, approval, and integration management.
- **Operator:** ticket/action operations and development telemetry simulation; cannot approve risky work.
- **Viewer:** tenant-scoped read-only access.

The UI removes controls that do not apply to the current role, but FastAPI authorization remains authoritative and returns `403` for prohibited writes.

## Local development without Compose

Requires Python 3.11+, PostgreSQL, and Node.js 22+.

```bash
python -m pip install -e ".[dev]"
alembic upgrade head
helpdesk-seed
uvicorn helpdesktool.api:app --reload
```

In another terminal:

```bash
cd frontend
npm install
npm run dev
```

## Linux agent

Copy `agent.example.json` to `~/.config/helpdesktool/agent.json`, insert a tenant/user identity for enrollment, and keep the same narrow service allowlist in the server and agent configuration.

```bash
python -m pip install -e .
mkdir -p ~/.config/helpdesktool
cp agent.example.json ~/.config/helpdesktool/agent.json
chmod 600 ~/.config/helpdesktool/agent.json
helpdesk-linux-agent --config ~/.config/helpdesktool/agent.json --once
```

The agent stores its one-time credential with owner-only permissions, sends heartbeat/inventory, claims only jobs addressed to its device, validates leases and exact parameters, invokes `systemctl` without a shell, verifies the outcome, attempts rollback when necessary, and posts a structured result. Do not run it as root merely to make remediation work; use a narrow PolicyKit rule for only the test service.

## Integrations

Generic webhook subscriptions are external consumers only. n8n, Slack, Teams, and ticketing systems cannot approve endpoint work, bypass policy, or enter the execution trust boundary.

Webhook signing secrets are environment references such as `env:HELPDESK_WEBHOOK_SECRET_N8N`; secret values are not stored in subscription rows or returned to the frontend. Deliveries carry `X-Helpdesk-Event-ID` and an `X-Helpdesk-Signature-256` HMAC header. HTTPS public destinations are required by default, and the worker uses bounded timeouts, retry backoff, and dead-letter state.

## Validation

```bash
python -m pip install -e ".[dev]"
python -c "import helpdesktool; import linux_agent"
python -m compileall helpdesktool linux_agent
pytest
ruff check .
ruff format --check .
mypy
cd frontend && npm install && npm run build
cd .. && docker compose config && docker compose build
```

CI performs the backend and frontend checks from the repository manifests.

## Shutdown and reset

Preserve development data:

```bash
docker compose down
docker compose up --build
```

Destroy and recreate the demo database only when intentionally resetting QA:

```bash
docker compose down -v
docker compose up --build
```

## Known limitations

- Development HMAC sessions and optional identity headers are not production identity. Production OIDC/JWT is deferred, and both development mechanisms must be disabled outside local development.
- Tenant filtering is enforced in application queries; PostgreSQL Row Level Security is not yet enabled.
- Agent bearer credentials are long-lived and require rotation/mTLS hardening before production endpoint deployment.
- The MVP detects and verifies low-disk recovery but does not ship an unsafe generic disk-cleanup command. A future cleanup skill must define exact safe targets, permission, verification, and rollback/escalation behavior.
- `service.restart` is the only mutating reference executor. It is appropriate for exercising policy/approval/job/verification/rollback, not for claiming that restarting a service fixes disk usage.
- Windows agent, production billing, OIDC, AI diagnosis, RAG, advanced ticketing integrations, and Kubernetes deployment are intentionally deferred.
