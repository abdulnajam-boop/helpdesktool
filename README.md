# Helpdesktool

Autonomous, safety-first AI IT help desk platform.

Canonical repository: [abdulnajam-boop/helpdesktool](https://github.com/abdulnajam-boop/helpdesktool)

## Mission

Helpdesktool is designed to monitor endpoints, diagnose common IT problems, select controlled remediation skills, verify outcomes, roll back failed changes, and maintain a complete audit trail with minimal human intervention.

## Core execution model

`Observe -> Diagnose -> Plan -> Risk Check -> Approve (when required) -> Execute -> Verify -> Rollback (if needed) -> Document -> Learn`

The LLM is a planner and skill selector. Privileged actions are performed only by deterministic, policy-controlled executors. Arbitrary unrestricted shell execution is not part of the architecture.

## Initial architecture

- `skills/` — versioned machine-readable skill contracts
- `policies/` — risk, approval, and execution rules
- `orchestrator/` — AI orchestration contract and prompts
- `agent/` — endpoint agent design and OS executors
- `tests/` — contract, policy, and executor tests
- `docs/` — architecture and threat-model documentation

## v1 goals

1. Establish a safe skill contract.
2. Implement read-only diagnostic skills first.
3. Add low-risk remediations with verification and rollback.
4. Introduce approval gates for medium/high-risk operations.
5. Build immutable-style audit events for every decision and action.
6. Support Windows first, followed by Linux and macOS parity.

## Security principles

- Least privilege
- Default deny
- Explicit skill allowlists
- No arbitrary LLM-generated privileged commands
- Input validation
- Command timeouts and output limits
- Approval gates based on risk
- Verification after every mutation
- Rollback where technically possible
- Complete audit trail
- Secrets never written to prompts or logs

## Status

The runnable FastAPI control plane persists tenants, users, devices, telemetry, tickets,
actions, approvals, results, idempotency records, and hash-chained audit events in
PostgreSQL. It reuses the default-deny policy and orchestration state machine. Approved
jobs are queued only; the control plane deliberately cannot execute OS commands.
The Linux agent v0.1 enrolls, reports health/inventory, polls device-bound jobs, and
executes only the allowlisted deterministic `service.restart` skill.

See the [repository audit](docs/REPOSITORY_AUDIT.md), [production architecture](docs/ARCHITECTURE.md),
and [prioritized implementation plan](docs/IMPLEMENTATION_PLAN.md). Current persistence
and executors are intentionally interfaces/reference adapters; they are not yet a
deployable endpoint management product.

## Development

### Docker Compose (recommended)

```bash
cp .env.example .env
# Replace every placeholder secret in .env, then:
docker compose up --build
curl http://localhost:8000/health/ready
```

Migrations run as a one-shot Compose service before the API starts. Interactive API
documentation is available at `http://localhost:8000/docs`.

### Bootstrap workflow

1. `POST /v1/tenants` with `X-Bootstrap-Token` creates a tenant and owner.
2. Use returned IDs as `X-Tenant-ID` and `X-User-ID` to enroll a device.
3. Store the returned agent token once; only its SHA-256 digest is persisted.
4. The agent uses `Authorization: Bearer <token>` plus a unique `Idempotency-Key` for
   heartbeat and inventory requests.
5. Users create tickets/actions. Medium/high risk actions require a different owner or
   admin to call the decision endpoint. All allowed actions remain queued for a future
   signed endpoint-agent job protocol.

### Local development

Requires Python 3.11+ and PostgreSQL. Install `.[dev]`, configure `.env`, run
`alembic upgrade head`, then `uvicorn helpdesktool.api:app --reload`.

```bash
pytest
ruff check .
ruff format --check .
mypy
```

`X-Tenant-ID` and `X-User-ID` are development scaffolding, not authentication. The
application refuses to start outside `development` while
`HELPDESK_ALLOW_INSECURE_HEADER_AUTH=true`. Do not expose development mode publicly.
See [the stabilization audit](docs/STABILIZATION_AUDIT.md) for schema and security status.

## Linux agent v0.1

The agent runs as the current unprivileged user. Copy `agent.example.json` to
`~/.config/helpdesktool/agent.json`, insert the tenant and owner IDs returned by tenant
bootstrap, and set the same service allowlist in both `.env` and agent configuration.

```bash
python -m pip install -e .
mkdir -p ~/.config/helpdesktool
cp agent.example.json ~/.config/helpdesktool/agent.json
chmod 600 ~/.config/helpdesktool/agent.json
helpdesk-linux-agent --config ~/.config/helpdesktool/agent.json --once
```

For continuous operation, install `deploy/helpdesk-linux-agent.service` as a systemd
**user** unit. Restart permission is not granted automatically: configure a narrow
PolicyKit rule for only the allowlisted demo unit. Never run the agent as root merely
to make remediation work.

### End-to-end demonstration

1. Start Compose and bootstrap a tenant using `POST /v1/tenants`.
2. Put the returned tenant/user IDs in the agent config and run the agent once. It
   enrolls, saves its one-time credential with mode `0600`, sends a heartbeat and full
   Linux inventory, then polls for work.
3. Create a ticket and a `service.restart` action whose parameters are
   `{"service":"helpdesk-demo.service"}` and include a unique `Idempotency-Key`.
4. A *different* owner/admin approves it through
   `POST /v1/actions/{id}/decision`. The action becomes `queued`.
5. Run the agent again. It claims the device-bound lease, checks the local allowlist and
   unit state, calls `systemctl restart` without a shell, verifies `active/running`, and
   reports a structured result. Query `GET /v1/actions/{id}` and `GET /v1/audit` to see
   the final status and complete transition history.

## External integrations and n8n

Helpdesk now publishes versioned domain events transactionally with state/audit changes.
Tenant administrators can register generic webhook subscriptions through
`POST /v1/integrations/webhooks`. n8n is only an external consumer: it cannot approve,
authorize, execute, or change remediation policy.

Webhook signing secrets are referenced as environment variables and are never stored in
the database. For example, configure `HELPDESK_WEBHOOK_SECRET_N8N`, then register
`env:HELPDESK_WEBHOOK_SECRET_N8N` as `secret_ref`. Deliveries include:

```text
X-Helpdesk-Event-ID: <uuid>
X-Helpdesk-Signature-256: sha256=<HMAC-SHA256 of exact request body>
```

Consumers must verify the signature before parsing or acting on a payload. HTTPS and
publicly routable destinations are required by default. The separate Compose worker
uses bounded timeouts, exponential retries, dead-letter state, and no inbound API
credentials. Local HTTP delivery can be enabled only with
`HELPDESK_WEBHOOK_ALLOW_HTTP=true`; this does not disable private-address rejection.

See [the external project evaluation](docs/OPEN_SOURCE_EVALUATION.md) for the explicit
build/integrate/avoid decisions and licensing cautions.
