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
