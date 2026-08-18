# Repository stabilization audit (2026-08-16)

## Installation and dependencies

The distribution explicitly installs the regular packages `helpdesktool` and
`linux_agent`. Runtime imports are covered by the declared FastAPI, Uvicorn, SQLAlchemy,
Alembic, Pydantic Settings and psycopg dependencies; HTTPX, pytest, Ruff and mypy are in
the `dev` extra. No required tests use conditional dependency skips.

## Schema consistency

Migration `0001` is a frozen baseline. Migration `0002` adds action claim token hash,
claim/lease timestamps, attempt count, verification, and rollback outcome; matching ORM
columns exist on `Action` and `ExecutionResultRow`. Migration `0003` adds domain events,
webhook subscriptions and webhook deliveries; all three have matching ORM models.
Migration `0004` adds the tenant-scoped incident lifecycle and correlation indexes;
the ORM and schema-contract tests contain matching fields. New schema changes must use
additive migrations rather than editing an applied revision.

## Canonical action flow

The FastAPI control plane uses the existing `PolicyEngine` and `ActionOrchestrator` with
SQL action/audit adapters and `execute_immediately=False`. It never performs endpoint
remediation. Approved actions become queued jobs; the authenticated device atomically
claims a lease, executes its local allowlisted deterministic skill, and reports the
structured execution/verification/rollback result. The integration test derives its
success report from the real `ServiceRestartExecutor` with a fake `systemctl` runner.

## Security status

- `X-Tenant-ID`/`X-User-ID` is explicitly development-only. Configuration refuses to
  start a non-development environment while insecure header authentication is enabled.
- PostgreSQL audit appends take a transaction-scoped tenant advisory lock before reading
  the chain head, preventing two writers from allocating the same sequence/hash parent.
- Agent bearer tokens remain long-lived; OIDC, PostgreSQL RLS, mTLS, rate limiting,
  signed job envelopes, secret rotation and durable endpoint execution journaling remain.
- Webhook URL validation reduces SSRF exposure, but production egress still requires a
  network-enforced proxy/allowlist to address DNS rebinding and routing changes.
