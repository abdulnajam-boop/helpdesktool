# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

Helpdesktool is a deterministic, safety-first IT operations SaaS MVP: a FastAPI/PostgreSQL control plane, an unprivileged Linux endpoint agent, and a React operator console. It is explicitly **not** a remote shell — neither browser input nor AI output can become an arbitrary shell/PowerShell command. The control plane only ever queues structured work that an authenticated endpoint agent executes via a locally allowlisted deterministic skill.

The trust boundary every feature must respect:

```
Observe -> Detect -> Correlate -> Ticket -> Structured action proposal
-> Policy -> Independent approval when required -> Device-bound job
-> Authenticated allowlisted agent executor -> Verify -> Roll back/escalate
-> Audit and domain events
```

## Commands

Backend (Python 3.11+, requires PostgreSQL):

```bash
python -m pip install -e ".[dev]"
alembic upgrade head
helpdesk-seed                              # idempotent demo tenant/data seed
uvicorn helpdesktool.api:app --reload
pytest                                     # full suite
pytest tests/test_orchestrator.py          # single file
pytest tests/test_orchestrator.py::test_name  # single test
ruff check .
ruff format --check .
mypy                                       # strict mode, see pyproject.toml
python -m compileall helpdesktool linux_agent
```

Frontend (Node.js 22+, in `frontend/`):

```bash
npm install
npm run dev          # vite dev server, host 0.0.0.0
npm run build         # tsc -b && vite build
npm run typecheck     # tsc -b only
```

Full stack via Docker Compose (preferred for end-to-end/manual testing):

```bash
cp .env.example .env   # then replace every replace-with-... value
docker compose up --build
```

Compose brings up Postgres, runs Alembic migrations, idempotently seeds the Acme demo tenant, starts the API + webhook worker, then the frontend once the API health check passes. `docker compose down` preserves the named Postgres volume; add `-v` to destroy and reset demo data.

CI (`.github/workflows/ci.yml`) runs, as two independent jobs:
- backend: `python -m compileall`, `ruff check .`, `ruff format --check .`, `mypy`, `pytest`
- frontend: `npm install && npm run build` (in `frontend/`)

Run the equivalent locally before considering backend or frontend work done.

### Known toolchain baseline (updated 2026-08-19, post-Milestone-1)

- `mypy` is clean (`strict = true`, `platform = "linux"` in `pyproject.toml` — this repo is Linux-deployed end to end, so mypy is pinned to that platform rather than whatever OS it happens to run on). Keep it clean; don't reintroduce `Optional`-access bugs or bare generic container types.
- `pytest` has 3 tests that only pass on Linux (`test_linux_agent.py`'s file-permission assertion, two `test_linux_collectors.py` tests reading `/proc/*`) — they fail on Windows dev machines by design (unmocked POSIX calls), not by regression. CI runs on `ubuntu-latest` where they're expected to pass.
- `tests/conftest.py` holds the shared fixtures: `client` (in-memory SQLite, used by most tests) and `postgres_session_factory` (real PostgreSQL, used only by `tests/test_persistence_postgres.py` to exercise the `pg_advisory_xact_lock` branch in `persistence.py::SqlAuditLog.append` — the one code path SQLite silently no-ops). Set `HELPDESK_TEST_DATABASE_URL` to a disposable Postgres database to run those tests locally; without it they skip cleanly. CI's `postgres` service container in `.github/workflows/ci.yml` sets this automatically.
- See `docs/IMPLEMENTATION_PLAN.md` for the full current-state audit and the milestone roadmap toward a production-ready SaaS — check its Milestone 1 "Actual completion status" block before assuming a capability is missing; check the numbered audit sections (1-9) for everything not yet started.

## Architecture

```
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

- `helpdesktool/` — control plane (FastAPI app, domain logic, persistence).
- `linux_agent/` — unprivileged Linux endpoint agent.
- `frontend/` — React/Vite operator console (single-file app at `frontend/src/main.tsx`).
- `migrations/versions/` — additive-only Alembic migrations.
- `tests/` — pytest suite mirroring the modules above, plus `test_api_integration.py` and `test_schema_contract.py`.

### Backend module map (`helpdesktool/`)

- `api.py` — the single FastAPI app; all `/v1/...` routes (auth, devices, heartbeats, inventory, incidents, tickets, actions/approvals, agent job claim/result, audit, webhooks, settings) live here as thin handlers over the modules below.
- `models.py` — typed domain contracts (`RiskLevel`, `ActionStatus`, `ActionRequest`, `SkillDefinition`, etc.) shared conceptually between control plane and agent.
- `policy.py` — `PolicyEngine`: default-deny evaluation of registered skills; unknown/prohibited skills always fail closed.
- `orchestrator.py` — the safety state machine coordinating policy evaluation, approval, execution dispatch, and rollback (`SkillExecutor` protocol).
- `incidents.py` — deterministic, tenant-scoped incident correlation (e.g. low-disk detection/recovery/reopen) from inventory telemetry.
- `persistence.py` — SQLAlchemy-backed adapters (`SqlAuditLog`, etc.) bridging domain state to `db_models`.
- `db_models.py` — SQLAlchemy ORM models (tenants, users, devices, tickets, incidents, actions, audit rows, webhook subscriptions/deliveries).
- `events.py` — canonical domain events (`EventType`) and transactional publication helpers; audit-producing state transitions map to these in the same DB transaction.
- `audit.py` — append-only, hash-chained audit event store contract.
- `integrations.py` — provider-neutral integration contracts and signed webhook delivery (SSRF-safe: rejects loopback/private/link-local/multicast destinations, HTTPS required by default).
- `webhook_worker.py` — separate long-running process draining the transactional webhook outbox with bounded retry/backoff and dead-lettering (`helpdesk-webhook-worker` entry point).
- `auth.py` / `development_auth.py` — request principal resolution; `development_auth.py` is an explicitly development-only signed browser session mechanism that must be disabled outside local development (see `Settings.development_login_enabled`).
- `config.py` — `pydantic-settings` `Settings`, env-prefixed `HELPDESK_`, loaded from `.env`.
- `seed.py` — idempotent demo-tenant seeding (`helpdesk-seed` entry point), safe to rerun.

### Linux agent (`linux_agent/`)

`agent.py` (entry point `helpdesk-linux-agent`) ties together `config.py` (enrollment/identity), `client.py` (HTTP transport), `collectors.py` (`/proc`-based inventory), and `executor.py` (deterministic execution). The agent claims only jobs addressed to its device via a leased, one-time claim secret, validates exact parameters against its local allowlist, executes via direct `systemctl` argument vectors (no shell), verifies the resulting unit state, and attempts rollback to the prior state on failure. Currently `service.restart` is the only mutating executor. Do not add shell-based or parameter-templated execution paths — this is the core safety invariant of the whole system.

### Frontend (`frontend/`)

Single-page app in `frontend/src/main.tsx` covering Dashboard, Devices, Tickets, Incidents, Actions, Approvals, Audit, Integrations, and Settings, talking to the API via `frontend/src/api.ts`. The UI hides controls that don't apply to the current role (Owner/Admin/Operator/Viewer), but FastAPI authorization is authoritative and returns 403 for prohibited writes regardless of what the UI shows.

### Data flow / safety invariants to preserve

- Tenant ID always comes from authenticated identity/request context, never from client-supplied payload fields.
- Every mutating action passes through `PolicyEngine` (default deny) before it can become a queued job; high-risk skills require independent approval (separation of duties — the approver cannot be the requester).
- Jobs are device-bound, lease-based, and idempotently claimed/reported by the agent.
- Audit events are hash-chained and written transactionally alongside the state change they describe; domain events for webhook delivery are expanded into durable outbox rows in the same transaction.
- Webhook signing secrets are environment references (e.g. `env:HELPDESK_WEBHOOK_SECRET_N8N`), never stored as literal values in subscription rows or returned to the frontend.
- External integrations (n8n, Slack, Teams, ticketing) are read-only consumers of facts/lifecycle events — they cannot approve work, bypass policy, or issue endpoint jobs.

### Known deferred/limited areas (see README "Known limitations")

- Auth is development-only (signed HMAC sessions / header auth); production OIDC/JWT is not implemented.
- Tenant isolation is enforced in application queries, not Postgres Row Level Security.
- Agent bearer credentials are long-lived; rotation/mTLS is not yet implemented.
- No generic disk-cleanup skill exists by design — only `service.restart` as a reference mutating executor.
- **Abandoned job claims never recover.** `claim_job` sets `status="claimed"` with a 60s `lease_expires_at`; nothing ever requeues an expired claim back to `queued` or fails it out. If an agent crashes between claiming and reporting, that action is stuck forever with no operator-visible signal. Don't build new features on top of the job-claim flow assuming lease expiry is handled — it isn't yet (see `docs/IMPLEMENTATION_PLAN.md` Milestone 3).
- The remediation "skill registry" is a hardcoded two-item list literal (`SKILLS` in `api.py`), not a versioned/signed/data-driven registry. Adding a skill today means shipping synchronized code changes to the control plane and every agent.

`docs/ARCHITECTURE.md` describes the target production architecture (multi-agent OS support, RLS, OIDC, LLM diagnosis provider adapter) that this MVP is a deliberately narrower foundation for; consult it before making structural decisions that the current code doesn't yet need but the target design anticipates. `docs/IMPLEMENTATION_PLAN.md` is the authoritative, current-dated (2026-08-19) audit and milestone roadmap — prefer it over `docs/REPOSITORY_AUDIT.md`/`docs/STABILIZATION_AUDIT.md`, which are now-stale historical snapshots kept for context only.
