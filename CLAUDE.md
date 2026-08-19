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

### Known toolchain baseline (updated 2026-08-19, post-Milestone-2)

- `mypy` is clean (`strict = true`, `platform = "linux"` in `pyproject.toml` — this repo is Linux-deployed end to end, so mypy is pinned to that platform rather than whatever OS it happens to run on). Keep it clean; don't reintroduce `Optional`-access bugs or bare generic container types.
- `pytest` has 3 tests that only pass on Linux (`test_linux_agent.py`'s file-permission assertion, two `test_linux_collectors.py` tests reading `/proc/*`) — they fail on Windows dev machines by design (unmocked POSIX calls), not by regression. CI runs on `ubuntu-latest` where they're expected to pass.
- `tests/conftest.py` holds the shared fixtures. SQLite: `client` (in-memory, used by most tests). Real PostgreSQL (skip cleanly unless `HELPDESK_TEST_DATABASE_URL` is set to a disposable database — CI's `postgres` service container sets this automatically): `postgres_session_factory` (schema-owner connection, no RLS — for `persistence.py`'s advisory-lock tests); `postgres_rls_session_factory` / `postgres_rls_single_connection_factory` (RLS applied, connects as the restricted `helpdesk_app` role — see below); `postgres_client` (full API TestClient in production-like mode: RLS + OIDC + restricted role together). `tests/support.py` holds shared OIDC test-token helpers.
- **Any fixture or code path that opens its own PostgreSQL session outside `helpdesktool.database.get_session()` must reset `app.current_tenant_id`/`app.rls_bypass` on teardown itself** (call `helpdesktool.database.reset_tenant_context`, or mirror its pattern). `get_session()` does this automatically; nothing else does — this was missed once in `webhook_worker.py`, once in a test fixture, and once in `helpdesktool/api.py`'s development-login endpoints (caught by an independent security review, not by testing — see `docs/IMPLEMENTATION_PLAN.md` Milestone 2's "bugs found"/security-review notes) before this session ended. Any new endpoint or script that queries `users`/`devices` before a tenant is known needs `helpdesktool.auth.resolving_identity`, the same narrow bypass those three fixes all use.
- See `docs/IMPLEMENTATION_PLAN.md` for the full current-state audit and the milestone roadmap toward a production-ready SaaS — check the relevant milestone's "Actual completion status" block before assuming a capability is missing; check the numbered audit sections (1-9) for everything not yet started.

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
- `database.py` — the module-level SQLAlchemy `engine`/`SessionLocal` (bound to the restricted `helpdesk_app` role via `Settings.runtime_database_url` for PostgreSQL) and `get_session()`, the FastAPI dependency every request uses. `get_session()` unconditionally resets the PostgreSQL tenant-context GUCs on teardown — see `set_tenant_context`/`set_rls_bypass` here and the trust-model note in `auth.py`.
- `events.py` — canonical domain events (`EventType`) and transactional publication helpers; audit-producing state transitions map to these in the same DB transaction.
- `audit.py` — append-only, hash-chained audit event store contract.
- `integrations.py` — provider-neutral integration contracts and signed webhook delivery (SSRF-safe: rejects loopback/private/link-local/multicast destinations, HTTPS required by default).
- `webhook_worker.py` — separate long-running process draining the transactional webhook outbox with bounded retry/backoff and dead-lettering (`helpdesk-webhook-worker` entry point); one of the two processes that legitimately sets the cross-tenant `rls_bypass` GUC (see `rls.py`), narrowly and only for its own batch.
- `lease_reaper.py` — separate long-running process (`helpdesk-lease-reaper` entry point) recovering `Action` jobs whose agent claim lease expired without a result ever being reported (agent crash/disconnect) — requeues them (bounded by `Settings.lease_reaper_max_attempts`) or escalates to `failed` once exhausted. The other process that sets `rls_bypass`. Without this, a crashed agent left a job `claimed` forever with no operator-visible signal — see `docs/IMPLEMENTATION_PLAN.md` Milestone 3.
- `auth.py` — request principal resolution and PostgreSQL tenant-context binding. Production human auth is OIDC (`oidc.py`) — a `Bearer` token is verified, then the tenant is resolved from its cryptographically verified `email` claim against `users`, never from a client header. Development browser sessions (`development_auth.py`) and the insecure `X-Tenant-ID`/`X-User-ID` header path stay available but are strictly gated to `environment == "development"` and fail closed otherwise (`Settings.validate_security`). See the module's docstring for the full trust model, including the narrow, documented `resolving_identity` exception (identity-resolution lookups must run before any tenant is known, so they can't themselves be RLS-scoped).
- `oidc.py` — provider-neutral OIDC access-token verification (`OIDCVerifier`). Not tied to any vendor; works with any standards-compliant provider that publishes a JWKS endpoint.
- `rls.py` — single source of truth for PostgreSQL row-level security: which tables are tenant-scoped, the `tenant_isolation` policy DDL, and provisioning of the restricted `helpdesk_app` database role RLS enforcement depends on (see `database.py` below). Shared by migration `0005` and by RLS-related test fixtures — never duplicate this DDL elsewhere.
- `config.py` — `pydantic-settings` `Settings`, env-prefixed `HELPDESK_`, loaded from `.env`. `runtime_database_url` derives the restricted-role connection the API/webhook-worker actually use at runtime from `database_url` + `app_role_password` — see `database.py`.
- `seed.py` — idempotent demo-tenant seeding (`helpdesk-seed` entry point), safe to rerun. Binds its own tenant context via `set_tenant_context` since it now runs as the restricted role too.

### Linux agent (`linux_agent/`)

`agent.py` (entry point `helpdesk-linux-agent`) ties together `config.py` (enrollment/identity), `client.py` (HTTP transport), `collectors.py` (`/proc`-based inventory), and `executor.py` (deterministic execution). The agent claims only jobs addressed to its device via a leased, one-time claim secret, validates exact parameters against its local allowlist, executes via direct `systemctl` argument vectors (no shell), verifies the resulting unit state, and attempts rollback to the prior state on failure. Currently `service.restart` is the only mutating executor. Do not add shell-based or parameter-templated execution paths — this is the core safety invariant of the whole system.

### Frontend (`frontend/`)

Single-page app in `frontend/src/main.tsx` covering Dashboard, Devices, Tickets, Incidents, Actions, Approvals, Audit, Integrations, and Settings, talking to the API via `frontend/src/api.ts`. The UI hides controls that don't apply to the current role (Owner/Admin/Operator/Viewer), but FastAPI authorization is authoritative and returns 403 for prohibited writes regardless of what the UI shows.

### Data flow / safety invariants to preserve

- Tenant ID always comes from authenticated identity/request context, never from client-supplied payload fields — enforced both in application queries and, since Milestone 2, by PostgreSQL Row-Level Security as a second, independent layer (see `auth.py`'s module docstring for the full trust model).
- Every mutating action passes through `PolicyEngine` (default deny) before it can become a queued job; high-risk skills require independent approval (separation of duties — the approver cannot be the requester).
- Jobs are device-bound, lease-based, and idempotently claimed/reported by the agent.
- Audit events are hash-chained and written transactionally alongside the state change they describe; domain events for webhook delivery are expanded into durable outbox rows in the same transaction.
- Webhook signing secrets are environment references (e.g. `env:HELPDESK_WEBHOOK_SECRET_N8N`), never stored as literal values in subscription rows or returned to the frontend.
- External integrations (n8n, Slack, Teams, ticketing) are read-only consumers of facts/lifecycle events — they cannot approve work, bypass policy, or issue endpoint jobs.

### Known deferred/limited areas (see README "Known limitations")

- Production human auth is OIDC (`helpdesktool/oidc.py` + `auth.py`), and tenant isolation is enforced by PostgreSQL Row-Level Security (`helpdesktool/rls.py`, migration `0005`) in addition to application-level filtering — both as of Milestone 2. There is still no frontend OIDC login UI; the browser can currently only authenticate via the development login page, which remains development-only.
- Device credentials can be rotated (admin-initiated or agent self-service) and revoked, and devices can self-enroll with a one-time admin-issued token (`helpdesktool/api.py`'s `/v1/devices/enrollment-tokens*`/`enroll-with-token` endpoints) — as of Milestone 3. mTLS itself and signed/versioned job envelopes are still not implemented.
- No generic disk-cleanup skill exists by design — only `service.restart` as a reference mutating executor.
- **Abandoned job claims now recover.** `helpdesktool/lease_reaper.py` (Milestone 3, `helpdesk-lease-reaper` entry point/Compose service) requeues or escalates any `Action` whose claim lease expired without a result being reported — previously (documented here as a known gap through Milestone 2) such a job stayed `claimed` forever with no operator-visible signal.
- The remediation "skill registry" is a hardcoded two-item list literal (`SKILLS` in `api.py`), not a versioned/signed/data-driven registry. Adding a skill today means shipping synchronized code changes to the control plane and every agent. (Milestone 4.)
- The Linux agent's local replay file (`processed.json`) still only guards against re-processing *completed* actions, not a crash between "restart succeeded" and "result reported" — the durable local execution journal half of Milestone 3 is not yet built.

`docs/ARCHITECTURE.md` describes the target production architecture (multi-agent OS support, RLS, OIDC, LLM diagnosis provider adapter) that this MVP is a deliberately narrower foundation for; consult it before making structural decisions that the current code doesn't yet need but the target design anticipates. `docs/IMPLEMENTATION_PLAN.md` is the authoritative, current-dated (2026-08-19) audit and milestone roadmap — prefer it over `docs/REPOSITORY_AUDIT.md`/`docs/STABILIZATION_AUDIT.md`, which are now-stale historical snapshots kept for context only.
