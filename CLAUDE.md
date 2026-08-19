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
npm test              # vitest run
```

Full stack via Docker Compose (preferred for end-to-end/manual testing):

```bash
cp .env.example .env   # then replace every replace-with-... value
docker compose up --build
```

Compose brings up Postgres, runs Alembic migrations, idempotently seeds the Acme demo tenant, starts the API + webhook worker, then the frontend once the API health check passes. `docker compose down` preserves the named Postgres volume; add `-v` to destroy and reset demo data.

CI (`.github/workflows/ci.yml`) runs, as three independent jobs:
- backend: `python -m compileall`, `ruff check .`, `ruff format --check .`, `mypy`, `pytest`
- frontend: `npm install`, `npm run typecheck`, `npm test`, `npm run build` (in `frontend/`)
- docker: builds the API and frontend Docker images and runs each one for real (curls `/health/live` / `/`) — catches import/startup failures a plain `docker build` can't; see `CLAUDE.md`'s Frontend section for the real bug this caught.

Run the equivalent locally before considering backend or frontend work done.

### Known toolchain baseline (updated 2026-08-19, post-Milestone-2)

- `mypy` is clean (`strict = true`, `platform = "linux"` in `pyproject.toml` — this repo is Linux-deployed end to end, so mypy is pinned to that platform rather than whatever OS it happens to run on). Keep it clean; don't reintroduce `Optional`-access bugs or bare generic container types.
- `pytest` has 4 tests that only pass on Linux (`test_linux_agent.py`'s and `test_execution_journal.py`'s file-permission assertions — both check `os.chmod`'s real effect, a no-op on Windows — plus two `test_linux_collectors.py` tests reading `/proc/*`) — they fail on Windows dev machines by design (unmocked POSIX calls), not by regression. CI runs on `ubuntu-latest` where they're expected to pass.
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
- `skills.py` — the versioned, integrity-checked remediation skill registry (Milestone 4): `SkillManifest`/`ParameterSpec` (shape-only parameter schema — names/types/required, never a command template) and `compute_manifest_hash` (a SHA-256 over a manifest's own canonical policy fields, recomputed and compared on every read in `api.py`'s `load_active_skill_manifests`/`get_active_manifest` — a stored row whose hash no longer matches fails the request closed). Replaces the old hardcoded `SKILLS` list literal in `api.py` with the `skills` table (migration `0008`, platform-wide/unscoped like `tenants`). See the module docstring for exactly what this does and does not change: registering a manifest is a data change, but an agent must still ship its own deterministic executor code for a skill to actually run — this registry can never itself describe *how* a skill executes.
- `orchestrator.py` — the safety state machine coordinating policy evaluation, approval, execution dispatch, and rollback (`SkillExecutor` protocol).
- `incidents.py` — deterministic, tenant-scoped incident correlation (e.g. low-disk detection/recovery/reopen) from inventory telemetry.
- `persistence.py` — SQLAlchemy-backed adapters (`SqlAuditLog`, etc.) bridging domain state to `db_models`.
- `db_models.py` — SQLAlchemy ORM models (tenants, users, devices, tickets, incidents, actions, audit rows, webhook subscriptions/deliveries).
- `database.py` — the module-level SQLAlchemy `engine`/`SessionLocal` (bound to the restricted `helpdesk_app` role via `Settings.runtime_database_url` for PostgreSQL) and `get_session()`, the FastAPI dependency every request uses. `get_session()` unconditionally resets the PostgreSQL tenant-context GUCs on teardown — see `set_tenant_context`/`set_rls_bypass` here and the trust-model note in `auth.py`.
- `events.py` — canonical domain events (`EventType`) and transactional publication helpers; audit-producing state transitions map to these in the same DB transaction.
- `audit.py` — append-only, hash-chained audit event store contract.
- `integrations.py` — provider-neutral integration contracts and signed webhook delivery (SSRF-safe: rejects loopback/private/link-local/multicast destinations, HTTPS required by default).
- `webhook_worker.py` — separate long-running process draining the transactional webhook outbox with bounded retry/backoff and dead-lettering (`helpdesk-webhook-worker` entry point); one of the three call sites that legitimately set the cross-tenant `rls_bypass` GUC (see `rls.py`), narrowly and only for its own batch. Upserts its liveness (`persistence.record_worker_heartbeat`) after every loop iteration, whether or not that batch found anything to do — see `metrics.py`.
- `lease_reaper.py` — separate long-running process (`helpdesk-lease-reaper` entry point) recovering `Action` jobs whose agent claim lease expired without a result ever being reported (agent crash/disconnect) — requeues them (bounded by `Settings.lease_reaper_max_attempts`) or escalates to `failed` once exhausted. Another of the three `rls_bypass` call sites, and also upserts its own liveness heartbeat every iteration. Without this recovery logic, a crashed agent left a job `claimed` forever with no operator-visible signal — see `docs/IMPLEMENTATION_PLAN.md` Milestone 3.
- `auth.py` — request principal resolution and PostgreSQL tenant-context binding. Production human auth is OIDC (`oidc.py`) — a `Bearer` token is verified, then the tenant is resolved from its cryptographically verified `email` claim against `users`, never from a client header. Development browser sessions (`development_auth.py`) and the insecure `X-Tenant-ID`/`X-User-ID` header path stay available but are strictly gated to `environment == "development"` and fail closed otherwise (`Settings.validate_security`). See the module's docstring for the full trust model, including the narrow, documented `resolving_identity` exception (identity-resolution lookups must run before any tenant is known, so they can't themselves be RLS-scoped).
- `oidc.py` — provider-neutral OIDC access-token verification (`OIDCVerifier`). Not tied to any vendor; works with any standards-compliant provider that publishes a JWKS endpoint.
- `rls.py` — single source of truth for PostgreSQL row-level security: which tables are tenant-scoped, the `tenant_isolation` policy DDL, and provisioning of the restricted `helpdesk_app` database role RLS enforcement depends on (see `database.py` below). Shared by migration `0005` and by RLS-related test fixtures — never duplicate this DDL elsewhere.
- `config.py` — `pydantic-settings` `Settings`, env-prefixed `HELPDESK_`, loaded from `.env`. `runtime_database_url` derives the restricted-role connection the API/webhook-worker actually use at runtime from `database_url` + `app_role_password` — see `database.py`.
- `seed.py` — idempotent demo-tenant seeding (`helpdesk-seed` entry point), safe to rerun. Binds its own tenant context via `set_tenant_context` since it now runs as the restricted role too.
- `job_signing.py` — control-plane side of signed job envelopes (Milestone 3). Derives an Ed25519 keypair from `Settings.job_signing_seed` (never stored — same dev-safe-default pattern as every other secret here) and signs `claim_job`'s envelope. Verification lives in `agent_common.signing` (shared with both agents); this module only adds the signing (private-key) side agents never need. See its module docstring for the key-rotation limitation.
- `ai/provider.py` — provider-neutral, advisory-only AI diagnosis (`POST /v1/incidents/{id}/diagnose`, Milestone 7). `DeterministicFallbackProvider` is the dev-safe default (no network/API key); `OpenAICompatibleProvider` talks to any OpenAI-compatible `/chat/completions` endpoint via `Settings.ai_provider_*` (all empty by default). `suggested_skill_id` is validated against `api.SKILLS` *inside the provider*, failing closed on anything unregistered/hallucinated/injected rather than passing it through. A `Diagnosis` row (migration `0007`, RLS-protected) is never turned into an `Action` automatically — an operator still has to explicitly call `POST /v1/actions` themselves. See the module docstring for the full trust model.
- `logging_config.py` — structured JSON logging (Milestone 6). `configure_logging()` (called once at startup by `api.py`, `webhook_worker.py`, `lease_reaper.py`) replaces the root logger's handler with a `JsonFormatter`; `set_request_id`/`get_request_id` bind a per-request correlation id (a contextvar) that every log line picks up automatically while that request is in flight — see `api.py`'s `RequestIdMiddleware`.
- `metrics.py` — Prometheus-compatible `GET /metrics` (Milestone 6). Real-time HTTP request count/duration (incremented by `RequestIdMiddleware` against the matched route *template*, never a raw path with ids in it) plus scrape-time gauges recomputed fresh from the database on every scrape (action/incident status counts, device online/offline, diagnosis fallback rate, webhook delivery outcomes, worker heartbeat age) — deliberately not incremented at call sites throughout the codebase, so they can never drift from what's actually in the database. The scrape-time aggregate queries need `helpdesktool.auth.aggregating_platform_metrics`, the third and only other legitimate use of the cross-tenant `rls_bypass` GUC beside `webhook_worker` and `resolving_identity` — see `rls.py`'s module docstring.

### Shared agent primitives (`agent_common/`)

Dependency-light package (stdlib + `cryptography` only) imported by both `linux_agent` and `windows_agent` but never by the control plane's own request-handling path — keeps either agent's install lightweight and independent of the FastAPI/SQLAlchemy stack. Two modules:
- `signing.py` — `verify_envelope`: the fixed-order check (malformed -> invalid signature -> wrong device -> wrong tenant -> expired -> unsupported skill version) every agent runs on a claimed job before it ever reaches the executor. `canonical_payload` here is imported by `helpdesktool/job_signing.py` too, so there is exactly one definition of "what bytes get signed" shared by the signer and every verifier.
- `journal.py` — `ExecutionJournal`: the durable, crash-safe local record of job progress (claimed -> executing -> executed -> reported), atomic-write same as `AgentConfig.save`. See its module docstring for exactly why a crash before/during execution is recovered via observe-only (`executor.verify_only`, never re-execute) while a crash after execution just resends the already-known result.

### Linux agent (`linux_agent/`)

`agent.py` (entry point `helpdesk-linux-agent`) ties together `config.py` (enrollment/identity, now also pins the job-signing public key via trust-on-first-use), `client.py` (HTTP transport), `collectors.py` (`/proc`-based inventory), `executor.py` (deterministic execution, plus `verify_only` for crash recovery), and `agent_common` (envelope verification + the durable journal). The agent claims only jobs addressed to its device via a leased, one-time claim secret, verifies the claimed job's signed envelope (device/tenant/expiry/skill-version, `agent_common.signing.verify_envelope`) before ever calling the executor, validates exact parameters against its own local allowlist (`SUPPORTED_SKILL_VERSIONS` — a registry entry existing server-side is necessary but not sufficient), executes via direct `systemctl` argument vectors (no shell), verifies the resulting unit state, and attempts rollback to the prior state on failure. Currently `service.restart` is the only mutating executor. Do not add shell-based or parameter-templated execution paths — this is the core safety invariant of the whole system.

### Windows agent (`windows_agent/`)

Mirrors `linux_agent/`'s exact contract (same `AgentConfig` shape, same `ControlPlaneClient`, same signed-envelope verification and journal-backed crash recovery in `agent.py`'s `WindowsAgent.execute_job`/`recover_interrupted_jobs`) so the control plane treats both OSes identically. Differences are purely OS-specific implementation, never a weaker safety model:
- `collectors.py` uses `psutil` (genuinely cross-platform — this is what makes the module importable/testable on Linux CI) for CPU/memory/disk/network/process data, and the stdlib `winreg` (Windows-only, imported lazily *inside* the functions that need it, never at module level) for DNS servers, installed applications, and pending-reboot state via registry reads only — no `ipconfig`/`wmic`/PowerShell ever spawned.
- `executor.py` defines the same allowlist/rollback/verification logic as the Linux executor, but against a `ServiceManager` Protocol rather than a subprocess `Runner` — the real implementation, `win32_service_manager.py`'s `Win32ServiceManager`, talks to the Service Control Manager entirely through the Win32 API (`win32service.OpenSCManager`/`OpenService`/`ControlService`/`StartService`/`QueryServiceStatus`), never a shell, `sc.exe`, or PowerShell process. **`win32service`/`pywintypes`/`servicemanager` (pywin32) are only ever imported lazily inside functions/constructors that actually need them** — never at module level in `executor.py`, `collectors.py`, `agent.py`, or `config.py` — specifically so those modules (and their tests) stay importable on Linux CI without pywin32 installed (which cannot even be pip-installed there). Only `win32_service_manager.py` and `service.py` import pywin32 at module level, and neither is imported by anything except real runtime usage (`agent.py`'s lazy `_default_manager()`) or the `helpdesk-windows-agent-service` entry point.
- `service.py` wraps the agent as a real Windows Service via `win32serviceutil.ServiceFramework` (`deploy/README-windows-agent.md` has install/uninstall steps) — the SCM-integrated equivalent of the Linux agent's systemd unit.
- The `windows` extra (`pip install helpdesktool[windows]`) declares `psutil` unconditionally and `pywin32` with a `sys_platform == "win32"` marker, so CI can install and test the cross-platform logic on Linux while pip correctly skips the Windows-only package there. **`windows_agent` is deliberately excluded from the enforced `mypy` run** (`pyproject.toml`'s `[tool.mypy] packages` list, which is pinned to `platform = "linux"`) since `winreg`/`win32service` can't resolve under that platform — it was verified separately and locally with `mypy --strict --platform win32 windows_agent` (clean) against a real Windows machine with pywin32 installed, but this isn't part of CI's gate. If a Windows CI runner is ever added, wire this in properly instead of relying on local verification.

### Frontend (`frontend/`)

Single-page app, `frontend/src/main.tsx` bootstrapping `App.tsx` (shell/routing/session state), covering Dashboard, Devices, Tickets, Incidents (incl. an AI-diagnosis panel, Milestone 9), Actions, Approvals, Skills (Milestone 9), Audit, Integrations, and Settings — one file per section under `pages/`, shared primitives in `components.tsx`, talking to the API via `frontend/src/api.ts`. The UI hides controls that don't apply to the current role (Owner/Admin/Operator/Viewer), but FastAPI authorization is authoritative and returns 403 for prohibited writes regardless of what the UI shows.
- `auth/oidc.ts` — a real, provider-neutral OIDC Authorization Code + PKCE flow for a public SPA client (no client secret — the correct pattern per RFC 8252/OAuth 2.0 Security BCP for a browser app). Uses standard `.well-known/openid-configuration` discovery rather than hardcoding any vendor's endpoints. Configured entirely via build-time Vite env vars (`VITE_OIDC_ISSUER`/`VITE_OIDC_CLIENT_ID`/...; see `.env.example`) — unset (the default) leaves the pre-existing development login page active, both paths use the same `helpdesk_session` localStorage slot so `App.tsx`'s session-restore logic doesn't need to know which one was used. `auth/oidc.test.ts` verifies the PKCE code-challenge derivation against the published RFC 7636 Appendix B test vector.
- `npm test` (Vitest + jsdom) is wired into `.github/workflows/ci.yml`'s frontend job alongside `npm run typecheck`.
- **`.github/workflows/ci.yml` also has a `docker` job** that builds both the API and frontend Docker images and actually runs each one (curling `/health/live` / `/`), not just `docker build`ing them — added after discovering the real `api` container had been crash-looping in production since the signed-job-envelopes milestone (the `Dockerfile` never `COPY`'d the new `agent_common/` package `helpdesktool/job_signing.py` imports at startup; every `pip install -e .`-based test run that whole session used a full repo checkout and never hit this). If you add a new top-level package `helpdesktool` imports, it must be added to `Dockerfile`'s `COPY` list too — this CI job is what actually catches that now.

### Data flow / safety invariants to preserve

- Tenant ID always comes from authenticated identity/request context, never from client-supplied payload fields — enforced both in application queries and, since Milestone 2, by PostgreSQL Row-Level Security as a second, independent layer (see `auth.py`'s module docstring for the full trust model).
- Every mutating action passes through `PolicyEngine` (default deny) before it can become a queued job; high-risk skills require independent approval (separation of duties — the approver cannot be the requester).
- Jobs are device-bound, lease-based, and idempotently claimed/reported by the agent.
- Audit events are hash-chained and written transactionally alongside the state change they describe; domain events for webhook delivery are expanded into durable outbox rows in the same transaction.
- Webhook signing secrets are environment references (e.g. `env:HELPDESK_WEBHOOK_SECRET_N8N`), never stored as literal values in subscription rows or returned to the frontend.
- External integrations (n8n, Slack, Teams, ticketing) are read-only consumers of facts/lifecycle events — they cannot approve work, bypass policy, or issue endpoint jobs.

### Known deferred/limited areas (see README "Known limitations")

- Production human auth is OIDC (`helpdesktool/oidc.py` + `auth.py`), and tenant isolation is enforced by PostgreSQL Row-Level Security (`helpdesktool/rls.py`, migration `0005`) in addition to application-level filtering — both as of Milestone 2. **A frontend OIDC login UI now exists** (`frontend/src/auth/oidc.ts`, Milestone 9) — Authorization Code + PKCE, provider-neutral via standard discovery, build-time configured. Not done: the frontend doesn't yet independently enforce role-based route visibility beyond what already existed (backend authorization remains authoritative either way), and there's no logout-triggered IdP session termination (RP-initiated logout) — sign-out only clears the local token.
- Device credentials can be rotated (admin-initiated or agent self-service) and revoked, and devices can self-enroll with a one-time admin-issued token (`helpdesktool/api.py`'s `/v1/devices/enrollment-tokens*`/`enroll-with-token` endpoints) — as of Milestone 3. **Signed, versioned job envelopes and a durable agent-side execution journal are now implemented** (`agent_common/signing.py`, `agent_common/journal.py`, `helpdesktool/job_signing.py`) — see Milestone 3's "Endpoint trust hardening" note in `docs/IMPLEMENTATION_PLAN.md`. mTLS itself (certificate-based transport identity, as opposed to the bearer-token device credential + envelope signature that exist today) is still not implemented — evaluated and deliberately deferred; see the same doc section for why.
- No generic disk-cleanup skill exists by design — only `service.restart` as a reference mutating executor.
- **Abandoned job claims now recover.** `helpdesktool/lease_reaper.py` (Milestone 3, `helpdesk-lease-reaper` entry point/Compose service) requeues or escalates any `Action` whose claim lease expired without a result being reported — previously (documented here as a known gap through Milestone 2) such a job stayed `claimed` forever with no operator-visible signal.
- The remediation skill registry is now a versioned, integrity-checked, data-driven table (`helpdesktool/skills.py`, migration `0008`) as of Milestone 4 — risk tier, OS support, timeout, versioning, and parameter shape are all a `POST /v1/skills` data change, not a control-plane code deploy. What's still true by design, not as a gap: an agent must still ship its own deterministic executor code for any genuinely new *mutating* skill id — this registry only ever carries policy metadata, never execution logic (see `skills.py`'s module docstring). Also not done in this pass: cryptographic signing (agents still trust the control plane's database directly rather than verifying an independent signature) and the `api.py` router split that was originally bundled into this milestone — see `docs/IMPLEMENTATION_PLAN.md` Milestone 4 for why both were deliberately deferred.
- AI-assisted diagnosis (`helpdesktool/ai/`, Milestone 7) is implemented and tested end-to-end at the API layer (`POST /v1/incidents/{id}/diagnose`, folded into `GET /v1/incidents/{id}`), but there is no frontend review panel yet — a diagnosis is currently only visible via the API, not the dashboard UI.
- Backend observability (structured JSON logs, per-request correlation ids, Prometheus `/metrics` with HTTP + business/domain metrics, worker heartbeats) is implemented as of Milestone 6 — see `logging_config.py`/`metrics.py`. Not done: OpenTelemetry tracing (evaluated, deferred — no OTLP collector target chosen yet), the frontend Reporting page, and list-endpoint pagination (`/v1/devices`, `/v1/tickets`, `/v1/actions`, `/v1/incidents` all still return unbounded/unpaginated results) — see `docs/IMPLEMENTATION_PLAN.md` Milestone 6 for the reasoning.
- The frontend is still the single-file console described above — no OIDC login UI, no Reporting page, no per-role admin screens beyond what the existing role-based control-hiding already does. Building it out into a full multi-route SaaS console is unstarted.

`docs/ARCHITECTURE.md` describes the target production architecture (multi-agent OS support, RLS, OIDC, LLM diagnosis provider adapter) that this MVP is a deliberately narrower foundation for; consult it before making structural decisions that the current code doesn't yet need but the target design anticipates. `docs/IMPLEMENTATION_PLAN.md` is the authoritative, current-dated (2026-08-19) audit and milestone roadmap — prefer it over `docs/REPOSITORY_AUDIT.md`/`docs/STABILIZATION_AUDIT.md`, which are now-stale historical snapshots kept for context only.
