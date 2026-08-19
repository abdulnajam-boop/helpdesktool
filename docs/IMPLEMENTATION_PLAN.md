# Implementation plan: Helpdesktool -> production-ready autonomous IT help desk SaaS

This document supersedes the milestone list previously in this file. It reflects a
full-repository audit performed 2026-08-19 against commit `c188165`, including a live
run of `pytest`, `mypy`, `ruff`, `npm run build`, and `docker compose config`. The prior
audits in `docs/REPOSITORY_AUDIT.md` and `docs/STABILIZATION_AUDIT.md` are historical
snapshots (2026-08-15/16) and are now stale on several points corrected below; they are
kept for history and should not be treated as current status.

> **Status update (2026-08-19, same day):** Milestone 1 is implemented, locally
> verified, merged to `main`, and confirmed green on a real GitHub Actions run — see
> its section below for exact results. Sections 1-9 of the audit below describe the
> state of the repository *before* Milestone 1 (i.e. they still describe the 24 mypy
> errors, missing Postgres CI coverage, etc., as the historical baseline the
> milestone plan was written against). Do not re-fix what Milestone 1 already fixed;
> check its "Actual completion status" block first.

## 1. What exists now

- FastAPI control plane (`helpdesktool/api.py`, 1385 lines, single module) exposing
  tenants, development auth, devices, heartbeats, inventory, incidents, tickets,
  actions/approvals, agent job claim/result, audit, webhooks, and settings.
- SQLAlchemy models (`db_models.py`) for tenants/users/devices/inventory/heartbeats/
  tickets/incidents/actions/approvals/execution results/audit events/idempotency
  records/domain events/webhook subscriptions+deliveries, all with `tenant_id` FKs.
- Deterministic policy engine (`policy.py`) and orchestrator state machine
  (`orchestrator.py`): default-deny, allowlisted skills, OS matching, risk-based
  approval, separation of duties (requester cannot approve their own action).
- Persistence layer (`persistence.py`): `SqlActionStore`, `SqlAuditLog` with a
  SHA-256 hash chain and a PostgreSQL advisory lock serializing each tenant's
  sequence within a transaction.
- Deterministic incident correlation (`incidents.py`): low-disk detection,
  correlation-window dedup, automatic ticket creation, recovery/resolve, and
  reopen-on-recurrence. **This is fully implemented** — `docs/REPOSITORY_AUDIT.md`
  and the old `docs/IMPLEMENTATION_PLAN.md` both call this "missing"/"P1 not built";
  that is stale.
- Domain events + transactional webhook outbox (`events.py`, `integrations.py`,
  `webhook_worker.py`): canonical event envelope, SSRF-safe URL validation
  (public-IP-only resolution, HTTPS default), HMAC-SHA256 signing, bounded
  exponential backoff, dead-lettering, sensitive-key redaction.
- Linux endpoint agent (`linux_agent/`): enrollment, heartbeat, `/proc`-based
  inventory collectors, job poll/claim/result with a leased claim-token, a local
  processed-job replay file (0600 permissions), and `service.restart` executed via
  a fixed `systemctl` argument vector (no shell) with pre/post state verification
  and best-effort rollback.
- React/Vite operator console (`frontend/src/main.tsx`, single file, 9 routes):
  Dashboard, Devices, Tickets, Incidents, Actions, Approvals, Audit, Integrations,
  Settings, plus a development-only low-disk telemetry simulator.
- Docker Compose stack with health-gated startup order (db -> migrate -> seed ->
  api/frontend/webhook-worker), non-root containers, `read_only` root filesystems,
  `cap_drop: ALL`, `no-new-privileges` on api/frontend/webhook-worker.
- 4 additive Alembic migrations, each with a working `downgrade()`.
- CI (`.github/workflows/ci.yml`): backend job runs `compileall`, `ruff check`,
  `ruff format --check`, `mypy`, `pytest`; frontend job runs `npm run build`. No
  Postgres service, no Docker build/scan, no deploy step.
- Idempotency-Key support on all mutating agent/action endpoints via
  `IdempotencyRecord`.

## 2. What actually works (verified by running it, not just reading it)

Confirmed by direct execution during this audit:

| Check | Result |
|---|---|
| `python -m compileall helpdesktool linux_agent` | Pass, 24 files |
| `ruff check .` | Pass |
| `ruff format --check .` | Pass, 132 files |
| `pytest -q` | 33 passed, 3 failed |
| `npm run typecheck` / `npm run build` | Pass (3.68s build) |
| `docker compose config` | Parses cleanly, 5 services resolve |
| `mypy` (strict) | **24 errors in 3 files** |

The 3 pytest failures (`test_linux_agent.py` file-permission assertion,
`test_linux_collectors.py` x2 reading `/proc/*`) are Windows-vs-Linux environment
artifacts, not logic bugs — they exercise POSIX-only behavior and will pass on the
Linux CI runner. Confirm this explicitly in CI logs before assuming it (see Milestone
1) rather than continuing to assume it.

No `conftest.py` exists anywhere in the repo. Only `tests/test_api_integration.py`
overrides `get_session` with an in-memory SQLite engine; every other test file is a
pure unit test with no database. **This means the PostgreSQL-only code path in
`persistence.py` — the tenant-serializing advisory lock around the audit hash chain —
has never been executed by CI or by any test**, because CI has no Postgres service and
SQLite silently no-ops the `if bind.dialect.name == "postgresql"` branch.

## 3. What is partially implemented

- **RBAC**: `require_roles(...)` gates most mutating endpoints correctly and the
  frontend hides controls per role, but there is no systematic role-matrix test
  (e.g. operator against every admin-only endpoint) — only a handful of endpoints
  are spot-checked in `test_api_integration.py`.
- **Multi-tenancy**: every table carries `tenant_id` and every query in `api.py`
  filters by it, but isolation is enforced only in application code — a single
  missed `WHERE tenant_id = ...` in a future endpoint is a full cross-tenant leak.
  No PostgreSQL Row-Level Security exists.
- **Authentication**: `development_auth.py` (signed, expiring browser sessions) and
  an insecure `X-Tenant-ID`/`X-User-ID` header path are both explicitly
  development-only and fail closed via `Settings.validate_security()` when
  `environment != "development"` — but there is still no production identity
  provider (OIDC/JWT) implemented at all; the app has literally no way to
  authenticate a real user outside development mode.
- **Agent trust**: device identity is a long-lived random bearer token, hashed with
  SHA-256 at rest and compared with `hmac.compare_digest`. There is no rotation, no
  mTLS, no monotonic replay counter beyond the per-action claim-token/lease.
- **Audit integrity**: the hash chain is written correctly and a `verify_chain()`
  helper exists on the in-memory reference adapter, but nothing periodically
  verifies the persisted PostgreSQL chain, and there is no API/tooling to detect
  tampering after the fact.
- **Secrets**: `EnvironmentSecretsProvider` resolves `env:HELPDESK_WEBHOOK_SECRET_*`
  references only; there is no cloud secrets-manager adapter (the target
  architecture in `docs/ARCHITECTURE.md` calls for one).
- **Remediation skills**: the "registry" is a hardcoded two-item Python list in
  `api.py` (`diagnostics.collect`, `service.restart`). It is not versioned, not
  signed, and not data-driven — adding a new skill means shipping new code to both
  the control plane and every agent simultaneously.

## 4. What is broken

- **`mypy --strict` fails with 24 errors** in 3 files:
  - `helpdesktool/db_models.py` (9x): bare `dict`/`list` column type annotations
    (e.g. lines 75, 90, 139, 165, 209, 235, 250, 266, 280) — need `dict[str, Any]` /
    `list[str]` etc.
  - `helpdesktool/api.py` (13x): unguarded access to values that can be `None` per
    their inferred type (`session.get(...)` results, `Result.rowcount`), around
    lines 303, 736, 774, 872, 892-898, 908. These are provably safe today given the
    call sequence (e.g. `require_agent` already validated the device exists before
    `heartbeat()` re-fetches it), but mypy cannot see that, and CI's `mypy` step is
    passing/failing inconsistently with the rest of the pipeline going green — this
    is a real, if currently low-severity, correctness-safety-net gap.
  - `linux_agent/collectors.py` (2x): `os.statvfs`/`fcntl.ioctl` reported missing —
    almost certainly a Windows-stub false positive from running mypy without a
    Linux target platform; needs confirming on the actual CI runner, not assumed.
- **Job lease abandonment has no recovery path.** `claim_job` sets
  `status="claimed"` with a 60-second `lease_expires_at`. `poll_jobs` only ever
  returns actions with `status="queued"`. `report_job_result` checks whether the
  lease has expired only to *reject* a late report — nothing ever moves an
  abandoned `claimed` action back to `queued` (or to `failed`) after its lease
  expires. If an agent crashes, loses network, or is killed between claiming a job
  and reporting a result, that action is stuck in `claimed` forever: it will never
  be redelivered, never time out, and never show up anywhere for an operator to
  intervene except a manual database edit. This is a genuine safety/liveness gap,
  not a cosmetic one — it directly contradicts the "verify -> rollback/escalate"
  half of the trust-boundary diagram in `README.md`.
- Nothing else in the runtime paths is currently broken; the failures above are
  the full list from actually running the toolchain.

## 5. What is missing entirely

- Windows endpoint agent (explicitly deferred in every prior doc; still true).
- AI diagnosis / LLM provider abstraction / RAG (no code at all).
- Versioned, signed skill/action registry (see "partially implemented" above).
- PostgreSQL Row-Level Security.
- Production identity provider (OIDC/JWT) integration.
- mTLS or any rotated agent credential mechanism.
- Rate limiting / WAF — `/v1/auth/development/login` and every other endpoint has
  no throttling beyond FastAPI/Starlette defaults.
- Observability: no metrics (Prometheus/OpenTelemetry), no tracing, no structured
  logging, no APM. `uvicorn` runs with framework defaults only.
- Reporting beyond the dashboard's raw counts (no MTTR, SLA, trend, or export
  views).
- Pagination on any list endpoint (`/v1/devices`, `/v1/tickets`, `/v1/actions`,
  `/v1/incidents`) — every one returns the full tenant result set.
- Retention/cleanup for `device_inventory`, `heartbeats`, `idempotency_records` —
  all grow unbounded.
- Frontend automated tests — `frontend/package.json` has no test runner at all.
- k8s/Helm/Terraform, staging/production environment overlays, backup/restore
  automation, secrets-manager integration.
- CI: no Postgres service container, no Docker image build, no vulnerability
  scan/SAST, no deployment step.
- nginx security headers (CSP/HSTS/X-Frame-Options), rate limiting, caching tuning
  in `frontend/nginx.conf` (currently a minimal single-purpose config).
- SSO/SCIM, approval quorum/expiry, policy-as-code, immutable audit export/legal
  hold — all P4-class enterprise features, correctly deferred so far.

## 6. Security risks, ranked

1. **No production identity provider.** Everything today either runs in
   development mode (fully insecure by design, intentionally) or has no way to
   authenticate a human at all. This blocks any real deployment outright, not just
   "hardens" one — it must be Milestone 1-class work before anything else in this
   plan matters for a real customer.
2. **Tenant isolation has no defense in depth.** RLS absence means the entire
   multi-tenant security model rests on every current and future engineer never
   forgetting a `WHERE tenant_id = ...` clause. One missed filter in one future
   endpoint is a full cross-tenant data breach.
3. **Abandoned job claims never recover** (Section 4). Beyond being a reliability
   bug, this is a safety-relevant gap: a partially-executed high-risk remediation
   (e.g. a failed `service.restart`) that the agent never gets to report back on
   leaves no operator-visible signal that verification/rollback never completed.
4. **Long-lived, unrotated agent bearer tokens** with no mTLS — a leaked token is
   valid indefinitely and grants job-claim/report ability for that device.
5. **No rate limiting anywhere**, including on the login and approval-decision
   endpoints — trivially abusable for credential/enumeration attacks once real
   auth exists, and for resource exhaustion today.
6. **PostgreSQL-only concurrency-safety code is untested.** The audit hash-chain's
   tenant-serializing advisory lock (`persistence.py`) has never run under CI or
   any test, because CI has no Postgres service. A regression here would silently
   corrupt the audit chain's ordering guarantee under concurrent writers and no
   test would catch it.
7. **mypy strict-mode regressions are not gated** — `mypy` is in CI but the repo
   currently ships 24 pre-existing errors, meaning the CI step is either not
   actually failing the build (worth confirming) or the build is currently red.
   Either way, real `Optional`-access bugs introduced going forward would be
   indistinguishable from the existing noise.
8. **No secrets-manager integration** — webhook secrets are environment variables
   only; fine for one Compose deployment, not for a multi-environment production
   fleet.

## 7. Architecture problems

- **`api.py` is a 1385-line single module** holding every route, every JSON
  serializer, and several inline helpers. It works today, but `docs/ARCHITECTURE.md`
  already calls for domain-module boundaries (identity/inventory/telemetry/skills/
  automation/tickets/audit/web); this file needs to split along those lines before
  it becomes unreviewable.
- **The skill registry is code, not data.** `SKILLS` is a hardcoded list literal in
  `api.py`; there is no way to add, version, or retire a skill without a control-
  plane deploy synchronized with every agent's own hardcoded allowlist.
- **`ActionOrchestrator` keeps a redundant in-memory `self._actions` dict** alongside
  the real `SqlActionStore`-backed persistence path used in production. It is
  harmless (each orchestrator instance is request-scoped) but is dead weight that
  will confuse the next person modifying the state machine — worth deleting when
  this file is next touched for Milestone 3/4 work, not a standalone task.
- **No pagination, no retention policy** on any high-growth table (see Sections 5).
  This is a scale problem, not a v0.1 problem, but it needs to be designed before
  Milestone 6+ (reporting) builds on top of unbounded tables.
- **Frontend is a single 177-line file with a URL-string router.** It is honestly
  well-factored for its size (a handful of small composable components), but it has
  zero test coverage and no framework for adding tests, and it will need real
  routing/state management once reporting, AI-diagnosis review, and Windows-agent
  device pages are added.

## 8. Test coverage and failures

See Section 2 for the executed-toolchain results. Coverage gaps identified by
reading every test file against every source module:

- `helpdesktool/api.py`: several endpoints have **zero** test references —
  `GET /v1/auth/development/users`, `GET /v1/tickets`, `GET /v1/actions`,
  `GET /v1/approvals`, `PATCH /v1/tickets/{id}`, `GET /v1/settings`, incident list
  filtering, `/health/live`, `/health/ready`.
- `helpdesktool/incidents.py`: correlation logic is only exercised through one
  integration-test scenario (single filesystem, single device). No unit tests for
  multiple concurrent filesystems/incident types, threshold boundary values, or
  resolving an incident that has no linked ticket.
- `helpdesktool/seed.py`: zero automated test coverage; idempotent-rerun behavior
  is asserted only in the manual `docs/MVP_TESTING.md` checklist.
- `helpdesktool/webhook_worker.py`: only the single-success-delivery path is
  covered. No test for a failing delivery, 4xx-vs-5xx handling, or the
  exhausted-retry -> `dead_letter` transition.
- `helpdesktool/persistence.py`: the Postgres advisory-lock path is entirely
  untested (Section 2/6).
- `helpdesktool/audit.py`: hash-chain tamper detection (`verify_chain()` returning
  `False`) has no direct test.
- `helpdesktool/auth.py`: role enforcement is spot-checked on a few endpoints, not
  systematically matrixed across all roles x all endpoints.
- Frontend: no test framework configured, zero tests.

## 9. Production-readiness gaps (summary)

Everything in Sections 4-8, condensed to the categories the target SaaS needs and
does not yet have: production identity, database-enforced tenant isolation, agent
credential rotation/mTLS, durable job-claim recovery, a data-driven skill registry,
a Windows agent, AI diagnosis, observability (metrics/tracing/logs), reporting,
rate limiting, pagination/retention, secrets management, CI Postgres coverage,
container image scanning, a real deployment target (k8s/Helm or an equivalent
hardened Compose-prod path), backup/restore automation, and frontend test coverage.

## 10. Best target architecture

The existing `docs/ARCHITECTURE.md` target (modular monolith, one control plane +
one Postgres, explicit domain module boundaries, provider-neutral LLM/secrets/
integration adapters, RLS + mTLS + signed job envelopes as production invariants)
remains correct and does not need to be re-derived. This plan's job is to get the
current code to that target, module by module, without a rewrite:

```
Windows/Linux Agent -- mTLS + signed jobs --> Control Plane API --> PostgreSQL (RLS)
       |                                          |   |
 collectors + allowlisted executor                |   +--> Object storage (future: large artifacts)
 signed skill catalog (M4)                         +------> Webhook outbox worker (exists)
                                                    +------> AI provider adapter (M7, advisory only)
Browser -- OIDC/HTTPS (M2) --> React operator console
```

Concretely: keep `helpdesktool/` as the control plane, keep `linux_agent/` as-is,
add `windows_agent/` as a sibling package sharing the same job/claim/lease contract,
split `api.py` into routers per domain (`identity`, `devices`, `incidents`,
`tickets`, `actions`, `audit`, `integrations`, `settings`) as part of Milestone 4
(when the skill registry work already touches most of these routes), and keep the
frontend as one console that grows new pages rather than a rewrite.

---

## Milestone plan

Each milestone lists what will be built, the files/components it touches, what it
depends on, the tests required to close it, and its definition of done (DoD).
Milestones are ordered so that trust-boundary and reliability fixes land before new
surface area, matching the philosophy already stated in the prior plan.

### Milestone 1 — Stabilize the toolchain and CI

> **Actual completion status (2026-08-19): DONE.** Every DoD item met, including a
> real green GitHub Actions run on both jobs, and merged to `main` via a `--no-ff`
> merge commit. See the verification block at the end of this section for exact
> commands/results, and Section "CI verification" for the two CI-only issues found
> and fixed after the initial local-only pass.

**Build:**
- Fix all 24 `mypy --strict` errors: proper generic type parameters in
  `db_models.py`; `None`-narrowing (or documented `assert`s) around the 13
  `Optional`-access sites in `api.py`; confirm and resolve (or suppress with a
  platform-scoped `# type: ignore[attr-defined]` and comment) the two
  `linux_agent/collectors.py` POSIX-only attribute errors.
- Add a PostgreSQL service container to the `backend` CI job and add an
  integration test run against it, so the advisory-lock/hash-chain code path in
  `persistence.py` actually executes somewhere.
- Add `tests/conftest.py` with shared fixtures (the SQLite override currently
  lives inline in `test_api_integration.py`; extract it, and add a
  Postgres-backed fixture used only by the new integration tests above).
- Confirm the 3 currently-Windows-failing tests actually pass on the Linux CI
  runner (read the latest CI run's logs); if they don't, fix them for real instead
  of assuming platform-only causes.

**Files/components:** `helpdesktool/db_models.py`, `helpdesktool/api.py`,
`linux_agent/collectors.py`, `.github/workflows/ci.yml`, new `tests/conftest.py`.

**Dependencies:** none — this is the prerequisite for everything else.

**Tests required:** `mypy` clean (0 errors); `pytest` green against both SQLite
(fast unit path) and the new Postgres service in CI; no behavior change to any
passing test.

**Definition of done:** `mypy`, `ruff check`, `ruff format --check`, and `pytest`
all pass in CI with zero errors, CI includes a real Postgres run, and this is
verified by an actual green CI run, not just local execution.

**Verification performed (2026-08-19):**

- `mypy`: fixed all 24 errors for real, not suppressed.
  - `db_models.py` (9x): added explicit `dict[str, Any]` / `list[str]` type
    parameters to every JSON-backed column (`DeviceInventory.payload`,
    `Heartbeat.status`, `Incident.evidence`, `Action.parameters`,
    `ExecutionResultRow.output`, `AuditEventRow.details`,
    `IdempotencyRecord.response`, `DomainEventRow.data`,
    `WebhookSubscription.event_types`).
  - `api.py` (13x): added real `None`-guards that fail closed with an explicit
    HTTP error (404/500) instead of crashing — in `heartbeat()` (device lookup),
    `create_action()` and `decide_action()` (post-write `Action` lookup), and
    `claim_job()` (post-update `Action` lookup plus its `lease_expires_at`). The
    `Result[Any]` vs. `CursorResult` `rowcount` error was fixed with an accurate
    `cast(CursorResult[Any], ...)` reflecting SQLAlchemy's actual runtime type for
    a Core `UPDATE` execute (confirmed by inspecting the installed SQLAlchemy 2.0.52
    source — there is no more specific typed overload available). None of this
    changed any endpoint's observable behavior; it only makes already-true
    invariants (e.g. "a device just fetched by `require_agent` still exists two
    lines later in the same transaction") explicit and defensive instead of
    implicit and unchecked.
  - `linux_agent/collectors.py` (2x): confirmed these were a platform-stub false
    positive (`os.statvfs`/`fcntl.ioctl` are POSIX-only stdlib members that mypy
    hides when its inferred target platform is Windows). Fixed properly by adding
    `platform = "linux"` to `[tool.mypy]` in `pyproject.toml` — this is a factual
    declaration of the actual target platform for `helpdesktool`/`linux_agent`
    (both are Linux-deployed; see `Dockerfile`, `deploy/helpdesk-linux-agent.service`,
    and every `/proc`/`systemctl` call in `linux_agent/`), not a suppression.
  - Result: `mypy` now reports `Success: no issues found in 24 source files`.
- `tests/conftest.py` created: extracted the existing in-memory-SQLite `client`
  fixture out of `test_api_integration.py` unchanged (no test removed or altered),
  and added a new `postgres_session_factory` fixture that skips (does not fail)
  when `HELPDESK_TEST_DATABASE_URL` is unset or unreachable, so local development
  without Postgres is unaffected.
- `tests/test_persistence_postgres.py` created: two new tests exercising the
  PostgreSQL-only `pg_advisory_xact_lock` branch in
  `helpdesktool/persistence.py::SqlAuditLog.append` that Section 2/6 of this audit
  found had **never executed under any test**. One spins up 20 concurrent threads
  each appending an audit event for the same tenant on separate DB sessions and
  asserts the resulting sequence is exactly `1..20` with no gaps/duplicates and an
  intact hash chain — the actual property the advisory lock exists to guarantee.
  The other confirms two different tenants' sequences stay independent. **Both were
  verified locally against a real, ephemeral `postgres:17-alpine` Docker container**
  (started and torn down solely for this verification, not part of any persistent
  environment) — both pass; without the lock this kind of test would be expected to
  intermittently produce duplicate/out-of-order sequence numbers under concurrency.
- `.github/workflows/ci.yml` updated: added a `postgres:17-alpine` service
  container to the `backend` job with a health check, and set
  `HELPDESK_TEST_DATABASE_URL` at the job level so `pytest` now runs the two new
  Postgres-only tests for real in CI instead of skipping them.
- **Verified by an actual green GitHub Actions run** (the DoD's remaining open
  item, now closed): pushed `milestone-1-stabilization` to GitHub. This surfaced
  two issues neither local execution nor code review had caught, both diagnosed
  from real CI evidence (API run/job/log inspection, not guessing) and fixed on
  the same branch:
  1. The repository's "CI" workflow was found to be in GitHub's
     `disabled_manually` state (confirmed via `GET .../actions/workflows`), so
     the first push queued no run at all. This was a repository setting, not a
     file problem — the user re-enabled it, and an empty, no-file-changes commit
     was pushed to produce a new event for GitHub Actions to pick up.
  2. On the first real run, the **backend job passed in full on the first try**
     (mypy, ruff, and — the actual point of this milestone — `pytest` including
     the two new PostgreSQL-only advisory-lock tests against the real `postgres`
     service container). The **frontend job failed** on `npm run build` with
     TypeScript errors TS6310/TS5096 in `frontend/tsconfig.node.json`
     (`composite: true` together with `noEmit: true` is invalid for a project
     reference target). This bug was invisible locally the entire time: the
     local working tree already had an uncommitted fix to this exact file
     present before Milestone 1 began, so every local `npm run build` in this
     milestone silently built against the already-fixed file while the
     committed version CI actually checks out still had the bug. Root-caused by
     reproducing CI's exact steps against the real committed tree (`git archive`
     of the pushed commit, fresh `npm install`, no local `node_modules`/lockfile)
     rather than guessing, fixed with the same one-line change already sitting
     uncommitted, re-verified in the same clean reproduction, then the full
     local suite was re-run once more (ruff/mypy/pytest against a real ephemeral
     Postgres, frontend typecheck/build) before committing.
  - Final result: run
    [32227036134](https://github.com/abdulnajam-boop/helpdesktool/actions/runs/32227036134)
    on commit `b4456d6`, **both jobs, every step: success.**
- Confirmed by direct code inspection (not assumption) that the 3 pre-existing
  Windows-platform test failures (`test_linux_agent.py`'s file-permission
  assertion, two `test_linux_collectors.py` tests) call directly into
  unmocked `/proc/*` reads and POSIX `st_mode` bits with no platform branching in
  either the test or the code under test — they are structurally incapable of
  passing anywhere except Linux, and CI's `ubuntu-latest` runner is Linux. This
  reasoning was verified by reading both test files in full, not inferred from the
  failure text alone.
- Full local validation suite run after all changes, from a clean state:
  `python -m compileall helpdesktool linux_agent tests` (clean), `ruff check .`
  (all checks passed), `ruff format --check .` (134 files formatted), `mypy`
  (0 errors), `pytest -q` without Postgres (**31 passed, 3 failed [pre-existing,
  Linux-only], 2 skipped [Postgres tests, correctly skipped]**), `pytest -q` with
  `HELPDESK_TEST_DATABASE_URL` pointed at a real Postgres (**33 passed, 3 failed
  [same pre-existing Linux-only failures], 0 skipped**), `npm run typecheck` and
  `npm run build` in `frontend/` (clean), `docker compose config` (parses).
  No test was removed, weakened, or had its assertions loosened to get here.

---

### Milestone 2 — Production identity and database-enforced tenant isolation

**Build:**
- Real OIDC/JWT verification (issuer, audience, algorithm, expiry, signing-key
  rotation via JWKS) as the production auth path in `auth.py`, replacing the
  current "no production path exists" gap. Development header/session auth stays,
  unchanged, behind the existing `environment == "development"` gate.
- PostgreSQL Row-Level Security policies for every tenant-scoped table, with the
  application setting a session-local tenant GUC per request/transaction.
- A negative-test harness that proves isolation even when application code
  "forgets" a `tenant_id` filter (raw SQL run as tenant A attempting to read
  tenant B's rows must return nothing).

**Files/components:** `helpdesktool/auth.py`, `helpdesktool/database.py`
(session/tenant-context wiring), new Alembic migration(s) for RLS policies,
`helpdesktool/config.py` (OIDC settings), `tests/`.

**Dependencies:** Milestone 1 (needs the Postgres-backed CI path to test RLS at
all).

**Tests required:** invalid/expired/wrong-audience/wrong-issuer JWT rejection;
full role matrix per endpoint; forced cross-tenant SQL denied by RLS even when the
app-layer filter is deliberately removed in a test; connection-pool tenant-context
leakage check (sequential requests from different tenants on a reused connection
never see each other's rows).

**Definition of done:** no client-supplied tenant/user identity is trusted outside
development mode; every tenant-scoped table has an enforced RLS policy; the
negative-isolation test suite passes and is part of CI.

---

### Milestone 3 — Agent/job trust hardening and durable job lifecycle

**Build:**
- A server-side lease reaper: a scheduled task (webhook-worker-style loop, or a
  new small worker process) that finds `Action` rows with `status="claimed"` and
  an expired `lease_expires_at`, and transitions them back to `queued` (bounded
  retry count) or to `failed` with an `action.escalation_required` audit event —
  closing the gap identified in Section 4.
- Agent credential rotation: short-lived, renewable agent tokens instead of the
  current unrotated bearer token (mTLS is the target end-state per
  `docs/ARCHITECTURE.md`; land token rotation first as an incremental step if a
  full CA/mTLS rollout is out of scope for this milestone — decide scope per the
  open question in the summary below).
- Signed, versioned job envelopes (ties into Milestone 4's skill registry —
  sequence these together if it reduces churn).
- A durable local execution journal on the Linux agent (the current
  `processed.json` replay file prevents double-execution of *completed* actions
  but does not protect against a crash between "restart succeeded" and "result
  reported").

**Files/components:** `helpdesktool/api.py` (job endpoints + new reaper),
`linux_agent/agent.py`, migrations, `deploy/`.

**Dependencies:** Milestone 1 (CI must catch regressions in this code via real
tests, not just review).

**Tests required:** crash-simulation at each phase of claim -> execute -> report;
expired-lease requeue observed end-to-end; duplicate delivery still idempotent;
revoked/rotated device credential rejected.

**Definition of done:** an agent crash or disconnect at any point cannot silently
lose or duplicate a mutation; an abandoned claim automatically becomes visible and
actionable again within one lease window.

---

### Milestone 4 — Versioned, signed remediation skill registry

**Build:**
- Replace the hardcoded `SKILLS` list in `api.py` with a data-driven, versioned,
  signed skill manifest (skill id, version, risk, supported OS, parameter schema,
  timeout, rollback skill id, signature/hash).
- Both the control plane and every agent validate a skill's hash/signature before
  trusting its contract; unknown or altered manifests fail closed.
- Split `api.py` into per-domain routers as part of this work, since the skill
  registry touches the policy, action, and agent-job routes together anyway
  (Section 7).

**Files/components:** new `helpdesktool/skills.py` (or package), `policy.py`,
`api.py` (router split), `linux_agent/executor.py`, migration for a `skills`
table, signing tooling.

**Dependencies:** Milestone 3 (job envelope signing).

**Tests required:** manifest tampering detected and rejected; unsupported OS/
version rejected; malformed parameters rejected at both boundaries; rollback
contract still enforced end-to-end.

**Definition of done:** `service.restart` executes from one versioned, hash-
verified manifest validated identically by the control plane and the agent;
adding a second skill requires a data change, not a synchronized code deploy.

---

### Milestone 5 — Windows endpoint agent

**Build:**
- A new `windows_agent/` package mirroring `linux_agent/`'s architecture:
  enrollment/config, HTTP client (reuse the same control-plane contract),
  collectors (CPU/memory/disk/services via WMI/`pywin32`, not shell), and a
  `service.restart` executor using the Windows Service Control Manager API
  (`win32serviceutil`/`OpenSCManager`/`ControlService`) — explicitly **not**
  PowerShell or `cmd.exe`, to preserve the "not a remote shell" invariant stated
  in `README.md`.
- A Windows service installer (parallel to `deploy/helpdesk-linux-agent.service`).

**Files/components:** new `windows_agent/` package (`agent.py`, `client.py`,
`collectors.py`, `executor.py`, `config.py`), `deploy/` (Windows service
install script/manifest), `pyproject.toml` (new optional dependency group for
`pywin32`), `tests/test_windows_agent.py`, `tests/test_windows_executor.py`,
`tests/test_windows_collectors.py`.

**Dependencies:** Milestone 3 (shared job/lease/claim contract must be stable
first) and Milestone 4 (shared skill manifest format).

**Tests required:** allowlist enforcement identical to the Linux executor; proof
that no shell/PowerShell process is ever spawned for `service.restart`; rollback
behavior; collector structural tests (can run against fixture data, not a live
Windows service, in CI).

**Definition of done:** a Windows device enrolls, reports inventory, and executes
`service.restart` via SCM APIs with the same verify/rollback guarantees as the
Linux agent — proven by tests, not just by symmetry with the Linux code.

---

### Milestone 6 — Observability, monitoring, and reporting

**Build:**
- Structured JSON logging with request/correlation IDs across the API and
  webhook worker.
- Prometheus-compatible `/metrics` endpoint (request rates/latencies, job
  claim/success/failure counts, webhook delivery outcomes, audit chain length).
- OpenTelemetry tracing across the API -> DB -> (future) agent round trip.
- A Reporting page in the frontend: MTTR, incident trend, ticket SLA/aging,
  remediation success rate — built on top of the pagination/retention work this
  milestone also needs to add for the underlying tables (Section 7).
- Pagination on `/v1/devices`, `/v1/tickets`, `/v1/actions`, `/v1/incidents`,
  `/v1/audit` (already has `limit`).

**Files/components:** `helpdesktool/api.py`, new `helpdesktool/observability.py`,
`compose.yaml` (optional Prometheus/Grafana services), `frontend/src/main.tsx`
(new Reporting route), migrations for any new aggregate/retention tables.

**Dependencies:** Milestone 1 (needs a stable CI/test baseline to build on).

**Tests required:** metrics endpoint exposes expected series after synthetic
traffic; log lines carry the correlation ID across a request; pagination
correctness (stable ordering, no duplicate/skipped rows across pages).

**Definition of done:** an operator can see MTTR/SLA/trend data in the console,
every list endpoint is paginated, and basic golden-signal metrics/traces exist for
production on-call use.

---

### Milestone 7 — AI-assisted diagnosis (advisory only, policy-gated)

**Build:**
- A provider-neutral `AIProvider` adapter (OpenAI-compatible, configurable
  endpoint/model, per `docs/ARCHITECTURE.md`'s stated LLM boundary) that consumes
  redacted evidence bundles and returns a structured diagnosis + a proposed,
  registered skill invocation (never free-text/shell).
- The AI's proposal enters the system exactly like any other `ActionCreate`
  request — it still passes through `PolicyEngine`, still requires human approval
  for medium/high risk, and cannot bypass Milestone 4's skill registry.
- Deterministic fallback when the provider is unavailable or returns an
  unparseable/invalid proposal (the existing rules-based incident detection keeps
  working with zero AI involvement).

**Files/components:** new `helpdesktool/ai/` package (`provider.py`,
`diagnosis.py`), `helpdesktool/api.py` (new diagnosis-review endpoint/UI hook),
`frontend/src/main.tsx` (diagnosis review panel on the incident/ticket views).

**Dependencies:** Milestone 4 (AI can only propose registered, versioned skills).

**Tests required:** prompt-injection resistance (malicious evidence content
cannot make the model emit an unregistered skill or bypass approval); redaction
of sensitive fields before any evidence reaches the provider; fallback behavior
when the provider errors or times out; a proposed action still lands in
`pending_approval`, never auto-executes.

**Definition of done:** AI can suggest a diagnosis and a specific registered
remediation, visible to an operator for approval, and it is provably
indistinguishable from a human-submitted action once it reaches the policy engine
— it cannot execute anything the policy/approval/skill-registry boundary would
otherwise deny.

---

### Milestone 8 — Production deployment infrastructure

**Build:**
- A documented, repeatable production deployment path: either hardened
  Kubernetes/Helm manifests or a `docker-compose.prod.yaml` overlay with resource
  limits, replicas, and health-based restarts (pick one — see open question
  below).
- Secrets-manager integration (extend the existing `SecretsProvider` protocol in
  `integrations.py` with a cloud-backed implementation — AWS Secrets Manager, GCP
  Secret Manager, or Vault, per the operator's target cloud).
- Backup/restore automation and a documented restore drill for PostgreSQL.
- Rate limiting middleware on the API (at minimum on auth and decision
  endpoints) and security headers (CSP/HSTS/X-Frame-Options) plus tuned
  caching/gzip in `frontend/nginx.conf`.
- CI: add container image build, a vulnerability scan (e.g. Trivy/Grype), and a
  deploy step gated on the target environment.

**Files/components:** `deploy/` (new manifests/overlay), `helpdesktool/config.py`
+ `integrations.py` (secrets provider), `frontend/nginx.conf`,
`.github/workflows/ci.yml` (or a new `cd.yml`).

**Dependencies:** Milestone 2 (do not deploy a real environment before OIDC/RLS
exist — deploying the current auth model to production would be the actual risk
this whole plan exists to avoid).

**Tests required:** a restore drill actually restores a backup to a working
database; rate-limit thresholds verified by a test that trips them; security
headers present in a response snapshot test; CI vulnerability scan runs and is
reviewed (not necessarily zero-findings-gated on day one).

**Definition of done:** there is one documented, repeatable way to stand up a real
production environment with secrets management, backups, rate limiting, and a
CI-gated container pipeline — not just `docker compose up` on a laptop.

---

### Milestone 9 — Frontend modernization and test coverage

**Build:**
- Add a test framework (Vitest + React Testing Library) and cover the existing 9
  routes' happy paths plus the role-gating logic (`canOperate`/`canAdmin`).
- Route/component modularization as the file grows past this milestone's new
  Reporting (M6) and AI-diagnosis-review (M7) surfaces — split `main.tsx` into
  per-page modules once it's clearly outgrown a single file, not preemptively.
- An accessibility pass (the current UI has no explicit ARIA/labeling work beyond
  semantic HTML).

**Files/components:** `frontend/package.json` (new devDependencies),
`frontend/src/*.test.tsx` (new), `frontend/src/main.tsx` (split as needed),
`.github/workflows/ci.yml` (add `npm test`).

**Dependencies:** Milestones 6 and 7 (so the new pages they add are covered from
the start rather than retrofitted).

**Tests required:** the tests *are* the deliverable here — route rendering, role-
gated action visibility, form submission error handling, at minimum.

**Definition of done:** `npm test` exists, runs in CI, and covers every route's
happy path and the role-gating logic; the frontend is no longer the only part of
the codebase with zero automated test coverage.

---

### Milestone 10 — Enterprise and scale hardening

**Build:**
- Retention/cleanup jobs for `device_inventory`, `heartbeats`,
  `idempotency_records` (age-based deletion or partitioning).
- SSO/SCIM provisioning on top of Milestone 2's OIDC integration.
- Approval quorum (N-of-M) and approval expiry.
- Policy-as-code (externalize the policy rules currently implicit in
  `PolicyEngine`/risk-level constants into a reviewable, versioned policy
  document).
- Immutable audit export and legal-hold support.

**Files/components:** new retention worker, `helpdesktool/auth.py` (SCIM),
`helpdesktool/orchestrator.py`/`policy.py` (quorum, policy-as-code),
`helpdesktool/api.py` (audit export endpoint), migrations.

**Dependencies:** Milestones 2, 3, 6 (identity, durable jobs, and reporting
infrastructure all need to exist first).

**Tests required:** retention jobs delete only what they should and never touch
active data; quorum approval requires the configured N distinct approvers;
audit export is complete and re-verifiable against the live hash chain.

**Definition of done:** the platform meets the enterprise bar implied by
"production-ready autonomous IT help desk SaaS" — bounded storage growth, SSO,
configurable approval policy, and exportable/auditable compliance evidence.

---

## Open questions to resolve before autonomous execution starts

1. **Target cloud/deployment substrate for Milestone 8** — Kubernetes/Helm vs. a
   hardened Compose overlay on a single/small VM fleet. This changes the shape of
   `deploy/` significantly and should be picked once, not iterated on per-
   milestone.
2. **OIDC provider for Milestone 2** — a specific provider (Auth0, Okta, Keycloak,
   AWS Cognito, or a generic OIDC-compliant one) needs to be named so JWKS/issuer
   config isn't hypothetical.
3. **mTLS/CA strategy for Milestone 3** — whether to stand up an internal CA, use
   a managed PKI (AWS Private CA, smallstep, etc.), or explicitly scope Milestone
   3 down to token rotation only and defer full mTLS to a later milestone.
4. **AI provider for Milestone 7** — which OpenAI-compatible endpoint(s) to
   support first, and whether real API keys/budget are available for development
   and evaluation.
5. **Secrets manager for Milestone 8** — which cloud/provider, to scope the
   `SecretsProvider` implementation correctly the first time.

None of these block starting Milestone 1, which has no external dependencies.
