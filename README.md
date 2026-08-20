# Helpdesktool

Helpdesktool is a deterministic, safety-first IT operations SaaS MVP. It combines a FastAPI/PostgreSQL control plane, unprivileged Linux and Windows endpoint agents, and a React operator console.

The executable trust boundary is:

```text
Observe -> Detect -> Correlate -> Ticket -> Structured action proposal
-> Policy -> Independent approval when required -> Device-bound job
-> Authenticated allowlisted agent executor -> Verify -> Roll back/escalate
-> Audit and domain events
```

The product is **not** a remote shell. Neither browser input nor future AI output can become an arbitrary shell or PowerShell command. The control plane queues structured work; only an authenticated endpoint agent can execute a locally allowlisted deterministic skill.

## What the MVP includes

- Multi-tenant tenants, users, roles, devices, inventory, heartbeats, tickets, incidents, actions, approvals, execution results, audit events, and webhook integrations, with PostgreSQL Row-Level Security enforcing tenant isolation as a second, independent layer beneath application-level filtering.
- Production human authentication via provider-neutral OIDC (Authorization Code + PKCE from the browser, standard `.well-known/openid-configuration` discovery -- no vendor hardcoded). Development-only browser sessions remain available for Owner/Admin/Operator/Viewer demo users; both development mechanisms fail closed outside `development` environment.
- Dashboard and searchable browser pages for Devices, Tickets, Incidents (with an AI-diagnosis panel), Actions, Approvals, Skills, Reports, Audit, Integrations, and Settings.
- Deterministic low-disk detection, correlation, automatic ticket creation, recovery detection, incident reopening, and domain events.
- A browser-accessible low-disk simulator which writes structured development telemetry without filling a real disk.
- Provider-neutral, advisory-only AI incident diagnosis (any OpenAI-compatible endpoint, or a deterministic no-network fallback) -- schema-validated output, never self-authorizing; a diagnosis still has to be manually submitted through the normal policy/approval pipeline to become an action.
- A versioned, integrity-checked remediation skill registry (risk tier, OS support, timeout, parameter shape as a `POST /v1/skills` data change) -- an agent still has to ship its own deterministic executor code for a skill to actually run.
- Risk-based policy and separation-of-duties approval before mutating endpoint work is queued.
- Device-bound job leases, cryptographically signed and versioned job envelopes (Ed25519, agents pin the public key via trust-on-first-use), replay protection, claim-token validation, idempotent reporting, verification and rollback outcomes.
- A durable local execution journal on both agents recovering cleanly from a crash at any point in claim -> execute -> report, without ever risking a duplicate mutation.
- Device credential rotation/revocation and one-time-token self-enrollment (`install-linux-agent.sh` / `install-windows-agent.ps1` use this to install with a single command).
- Hash-chained tenant audit history and a transactional signed-webhook outbox.
- Structured JSON logging with per-request correlation ids, a Prometheus `/metrics` endpoint, and background-worker liveness heartbeats.
- Unprivileged Linux and Windows agents, each with inventory collectors and one allowlisted `service.restart` executor -- fixed `systemctl` argument vectors (Linux) or direct Win32 Service Control Manager calls (Windows), never a shell.

## Architecture

```text
React/Vite operator console (:3000)
              |
              v
FastAPI control plane (:8000) ----> PostgreSQL
  |       |       |                      |
  |       |       +--> audit + events --> webhook outbox worker
  |       +----------> incident correlation + tickets + AI diagnosis
  +------------------> policy + approvals + signed, versioned jobs
                                      |
                                      v
                    authenticated Linux or Windows agent
                     (signed-envelope verification + a
                      durable local execution journal)
                                      |
                                      v
                    allowlisted deterministic executor
```

Core backend modules live in `helpdesktool/`, the Linux agent in `linux_agent/`, the Windows agent in `windows_agent/`, primitives shared by both agents (job-envelope verification, the execution journal) in `agent_common/`, the browser application in `frontend/`, and additive Alembic migrations in `migrations/versions/`.

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

Production install (single command, run as root -- installs a dedicated `helpdesk-agent` service account, a system-level systemd unit, and self-enrolls with a one-time token generated by an admin via `POST /v1/devices/enrollment-tokens` or the operator console's Devices page):

```bash
sudo ./deploy/install-linux-agent.sh \
  --server-url https://api.example.com \
  --enrollment-token <token> \
  --allowed-services demo.service
```

Uninstall with `sudo ./deploy/uninstall-linux-agent.sh` (revoke the device's credential on the control plane first). See the script's `--help` and header comments for the full option list, including `--package-source` for pinning an exact release once one is published (it defaults to installing from this repo's `main` branch, which is fine for a demo/pilot but not for a real fleet rollout).

For local development instead of a production install, copy `agent.example.json` to `~/.config/helpdesktool/agent.json`, insert a tenant/user identity for admin-mediated enrollment, and run it directly:

```bash
python -m pip install -e .
mkdir -p ~/.config/helpdesktool
cp agent.example.json ~/.config/helpdesktool/agent.json
chmod 600 ~/.config/helpdesktool/agent.json
helpdesk-linux-agent --config ~/.config/helpdesktool/agent.json --once
```

Either way, the agent stores its credential with owner-only permissions, sends heartbeat/inventory, claims only jobs addressed to its device, verifies each job's signed envelope (device/tenant/expiry/skill-version) before ever touching the executor, validates exact parameters against its own local allowlist, invokes `systemctl` without a shell, verifies the outcome, attempts rollback when necessary, durably journals every step so a crash at any point recovers cleanly on restart, and posts a structured result. Do not run it as root merely to make remediation work; the installer's dedicated service account already handles this correctly.

Upgrade in place (config, credential, and execution journal are untouched -- only the installed package changes, no re-enrollment needed):

```bash
sudo systemctl stop helpdesk-linux-agent
sudo /opt/helpdesktool/venv/bin/pip install --upgrade helpdesktool
sudo systemctl start helpdesk-linux-agent
```

## Windows agent

Production install (single command, run from an elevated PowerShell prompt -- installs the agent as a Windows Service under a low-privilege virtual service account, not `LocalSystem`, and self-enrolls with a one-time token):

```powershell
.\deploy\install-windows-agent.ps1 -ServerUrl https://api.example.com -EnrollmentToken <token> -AllowedServices Spooler
```

Uninstall with `.\deploy\uninstall-windows-agent.ps1`. See `deploy/README-windows-agent.md` for the full manual-step walkthrough (useful for understanding exactly what the script automates, or for environments that can't run it directly), NTFS ACL details, and the Win32 Service Control Manager trust model (no `sc.exe`, no shell, no PowerShell ever spawned by the agent itself to control a service).

## Integrations

Generic webhook subscriptions are external consumers only. n8n, Slack, Teams, and ticketing systems cannot approve endpoint work, bypass policy, or enter the execution trust boundary.

Webhook signing secrets are environment references such as `env:HELPDESK_WEBHOOK_SECRET_N8N`; secret values are not stored in subscription rows or returned to the frontend. Deliveries carry `X-Helpdesk-Event-ID` and an `X-Helpdesk-Signature-256` HMAC header. HTTPS public destinations are required by default, and the worker uses bounded timeouts, retry backoff, and dead-letter state.

## Validation

```bash
python -m pip install -e ".[dev,windows]"
python -c "import helpdesktool; import agent_common; import linux_agent; import windows_agent"
python -m compileall helpdesktool agent_common linux_agent windows_agent
pytest
ruff check .
ruff format --check .
mypy
cd frontend && npm install && npm run typecheck && npm test && npm run build
cd .. && docker compose config && docker compose build
```

CI (`.github/workflows/ci.yml`) runs four independent jobs from the repository manifests: `backend` (the Python checks above), `frontend` (typecheck/test/build), `security` (`gitleaks` secret scanning, `pip-audit` for backend dependency CVEs, `npm audit --audit-level=high` for frontend dependency CVEs), and `docker` (builds the API and frontend Docker images, scans each with `trivy` for fixable CRITICAL/HIGH vulnerabilities, then actually runs each one -- not just `docker build` -- specifically to catch startup failures a build alone can't).

## Backup and restore

Standard `pg_dump`/`pg_restore` against the `db` service works unmodified — nothing
here is Helpdesktool-specific, since the schema, RLS policies, and the restricted
`helpdesk_app` role are all owned by the database itself, not by anything the API
process holds in memory. Verified end to end (dump → drop the database → recreate
it → restore → confirmed `pg_policies` and the `helpdesk_app` role survive intact →
a real API process started against the restored database serves `/health/ready`
successfully) as part of this project's own release validation, not just asserted:

```bash
# Backup (run against the db service/container)
pg_dump -U helpdesk -d helpdesk -Fc -f backup.dump

# Restore into a fresh database (the target database must already exist and
# be empty -- pg_restore does not create it)
createdb -U helpdesk helpdesk_restored
pg_restore -U helpdesk -d helpdesk_restored backup.dump
```

`helpdesk_app` (the restricted runtime role) is cluster-level, not database-level,
so restoring into the *same* PostgreSQL cluster the backup came from needs no extra
step. Restoring into a *different* cluster (e.g. a new deployment) needs migration
`0005` run first (`alembic upgrade head` against an empty database, which creates
that role) — this is exactly what `docker compose`'s `migrate` service already does
on every startup, so a fresh cluster with `docker compose up` followed by a
`pg_restore` into its (now-schema-owning, empty) database works the same way.
Audit events are append-only and hash-chained by design (see
`helpdesktool/audit.py`/`retention_worker.py`'s module docstrings) — a restored
backup's audit chain is exactly as verifiable as it was at backup time, nothing
about backup/restore weakens that guarantee.

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

This section is kept current as of 2026-08-20; see `docs/IMPLEMENTATION_PLAN.md` for the full, per-milestone audit this summary is drawn from.

- **mTLS is not implemented.** Endpoint identity today is a bearer device credential (rotatable/revocable) plus cryptographically signed, versioned, replay-resistant job envelopes -- a real, tested layer of defense, but not certificate-based transport identity. Evaluated and deliberately deferred; see Milestone 3's notes for the reasoning and what a real rollout would need (a CA, cert issuance/rotation, reverse-proxy client-cert verification).
- **No cryptographic signing on skill manifests.** The skill registry has integrity verification (a stored manifest's hash is recomputed and checked on every read, catching direct database tampering) but not an independent signature scheme.
- **No key rotation story for job-envelope signing.** Only one signing key version exists; a rotated key makes every already-enrolled agent fail closed until an operator clears its locally pinned key to force re-pinning.
- **No published package release yet.** The install scripts default to installing straight from this repo's `main` branch via `pip`'s `git+https` support (`--package-source`/`-PackageSource` overrides this) -- fine for a demo or pilot, not for a fleet rollout that needs an exact, pinned, reviewed version.
- **The frontend has no route-level automated test coverage** beyond the OIDC/PKCE login-flow logic (`frontend/src/auth/oidc.test.ts`) -- no React Testing Library component tests yet, and no accessibility audit has been done.
- **No frontend pager UI.** `/v1/devices`, `/v1/tickets`, `/v1/actions`, and `/v1/incidents` now accept `limit`/`offset` (default `limit=100`, capped at 500) so none of them can return an unbounded result set, but there's no frontend pager control or `total`-count response shape yet — that's real, separately-scoped work.
- **The reporting layer computes on demand, not on a schedule.** `GET /v1/reports/summary` (and the frontend Reports page) recompute every figure fresh from the database for the requested period rather than reading a pre-generated daily snapshot -- deliberate, for the same reason `metrics.py`'s gauges are scrape-time: a live query can never drift from what's actually in the database. There is no scheduled "generate and archive a daily report" worker; an external scheduler can call the same endpoint on a cron if a stored history of past reports is ever needed.
- **No OpenTelemetry tracing.** Structured JSON logs with per-request correlation ids and Prometheus metrics exist; distributed tracing does not (no OTLP collector target has been chosen).
- **The API rate limiter is per-process, in-memory.** A real, complete guarantee for this platform's default single-API-process `compose.yaml` topology, but a multi-replica production deployment needs a shared store (e.g. Redis) or gateway-level limiting for a consistent limit across replicas -- not built yet.
- The MVP detects and verifies low-disk recovery but does not ship an unsafe generic disk-cleanup command. A future cleanup skill must define exact safe targets, permission, verification, and rollback/escalation behavior.
- `service.restart` is the only mutating reference executor. It is appropriate for exercising policy/approval/job/verification/rollback, not for claiming that restarting a service fixes disk usage. Adding a genuinely new mutating skill always requires an agent code change -- the skill registry can declare policy metadata for a skill id, but never ships new execution logic, by design.
- Production billing, RAG, advanced ticketing integrations, and Kubernetes deployment are intentionally deferred and out of scope for this MVP.
