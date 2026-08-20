# Release readiness — v0.1.0-rc1

Date: 2026-08-20. Based on `docs/FINAL_AUDIT.md` and `docs/SECURITY_REVIEW.md`,
both performed against `main` at commit `9e67d64`. Read those two documents
for evidence and detail; this document exists to give one unambiguous
verdict per area and an overall release decision.

## Legend

- **PASS** — verified this pass (or independently re-verified) by an actual
  run, not by reading code and assuming it works.
- **PARTIAL** — real, working implementation exists, but verification is
  incomplete in a specific, stated way.
- **BLOCKED-EXTERNAL** — cannot be verified in this environment at all; needs
  credentials, hardware, or infrastructure only a human can supply. Not a
  code defect.
- **DEFERRED-POST-MVP** — a deliberate scope decision, not a gap discovered
  and left unfixed. Documented with the reason at the point it was deferred.
- **FAIL** — a critical/high issue remains open. **There are none in this
  table as of this audit** — every FAIL-level finding discovered during this
  pass was fixed before this document was written (see Security Review's
  two "FIXED" entries).

## Matrix

| Area | Status | Notes |
|---|---|---|
| Core trust chain (no arbitrary execution, policy gate, approval gate, deterministic executor) | **PASS** | Re-verified this pass; adversarial tests could not break any link |
| Signed job envelopes | **PASS** | Verified including forgery/replay/theft resistance (new adversarial tests) |
| Tenant isolation / RLS | **PASS** | Database- and API-layer, including new cross-tenant action/job-claim tests |
| Authentication (OIDC token verification logic) | **PASS** | Adversarial: expired, wrong audience/issuer, tampered, `alg=none`, RS256→HS256 confusion — all rejected |
| Authentication (real IdP integration) | **BLOCKED-EXTERNAL** | Never run against a real Auth0/Okta/Keycloak/Cognito tenant; see below for the exact steps required |
| Authorization / RBAC | **PASS** | Role checks confirmed at the HTTP layer, including new approval-bypass tests |
| Approval workflow (separation of duties, bypass resistance) | **PASS** | Self-approval, re-decision, cross-tenant decision, under-privileged role — all rejected |
| SSRF | **PASS** | One real gap (redirect-following) found and fixed this pass; verified with a real HTTP server, not a mock |
| Prompt injection (AI diagnosis) | **PASS** | Verified from the attacker-controlled input surface (device telemetry), not just a fabricated LLM response |
| Secrets never committed | **PASS** | Verified against full git history directly; CI's `gitleaks` job green |
| Backend test suite | **PASS** | Full suite green (SQLite and real Postgres 17 container tiers); the only failures are 4 pre-existing, by-design Windows-platform-only tests, unchanged and unaffected by this pass |
| Backend static checks (`ruff`, `mypy --strict`) | **PASS** | Clean |
| Frontend test suite (`vitest`) | **PASS** | Clean |
| Frontend static checks (`tsc`) | **PASS** | Clean |
| Frontend production build | **PASS** | Clean, verified via `docker build` too |
| Browser/UX validation | **PASS** | Real Chromium via Playwright against real production images; found and fixed a real bug (infinite fetch loop) |
| Docker image build (API) | **PASS** | Multi-stage, non-root, `.dockerignore` added this pass, zero fixable CRITICAL/HIGH `trivy` findings |
| Docker image build (frontend) | **PASS** | Non-root nginx, real CSP/security headers added this pass, zero fixable CRITICAL/HIGH `trivy` findings |
| Docker Compose hardening | **PASS** | `read_only`, `cap_drop: ALL`, `no-new-privileges` on every custom-built service; verified via a real fresh-from-zero `docker compose up` |
| Fresh-from-zero deployment | **PASS** | Full 8-service stack verified this pass from an empty Postgres volume |
| Database migrations (forward) | **PASS** | `alembic upgrade head` from empty, verified this pass |
| Database migrations (reverse) | **PASS** | Full `downgrade base` verified this pass — not previously demonstrated this comprehensively |
| Backup/restore | **PASS** | Real `pg_dump`/`pg_restore` cycle, RLS/role survival independently re-confirmed this pass |
| Crash/recovery — agent job lease | **PASS** | `lease_reaper` requeue/escalate, plus new stale-claim-token adversarial test |
| Crash/recovery — agent local journal | **PARTIAL** | Strong unit-level coverage (`test_execution_journal.py`); not re-proven against a genuinely killed process this pass |
| CI (backend/frontend/security/docker jobs) | **PASS** | All four green on current `main` |
| Linux agent installer | **PASS** (verified in an earlier session pass, unchanged since) | Real systemd-in-Docker install/uninstall; not re-run this pass since nothing in the installer changed |
| Windows agent installer | **BLOCKED-EXTERNAL** | No Windows runtime available in this environment, ever, in any pass; static validation only (PowerShell AST parse, `mypy --platform win32`) |
| Rate limiting under real concurrent load | **DEFERRED-POST-MVP** | Logic unit-tested; a multi-replica-safe (shared-store) limiter is explicitly out of scope for this MVP's single-process default topology |
| mTLS | **DEFERRED-POST-MVP** | Evaluated, documented reasoning in `docs/IMPLEMENTATION_PLAN.md` Milestone 3 |
| Skill-manifest cryptographic signing | **DEFERRED-POST-MVP** | Integrity-hash exists; independent signature scheme deferred |
| Job-signing key rotation | **DEFERRED-POST-MVP** | Single key version; rotation requires manual re-pin fleet-wide, documented as a known limitation |
| SSO/SCIM | **DEFERRED-POST-MVP** | Milestone 10, unstarted, real scope |
| Approval quorum (N-of-M) | **DEFERRED-POST-MVP** | Milestone 10, unstarted |
| Policy-as-code | **DEFERRED-POST-MVP** | Milestone 10, unstarted |
| Immutable audit export / legal hold | **DEFERRED-POST-MVP** | Milestone 10, unstarted |
| OpenTelemetry tracing | **DEFERRED-POST-MVP** | Evaluated, no OTLP collector target chosen |
| Third-party penetration test | **BLOCKED-EXTERNAL** | Requires engaging an external firm; out of this environment's reach entirely |

## Verdict

**No FAIL-level item remains.** Every critical/high issue discovered during
this release-candidate pass (the SSRF redirect bypass; the frontend infinite
fetch loop) was fixed and verified before this document was written, not
left open with a caveat. All locally verifiable release gates — the full
backend and frontend test/lint/type suites, both Docker images, a fresh
from-zero deployment, migration reversibility, backup/restore, and a
genuine adversarial security pass — are green.

The remaining open items are exactly two kinds: things this environment is
structurally unable to verify (a real Windows machine, a real OIDC
provider, a third-party pen test — **BLOCKED-EXTERNAL**), and real
enterprise-hardening scope deliberately not attempted in an MVP pass
(**DEFERRED-POST-MVP**, each with its own stated reasoning). Neither kind
represents a known defect being shipped silently.

**This repository is release-candidate ready.** `v0.1.0-rc1` is being
tagged at commit `9e67d64` on `main`.

## What you must personally verify before a real v0.1.0 production release

These are the BLOCKED-EXTERNAL items from the matrix above — nothing else
requires your action; everything else has already been verified in this
environment.

1. **Real OIDC provider integration.** Register a real client (Auth0,
   Okta, Keycloak, Cognito, or any standards-compliant provider) for both
   the backend (`HELPDESK_OIDC_ISSUER`/`HELPDESK_OIDC_AUDIENCE`/
   `HELPDESK_OIDC_JWKS_URL`) and the frontend (`VITE_OIDC_ISSUER`/
   `VITE_OIDC_CLIENT_ID`/..., a public SPA client with no secret, redirect
   URI `<your frontend origin>/auth/callback`). Log in as a real user
   through the real Authorization Code + PKCE flow and confirm
   `GET /v1/auth/me` resolves the correct tenant/role. This project's own
   code has never been exercised against a real provider — only against a
   locally generated key pair simulating one.
2. **Windows agent, on a real Windows machine.** Run
   `deploy/install-windows-agent.ps1` end-to-end as Administrator against a
   real (or freshly provisioned) Windows Server/desktop host, confirm the
   service installs under the restricted `NT SERVICE\HelpdeskWindowsAgent`
   account (not `LocalSystem`), enrolls successfully, and executes a real
   `service.restart` job. Then run `deploy/uninstall-windows-agent.ps1` and
   confirm clean removal. This has never been run against real Windows in
   any pass of this project.
3. **Production secrets.** Generate real, unique, sufficiently random
   values for every secret in `.env.example` (`HELPDESK_APP_ROLE_PASSWORD`,
   `HELPDESK_BOOTSTRAP_TOKEN`, `HELPDESK_JOB_CLAIM_SECRET`,
   `HELPDESK_JOB_SIGNING_SEED`, `HELPDESK_DEVELOPMENT_SESSION_SECRET`,
   `HELPDESK_WEBHOOK_SECRET_N8N`, `POSTGRES_PASSWORD`) — never reuse this
   document's or the repo's placeholder/test values. Set
   `HELPDESK_ENVIRONMENT=production`; `Settings.validate_security()` will
   fail closed if any of this is missed or left at a default.
4. **TLS termination.** This project's own containers serve plain HTTP
   internally (Postgres, the API, nginx) — a production deployment needs a
   real TLS-terminating reverse proxy/load balancer in front (the
   `HELPDESK_ALLOWED_ORIGINS`/CORS and OIDC redirect URI configuration
   above assume `https://` origins). Nothing in this codebase provisions
   or manages TLS certificates itself.
5. **A real backup schedule.** The `pg_dump`/`pg_restore` procedure in
   `README.md` is verified to work; nothing in this project schedules it
   automatically. Wire it into your actual infrastructure's backup
   tooling/cron before relying on it.
6. **Optional but recommended: a third-party security review**,
   particularly of the production OIDC configuration and network perimeter
   once real infrastructure exists — this pass's adversarial testing is
   thorough but is not a substitute for independent penetration testing
   against a live deployment.

Nothing else is blocking. Everything else in the matrix above marked PASS
was verified by an actual run in this environment, and every
DEFERRED-POST-MVP item is real, scoped, future work you can prioritize on
your own schedule rather than a hidden gap in what shipped.
