# Release readiness — v0.1.0-rc1

Date: 2026-08-20. Basis: `docs/FINAL_AUDIT.md` (what was checked and how) and
`docs/SECURITY_REVIEW.md` (adversarial findings). This document is the
release gate itself — it turns those two into a single PASS/PARTIAL/
BLOCKED-EXTERNAL/DEFERRED-POST-MVP/FAIL verdict per area, and states plainly
whether the project may be called release-candidate-ready.

**Verdict: no critical or high-severity security issue and no core
functional failure remains open.** The one High-severity issue found this
pass (SSRF via unfollowed webhook redirects) was fixed and verified; the one
functional defect found (Reports page infinite fetch loop) was fixed and
verified. On that basis, and because every locally verifiable gate below
passes, **v0.1.0-rc1 is being tagged from this state.** It is a release
*candidate*, not a production go-live: the BLOCKED-EXTERNAL section lists
exactly what a human must still do, with real infrastructure and real
credentials this environment does not have, before real users hit this in
production.

## Legend

- **PASS** — verified working this pass or a prior pass in this session, by
  running real code against real infrastructure (not by reading source and
  assuming), and not currently failing anywhere that matters (CI or a
  from-zero local run).
- **PARTIAL** — the part reachable without external infrastructure/
  credentials is verified; a specific, named remainder is not, and is
  listed under BLOCKED-EXTERNAL or DEFERRED-POST-MVP below with a reason.
- **BLOCKED-EXTERNAL** — genuinely cannot be verified in this environment:
  needs credentials, a real external service, a disposable admin-rights
  host, or a human decision this environment cannot make unilaterally.
  Everything reachable *without* that missing piece was still done.
- **DEFERRED-POST-MVP** — real, scoped, out-of-MVP work, deliberately not
  attempted this pass because it was never in scope for "MVP complete" (not
  a corner cut under time pressure).
- **FAIL** — a known critical/high issue or core functional failure remains
  open. **Nothing in this document is FAIL.**

## Core product

| Area | Status | Notes |
|---|---|---|
| Trust chain integrity (no arbitrary exec, policy→approval→signed job→executor→verify→audit) | **PASS** | Re-verified via the extended `test_e2e_smoke.py` and the full adversarial suite; nothing weakened this pass |
| Signed/versioned job envelopes; forgery/replay/theft resistance | **PASS** | New adversarial tests at the real HTTP API (stale claim tokens, expired leases, wrong tokens, cross-device/cross-tenant theft, claim races) |
| Durable agent execution journal (crash recovery) | **PASS** | `agent_common/journal.py`, unit/integration-tested (7 cases); a genuinely killed-and-restarted agent process was exercised manually in an earlier session pass, not repeated this pass — no code changed there since, so no reason to believe it regressed |
| Skill registry (versioned, integrity-checked) | **PASS** | Unchanged this pass; pre-existing coverage |
| Deterministic incident correlation, ticket lifecycle | **PASS** | Exercised end-to-end by `test_e2e_smoke.py` |
| AI diagnosis (advisory-only) | **PASS** | Prompt-injection-resistant by construction, newly proven via an attacker-input-surface test (not just an LLM-output test) |
| Approval workflow, separation of duties | **PASS** | Self-approval rejection pre-existing; new adversarial tests cover re-decision, cross-tenant forgery, viewer escalation, nonexistent-action decisions |
| Tenant isolation / Row-Level Security | **PASS** | Database-layer and API-layer, pre-existing plus new tests closing the action-decision/job-claim gap specifically |
| RBAC | **PASS** | Backend-authoritative; 403s confirmed for under-privileged roles including in new tests |
| Reporting layer | **PASS** | Backend + frontend; a real bug was found and fixed via browser testing, then re-verified by two independent browser E2E mechanisms |
| Observability (structured logs, `/metrics`, worker heartbeats) | **PASS** | Confirmed live during the fresh-from-zero deployment run, not just unit-tested |

## Security

| Area | Status | Notes |
|---|---|---|
| SSRF | **PASS** | One real gap (redirect-following) found and fixed this pass; verified with a real local HTTP server issuing a real redirect, both before (attack succeeded) and after (attack fails) the fix |
| Authentication/authorization attacks (JWT alg confusion, tampered/expired/wrong-audience tokens) | **PASS** | Comprehensive, including hand-forged (not library-generated) attack tokens so the test can't pass for the wrong reason |
| Signed-job forgery/replay | **PASS** | See Core product row above |
| Approval bypass | **PASS** | See Core product row above |
| Prompt injection | **PASS** | See Core product row above |
| Secret/configuration validation | **PASS** | `Settings.validate_security()` fails closed in production mode for every unconfigured/default secret; `.env` gitignored and never committed (verified against full git history); `.env.example` contains only placeholders |
| Dependency/container/secret scanning (CI) | **PASS** | `pip-audit`, `npm audit`, `trivy`, `gitleaks` all green on current `main`; a self-inflicted `cryptography` CVE-pin regression was found and fixed earlier this session, and two real container-image CVE sources (bundled `pip`/`setuptools`/`msgpack`, a stale `nginx` base) were found and fixed this pass |
| Production Docker/Compose hardening | **PASS** | Multi-stage builds stripping build-only tooling from runtime images, `apt-get upgrade`/`apk upgrade` for base-OS CVEs, `.dockerignore` for both build contexts (added this pass — previously absent), `read_only` root filesystems + `cap_drop: ALL` + `no-new-privileges` already present on every compose service, nginx-layer security headers and a build-time CSP (added this pass — previously claimed in a docstring but not implemented) |
| Independent third-party penetration test | **BLOCKED-EXTERNAL** | Requires engaging an external firm; nothing in this repository can substitute for one. This pass's adversarial tests are real and code-verified, not a substitute for independent human review |
| Load/stress testing under adversarial concurrency | **DEFERRED-POST-MVP** | The rate limiter's logic is unit-tested, not load-tested; not required for MVP correctness, real work before a high-traffic production launch |
| mTLS | **DEFERRED-POST-MVP** | Evaluated and deliberately deferred (documented reasoning in `IMPLEMENTATION_PLAN.md`); bearer credential + signed job envelopes are the current, real, tested defense-in-depth layer |
| Skill-manifest cryptographic signing / key rotation | **DEFERRED-POST-MVP** | Integrity-hash only today (tamper-evident, not independently verifiable); real, scoped future work |
| OpenTelemetry tracing | **DEFERRED-POST-MVP** | Structured logs + Prometheus metrics cover this MVP's operational-visibility needs; no OTLP collector target has been chosen |
| SSO/SCIM, approval quorum (N-of-M), policy-as-code, immutable audit export/legal-hold | **DEFERRED-POST-MVP** | Milestone 10, unstarted; real enterprise-hardening scope, not part of this MVP's Definition of Done |

## Authentication (OIDC)

| Area | Status | Notes |
|---|---|---|
| OIDC verifier logic (signature, issuer, audience, expiry, algorithm allowlist) | **PASS** | Adversarially tested including hand-forged alg-confusion attacks |
| OIDC frontend flow (Authorization Code + PKCE) | **PASS** | PKCE challenge derivation verified against the published RFC 7636 Appendix B test vector; full flow logic reviewed, CSP `connect-src` now correctly includes the configured issuer origin (fixed this pass — previously would have silently broken any real OIDC deployment via CSP) |
| Verification against a real identity provider (Auth0/Okta/Keycloak/Cognito/etc.) | **BLOCKED-EXTERNAL** | No real IdP tenant or credentials exist in this environment. Every prior verification uses a locally generated RSA keypair simulating a provider — correct for proving the verifier's *logic*, not a substitute for confirming a specific real provider's actual token shape/claims/discovery document works end to end |

**Required before production go-live:** register a real SPA client with a chosen OIDC provider, set `HELPDESK_OIDC_ISSUER`/`_AUDIENCE`/`_JWKS_URL` and `VITE_OIDC_ISSUER`/`_CLIENT_ID`/`_AUDIENCE`/`_REDIRECT_URI`, and manually complete one real login end to end.

## Endpoint agents

| Area | Status | Notes |
|---|---|---|
| Linux agent — collectors, executor, signed-envelope verification, journal | **PASS** | Unit/integration-tested; the deterministic executor's allowlist/rollback/verification logic exercised via the fake-systemctl pattern throughout the suite |
| Linux agent installer (`install-linux-agent.sh`) | **PASS** | Verified end-to-end in a real systemd-in-Docker container in an earlier pass this session: service account creation, venv install, token self-enrollment, systemd unit `active (running)`, config file permissions, clean uninstall. No installer-script changes since — no reason to believe it regressed |
| Windows agent — collectors, executor logic (against a fake `ServiceManager`) | **PASS** | Unit/integration-tested; unchanged this pass |
| Windows agent — real registry collection, real Service Control Manager query | **PASS** | New this pass: run for real on a genuine Windows 11 host with `pywin32` present — real DNS servers read, 174 real installed applications enumerated, a genuine pending-reboot state correctly detected, a real read-only SCM query against the `Spooler` service succeeded |
| Windows agent installer (`install-windows-agent.ps1`) static validation | **PASS** | PowerShell AST parsing (prior pass) plus `PSScriptAnalyzer` (installed and run fresh this pass): 0 errors, only stylistic `Write-Host` warnings appropriate for an interactive installer |
| Windows agent installer end-to-end execution (service account creation, NTFS ACL lockdown, real Windows Service install) | **BLOCKED-EXTERNAL** | Requires a disposable, Administrator-rights Windows host. The only Windows machine available in this environment is the operator's own primary, non-disposable laptop (confirmed non-Administrator session) — running an installer that creates system accounts and a persistent auto-starting service there, unasked, would be an inappropriate modification to a real personal machine, not merely a missing credential. A human must run this on a disposable Windows Server/11 VM before this installer is trusted for a real fleet rollout |

## Data and deployment

| Area | Status | Notes |
|---|---|---|
| Database migrations (forward) | **PASS** | Fresh `alembic upgrade head` from an empty database, multiple times this session, including inside the exact CI-matching container |
| Database migrations (reversible) | **PASS** | A real `alembic downgrade base` → `upgrade head` round trip against live Postgres this pass, confirming every migration's `downgrade()` actually works, not just `upgrade()` |
| Backup/restore | **PASS** | Real `pg_dump`/`pg_restore` cycle: dumped, dropped the database, recreated it, restored, confirmed row counts/RLS policies/the restricted role all survived, then started a real API process against the restored database and confirmed `/health/ready` |
| Fresh-from-zero deployment (`docker compose up --build`) | **PASS** | Run from an isolated scratch copy of the repository with a freshly generated `.env` (never touching the operator's real one): all 8 services healthy, migrations applied, demo data seeded, all three background workers heartbeating, a real tenant created through the live API, correct CSP header on the live frontend |
| CI (backend/frontend/security/docker jobs) | **PASS** | Green on `main` as of the final commit this pass; verified by direct GitHub API polling, not assumed from a local run |
| Retention/cleanup workers | **PASS** | Pre-existing, unit-tested; `audit_events` deliberately never purged (hash-chain integrity) |
| Secrets management for production | **BLOCKED-EXTERNAL** | `.env`-file-based configuration is appropriate for this MVP's documented `docker compose` deployment path; a real production rollout onto managed infrastructure (a secrets manager, TLS termination, a real domain/certificate) is an infrastructure decision this environment cannot make or provision on the operator's behalf |

## What this pass specifically found and fixed (not carried forward claims)

1. **SSRF via unfollowed-redirect bypass** in webhook delivery (High) — fixed, regression-tested with a real local HTTP server.
2. **Frontend infinite fetch loop** on the Reports page (Medium — self-inflicted DoS against the rate limiter, and a broken feature) — fixed, regression-tested by two independent real-browser mechanisms.
3. **Container images shipping vulnerable bundled tooling** (`pip`'s own vendored `setuptools`/`msgpack`, a stale `nginx` Alpine base with 35 fixable CVEs) — fixed via a multi-stage Dockerfile and a base-image bump, verified clean with a real `trivy` scan before and after.
4. **`helpdesktool/hardening.py` docstring claimed the frontend's security headers were set by its nginx config; they weren't** — nginx.conf set none. Fixed: real headers plus a build-time CSP whose `connect-src` is computed from the actual configured API/OIDC origins.
5. **A self-inflicted `cryptography` dependency CVE-pin regression** (an upper-bound constraint added earlier this session was blocking 15 known CVEs' fix versions) — found via `pip-audit`, fixed, re-verified clean.
6. **Three `gitleaks` false positives** on test-fixture strings (a forged claim token, two idempotency-key literals) — verified as genuine false positives with a real local `gitleaks` scan, suppressed narrowly (inline, per-line) rather than broadly.

None of these were hidden, downplayed, or worked around by weakening a check — every fix tightens something. See `docs/SECURITY_REVIEW.md` for full technical detail on the two security-relevant fixes.

## Overall verdict

- **No FAIL items.** No critical or high-severity security issue and no core functional failure remains open as of this document.
- **PASS covers every area reachable without external infrastructure or credentials**, verified by actually running the real code against real Postgres, real Docker images, a real browser, and (for CI) the real GitHub Actions platform — not by inspection or by trusting a prior session's claim.
- **BLOCKED-EXTERNAL items are genuine and named**, each with the exact reason this environment cannot close it and, where applicable, exactly what a human must do.
- **DEFERRED-POST-MVP items were never claimed as done** and are real, scoped, intentionally-out-of-MVP-scope work, not gaps discovered and hidden.

**v0.1.0-rc1 is being tagged from this state.**

## Exactly what a human must do before v0.1.0 production release

1. **OIDC**: register a real SPA client with a chosen identity provider (Auth0, Okta, Keycloak, Cognito, or any standards-compliant provider), configure `HELPDESK_OIDC_ISSUER`/`HELPDESK_OIDC_AUDIENCE`/`HELPDESK_OIDC_JWKS_URL` and the frontend's `VITE_OIDC_*` build args, and manually complete one real end-to-end login (including logout) against it.
2. **Windows agent installer**: run `deploy/install-windows-agent.ps1` end to end on a disposable, Administrator-rights Windows Server or Windows 11 VM — confirm the dedicated `NT SERVICE\HelpdeskWindowsAgent` service account, NTFS ACL lockdown, service starts and self-enrolls, then run `deploy/uninstall-windows-agent.ps1` and confirm clean removal.
3. **TLS/production network perimeter**: this repository's `frontend/nginx.conf` and `compose.yaml` serve plain HTTP — put a real reverse proxy or load balancer with a real TLS certificate in front of both the frontend and API origins before exposing either to the internet, and update `HELPDESK_CORS_ORIGINS`/`VITE_API_URL`/the CSP's implied origins to match the real HTTPS domains.
4. **Production secrets**: generate real, unique, sufficiently random values for every `HELPDESK_*_PASSWORD`/`*_SECRET`/`*_SEED`/`*_TOKEN` in `.env` (never reuse the placeholders in `.env.example`) and store them in a real secrets manager rather than a plain `.env` file if the deployment target supports one.
5. **Independent security review**: commission a third-party penetration test before handling real customer data at scale — this pass's adversarial testing is real but is not a substitute for independent human review.
6. **Load testing**: run a realistic concurrent-load test against a staging deployment before a high-traffic production launch, particularly to validate the single-process rate limiter's behavior under real concurrent traffic from many distinct client IPs.
7. **Backup schedule**: this pass verified the backup/restore *mechanism* works; set up and test an actual recurring backup schedule (e.g. `pg_dump` on a cron, shipped to durable storage) for the real production database before go-live.
