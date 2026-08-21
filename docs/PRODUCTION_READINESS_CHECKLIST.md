# Production readiness checklist

Date: 2026-08-21. Living document — update this in place as work lands,
rather than creating a new one per pass. Uses the category taxonomy
requested for this checklist specifically (P0 Security, P1 Architecture,
P2 Reliability, P3 Automation, P4 Integrations, P5 UI/UX, P6
Infrastructure, P7 Operations) — a different axis from
`docs/HELPDESK_MATURITY_GAP_ANALYSIS.md`'s P0-P5 (security/architecture/
endpoint/automation/knowledge/optimization) and `docs/RELEASE_READINESS.md`'s
PASS/PARTIAL/BLOCKED-EXTERNAL/DEFERRED-POST-MVP v0.1.0-rc1 snapshot. All
three are kept, not merged — each answers a different question (this one:
"what's left before real orgs/real endpoints", the maturity analysis:
"what's the next priority", release readiness: "was rc1 safe to tag").

**Status legend** (exactly as specified): **DONE** — appropriately tested
and verified, not merely present in source. **PARTIAL** — real, working,
with a specific named remainder. **BLOCKED-EXTERNAL** — genuinely cannot
be completed in this environment (credentials, a live registration, a
disposable host, a human decision). **NOT STARTED** — no code exists yet.

A status of DONE below means: real code, exercised by a real test run
(unit/integration, and where noted a real Postgres/Docker/Linux-container/
live-Windows-host run), with no known regression as of the date above —
not "the file exists."

## P0 — Security

| Item | Status | Notes |
|---|---|---|
| Tenant isolation (RLS + app-level, independent layers) | **DONE** | Adversarially tested (`tests/test_tenant_isolation_postgres.py`, `test_auth_tenant_isolation_api_postgres.py`, cross-tenant forgery tests) |
| RBAC (owner/admin/operator/viewer) | **DONE** | Backend-authoritative; 403 confirmed for under-privileged roles in adversarial tests |
| OIDC verifier logic (signature/issuer/audience/expiry/alg-confusion resistance) | **DONE** | Hand-forged attack tokens (`alg: none`, RS256→HS256 confusion), not library-generated, so tests can't pass for the wrong reason |
| OIDC against a real identity provider | **BLOCKED-EXTERNAL** | No real IdP tenant/credentials in this environment; only a locally generated RSA keypair standing in for a provider's JWKS has been used |
| Signed, versioned job envelopes (Ed25519) + replay protection | **DONE** | Forgery/replay/theft adversarially tested at the real HTTP API |
| Job-signing key rotation | **DONE** | Milestone 27 — real API test rotates the active version mid-test and proves both pre- and post-rotation envelopes verify; also checked against a real disposable Postgres container |
| Destructive-action hard block (`PolicyEngine`) | **DONE** | Unconditional, independent of risk tier; tested |
| Step-up verification for high-risk connector operations | **DONE** | Milestone 26 — a requester must retrieve a short-lived code through a separately authenticated call before an approver can act; 8 tests including single-use/expiry |
| Separation-of-duties (action + connector-request approval) | **DONE** | Adversarially tested: self-approval, re-decision, cross-tenant forgery, viewer escalation |
| AI-invented confidence prevention | **DONE** | Hostile-fake-provider test proves a claimed 0.99 confidence is discarded and recomputed deterministically |
| Security classification correlation (no single-signal escalation) | **DONE** | 15 tests covering every documented anti-pattern (high CPU alone, one Event ID, etc.) |
| Channel identity trust model (never trust chat text for identity) | **DONE** | Slack/Google Chat/Teams all resolve identity only from an already-verified provider payload field, never message text |
| mTLS (endpoint transport identity) | **NOT STARTED** | Evaluated, deliberately deferred; bearer credential + signed envelopes are the current real defense-in-depth layer |
| Skill-manifest cryptographic signing | **NOT STARTED** | Integrity-hash only today (tamper-evident on direct DB edit, not independently signed) |
| Container/release signing (Sigstore/cosign) | **NOT STARTED** | SBOM generation exists in CI; image/release signing does not |
| Secret scanning (`gitleaks`, full history) | **DONE** | Green in CI |
| Dependency CVE scanning (`pip-audit`/`npm audit`) | **DONE** | Zero known CVEs as of `docs/DEPENDENCY_AUDIT.md`'s date; re-run, don't trust the number past that date |
| Container image scanning (`trivy`) | **DONE** | Fails CI on fixable CRITICAL/HIGH |
| API rate limiting | **PARTIAL** | Real, complete for the default single-API-process topology; needs a shared store (e.g. Redis) for a multi-replica deployment |
| Security headers / CSP | **DONE** | `hardening.py`, verified present on live responses in an earlier pass |
| `LICENSE` file | **NOT STARTED** | `pyproject.toml` declares `Apache-2.0`; no file exists. **Needs a human decision** (copyright holder name + year) — not something to invent |
| Independent third-party penetration test | **BLOCKED-EXTERNAL** | Requires engaging an external firm |

## P1 — Architecture

| Item | Status | Notes |
|---|---|---|
| Core trust chain (observe→detect→correlate→ticket→policy→approval→signed job→executor→verify→audit) | **DONE** | Enforced by real code at every step; re-verified via `test_e2e_smoke.py` |
| Knowledge schema (`IssueDefinition`/`DiagnosticWorkflow`/etc.) | **DONE** | 10 curated reference issues, structurally validated |
| Omnichannel Conversation Service (channel-agnostic) | **DONE** | One shared `handle_message` orchestration layer for all 4 channels |
| Slack channel adapter | **DONE** | Real HMAC verification + replay protection; outbound reply BLOCKED-EXTERNAL (needs a live bot token) |
| Google Chat channel adapter | **DONE** | Real Bearer-JWT verification; full loop including synchronous reply, no external dependency for the reply path |
| Microsoft Teams channel adapter | **DONE** | Milestone 28 — real Bot Framework Bearer-JWT verification; outbound reply BLOCKED-EXTERNAL |
| Live-provider verification for all 3 channels | **BLOCKED-EXTERNAL** | Each verified only against a locally generated keypair standing in for the real JWKS — none exercised against a live Slack/Google/Microsoft registration |
| Application Connector Framework (interface + registry) | **DONE** | `ApplicationConnector` Protocol enforced; self-service only, no "act on someone else's account" path |
| Mock connector (dev-safe, proves the pipeline) | **DONE** | Full chat→policy→step-up→connector→ticket→audit loop proven end to end |
| Real (non-mock) application connectors | **BLOCKED-EXTERNAL** | Need real per-application credentials (Entra ID/M365, Google Workspace, Okta, GitHub) |
| Known-good organizational baseline | **DONE** | Precedence rules tested against real Postgres RLS; not yet wired into a live remediation decision path |
| Action-preview/dry-run surface | **DONE** | Computed fresh from the live skill manifest every call; no frontend panel yet |

## P2 — Reliability

| Item | Status | Notes |
|---|---|---|
| Durable agent execution journal (crash recovery) | **DONE** | Unit/integration-tested; a genuinely killed-and-restarted agent process was verified manually in an earlier pass |
| Lease reaper (abandoned agent job claims) | **DONE** | Requeues or escalates; own liveness heartbeat |
| Connector-request reaper (stale approval sweep) | **DONE** | Marks `expired` past the configured staleness window |
| Retention worker (heartbeats/inventory/idempotency) | **DONE** | Deliberately never purges `audit_events` (hash-chain integrity) |
| Webhook outbox worker (retry/backoff/dead-letter) | **DONE** | Transactional outbox, bounded retry |
| Database migration reversibility | **DONE** | Real `alembic downgrade base` → `upgrade head` round trip verified against live Postgres in an earlier pass; this session's new migrations (0016-0018) each independently round-tripped too |
| Backup/restore | **DONE** | Real `pg_dump`/`pg_restore` cycle verified in an earlier pass: dumped, dropped, recreated, restored, confirmed RLS policies/restricted role survive, a real API process served `/health/ready` against the restored database |
| Automated recurring backup schedule | **NOT STARTED** | The *mechanism* is verified; no cron/scheduled job exists to run it automatically in production |

## P3 — Automation

| Item | Status | Notes |
|---|---|---|
| Automation-level (L0-L5) classification | **DONE** | Milestone 23 closed a real orchestrator/policy consistency gap (rollback gate now requires `reversible` too) |
| `service.restart` executor (both agents) | **DONE** | Verify+rollback; no shell, fixed argument vectors / direct Win32 SCM calls |
| `dns.flush_cache` executor (both agents) | **DONE** | Milestone 24 — Windows side live-verified on real hardware (`Win32DnsResolver().flush()` returned success) |
| High-CPU investigation evidence (process inventory) | **DONE** | Milestone 29 — read-only; Linux verified inside a real container against real `/proc`, Windows verified live |
| Disk cleanup remediation | **NOT STARTED** | Deliberately deferred — file-mutation risk needs its own dedicated safety design (safe target scoping, path-traversal defense), not batched with lower-risk work |
| Windows Update repair | **NOT STARTED** | Same reasoning — needs its own safety analysis |
| SSH auth-failure remediation | **NOT STARTED** | Correctly scoped as a security-response question (escalate to security team), not an auto-fix candidate |
| Unauthorized-software removal | **NOT STARTED** | Uninstallation is destructive-adjacent; deliberately deferred |
| High-CPU mitigation (kill/throttle a process) | **NOT STARTED** | Investigation (evidence) is done; mitigation is a distinct, higher-risk capability not yet built |
| Security-agent health repair | **DONE** | Already covered generically by `service.restart` against the agent's own service name |
| AI-assisted diagnosis (advisory-only) | **DONE** | Never auto-creates an `Action`; prompt-injection-resistant by construction |

## P4 — Integrations

| Item | Status | Notes |
|---|---|---|
| Slack / Google Chat / Microsoft Teams channels | **DONE** | See P1 — all three real; see BLOCKED-EXTERNAL rows there for live-registration/reply-sending gaps |
| Real application connectors (Entra ID, Google Workspace, Okta, GitHub) | **BLOCKED-EXTERNAL** | See P1 |
| Generic outbound webhook integrations (n8n, ticketing) | **DONE** | Signed HMAC deliveries, SSRF-safe, read-only consumers by design — cannot approve work or bypass policy |

## P5 — UI/UX

| Item | Status | Notes |
|---|---|---|
| Core operator console (Dashboard/Devices/Tickets/Incidents/Actions/Approvals/HelpDesk/Conversations/Applications/Skills/Reports/Audit/Integrations/Settings) | **DONE** | Functional, role-based control hiding, backend-authoritative authorization |
| OIDC login UI (Authorization Code + PKCE) | **DONE** | PKCE derivation verified against the published RFC 7636 test vector |
| Design-system modernization (dark mode, tokens, consistent spacing/typography) | **NOT STARTED** | Still the original functional-but-minimal design |
| Frontend route-level automated test coverage | **NOT STARTED** | Only the OIDC/PKCE login-flow logic is tested (`auth/oidc.test.ts`) |
| Frontend pagination UI | **NOT STARTED** | Backend already accepts `limit`/`offset` on every list endpoint; no pager control or `total`-count response shape yet |
| Accessibility audit | **NOT STARTED** | Not yet done at all |
| Confirmation dialogs for dangerous operations | **PARTIAL** | Backend requires explicit approval/step-up for anything dangerous; frontend-side confirm-before-submit UX has not been reviewed as its own design pass |

## P6 — Infrastructure

| Item | Status | Notes |
|---|---|---|
| Docker images (multi-stage, stripped build tooling) | **DONE** | Verified with real `trivy` scans before/after a base-image bump in an earlier pass |
| Docker Compose (hardened: `read_only`, `cap_drop: ALL`, `no-new-privileges`) | **DONE** | Every service; fresh-from-zero `docker compose up --build` independently re-verified |
| Database migrations | **DONE** | See P2 |
| Environment/secret configuration (`Settings.validate_security`) | **DONE** | Fails closed in production mode for every unconfigured/default secret |
| Health checks (`/health/live`, `/health/ready`) | **DONE** | Used by the `docker` CI job and Compose startup ordering alike |
| CORS | **DONE** | Configured via `Settings.cors_origins`, enforced |
| Terraform / other infrastructure-as-code | **NOT STARTED** | No `.tf` files or `terraform/` directory exist; only `docker compose` deployment exists today |
| Staging environment | **NOT STARTED** | No staging deployment target has been provisioned |
| Production secrets management (vault/KMS-backed) | **BLOCKED-EXTERNAL** | `.env`-file configuration is correct for the documented Compose path; a real managed-secrets integration needs a chosen target platform this environment can't provision |
| Container/release signing | **NOT STARTED** | See P0 |

## P7 — Operations

| Item | Status | Notes |
|---|---|---|
| Structured JSON logging with correlation ids | **DONE** | `logging_config.py`, confirmed live during a fresh-from-zero deployment |
| Prometheus `/metrics` | **DONE** | Real-time + scrape-time gauges recomputed from the database on every scrape |
| Background-worker liveness heartbeats | **DONE** | webhook worker, lease reaper, connector-request reaper, retention worker all upsert their own heartbeat every iteration |
| OpenTelemetry distributed tracing | **NOT STARTED** | Evaluated, deferred — no OTLP collector target chosen |
| Linux agent installer, end-to-end | **DONE** | Verified in a real systemd-in-Docker container: service account, venv, token self-enrollment, unit `active (running)`, clean uninstall |
| Windows agent installer, end-to-end | **BLOCKED-EXTERNAL** | Static validation only (`PSScriptAnalyzer`, 0 errors); needs a disposable Administrator-rights Windows host — the only Windows machine available in this environment is a real, non-disposable personal development machine, and running a system-service-installing script there unasked would be an inappropriate, unrequested modification, not merely a missing credential |
| Load/stress testing under adversarial concurrency | **NOT STARTED** | The rate limiter's logic is unit-tested, not load-tested |
| Recurring backup schedule | **NOT STARTED** | See P2 |
| This production readiness checklist | **DONE** | This document, created this pass; keep it updated in place going forward rather than creating a new one per milestone |

## Summary

No item above is FAIL-equivalent (a known critical/high security issue or
core functional failure) as of this date — see `docs/RELEASE_READINESS.md`
for the last formal PASS/FAIL release-gate verdict (v0.1.0-rc1, predates
Milestones 13-29 and is not re-run here). The honest overall state: the
core safety architecture (trust chain, tenant isolation, approval/
step-up/policy, signed jobs, audit) is genuinely production-grade and
verified. What stands between here and a real multi-org production
launch is almost entirely **either BLOCKED-EXTERNAL** (real credentials/
registrations/hosts this environment cannot obtain) **or NOT STARTED
work with no safety risk in leaving it unstarted** (UI modernization,
Terraform, tracing, container signing) — not a hidden defect in what
already exists.
