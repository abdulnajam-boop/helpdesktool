# Current architecture audit

Date: 2026-08-20. Audited: `main` at commit `87d6cc9` plus this pass's own
uncommitted work (Phase 2-5 safety foundations — see below). Every
classification here is checked against actual source, actual tests, or an
actual run performed this pass or a verified prior pass this session — not
guessed, and not carried forward from a stale prior document.

**Classification legend:** WORKING (real, tested, in production code
paths) · PARTIAL (real but with a named, bounded gap) · PLACEHOLDER
(interface/scaffold exists, behavior does not) · MISSING (not started) ·
UNSAFE (a real defect with security/safety consequence) · UNKNOWN (not
verifiable in this environment).

## 1. Architecture

**WORKING.** FastAPI control plane + PostgreSQL + Alembic + RLS + an
unprivileged Linux/Windows agent pair + a React operator console, exactly
as `CLAUDE.md` describes. The trust chain (`Observe → Detect → Correlate →
Ticket → Structured action proposal → Policy → Independent approval when
required → Device-bound signed job → Authenticated allowlisted agent
executor → Verify → Roll back/escalate → Audit`) is enforced by real code
at every step, not aspirational — see `helpdesktool/orchestrator.py`,
`policy.py`, `job_signing.py`, `agent_common/signing.py`. Re-verified this
pass via `tests/test_e2e_smoke.py` (extended in an earlier pass this
session to also cover signed-envelope verification, AI diagnosis, reports,
and metrics in one composite proof).

## 2. Windows agent

**WORKING** for collectors/executor/signed-envelope verification/durable
journal (`windows_agent/collectors.py`, `executor.py`,
`win32_service_manager.py`) — this pass additionally ran the registry
collectors and `Win32ServiceManager.query_state` for real against a
genuine Windows 11 host (`pywin32` present), not just against the fake
`ServiceManager` the unit suite uses. **PARTIAL** for the installer:
`deploy/install-windows-agent.ps1` is real (dedicated service account,
NTFS ACL lockdown, `NT SERVICE\HelpdeskWindowsAgent` — not `LocalSystem`)
and syntax-validated (`PSScriptAnalyzer`, zero errors, only stylistic
`Write-Host` warnings), but has never been run end-to-end (no disposable
Administrator-rights Windows host has been available in any pass —
running it on the only Windows machine in this environment, the
operator's own primary laptop, would create real unrequested system
state, so this stays a documented gap, not a shortcut taken).

## 3. Linux agent

**WORKING**, including the installer. `deploy/install-linux-agent.sh` was
run to completion in a real systemd-in-Docker container in an earlier
pass this session: dedicated `helpdesk-agent` system account, isolated
venv, token self-enrollment, `systemctl` unit `active (running)`, correct
file permissions, then a clean `deploy/uninstall-linux-agent.sh` run. No
installer-script changes since.

## 4. Backend/API

**WORKING.** `helpdesktool/api.py` is the single FastAPI app; every
mutating endpoint is role-gated (`require_roles`) and tenant-scoped. This
pass added the Phase 2 skill-safety-metadata surface
(`command_type`/`requires_user_approval`/`requires_admin_approval`/
`security_sensitive`/`reversible`/descriptive fields on `POST`/`GET
/v1/skills`) and the confidence-engine wiring in `diagnose_incident` —
both verified against real Postgres this pass (see §15).

## 5. Frontend/dashboard

**PARTIAL.** React/Vite SPA, one file per page under `frontend/src/pages/`
(14 pages as of this pass: Dashboard, Devices, Tickets, Incidents,
Actions, Approvals, Skills, Reports, Audit, Integrations, Settings,
HelpDesk/Conversations, Applications). Functional and tested (real
browser/Playwright runs this session caught and fixed a real bug — the
Reports page's infinite-fetch loop), but still the existing, minimal
design language (no dark mode, no design-token system, no
Overview/Users/Security/Analytics pages yet) — Phase 20's UI/UX
modernization is real, scoped, not-yet-started work, not a regression.

## 6. Database/data model

**WORKING.** 11 migrations (`0001`-`0011`), every one with a real,
tested `downgrade()`. RLS applied to every tenant-scoped table (20 as of
this pass); `tenants`/`skills`/`worker_heartbeats` are the only
deliberately unscoped, platform-wide tables. Migration reversibility
(`downgrade base` → `upgrade head` round trip) and a real `pg_dump`/
`pg_restore` cycle were both independently re-verified in the prior
release-candidate pass; this pass added migration `0010`
(connectors/conversations) and `0011` (skill safety metadata), both
freshly verified against real Postgres 17 in this pass specifically
(§15).

## 7. Ticket lifecycle

**WORKING.** `Ticket` create/update/resolve, linked to incidents and
actions; the conversation service (Milestone 11) now also creates tickets
from chat-originated issues. No knowledge-driven ticket enrichment yet
(Phase 1/5 knowledge schema — see §24).

## 8. Collectors

**WORKING** on both agents (`/proc`-based on Linux, `psutil`+`winreg`-based
on Windows) — see §2/§3.

## 9. Remediation skills

**WORKING**, now with real safety metadata (this pass). Exactly one
mutating skill exists (`service.restart`) plus one read-only
(`diagnostics.collect`) — deliberately narrow by design (`CLAUDE.md`: "no
generic disk-cleanup skill exists by design"). Phase 13's 5-10 reference
skills are real, scoped, not-yet-built work (see the maturity gap
analysis).

## 10. Security controls

**WORKING**, and materially strengthened this pass. Pre-existing: OIDC
(algorithm-confusion-resistant, adversarially tested), RLS, RBAC, signed/
versioned job envelopes, rate limiting, security headers/CSP, SSRF
defenses (a real redirect-following gap was found and fixed in the
prior release-candidate pass). **New this pass:** `PolicyEngine` now
hard-blocks any skill whose `command_type` is `DESTRUCTIVE`
unconditionally, independent of its risk tier — see `helpdesktool/
policy.py`'s module docstring and `tests/test_policy.py`'s
`test_destructive_command_type_is_refused_even_at_read_only_risk`.

## 11. Audit system

**WORKING.** Append-only, hash-chained (`helpdesktool/audit.py`), never
purged by the retention worker (deliberately). This pass added
`automation_level` to every `policy.evaluated` audit event and
`confidence_score`/`confidence_band`/`confidence_evidence_summary` to
every `incident.diagnosed` event — both verified present in a real audit
query against live Postgres this pass (§15).

## 12. Approvals

**WORKING.** Separation-of-duties (requester ≠ approver) enforced for
both `Action` approval and (Milestone 11) `ConnectorRequest` approval —
adversarially tested (`tests/test_adversarial_security.py`,
`tests/test_conversation.py`) for self-approval, re-decision, cross-tenant
forgery, and viewer-role escalation attempts.

## 13. Rollback

**WORKING** for the one skill that has a rollback pair
(`service.restart`/`service.restore`); the automation-level classifier
added this pass (`policy.automation_level_for`) treats "reversible with a
declared rollback skill" as a distinct, more-automatable state (L2) from
"no rollback story" (L1) — a real, structural use of that data, not just
a stored field.

## 14. AI/LLM

**WORKING**, and a real defect fixed this pass. Advisory-only by
construction (never auto-creates an `Action` — reconfirmed by a new
prompt-injection test in the prior pass). **The defect:**
`OpenAICompatibleProvider`'s prompt asked the model to invent its own
`confidence` number directly — precisely the anti-pattern Phase 5
prohibits. Fixed: the prompt no longer requests one, the parser discards
whatever a model returns anyway (`proposal.model_copy(update=
{"confidence": 0.0})`), and `api.py`'s `diagnose_incident` computes the
real score deterministically via the new `helpdesktool/confidence.py`
from actual incident evidence (recurrence, severity, telemetry
freshness). Proven with a hostile fake provider claiming 0.99 confidence
for a single low-severity incident and asserting the persisted/returned
score is nowhere near that (`tests/test_diagnosis_confidence.py`).

## 15. Tests

**WORKING.** 273 collected test cases as of this pass (up from 217 before
it), all passing except the 4 pre-existing Windows-platform-only failures
(POSIX file-permission/`/proc` assertions that pass on the real Linux CI
target — documented in `CLAUDE.md`) and one intermittent Windows-local-only
socket flake in `test_webhook_delivery_refuses_to_follow_a_redirect_to_a_private_address`
(a documented `WinError 10053` artifact, passes reliably on the real CI
platform). This pass's new coverage: `tests/test_confidence.py` (13
cases), `tests/test_security_classification.py` (15 cases), 9 new cases
in `tests/test_policy.py` (destructive-block + automation-level), 2 new
cases in `tests/test_ai_provider.py` (confidence discard), and
`tests/test_diagnosis_confidence.py` (1 case, the hostile-provider
integration proof). Full suite, `ruff`, `ruff format --check`, and `mypy
--strict` all verified clean both locally (SQLite) and in a real
`python:3.13` Linux container against real Postgres 17, including a fresh
`alembic upgrade head` from empty confirming the migration `0008`/`0011`
hash-consistency interaction documented in `0011`'s own module docstring
actually holds (not just reasoned about — a real `GET /v1/skills` and a
real `POST /v1/actions` against the freshly migrated database both
succeeded with no integrity-check failure).

## 16. CI/CD

**WORKING.** Four jobs (`backend`, `frontend`, `security`, `docker`), all
green on `main` as of the last verified commit. `security` runs
`gitleaks`/`pip-audit`/`npm audit`; `docker` builds and scans both images
with `trivy` and runs each for real. Unchanged this pass (no CI workflow
edits were needed).

## 17. Docker

**WORKING.** Multi-stage `Dockerfile` (strips build-only tooling from the
runtime image — a real CVE-reduction fix from the prior pass), `.dockerignore`
for both build contexts, `read_only`+`cap_drop: ALL`+`no-new-privileges`
on every compose service. A genuine fresh-from-zero `docker compose up
--build` (all 8 services, a brand-new Postgres volume) was independently
re-verified in the prior release-candidate pass.

## 18. Configuration

**WORKING.** `pydantic-settings`-based `Settings`, `validate_security()`
fails closed in production mode for every unconfigured/default secret —
including `job_signing_seed`, added earlier this session and covered by
`tests/test_config.py`.

## 19. Authentication/authorization

**WORKING.** OIDC in production (algorithm-confusion attacks — `alg:
none` and RS256→HS256 key confusion — both adversarially tested with
hand-forged tokens, not library-generated ones, so the test can't pass
for the wrong reason); insecure header auth and dev login both fail
closed outside `environment == "development"`.

## 20. Multi-tenant boundaries

**WORKING.** RLS at the database layer plus application-level tenant
filtering as an independent second layer — adversarially tested
(`tests/test_tenant_isolation_postgres.py`,
`tests/test_auth_tenant_isolation_api_postgres.py`,
`tests/test_adversarial_security.py`'s cross-tenant action-decision and
job-claim forgery tests, and Milestone 11's cross-tenant connector-request
test). This pass's four new database tables (`0010`/`0011` didn't add
tables, `0010` did: `application_connectors`, `conversations`,
`conversation_messages`, `connector_requests`) all carry the same
`tenant_isolation` RLS policy, confirmed via `pg_policies` against real
Postgres in the Milestone 11 pass.

## 21. Omnichannel/conversation system

**PARTIAL**, exactly as documented in `docs/IMPLEMENTATION_PLAN.md`
Milestone 11. **Working:** the shared Conversation Service
(`helpdesktool/conversation.py`), deterministic intent classification,
policy-gated connector requests, the web channel adapter end to end
(chat → identity → intent → policy → pending approval → independent
admin approves → mock connector executes → verified → ticket → audit →
response), proven via 15 backend tests plus a real browser run.
**Missing:** Slack, Microsoft Teams, and Google Chat channel adapters —
no external SDK has been chosen or vendored (Phase 18 continuation work,
not started this pass; the Conversation Service is already
channel-agnostic, so adding a channel is additive, not a rearchitecture).

## 22. Identity resolution

**WORKING** for its actual scope: `helpdesktool/identity_resolution.py`
maps an already-authenticated channel identity to a Helpdesktool `User`
by exact email match within a tenant, never from unverified chat message
text. The web channel's identity is its own authenticated session; a
future Slack/Teams/Google Chat adapter resolves its own signature-verified
provider identity through the same function — the function itself needs
no changes to support that, only a caller.

## 23. Application connectors

**PARTIAL.** `helpdesktool/connectors/`'s `ApplicationConnector` Protocol
(`resolve_user`/`check_account`/`reset_password`/`unlock_account`/
`reset_mfa`/`check_permissions`/`verify_result`) is real and enforced —
high-risk operations always require independent approval, self-service
only (no "reset someone else's password" path exists). `connectors/
mock.py` is a real, working, dev-safe implementation proving the whole
pipeline. **Missing:** every real (non-mock) connector — Entra ID/M365,
Google Workspace, Okta, Salesforce, GitHub, generic REST — none of which
can be built without real per-application credentials this environment
doesn't have (Phase 19, BLOCKED-EXTERNAL for the credential-dependent
parts, though the connector *interface* is ready for one to register the
moment credentials exist).

## 24. Knowledge functionality

**MISSING.** Phase 1's `IssueDefinition`/`Detector`/`EvidenceRequirement`/
`DiagnosticWorkflow`/`DiagnosticStep`/`VerificationTest`/`EscalationPolicy`/
`KnowledgeSource`/`MITREMapping`/`CVEReference`/`OperatingSystemConstraint`/
`SoftwareVersionConstraint`/`CommandDefinition` schema does not exist yet.
Today's single detector (`helpdesktool/incidents.py`'s low-disk rule) is
hardcoded Python, not data-driven knowledge — real, substantial,
correctly-scoped-as-not-yet-started work; see the maturity gap analysis
for why this was sequenced after the Phase 2-5 safety foundations rather
than before them (a data-driven knowledge system that feeds into an
execution pipeline without the safety metadata/automation-level/security-
classification/confidence primitives in place first would have nothing
correct to plug into).

## 25. Existing simulation/dry-run functionality

**WORKING**, in the sense that already matters: AI diagnosis
(`POST /v1/incidents/{id}/diagnose`) is *unconditionally* simulation —
it can never, by any code path, auto-create an `Action` (re-proven this
pass via the hostile-provider test in §14/§15). Explicit dry-run *preview*
of what a specific skill execution *would* do (Phase 14's fuller spec —
showing the exact planned action/verification/rollback/ticket changes
before an operator approves) does not exist as a separate mode; today an
operator sees the same information by inspecting a `pending_approval`
`Action`'s manifest before deciding. Phase 14's stated requirement that
"newly imported or newly generated remediation knowledge must default to
simulation-only until explicitly approved for execution" has no knowledge
*import* pathway yet to apply that default to (§24) — real gap, correctly
attributed to the knowledge system's absence rather than this module.

---

## Summary table

| # | Area | Status |
|---|---|---|
| 1 | Architecture | WORKING |
| 2 | Windows agent | WORKING (installer script PARTIAL — static-validated only) |
| 3 | Linux agent | WORKING |
| 4 | Backend/API | WORKING |
| 5 | Frontend/dashboard | PARTIAL (functional, design modernization not started) |
| 6 | Database/data model | WORKING |
| 7 | Ticket lifecycle | WORKING |
| 8 | Collectors | WORKING |
| 9 | Remediation skills | WORKING (narrow by design; reference-skill expansion not started) |
| 10 | Security controls | WORKING |
| 11 | Audit system | WORKING |
| 12 | Approvals | WORKING |
| 13 | Rollback | WORKING (for the one skill with a rollback pair) |
| 14 | AI/LLM | WORKING (a real confidence-invention defect found and fixed this pass) |
| 15 | Tests | WORKING |
| 16 | CI/CD | WORKING |
| 17 | Docker | WORKING |
| 18 | Configuration | WORKING |
| 19 | Authentication/authorization | WORKING |
| 20 | Multi-tenant boundaries | WORKING |
| 21 | Omnichannel/conversation system | PARTIAL (web channel only; Slack/Teams/Google Chat missing) |
| 22 | Identity resolution | WORKING (for its actual scope) |
| 23 | Application connectors | PARTIAL (framework + mock working; real connectors BLOCKED-EXTERNAL) |
| 24 | Knowledge functionality | MISSING |
| 25 | Simulation/dry-run | WORKING (diagnosis); PARTIAL (no standalone execution-preview mode) |

No area is classified UNSAFE as of this pass — the one defect found
(AI-invented confidence) has been fixed and verified, not merely flagged.
See `docs/HELPDESK_MATURITY_GAP_ANALYSIS.md` for prioritized next work and
`docs/IMPLEMENTATION_PLAN.md` for the full milestone history this audit
builds on.
