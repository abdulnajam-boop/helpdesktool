# Helpdesk maturity gap analysis

Date: 2026-08-20. Builds on `docs/CURRENT_ARCHITECTURE_AUDIT.md` (what was
checked and how) and preserves, rather than replaces,
`docs/IMPLEMENTATION_PLAN.md`'s milestone history. This document is the
forward-looking prioritized backlog; `IMPLEMENTATION_PLAN.md` remains the
authoritative record of what was actually built, when, and how it was
verified.

Priority tiers, per the governing mandate:

- **P0 — Security/safety.** A gap here is a real or potential safety
  defect, not a missing feature.
- **P1 — Architectural foundations.** Structural work everything else
  depends on.
- **P2 — Endpoint reliability.** Agent/execution robustness.
- **P3 — Automation.** Expanding what runs safely without a human.
- **P4 — Knowledge expansion.** More issue types, more channels, more
  connectors.
- **P5 — Optimization.** Polish, UX, performance.

## P0 — Security/safety

| Gap | Status |
|---|---|
| AI-invented confidence numbers | **CLOSED this pass** — `helpdesktool/confidence.py`, wired into `diagnose_incident`, proven against a hostile fake provider (`tests/test_diagnosis_confidence.py`). |
| Destructive actions executing autonomously | **CLOSED this pass** — `PolicyEngine` hard-blocks `CommandType.DESTRUCTIVE` unconditionally, independent of risk tier. No destructive skill is registered today; the block exists so one registered in the future can never bypass it via a risk-tier misconfiguration alone. |
| Security classification conflated with automation level | **CLOSED this pass** — `helpdesktool/models.py`'s `SecurityClassification`/`AutomationLevel` are separate enums; `helpdesktool/security_classification.py`'s correlation rule (2+ distinct evidence categories required) and `policy.automation_level_for`'s skill-property-only logic are independently testable and tested. |
| Single-signal malicious classification (high CPU, PowerShell, one Event ID, etc.) | **CLOSED this pass** — `classify_security_state` structurally requires cross-category correlation; 15 tests in `tests/test_security_classification.py` cover every example the mandate names explicitly. |
| `CONFIRMED_COMPROMISE` reachable from signal accumulation alone | **CLOSED this pass** — only reachable via an explicit `confirmed_by_authoritative_source` flag this module never sets itself. |
| MITRE ATT&CK technique treated as proof rather than metadata | **CLOSED** — `security_classification.py`'s design already treated any single signal as insufficient alone; the dedicated `MitreMapping` schema (`helpdesktool/knowledge.py`, `mapping_confidence`/`mapping_evidence` fields, Milestone 13) now exists and is exercised by 3 of the 10 Milestone 14 reference issues, each with deliberately moderate confidence and explicit "metadata, not proof" evidence text. |
| Knowledge/research text becoming directly executable | **STRUCTURALLY CLOSED, NOW ACTUALLY EXERCISED (not just absent).** The knowledge schema now exists (Milestone 13) and holds real content (Milestone 14's 10 reference issues) — `validate_remediation_skill_references` is the concrete enforcement: a `DiagnosticStep.remediation_skill_id` must already be a real, registered skill or registration fails closed (422), proven by both a unit test and a live-Postgres API call rejecting a fake skill id. Still true: no code path anywhere turns arbitrary text (a ticket, a chat message, a CVE description) into anything that resolves a `remediation_skill_id` automatically — that would be the actual knowledge-ingestion pipeline (P4), still not built. |
| Windows agent installer never run end-to-end | **BLOCKED-EXTERNAL** — needs a disposable Administrator-rights Windows host; see the architecture audit's §2. |
| Real (non-mock) application connectors | **BLOCKED-EXTERNAL** — needs real per-application credentials (Entra ID, Google Workspace, Okta, Salesforce, GitHub). |
| Account-recovery step-up verification (never authorize a password reset from a name/email/employee ID typed into chat) | **CLOSED this pass (Milestone 26)** — `conversation.py`'s existing separation-of-duties rule (an approver other than the requester) is real but was not, on its own, proof the requester is who the channel claims: an approver could still approve blind off nothing but the original channel-native identity link. Migration `0018` adds a short-lived, single-use, hashed step-up code (`ConnectorRequest.step_up_code_hash`, mirroring `EnrollmentToken.token_hash`'s exact pattern) the requester must retrieve through a *separate, independently authenticated* call (`GET /v1/connector-requests/{id}/step-up-code`) and hand to their approver out of band — reaching that endpoint at all requires an authenticated session distinct from whatever chat message created the request. `POST /v1/connector-requests/{id}/decision` refuses to approve (never "deny", which executes nothing) without the correct, unexpired code — fails closed on missing/wrong/expired in every case, proven by 8 new tests (`tests/test_connector_step_up.py`). |

## P1 — Architectural foundations

| Gap | Priority rationale |
|---|---|
| Knowledge schema (`IssueDefinition`/`EvidenceRequirement`/`DiagnosticWorkflow`/`DiagnosticStep`/`EscalationPolicy`/`KnowledgeSource`/`MitreMapping`/`CveReference`) | **CLOSED** — `helpdesktool/knowledge.py` (Milestone 13), populated with 10 curated reference issues (Milestone 14). Not modeled as separate schema types (folded into the shapes above instead, which cover the same ground more simply): `Detector`/`VerificationTest`/`OperatingSystemConstraint`/`SoftwareVersionConstraint`/`CommandDefinition` — a `DiagnosticStep`'s `step_type`/`verification_description`/`applicable_os` on `IssueDefinition` already cover what those would have. |
| Action-preview / dry-run execution surface (Phase 14, beyond diagnosis) | **CLOSED** — see P3 below (`action_preview.py`). |
| Idempotency/loop prevention for the connector-request pipeline (Phase 8) | **CLOSED** — see P2 below (`connector_request_reaper.py`). |
| Slack/Teams/Google Chat channel adapters | **ALL THREE DONE.** `helpdesktool/channels/slack.py` (Milestone 17) — real request-signature verification, replay protection, per-tenant workspace/identity link tables, `POST /v1/channels/slack/events/{link_id}` wired into `handle_message`; outbound reply is BLOCKED-EXTERNAL (needs a live Slack bot token). `helpdesktool/channels/google_chat.py` (Milestone 25) — real Bearer-ID-token verification reusing `oidc.py`'s `OIDCVerifier` unchanged, `POST /v1/channels/google-chat/events/{link_id}`, and a **synchronous reply that is not BLOCKED-EXTERNAL** (Google Chat's HTTP contract lets an app reply in the same response). `helpdesktool/channels/teams.py` (Milestone 28) — real Bot Framework JWT verification via a dedicated `pyjwt`/`PyJWKClient` verifier (not `OIDCVerifier` reuse, since a Bot Framework connector-service token's claim set is less certain than a human OIDC login token's — deliberately doesn't require a `sub` claim it can't be sure exists), issuer/audience/JWKS checks plus the documented conditional `serviceUrl` claim match, `POST /v1/channels/teams/events/{link_id}`; outbound reply is BLOCKED-EXTERNAL (needs a real Azure AD client secret). All three verified only against a locally generated keypair standing in for each provider's real JWKS — none has been exercised against a live registration. `ChannelWorkspaceLink`/`ChannelIdentityLink` needed no new migration for any of the three — the `channel` column was always a plain string. |
| Known-good organizational state (Phase 6) | **CLOSED** — `helpdesktool/baseline.py`'s `BaselineEntry`/`resolve_known_good`, `organizational_baselines` table (migration `0014`, tenant-scoped/RLS-protected), `/v1/baselines` + `/v1/baselines/resolve` API. Precedence: device_baseline > user_baseline > organizational_policy > generic_best_practice; `current_state` is never itself a valid resolution. Verified against real Postgres RLS: tenant A's baseline is invisible to tenant B's `resolve` call. Not yet wired into any live diagnosis/remediation code path — same "ship as inert, reviewable data first" pattern as the Milestone 13 knowledge schema. |

## P2 — Endpoint reliability

| Gap | Status |
|---|---|
| Durable execution journal crash recovery | Unit/integration-tested (`tests/test_execution_journal.py`); a genuinely killed-and-restarted agent process was verified manually in an earlier session pass, not repeated this pass (no code changed there). Real future work: an automated (not manual) crash-recovery test harness. |
| Idempotency/loop prevention for the *new* connector-request pipeline | **CLOSED** — `helpdesktool/connector_request_reaper.py` (`helpdesk-connector-request-reaper` entry point/Compose service) sweeps `ConnectorRequest` rows stuck `pending_approval` past `Settings.connector_request_stale_after_hours` (default 24h) and marks them `expired` with an audit event. Not a claim/lease recovery like `lease_reaper` (a connector request has no agent claim step to lose) — a staleness sweep on "no approver ever decided," with no auto-retry (a still-wanted request is resubmitted by a human). |
| mTLS / certificate lifecycle | Evaluated and deliberately deferred in an earlier pass (documented reasoning in `IMPLEMENTATION_PLAN.md`); unchanged this pass. |
| Job-signing key rotation (`job_signing.py`'s previously-documented limitation) | **CLOSED this pass (Milestone 27)** — bumping `Settings.job_signing_key_version` alone (a config change, no new secret, no code deploy) now derives a genuinely different Ed25519 keypair from the same seed; `active_public_keys` exposes a trailing window of still-trusted versions, and both agents' `ensure_signing_key` refreshes its locally-trusted set every cycle, only ever adding new versions, never overwriting an already-pinned one. Verified end-to-end via a real API test that rotates the version mid-test and confirms both the pre- and post-rotation envelopes still verify (`tests/test_job_envelope_api.py::test_signing_key_rotation_keeps_the_old_version_verifiable`), plus against a real disposable Postgres container. A full break-glass rotation invalidating every version at once still requires changing `job_signing_seed` itself — a separate, heavier, deliberately distinct action. |

## P3 — Automation

| Gap | Status |
|---|---|
| Automation-level (L0-L5) enforcement beyond classification | **Mostly re-scoped after closer inspection (Milestone 23), one real inconsistency found and fixed.** `orchestrator.py`'s `_run` already unconditionally verifies every execution and already gates the rollback attempt on the skill's own `rollback_skill_id` — which, for L1 skills, is `None` by construction (see `automation_level_for`), so L1 already never gets an automatic rollback attempt; always verifying (even for L1) is strictly safer, not a gap to "fix" by skipping it. The one real bug: `_run`'s rollback gate checked only `rollback_skill_id`, not `reversible` — so a manifest inconsistently declaring `reversible=False` while still carrying a `rollback_skill_id` label would have gotten an automatic rollback attempt anyway, disagreeing with the `automation_level` already recorded on the same `policy.evaluated` audit event. Fixed to require both, matching `automation_level_for`'s L2 condition exactly; proven by a new test (`test_failed_verification_does_not_roll_back_a_skill_marked_not_reversible`). |
| Reference skills content (Phase 13) | **Knowledge content DONE; a second executor now real (Milestone 24).** All 10 issues the mandate proposes (Windows/Linux disk space, Windows/Linux service failure, Windows Update, DNS resolution, SSH auth, high CPU, unauthorized software, security-agent health) exist as real `IssueDefinition`/`DiagnosticWorkflow` records (Milestone 14). Two mutating skills now exist with real, deterministic, allowlisted executors on *both* agents: `service.restart` (since Milestone 4/5) and `dns.flush_cache` (Milestone 24 — `linux_agent`'s `resolvectl flush-caches`, `windows_agent`'s Win32 `DnsFlushResolverCache` via `ctypes`, no shell in either). Migration 0016 registers the skill; migration 0017 rewires the `dns_resolution_failure` workflow's final step from `escalate` to a real `remediate` step referencing it, without weakening the workflow's own DNS-misconfiguration judgment (it still escalates whenever configured servers deviate from baseline, or resolution still fails after the flush). 4 of the 10 workflows now have a real `remediate` step; the rest correctly terminate in `escalate`, per `validate_remediation_skill_references`'s core invariant. Verified against a real disposable Postgres container, not just SQLite: `alembic upgrade head`/`downgrade -1`/`upgrade head` round-tripped cleanly and produced exactly the intended skill row and 5-step workflow; `Win32DnsResolver().flush()` was also called live on a real Windows host in this pass and returned success. Building executors for the remaining 6 issues (disk cleanup, Windows Update, SSH auth remediation, unauthorized-software removal, high-CPU mitigation, security-agent repair) is separate, real future work — each needs its own safety analysis, not a batch add. **High-CPU investigation's evidence gap closed this pass (Milestone 29):** the `high_cpu_usage` issue's own `collect_evidence` step already described wanting "top_processes_by_memory/process inventory," but no collector produced it — `linux_agent` had no process inventory at all, and `windows_agent`'s only sorted by memory. Both agents now sample real per-process CPU usage (Linux: a second `/proc/<pid>/stat` delta reading, the same technique `cpu_inventory` already uses for the aggregate figure; Windows: psutil's documented prime-then-resample pattern) and expose `top_processes_by_cpu` alongside the existing memory ranking — read-only, no new mutating capability, evaluated and deliberately NOT extended to kill/throttle a process (that remains its own, separate, higher-risk safety analysis, correctly still ending in `escalate`). |
| Simulation/dry-run *execution preview* mode (Phase 14, beyond diagnosis) | **DONE** — `helpdesktool/action_preview.py` + `GET /v1/actions/{id}/preview`. Computed fresh from the current active skill manifest every call (never a stale cache); returns what would execute, the verification plan, the rollback plan, policy allowed/approval-required, and the automation level — all templated from real stored manifest fields, never free-form text. No frontend panel for it yet (API-only, same gap diagnosis had before its own frontend panel). |

## P4 — Knowledge expansion

| Gap | Status |
|---|---|
| Real (non-mock) application connectors | BLOCKED-EXTERNAL (credentials). |
| Slack/Teams/Google Chat adapters | All three done (see P1). |
| Knowledge provenance tracking (Phase 12) | **Schema/tracking DONE, automated ingestion NOT.** `KnowledgeSourceRow` (source_organization/source_url/retrieval_date/last_verified_date/source_reliability/deprecated/superseded_by, Milestone 13) exists and is populated (Milestone 14's 10 reference issues are honestly attributed to a single internal `KnowledgeSource`, not a fabricated external citation). What's still genuinely missing: an automated pipeline that fetches/parses real external knowledge sources (a CVE feed, a vendor KB) and proposes new `IssueDefinition` records for human review — today every knowledge record is hand-authored. |
| MITRE/CVE mapping tables | **DONE** — `MitreMapping`/`CveReference` in `helpdesktool/knowledge.py` (Milestone 13), both structurally validated (technique-id/CVE-id regex) and exercised by real reference content (Milestone 14). |

## P5 — Optimization

| Gap | Status |
|---|---|
| Full UI/UX modernization (Phase 20) | Not started; functional but not yet the target design system. |
| OpenTelemetry tracing | Evaluated, deliberately deferred (documented in an earlier pass). |
| Terraform / staging / production deployment | Not started; current deployment story is `docker compose`, independently verified fresh-from-zero in an earlier pass. |
| SBOM / release signing | **SBOM generation DONE.** CI's `security` job generates a real CycloneDX SBOM for both the backend (`pip-audit --format=cyclonedx-json`) and frontend (`npm sbom --sbom-format=cyclonedx`) on every push/PR, uploaded as a 90-day build artifact (`sbom-<commit-sha>`) — not a committed file, since an SBOM goes stale the moment dependencies change. **Container image publishing + keyless signing now real (Milestone 31)** — the `docker` job's already-scanned, already-smoke-tested images are pushed to GHCR and `cosign`-signed (Sigstore Fulcio/Rekor via the job's own GitHub Actions OIDC token, no new secret) on every `main` push, with an in-job `cosign verify` round-trip. Signed release archives (as opposed to container images) are still not started. |
| Dependency/provenance audit (`docs/DEPENDENCY_AUDIT.md` etc.) | **DONE** — `docs/DEPENDENCY_AUDIT.md`, `docs/THIRD_PARTY_LICENSES.md`, `docs/SOFTWARE_PROVENANCE.md`. Zero known CVEs in any declared dependency (`pip-audit`/`npm audit` both clean, matching CI); `psycopg`'s LGPL-3.0 license flagged explicitly (the one non-permissive dependency); no runtime remote-code-execution path found anywhere (checked directly, not assumed). **Real gap surfaced, not fixed:** `pyproject.toml` declares `license = "Apache-2.0"` but no `LICENSE` file exists at the repo root — deliberately not auto-created (needs a real copyright holder name/year, the repo owner's call) — flagged for a human decision, per the mandate's own stop condition for genuine license issues. |

## What changed in the Milestone 12 pass, in priority order (historical)

1. (P0) Fixed AI-invented confidence — a real defect, not a hardening
   exercise; an operator trusting a diagnosis's confidence field before
   this pass was trusting a number an LLM made up.
2. (P0) Added the destructive-action hard block, security classification
   correlation rule, and automation-level classification — none of these
   existed as distinct concepts before this pass (risk tier alone
   conflated all three).
3. (P0/P1) Extended the skill registry with real safety metadata rather
   than building a parallel "action" system — the mandate's own
   instruction to extend, not duplicate, existing architecture.
4. (P0) Verified all of the above against real Postgres, not just SQLite
   — including the subtle migration `0008`/`0011` hash-consistency
   interaction, which was reasoned about *and* empirically proven via a
   real `alembic upgrade head` and real API calls against the freshly
   migrated database.

## What changed in Milestones 13-21 (this document's current refresh)

The table rows above have been updated in place to reflect all of the
following as actually built — `docs/IMPLEMENTATION_PLAN.md` has the full
detail for each; this is the summary that keeps this backlog document
itself from going stale relative to it:

- (P1) The knowledge schema (Milestone 13) and 10 curated reference
  issues exercising it (Milestone 14), including real MITRE/CVE mapping
  and knowledge-source provenance — closing three P1/P4 rows at once.
- (P1) Known-good organizational state / Phase 6 (Milestone 15), verified
  against real Postgres RLS.
- (P2) Connector-request idempotency (Milestone 16) — the fifth
  documented `rls_bypass` call site.
- (P1) The Slack channel adapter (Milestone 17) — real signature
  verification and replay protection, plus two genuine bugs (an
  idempotency truthy-check, and a real-RLS-only tenant-context bug) found
  and fixed via the same "verify against real Postgres" discipline that
  caught Milestone 12's migration hash issue.
- (P5) Dependency/license/provenance audit (Milestone 18) and SBOM
  generation in CI (Milestone 21) — including one genuine unresolved gap
  surfaced for a human decision (no `LICENSE` file despite a declared
  license) and one real would-have-broken-CI issue caught before merge.
- (Phase 16 adversarial coverage) A knowledge-registry tamper test
  (Milestone 19), mirroring the skill registry's own precedent.
- (P3) The action-preview/dry-run execution surface (Milestone 20),
  closing the diagnosis-only half of Phase 14's simulation-mode
  requirement.

## What changed in Milestones 22-31

- (docs) Refreshed this document against Milestones 13-21 (Milestone 22);
  no code changes.
- (P3) Fixed a real orchestrator/policy consistency gap: the rollback gate
  now requires `reversible` in addition to `rollback_skill_id`, matching
  `automation_level_for`'s L2 condition exactly (Milestone 23).
- (P3/P2) **First new genuinely executable reference skill since
  `service.restart`: `dns.flush_cache` (Milestone 24)**, directly
  answering the mandate's "implement and safely test the real
  Windows/Linux executors for the existing reference skills — do not
  merely add more manifests" instruction. Real, deterministic,
  no-shell executors on both agents (`linux_agent`'s `resolvectl
  flush-caches`, `windows_agent`'s Win32 `DnsFlushResolverCache` via
  `ctypes`), dispatched by a new `_executor_for` lookup on each agent
  rather than a single hardcoded executor. Registered via migration 0016
  (L1 automation level: low risk, no rollback story, honestly declared).
  Migration 0017 wires it into the existing `dns_resolution_failure`
  knowledge workflow as a real `remediate` step, without loosening the
  workflow's own judgment about actual DNS misconfiguration (still
  escalates in that case). Verified against a real disposable Postgres
  container (`alembic upgrade head`/`downgrade -1`/`upgrade head`
  round-tripped cleanly) and, unusually for this codebase's Windows-only
  pieces, against a real Windows host directly (`Win32DnsResolver().flush()`
  called live, returned success) — not merely reasoned about.
- (P1/P4) **Second omnichannel adapter: Google Chat (Milestone 25)**,
  reusing `oidc.py`'s `OIDCVerifier` unchanged rather than writing a
  second JWT/JWKS implementation — Google Chat's inbound Bearer token is
  a standard RS256 JWT against a published JWKS, so verifying it is a
  configuration change (issuer/JWKS/audience), the same "swap providers,
  not code" property `oidc.py` already gives human OIDC login. The first
  channel adapter whose reply is not BLOCKED-EXTERNAL: Google Chat's HTTP
  contract supports a synchronous JSON reply in the same response, so the
  full identity → conversation → ticket → reply loop is real end-to-end
  here, unlike Slack's still-BLOCKED-EXTERNAL bot-token reply path.
  `ChannelWorkspaceLink`/`ChannelIdentityLink` needed no new migration —
  their `channel` column was already a plain string, not a Slack-specific
  enum.
- (P0) **Account-recovery step-up verification (Milestone 26)** — closes
  the mandate's explicit safety directive on never authorizing a
  credential-affecting operation from a chat-native identity claim alone.
  A short-lived, single-use, hashed step-up code the requester must
  retrieve through a separate authenticated call now gates approval of
  every high-risk connector request, on top of the pre-existing
  separation-of-duties rule (an approver other than the requester) —
  neither alone was sufficient; both are now required.
- (P2) **Job-signing key rotation (Milestone 27)** — closes the
  `job_signing.py`-documented limitation directly. Rotation is now a
  config change (bump `Settings.job_signing_key_version`), not a new
  secret or a code deploy; both agents automatically pick up a rotated
  key within one heartbeat interval via a refreshed trailing window of
  trusted versions, never losing trust in an already-pinned one. Verified
  end-to-end, not just reasoned about: a real API test rotates the
  version mid-test and proves both the old and new envelopes still
  verify.
- (P1) **Third and final planned omnichannel adapter: Microsoft Teams
  (Milestone 28)**, via the Bot Framework Connector Service. A dedicated
  verifier (not `OIDCVerifier` reuse) checks signature/issuer/audience/
  expiry plus the documented conditional `serviceUrl` claim match,
  deliberately not requiring a `sub` claim the connector-service token
  type isn't certain to carry. Same never-trust-message-text identity
  model as Slack/Google Chat: the real Teams user comes from the
  already-verified Activity's `from.aadObjectId`. No new migration --
  `ChannelWorkspaceLink.workspace_id` stores the Microsoft 365/Azure AD
  tenant id (the multi-tenant discriminator) while the bot's single
  platform-wide App ID lives in `Settings.teams_bot_app_id` (the JWT
  audience, fixed regardless of which customer tenant is calling).
  Outbound reply is BLOCKED-EXTERNAL, same as Slack.
- (P3) **High-CPU investigation evidence gap closed (Milestone 29)** —
  read-only process-level CPU sampling on both agents (`top_processes_by_
  cpu`), closing the gap between the `high_cpu_usage` reference issue's
  stated evidence need and actual collector output. No new mutating
  capability; killing/throttling a process remains its own, deliberately
  separate, higher-risk safety analysis, correctly still `escalate`-only.
  A `tests/test_windows_collectors.py` file now exists (none did before);
  the Linux addition was verified for real inside a genuine
  `python:3.12-slim` container against real `/proc`, and the Windows
  addition was verified live on a real Windows host in this same pass.
- (docs) New `docs/PRODUCTION_READINESS_CHECKLIST.md` (Milestone 30) — a
  living P0 Security-through-P7 Operations checklist, a genuinely
  different axis from this document's own P0-P5. No code changes.
- (P5) **Container image publishing + keyless signing (Milestone 31)** —
  the `docker` CI job now pushes its already-scanned, already-smoke-tested
  images to GHCR and `cosign`-signs them (Sigstore Fulcio/Rekor via the
  job's own GitHub Actions OIDC token, no new secret to generate or
  store) on every `main` push, with an in-job `cosign verify` round-trip
  rather than trusting `cosign sign`'s exit code alone. Explicitly asked
  the user first, since this publishes real, persistent, publicly-visible
  artifacts under their account — not an internal-only change.

Continuing into the next highest-priority item per the mandate's explicit
instruction not to stop between phases.
