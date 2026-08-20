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

## P1 — Architectural foundations

| Gap | Priority rationale |
|---|---|
| Knowledge schema (`IssueDefinition`/`EvidenceRequirement`/`DiagnosticWorkflow`/`DiagnosticStep`/`EscalationPolicy`/`KnowledgeSource`/`MitreMapping`/`CveReference`) | **CLOSED** — `helpdesktool/knowledge.py` (Milestone 13), populated with 10 curated reference issues (Milestone 14). Not modeled as separate schema types (folded into the shapes above instead, which cover the same ground more simply): `Detector`/`VerificationTest`/`OperatingSystemConstraint`/`SoftwareVersionConstraint`/`CommandDefinition` — a `DiagnosticStep`'s `step_type`/`verification_description`/`applicable_os` on `IssueDefinition` already cover what those would have. |
| Action-preview / dry-run execution surface (Phase 14, beyond diagnosis) | **CLOSED** — see P3 below (`action_preview.py`). |
| Idempotency/loop prevention for the connector-request pipeline (Phase 8) | **CLOSED** — see P2 below (`connector_request_reaper.py`). |
| Slack/Teams/Google Chat channel adapters | **Slack DONE this pass** (`helpdesktool/channels/slack.py`, no SDK dependency — stdlib `hmac` only) — real request-signature verification, replay protection, per-tenant workspace/identity link tables, and a live `POST /v1/channels/slack/events/{link_id}` wired into the existing `handle_message`. Outbound reply-sending is BLOCKED-EXTERNAL (needs a live Slack bot token — see `channels/slack.py`'s `SlackReplySender`/`NullSlackReplySender`). Teams/Google Chat are not started — same additive shape, blocked on SDK choice/vendoring, not infrastructure. |
| Known-good organizational state (Phase 6) | **CLOSED** — `helpdesktool/baseline.py`'s `BaselineEntry`/`resolve_known_good`, `organizational_baselines` table (migration `0014`, tenant-scoped/RLS-protected), `/v1/baselines` + `/v1/baselines/resolve` API. Precedence: device_baseline > user_baseline > organizational_policy > generic_best_practice; `current_state` is never itself a valid resolution. Verified against real Postgres RLS: tenant A's baseline is invisible to tenant B's `resolve` call. Not yet wired into any live diagnosis/remediation code path — same "ship as inert, reviewable data first" pattern as the Milestone 13 knowledge schema. |

## P2 — Endpoint reliability

| Gap | Status |
|---|---|
| Durable execution journal crash recovery | Unit/integration-tested (`tests/test_execution_journal.py`); a genuinely killed-and-restarted agent process was verified manually in an earlier session pass, not repeated this pass (no code changed there). Real future work: an automated (not manual) crash-recovery test harness. |
| Idempotency/loop prevention for the *new* connector-request pipeline | **CLOSED** — `helpdesktool/connector_request_reaper.py` (`helpdesk-connector-request-reaper` entry point/Compose service) sweeps `ConnectorRequest` rows stuck `pending_approval` past `Settings.connector_request_stale_after_hours` (default 24h) and marks them `expired` with an audit event. Not a claim/lease recovery like `lease_reaper` (a connector request has no agent claim step to lose) — a staleness sweep on "no approver ever decided," with no auto-retry (a still-wanted request is resubmitted by a human). |
| mTLS / certificate lifecycle | Evaluated and deliberately deferred in an earlier pass (documented reasoning in `IMPLEMENTATION_PLAN.md`); unchanged this pass. |

## P3 — Automation

| Gap | Status |
|---|---|
| Automation-level (L0-L5) enforcement beyond classification | **Mostly re-scoped after closer inspection (Milestone 23), one real inconsistency found and fixed.** `orchestrator.py`'s `_run` already unconditionally verifies every execution and already gates the rollback attempt on the skill's own `rollback_skill_id` — which, for L1 skills, is `None` by construction (see `automation_level_for`), so L1 already never gets an automatic rollback attempt; always verifying (even for L1) is strictly safer, not a gap to "fix" by skipping it. The one real bug: `_run`'s rollback gate checked only `rollback_skill_id`, not `reversible` — so a manifest inconsistently declaring `reversible=False` while still carrying a `rollback_skill_id` label would have gotten an automatic rollback attempt anyway, disagreeing with the `automation_level` already recorded on the same `policy.evaluated` audit event. Fixed to require both, matching `automation_level_for`'s L2 condition exactly; proven by a new test (`test_failed_verification_does_not_roll_back_a_skill_marked_not_reversible`). |
| Reference skills content (Phase 13) | **Knowledge content DONE, executor code NOT** — all 10 issues the mandate proposes (Windows/Linux disk space, Windows/Linux service failure, Windows Update, DNS resolution, SSH auth, high CPU, unauthorized software, security-agent health) exist as real `IssueDefinition`/`DiagnosticWorkflow` records (Milestone 14). Exactly one mutating skill still exists (`service.restart`), so only 3 of the 10 workflows have a real `remediate` step — the rest correctly terminate in `escalate`, per `validate_remediation_skill_references`'s core invariant (knowledge may reference an existing skill, never invent one). Building real agent-side executors for disk-space/DNS/etc. is separate, real future work — see `skills.py`'s module docstring for why a registry entry alone was never going to be sufficient. |
| Simulation/dry-run *execution preview* mode (Phase 14, beyond diagnosis) | **DONE** — `helpdesktool/action_preview.py` + `GET /v1/actions/{id}/preview`. Computed fresh from the current active skill manifest every call (never a stale cache); returns what would execute, the verification plan, the rollback plan, policy allowed/approval-required, and the automation level — all templated from real stored manifest fields, never free-form text. No frontend panel for it yet (API-only, same gap diagnosis had before its own frontend panel). |

## P4 — Knowledge expansion

| Gap | Status |
|---|---|
| Real (non-mock) application connectors | BLOCKED-EXTERNAL (credentials). |
| Slack/Teams/Google Chat adapters | Slack done (see P1). Teams/Google Chat not started. |
| Knowledge provenance tracking (Phase 12) | **Schema/tracking DONE, automated ingestion NOT.** `KnowledgeSourceRow` (source_organization/source_url/retrieval_date/last_verified_date/source_reliability/deprecated/superseded_by, Milestone 13) exists and is populated (Milestone 14's 10 reference issues are honestly attributed to a single internal `KnowledgeSource`, not a fabricated external citation). What's still genuinely missing: an automated pipeline that fetches/parses real external knowledge sources (a CVE feed, a vendor KB) and proposes new `IssueDefinition` records for human review — today every knowledge record is hand-authored. |
| MITRE/CVE mapping tables | **DONE** — `MitreMapping`/`CveReference` in `helpdesktool/knowledge.py` (Milestone 13), both structurally validated (technique-id/CVE-id regex) and exercised by real reference content (Milestone 14). |

## P5 — Optimization

| Gap | Status |
|---|---|
| Full UI/UX modernization (Phase 20) | Not started; functional but not yet the target design system. |
| OpenTelemetry tracing | Evaluated, deliberately deferred (documented in an earlier pass). |
| Terraform / staging / production deployment | Not started; current deployment story is `docker compose`, independently verified fresh-from-zero in an earlier pass. |
| SBOM / release signing | **SBOM generation DONE** — CI's `security` job now generates a real CycloneDX SBOM for both the backend (`pip-audit --format=cyclonedx-json`) and frontend (`npm sbom --sbom-format=cyclonedx`) on every push/PR, uploaded as a 90-day build artifact (`sbom-<commit-sha>`) — not a committed file, since an SBOM goes stale the moment dependencies change, same reasoning `docs/DEPENDENCY_AUDIT.md` already gives for its own point-in-time framing. Release signing (Sigstore/cosign for container images, signed release archives) is still not started. |
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

Continuing into the next highest-priority item per the mandate's explicit
instruction not to stop between phases.
