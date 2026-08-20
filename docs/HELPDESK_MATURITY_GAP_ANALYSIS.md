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
| MITRE ATT&CK technique treated as proof rather than metadata | **PARTIAL** — `security_classification.py`'s design already treats any single signal (MITRE-tagged or not) as insufficient alone; a dedicated `MITREMapping` schema with `mapping_confidence`/`mapping_evidence` fields (Phase 11) does not exist yet — real work, tracked under P4/knowledge expansion since it's part of the not-yet-built knowledge schema. |
| Knowledge/research text becoming directly executable | **STRUCTURALLY CLOSED, NOT YET EXERCISED** — there is no code path from any text (ticket, chat message, CVE description, imported research) to endpoint execution today; execution is only ever a registered `skill_id` looked up by exact id and validated by a local agent-side allowlist. This invariant has nothing to violate yet because the knowledge-ingestion pathway (P4) doesn't exist — closing the *risk* is trivial until that pathway is built, at which point it must be re-verified against real ingested content, not just against the absence of a pathway. |
| Windows agent installer never run end-to-end | **BLOCKED-EXTERNAL** — needs a disposable Administrator-rights Windows host; see the architecture audit's §2. |
| Real (non-mock) application connectors | **BLOCKED-EXTERNAL** — needs real per-application credentials (Entra ID, Google Workspace, Okta, Salesforce, GitHub). |

## P1 — Architectural foundations

| Gap | Priority rationale |
|---|---|
| Knowledge schema (`IssueDefinition`/`Detector`/`EvidenceRequirement`/`DiagnosticWorkflow`/`DiagnosticStep`/`VerificationTest`/`EscalationPolicy`/`KnowledgeSource`/`MITREMapping`/`CVEReference`/`OperatingSystemConstraint`/`SoftwareVersionConstraint`/`CommandDefinition`) | The single largest remaining P1 item. Deliberately sequenced *after* this pass's safety primitives (confidence, automation level, security classification, destructive-action blocking) rather than before — a data-driven knowledge/detection system with nowhere safe to plug into would either sit unused or get wired in unsafely under time pressure. Now that the safety primitives exist and are tested, this is the correct next P1. |
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
| Automation-level (L0-L5) enforcement beyond classification | `automation_level_for` computes and audits the correct level, but nothing in the orchestrator *branches* on it yet beyond what risk/approval already drove — i.e. L2 vs. L1 is recorded and auditable but doesn't yet change execution behavior (both still execute immediately once approved/allowed). Real future work: differentiate L1 ("fire and forget") from L2 ("execute, then mandatorily verify and offer rollback") in the orchestrator's own control flow, not just in the audit record. |
| Reference skills (Phase 13) | Not started. Exactly one mutating skill exists today (`service.restart`); the 5-10 reference skills the mandate proposes (Windows disk-space, Windows service failure, Windows Update, Linux disk-space, systemd service failure, DNS resolution, SSH auth, high CPU, unauthorized software, security-agent health) all require both a knowledge-schema entry (P1, not yet built) and, for any *new mutating* skill among them, real agent-side executor code — see `skills.py`'s module docstring for why a registry entry alone is never sufficient. |
| Simulation/dry-run *execution preview* mode (Phase 14, beyond diagnosis) | **DONE** — `helpdesktool/action_preview.py` + `GET /v1/actions/{id}/preview`. Computed fresh from the current active skill manifest every call (never a stale cache); returns what would execute, the verification plan, the rollback plan, policy allowed/approval-required, and the automation level — all templated from real stored manifest fields, never free-form text. No frontend panel for it yet (API-only, same gap diagnosis had before its own frontend panel). |

## P4 — Knowledge expansion

| Gap | Status |
|---|---|
| Real (non-mock) application connectors | BLOCKED-EXTERNAL (credentials). |
| Slack/Teams/Google Chat adapters | Slack done (see P1). Teams/Google Chat not started. |
| Knowledge ingestion pipeline + provenance tracking (Phase 12) | Not started — depends on the P1 knowledge schema existing first. |
| MITRE/CVE mapping tables | Not started — same dependency. |

## P5 — Optimization

| Gap | Status |
|---|---|
| Full UI/UX modernization (Phase 20) | Not started; functional but not yet the target design system. |
| OpenTelemetry tracing | Evaluated, deliberately deferred (documented in an earlier pass). |
| Terraform / staging / production deployment | Not started; current deployment story is `docker compose`, independently verified fresh-from-zero in an earlier pass. |
| SBOM / release signing | **SBOM generation DONE** — CI's `security` job now generates a real CycloneDX SBOM for both the backend (`pip-audit --format=cyclonedx-json`) and frontend (`npm sbom --sbom-format=cyclonedx`) on every push/PR, uploaded as a 90-day build artifact (`sbom-<commit-sha>`) — not a committed file, since an SBOM goes stale the moment dependencies change, same reasoning `docs/DEPENDENCY_AUDIT.md` already gives for its own point-in-time framing. Release signing (Sigstore/cosign for container images, signed release archives) is still not started. |
| Dependency/provenance audit (`docs/DEPENDENCY_AUDIT.md` etc.) | **DONE** — `docs/DEPENDENCY_AUDIT.md`, `docs/THIRD_PARTY_LICENSES.md`, `docs/SOFTWARE_PROVENANCE.md`. Zero known CVEs in any declared dependency (`pip-audit`/`npm audit` both clean, matching CI); `psycopg`'s LGPL-3.0 license flagged explicitly (the one non-permissive dependency); no runtime remote-code-execution path found anywhere (checked directly, not assumed). **Real gap surfaced, not fixed:** `pyproject.toml` declares `license = "Apache-2.0"` but no `LICENSE` file exists at the repo root — deliberately not auto-created (needs a real copyright holder name/year, the repo owner's call) — flagged for a human decision, per the mandate's own stop condition for genuine license issues. |

## What changed this pass, in priority order

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

Continuing into the next highest-priority item (the P1 knowledge schema)
per the mandate's explicit instruction not to stop between phases.
