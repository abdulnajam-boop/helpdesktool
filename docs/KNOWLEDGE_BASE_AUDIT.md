# Knowledge base audit

Date: 2026-08-20. **Honest scope note:** no external (Gemini-researched or
otherwise) knowledge content has been imported into this repository as of
this pass — the Phase 1 knowledge schema (`IssueDefinition`/`Detector`/
etc.) does not exist yet (see `docs/HELPDESK_MATURITY_GAP_ANALYSIS.md`'s
P1 section). This document is therefore not an audit of existing content;
there is none to audit. It is the **binding technical-correctness
guardrail set** the future knowledge-ingestion pipeline must validate
every imported record against before that record can ever back a
`Detector`, `DiagnosticWorkflow`, or `RemediationAction`. Recording these
corrections now — before any content exists — means the ingestion
pipeline can be built test-first against them, rather than discovering
these errors after bad knowledge has already backed a real remediation.

## The specific corrections the mandate calls out

Each of these must have an automated check in the eventual knowledge
validation pipeline, not just a human-reviewed guideline:

1. **NIST SP 800-61 Rev.2 is superseded by Rev.3.** Any imported reference
   to "NIST SP 800-61" without a revision number, or explicitly citing
   Rev.2, should be flagged for review before being trusted as current
   guidance. `helpdesktool/security_classification.py`'s design already
   aligns with Rev.3's phase model (preparation/detection/analysis/
   response/recovery/post-incident) conceptually, but no automated
   citation-currency check exists yet — real, tractable future work once
   `KnowledgeSource` (with `retrieval_date`/`last_verified_date`) exists.
2. **Windows Event ID 4688 is process creation, not LSASS handle access.**
   A knowledge record describing 4688 as anything related to credential
   access (LSASS handle opens are Sysmon Event ID 10 / Windows Defender
   Credential Guard telemetry, a completely different signal) must be
   rejected by validation, not silently accepted.
3. **Sysmon `ProcessAccess` (Event ID 10) and Windows Security
   process-creation telemetry (Event ID 4688) must not be conflated.**
   They come from different logging subsystems with different semantics;
   a knowledge record treating them as interchangeable evidence sources
   is malformed.
4. **MITRE T1059 is "Command and Scripting Interpreter," not
   "CommandLine."** A record citing T1059 must describe an actual
   scripting/interpreter execution technique, not merely "a command line
   was involved" — see `security_classification.py`'s
   `test_mitre_technique_alone_is_metadata_not_evidence_of_compromise`
   for why this distinction has direct safety consequences (a single
   PowerShell invocation is not, by itself, T1059-confirmed malicious
   activity).
5. **Cryptominer detection does not automatically imply T1059.** A
   cryptominer is typically detected via resource-usage and network
   signals (sustained CPU, known mining-pool ports/domains), not
   necessarily via scripting-interpreter execution at all — conflating
   the two in a knowledge record would misattribute a technique with no
   supporting evidence.
6. **Do not automatically configure public DNS (8.8.8.8, 1.1.1.1, etc.)
   on enterprise/domain endpoints.** No remediation skill in this
   codebase does this today (only `service.restart` exists as a mutating
   skill), so there is nothing to violate this yet — but it is recorded
   here explicitly so that if a future "DNS resolution diagnosis" skill
   (Phase 13's reference-skill list includes one) is ever built, its
   remediation step must resolve expected DNS servers from organizational
   policy/MDM/device baseline (Phase 6's "known-good state," not yet
   built) — never from a hardcoded public resolver.
7. **High CPU + a mining-related port alone is insufficient malware
   evidence.** Directly enforced by `classify_security_state`'s
   correlation rule — see
   `tests/test_security_classification.py::test_cryptominer_style_signals_need_correlation_too`,
   which asserts this exact scenario lands at `SUSPICIOUS`, never an
   automatic compromise verdict.
8. **Ambiguous security anomalies must not automatically become confirmed
   compromise.** Directly enforced — `CONFIRMED_COMPROMISE` is reachable
   only via an explicit `confirmed_by_authoritative_source` flag, never
   from any amount of accumulated signal evidence. See
   `test_ambiguous_evidence_never_auto_reaches_confirmed_compromise`.
9. **Security classification and remediation/automation level must remain
   separate.** Directly enforced — `SecurityClassification` and
   `AutomationLevel` are independent enums computed by independent
   functions (`classify_security_state` vs. `automation_level_for`);
   neither takes the other as an input. A suspicious finding does not by
   itself change what automation level applies to a remediation action.
10. **Individual actions inside one remediation workflow may require
    different risk levels.** Not yet directly exercisable — today's
    `Action`/skill model is one skill per submission, not a multi-step
    workflow. This is a real design implication for the not-yet-built
    `DiagnosticWorkflow`/`DiagnosticStep` schema (Phase 1): a workflow's
    overall risk must be computed as (at minimum) the maximum of its
    steps' individual risk/command-type/automation-level, never a single
    workflow-level risk tier that could understate an individual
    high-risk step. Recorded here as a binding design requirement for
    when that schema is built, not yet implemented since the schema
    itself doesn't exist.

## What this means for the eventual knowledge-ingestion pipeline

Every one of the ten corrections above must become an automated
validation rule (not a documentation-only guideline) before the pipeline
that turns imported knowledge into an executable `RemediationAction`
reference is built. The existing precedent for "validated knowledge,
never raw text, becomes anything executable" is
`helpdesktool/skills.py`'s integrity-hash model: a stored skill manifest
is re-verified on every read and fails the request closed if tampered.
The knowledge schema, when built, should apply an equivalent principle:
an `IssueDefinition`/`DiagnosticWorkflow` whose validation rules (the ten
above, plus schema-shape validation) fail must never become reachable by
`conversation.py`'s planning path — it should remain visible as analyst
reference material only, exactly as Phase 14 specifies for newly imported
knowledge defaulting to simulation-only until explicitly approved.

## Provenance requirements (Phase 12), for when ingestion exists

Every knowledge record must carry, at minimum: `source_id`,
`source_organization`, `source_url`, `retrieval_date`,
`last_verified_date`, `applicable_versions`, `confidence` (as a
*declared* value about the source's own reliability, not to be confused
with `helpdesktool/confidence.py`'s per-diagnosis computed score — these
are different concepts that happen to share a name in the mandate's
vocabulary; the knowledge schema should name the source-level field
distinctly, e.g. `source_reliability`, to avoid exactly that confusion),
`deprecated`, and `superseded_by`. A record missing required provenance
fields must be rejected by ingestion, not accepted with nulls.

## Summary

No content violates these corrections today because no content has been
imported yet. This document exists so that claim remains true by
construction — the validation rules above are specified before ingestion
exists, not retrofitted after a bad record has already influenced a real
diagnosis or remediation.
