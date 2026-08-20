"""Tests for helpdesktool.knowledge (Phase 1 schema, unit) and the
GET/POST /v1/knowledge/* API surface (integration). Central invariants
under test: knowledge is reference data, never executable (a
DiagnosticStep can only reference an already-registered skill id, never
invent one), and structural validation catches the malformed-knowledge
classes docs/KNOWLEDGE_BASE_AUDIT.md calls out (bad MITRE/CVE ids).
"""

from __future__ import annotations

import pytest

from helpdesktool.knowledge import (
    CveReference,
    DiagnosticStep,
    EscalationPolicy,
    EvidenceRequirement,
    IssueDefinition,
    KnowledgeValidationError,
    MitreMapping,
    validate_remediation_skill_references,
)


def _valid_issue_definition(**overrides) -> IssueDefinition:
    defaults = dict(
        issue_key="windows_disk_space_low",
        version=1,
        title="Windows disk space low",
        description="",
        category="disk",
        applicable_os=frozenset({"windows"}),
    )
    defaults.update(overrides)
    return IssueDefinition(**defaults)


# --- structural validation ---------------------------------------------


def test_valid_issue_definition_constructs_cleanly():
    definition = _valid_issue_definition()
    assert definition.content_hash()


def test_issue_key_must_not_be_empty():
    with pytest.raises(KnowledgeValidationError, match="issue_key"):
        _valid_issue_definition(issue_key="")


def test_at_least_one_applicable_os_is_required():
    with pytest.raises(KnowledgeValidationError, match="applicable_os"):
        _valid_issue_definition(applicable_os=frozenset())


def test_malformed_mitre_technique_id_is_rejected():
    with pytest.raises(KnowledgeValidationError, match="MITRE"):
        MitreMapping("NOT-A-TECHNIQUE")


def test_valid_mitre_technique_ids_are_accepted():
    MitreMapping("T1059")
    MitreMapping("T1059.001")


def test_malformed_cve_id_is_rejected():
    with pytest.raises(KnowledgeValidationError, match="CVE"):
        CveReference("not-a-cve")


def test_valid_cve_id_is_accepted():
    CveReference("CVE-2024-12345")


def test_escalation_policy_rejects_unknown_role():
    with pytest.raises(KnowledgeValidationError, match="escalate_to_role"):
        EscalationPolicy("low confidence", escalate_to_role="nobody")


def test_evidence_requirement_name_must_not_be_empty():
    with pytest.raises(KnowledgeValidationError, match="name"):
        EvidenceRequirement("")


# --- content hash ---------------------------------------------------------


def test_content_hash_is_stable_for_identical_input():
    a = _valid_issue_definition()
    b = _valid_issue_definition()
    assert a.content_hash() == b.content_hash()


def test_content_hash_changes_when_category_changes():
    a = _valid_issue_definition(category="disk")
    b = _valid_issue_definition(category="network")
    assert a.content_hash() != b.content_hash()


def test_content_hash_ignores_free_text_description():
    """title/description are documentation, deliberately not hash-covered
    -- see compute_issue_definition_hash's docstring."""
    a = _valid_issue_definition(description="one description")
    b = _valid_issue_definition(description="a totally different description")
    assert a.content_hash() == b.content_hash()


def test_content_hash_is_order_independent_for_evidence_requirements():
    a = _valid_issue_definition(
        evidence_requirements=(
            EvidenceRequirement("free_disk_percent"),
            EvidenceRequirement("device_online"),
        )
    )
    b = _valid_issue_definition(
        evidence_requirements=(
            EvidenceRequirement("device_online"),
            EvidenceRequirement("free_disk_percent"),
        )
    )
    assert a.content_hash() == b.content_hash()


# --- diagnostic steps / skill-reference validation -------------------------


def test_remediate_step_requires_a_remediation_skill_id():
    with pytest.raises(KnowledgeValidationError, match="remediate"):
        DiagnosticStep(0, "remediate", "restart the service")


def test_unknown_step_type_is_rejected():
    with pytest.raises(KnowledgeValidationError, match="step_type"):
        DiagnosticStep(0, "not_a_real_step_type", "x")


def test_step_referencing_a_registered_skill_passes_validation():
    steps = (
        DiagnosticStep(
            0, "remediate", "restart", remediation_skill_id="service.restart"
        ),
    )
    validate_remediation_skill_references(steps, frozenset({"service.restart"}))


def test_step_referencing_an_unregistered_skill_fails_closed():
    """The core safety invariant: knowledge can never invent an
    executable capability -- it may only reference a skill that is
    genuinely, independently registered."""
    steps = (
        DiagnosticStep(
            0, "remediate", "wipe the disk", remediation_skill_id="disk.wipe"
        ),
    )
    with pytest.raises(KnowledgeValidationError, match="unregistered"):
        validate_remediation_skill_references(steps, frozenset({"service.restart"}))


def test_rollback_skill_reference_is_not_required_to_be_independently_registered():
    """Matches the existing precedent set by SkillManifest.rollback_skill_id
    itself: the real service.restart manifest declares rollback_skill_id=
    "service.restore", and no such skill has ever been independently
    registered -- the rollback mechanism lives inside the executor's own
    code, not a registry lookup. See validate_remediation_skill_references's
    docstring for the full reasoning."""
    steps = (
        DiagnosticStep(
            0,
            "remediate",
            "restart",
            remediation_skill_id="service.restart",
            rollback_skill_id="service.restore",
        ),
    )
    # Does not raise, even though "service.restore" isn't in known_skill_ids.
    validate_remediation_skill_references(steps, frozenset({"service.restart"}))


def test_dns_resolution_failure_workflow_with_flush_cache_remediation_validates():
    """Mirrors the exact 5-step sequence migration 0017 writes for the
    dns_resolution_failure reference issue: collect_evidence and
    check_precondition are unchanged from migration 0013's original
    escalate-only workflow; a new remediate step references the
    dns.flush_cache skill registered by migration 0016; a verify step
    follows it; escalate still fires for a real DNS misconfiguration or a
    flush that didn't fix resolution. Proves the updated knowledge content
    is valid and only ever references a real, registered skill."""
    steps = (
        DiagnosticStep(
            0, "collect_evidence", "Collect network.dns_servers from device inventory."
        ),
        DiagnosticStep(
            1,
            "check_precondition",
            "Compare configured DNS servers against the organization's baseline.",
        ),
        DiagnosticStep(
            2,
            "remediate",
            "Attempt dns.flush_cache before escalating.",
            remediation_skill_id="dns.flush_cache",
        ),
        DiagnosticStep(3, "verify", "Confirm resolution succeeds afterward."),
        DiagnosticStep(
            4, "escalate", "Escalate if config deviates or resolution still fails."
        ),
    )
    validate_remediation_skill_references(
        steps, frozenset({"diagnostics.collect", "service.restart", "dns.flush_cache"})
    )
