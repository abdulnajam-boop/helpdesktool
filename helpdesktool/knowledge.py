"""Phase 1 knowledge schema: validated, versioned, integrity-checked issue
definitions and diagnostic workflows.

**Knowledge is reference data. Knowledge is not executable code.** Nothing
in this module can execute anything, on any endpoint, ever. A
``DiagnosticStep`` never carries a command, script, or template — only an
optional ``remediation_skill_id`` / ``rollback_skill_id`` *reference* into
the existing, independently governed skill registry
(``helpdesktool/skills.py``). Validating an issue definition here means
validating that any such reference actually points at a real, registered
skill — never validating or storing *how* that skill executes, which
remains exactly where it has always lived: an agent's own hardcoded,
allowlisted executor (`linux_agent/executor.py`, `windows_agent/
executor.py`). This module cannot create a new way for text to become a
command; it can only describe, in structured and validated form, which
*already-trusted* skill (if any) is relevant to a given issue.

Mirrors ``skills.py``'s integrity model deliberately: each
``IssueDefinition`` carries a ``content_hash`` recomputed and compared on
every read, so a row edited directly in the database (bypassing the
registration API) is caught and dropped rather than silently trusted --
the same "validated knowledge, never raw text, becomes anything
authoritative" principle applied to knowledge instead of skills.

See ``docs/KNOWLEDGE_BASE_AUDIT.md`` for the specific technical
corrections (NIST revision currency, MITRE technique semantics, Windows
Event ID meanings, ...) this module's validation rules enforce, and for
which corrections remain human-review-only because they require judgment
this module cannot structurally verify (e.g. "is this citation actually
current" is not decidable from the citation text alone).

**Deliberately not wired into ``conversation.py``'s live planning path
this pass** — Phase 14 requires newly imported/generated knowledge to
default to simulation-only until explicitly approved; the safest way to
honor that for a knowledge system's *first* pass is to ship the schema
and its validation as inert, reviewable data before any code path can act
on it autonomously. Wiring this into live diagnosis/remediation planning
is real, separately-scoped future work.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from typing import Any, Mapping

_MITRE_TECHNIQUE_RE = re.compile(r"^T\d{4}(\.\d{3})?$")
_CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")
_STEP_TYPES = frozenset(
    {"collect_evidence", "check_precondition", "remediate", "verify", "escalate"}
)


class KnowledgeValidationError(ValueError):
    """A knowledge record failed validation and must not be trusted."""


@dataclass(frozen=True, slots=True)
class EvidenceRequirement:
    name: str
    description: str = ""
    required: bool = True

    def __post_init__(self) -> None:
        if not self.name.strip():
            raise KnowledgeValidationError(
                "evidence requirement name must not be empty"
            )


@dataclass(frozen=True, slots=True)
class MitreMapping:
    """Metadata, never proof -- see ``docs/KNOWLEDGE_BASE_AUDIT.md``
    correction #4/#9: a technique mapping alone is never evidence of
    compromise, and must not be conflated with security classification
    (``helpdesktool.security_classification``).
    """

    technique_id: str
    tactic: str = ""
    mapping_confidence: float = 0.5
    mapping_evidence: str = ""

    def __post_init__(self) -> None:
        if not _MITRE_TECHNIQUE_RE.match(self.technique_id):
            raise KnowledgeValidationError(
                f"malformed MITRE technique id: {self.technique_id!r}"
            )
        if not 0.0 <= self.mapping_confidence <= 1.0:
            raise KnowledgeValidationError("mapping_confidence must be within [0, 1]")


@dataclass(frozen=True, slots=True)
class CveReference:
    cve_id: str
    applicable_versions: str = ""

    def __post_init__(self) -> None:
        if not _CVE_RE.match(self.cve_id):
            raise KnowledgeValidationError(f"malformed CVE id: {self.cve_id!r}")


@dataclass(frozen=True, slots=True)
class EscalationPolicy:
    condition: str
    escalate_to_role: str = "admin"
    priority: str = "normal"

    def __post_init__(self) -> None:
        if not self.condition.strip():
            raise KnowledgeValidationError("escalation condition must not be empty")
        if self.escalate_to_role not in {"operator", "admin", "owner", "security_team"}:
            raise KnowledgeValidationError(
                f"unknown escalate_to_role: {self.escalate_to_role!r}"
            )


@dataclass(frozen=True, slots=True)
class IssueDefinition:
    issue_key: str
    version: int
    title: str
    description: str
    category: str
    applicable_os: frozenset[str]
    source_id: str | None = None
    applicable_software_versions: Mapping[str, str] = field(default_factory=dict)
    evidence_requirements: tuple[EvidenceRequirement, ...] = field(
        default_factory=tuple
    )
    mitre_mappings: tuple[MitreMapping, ...] = field(default_factory=tuple)
    cve_references: tuple[CveReference, ...] = field(default_factory=tuple)
    escalation_policy: EscalationPolicy | None = None

    def __post_init__(self) -> None:
        if not self.issue_key.strip():
            raise KnowledgeValidationError("issue_key must not be empty")
        if not self.applicable_os:
            raise KnowledgeValidationError("at least one applicable_os is required")
        if not self.title.strip():
            raise KnowledgeValidationError("title must not be empty")

    def content_hash(self) -> str:
        return compute_issue_definition_hash(
            issue_key=self.issue_key,
            version=self.version,
            category=self.category,
            applicable_os=self.applicable_os,
            evidence_requirements=self.evidence_requirements,
            mitre_mappings=self.mitre_mappings,
            cve_references=self.cve_references,
        )


def compute_issue_definition_hash(
    *,
    issue_key: str,
    version: int,
    category: str,
    applicable_os: frozenset[str] | list[str],
    evidence_requirements: tuple[EvidenceRequirement, ...] | list[Mapping[str, Any]],
    mitre_mappings: tuple[MitreMapping, ...] | list[Mapping[str, Any]],
    cve_references: tuple[CveReference, ...] | list[Mapping[str, Any]],
) -> str:
    """Deterministic hash over an issue definition's policy-relevant
    fields — mirrors ``skills.compute_manifest_hash`` exactly in spirit.
    Free-text fields (``title``/``description``) are deliberately not
    hash-covered: they're documentation, not something a downstream
    decision is gated on, unlike ``category``/``applicable_os``/the
    evidence-requirement shape.
    """

    def _evidence(item: EvidenceRequirement | Mapping[str, Any]) -> dict[str, Any]:
        if isinstance(item, EvidenceRequirement):
            return {"name": item.name, "required": item.required}
        return {"name": item["name"], "required": item["required"]}

    def _mitre(item: MitreMapping | Mapping[str, Any]) -> dict[str, Any]:
        if isinstance(item, MitreMapping):
            return {"technique_id": item.technique_id}
        return {"technique_id": item["technique_id"]}

    def _cve(item: CveReference | Mapping[str, Any]) -> dict[str, Any]:
        if isinstance(item, CveReference):
            return {"cve_id": item.cve_id}
        return {"cve_id": item["cve_id"]}

    canonical = json.dumps(
        {
            "issue_key": issue_key,
            "version": version,
            "category": category,
            "applicable_os": sorted(applicable_os),
            "evidence_requirements": sorted(
                (_evidence(item) for item in evidence_requirements),
                key=lambda x: x["name"],
            ),
            "mitre_mappings": sorted(
                (_mitre(item) for item in mitre_mappings),
                key=lambda x: x["technique_id"],
            ),
            "cve_references": sorted(
                (_cve(item) for item in cve_references), key=lambda x: x["cve_id"]
            ),
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(canonical.encode()).hexdigest()


@dataclass(frozen=True, slots=True)
class DiagnosticStep:
    """One ordered step in a diagnostic workflow.

    ``remediation_skill_id``/``rollback_skill_id`` are references into the
    existing skill registry, never a command — see the module docstring.
    ``reference_description`` is documentation-only prose describing what
    the referenced skill conceptually does, for a human reviewing this
    knowledge record; it is never parsed, templated, or executed.
    """

    step_order: int
    step_type: str
    description: str
    remediation_skill_id: str | None = None
    verification_description: str = ""
    rollback_skill_id: str | None = None
    reference_description: str = ""

    def __post_init__(self) -> None:
        if self.step_type not in _STEP_TYPES:
            raise KnowledgeValidationError(f"unknown step_type: {self.step_type!r}")
        if self.step_order < 0:
            raise KnowledgeValidationError("step_order must not be negative")
        if self.step_type == "remediate" and not self.remediation_skill_id:
            raise KnowledgeValidationError(
                "a 'remediate' step must reference a remediation_skill_id"
            )


def validate_remediation_skill_references(
    steps: tuple[DiagnosticStep, ...], known_skill_ids: frozenset[str]
) -> None:
    """Raises ``KnowledgeValidationError`` if any step's
    ``remediation_skill_id`` isn't actually registered — the concrete
    enforcement of "never let unvalidated knowledge become executable": an
    issue definition can describe a remediation only in terms of a skill
    that already exists and is independently governed by ``policy.py``/the
    skill registry's own integrity checks.

    ``rollback_skill_id`` is deliberately **not** validated against the
    registry here, matching the existing precedent set by
    ``skills.SkillManifest.rollback_skill_id`` itself: e.g. the real
    ``service.restart`` manifest declares ``rollback_skill_id=
    "service.restore"``, and no ``service.restore`` skill has ever been
    independently registered — the actual rollback mechanism lives inside
    the executor's own code (``linux_agent/executor.py``'s ``_rollback``),
    never a registry lookup. A knowledge step's rollback reference is the
    same kind of descriptive label, not a second remediation that must
    itself be independently executable.
    """
    for step in steps:
        if (
            step.remediation_skill_id is not None
            and step.remediation_skill_id not in known_skill_ids
        ):
            raise KnowledgeValidationError(
                f"step {step.step_order} references unregistered skill id "
                f"{step.remediation_skill_id!r} — knowledge may only "
                "reference real, registered skills, never invent one"
            )


__all__ = [
    "CveReference",
    "DiagnosticStep",
    "EscalationPolicy",
    "EvidenceRequirement",
    "IssueDefinition",
    "KnowledgeValidationError",
    "MitreMapping",
    "compute_issue_definition_hash",
    "validate_remediation_skill_references",
]
