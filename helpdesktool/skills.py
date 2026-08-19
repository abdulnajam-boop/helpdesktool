"""Versioned, integrity-checked remediation skill registry.

Trust model
-----------
Before this module, the set of remediation skills the control plane would
ever policy-evaluate or hand to an agent was a hardcoded Python list literal
(`SKILLS` in `api.py`). That made every change — even a pure risk-tier or
timeout adjustment — a code deploy, and gave an operator no way to see what
was registered without reading source.

This module replaces that literal with a data-driven registry (`skills`
table, migration `0008`) while changing **nothing** about the deeper safety
invariant described in `CLAUDE.md`: a skill manifest only ever carries
*policy metadata* — id, version, risk tier, supported OS, timeout, a
declared rollback skill id, and a shape-only parameter schema (parameter
names/types, never a command template). It can never itself describe
*how* a skill executes. Each OS agent still ships its own hardcoded,
deterministic executor per skill id (`linux_agent/executor.py`,
`windows_agent/executor.py`) and validates exact parameters against its own
local allowlist before running anything — see those modules' docstrings.
Registering a manifest here for a skill id no agent implements is harmless
by construction: the agent's own allowlist independently rejects any
unknown skill id, exactly as it does today. Adding a new *mutating*
capability therefore still requires an agent code change; what this
registry removes is needing a control-plane code change too for anything
short of that (risk tier, OS support, timeout, versioning, parameter shape).

Integrity: each stored manifest carries a `content_hash` — a SHA-256 over
its own canonical field values, computed once at write time and re-verified
by `load_active_skills` on every read. A manifest whose stored hash no
longer matches its recomputed hash (e.g. a row edited directly in the
database, bypassing `POST /v1/skills`) is dropped and raises
`SkillIntegrityError` rather than being silently trusted — fail closed, the
same posture as everywhere else in this codebase.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import Any, Mapping

from .models import RiskLevel, SkillDefinition

_ALLOWED_PARAMETER_TYPES = frozenset({"string", "number", "boolean"})


class SkillIntegrityError(RuntimeError):
    """A stored manifest's hash does not match its recomputed content hash."""


@dataclass(frozen=True, slots=True)
class ParameterSpec:
    type: str
    required: bool = True

    def __post_init__(self) -> None:
        if self.type not in _ALLOWED_PARAMETER_TYPES:
            raise ValueError(f"unsupported parameter type: {self.type!r}")


@dataclass(frozen=True, slots=True)
class SkillManifest:
    skill_id: str
    version: int
    risk: RiskLevel
    supported_os: frozenset[str]
    timeout_seconds: int
    rollback_skill_id: str | None
    parameters: Mapping[str, ParameterSpec] = field(default_factory=dict)

    def to_skill_definition(self) -> SkillDefinition:
        return SkillDefinition(
            self.skill_id,
            self.risk,
            self.supported_os,
            self.timeout_seconds,
            self.rollback_skill_id,
        )

    def content_hash(self) -> str:
        return compute_manifest_hash(
            skill_id=self.skill_id,
            version=self.version,
            risk=self.risk,
            supported_os=self.supported_os,
            timeout_seconds=self.timeout_seconds,
            rollback_skill_id=self.rollback_skill_id,
            parameters=self.parameters,
        )


def compute_manifest_hash(
    *,
    skill_id: str,
    version: int,
    risk: RiskLevel,
    supported_os: frozenset[str] | list[str],
    timeout_seconds: int,
    rollback_skill_id: str | None,
    parameters: Mapping[str, ParameterSpec] | Mapping[str, Mapping[str, Any]],
) -> str:
    """Deterministic, order-independent hash over a manifest's policy fields.

    Callers pass either live ``ParameterSpec`` objects (in-process) or plain
    dicts (as decoded from the ``parameters`` JSON column) — both normalize
    to the same canonical form so a value round-tripped through storage
    hashes identically to the value that produced it.
    """
    normalized_parameters = {
        name: {
            "type": spec.type if isinstance(spec, ParameterSpec) else spec["type"],
            "required": (
                spec.required if isinstance(spec, ParameterSpec) else spec["required"]
            ),
        }
        for name, spec in parameters.items()
    }
    canonical = json.dumps(
        {
            "skill_id": skill_id,
            "version": version,
            "risk": str(risk),
            "supported_os": sorted(supported_os),
            "timeout_seconds": timeout_seconds,
            "rollback_skill_id": rollback_skill_id,
            "parameters": normalized_parameters,
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(canonical.encode()).hexdigest()


def validate_parameters(
    manifest: SkillManifest, parameters: Mapping[str, Any]
) -> str | None:
    """Returns a human-readable error if ``parameters`` doesn't match the
    manifest's declared shape, else ``None``. Shape-only: names, types, and
    which are required — never a value/command template.
    """
    provided = set(parameters)
    expected = set(manifest.parameters)
    unexpected = provided - expected
    if unexpected:
        return f"unexpected parameter(s): {', '.join(sorted(unexpected))}"
    missing = {
        name
        for name, spec in manifest.parameters.items()
        if spec.required and name not in provided
    }
    if missing:
        return f"missing required parameter(s): {', '.join(sorted(missing))}"
    type_checks: dict[str, type | tuple[type, ...]] = {
        "string": str,
        "number": (int, float),
        "boolean": bool,
    }
    for name, value in parameters.items():
        spec = manifest.parameters[name]
        expected_type = type_checks[spec.type]
        # bool is a subclass of int in Python; keep "number" and "boolean"
        # from accepting each other's values.
        if spec.type == "number" and isinstance(value, bool):
            return f"{name} must be a number"
        if not isinstance(value, expected_type):
            return f"{name} must be a {spec.type}"
    return None
