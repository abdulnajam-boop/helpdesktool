"""Phase 14: a standalone action-preview surface -- "show exactly what
this specific pending action would do, including its verification and
rollback plan, without running it." Diagnosis (``ai/provider.py``) was
already unconditionally simulation-only; this closes the matching gap on
the remediation side, where an operator previously had to infer intent
from a pending ``Action``'s raw stored manifest fields rather than reading
one explicit, structured answer.

Computed fresh from the current active skill manifest on every call, the
same "never drift from the database" pattern ``reporting.py``/
``metrics.py`` already use — there is no separate cached preview row that
could go stale relative to the manifest or the policy that governs it.
Every sentence in an ``ActionPreview`` is templated from real, stored
manifest fields -- never free-form or AI-generated text -- matching this
system's deterministic-explanation theme elsewhere (``confidence.py``,
``security_classification.py``).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping

from .models import AutomationLevel
from .policy import PolicyDecision
from .skills import SkillManifest


@dataclass(frozen=True, slots=True)
class ActionPreview:
    skill_id: str
    skill_version: int
    command_type: str
    risk: str
    required_privilege: str
    timeout_seconds: int
    parameters: Mapping[str, Any]
    preconditions: Mapping[str, Any]
    expected_output: str
    success_condition: str
    failure_condition: str
    side_effects: str
    requires_reboot: bool
    reversible: bool
    rollback_skill_id: str | None
    automation_level: AutomationLevel
    policy_allowed: bool
    approval_required: bool
    policy_reason: str
    what_would_execute: str
    verification_plan: str
    rollback_plan: str


def build_action_preview(
    *,
    manifest: SkillManifest,
    parameters: Mapping[str, Any],
    policy_decision: PolicyDecision,
    automation_level: AutomationLevel,
) -> ActionPreview:
    what_would_execute = (
        f"The agent would run the registered {manifest.skill_id!r} skill "
        f"(version {manifest.version}, {manifest.command_type.value}) "
        f"against the target device with parameters {dict(parameters)!r}, "
        f"timing out after {manifest.timeout_seconds}s if it does not "
        "complete."
    )

    verification_plan = (
        manifest.success_condition.strip()
        or "No explicit success_condition is registered for this skill; "
        "the agent's own hardcoded post-execution check determines "
        "success (see the agent executor's verify logic)."
    )

    if manifest.reversible and manifest.rollback_skill_id:
        rollback_plan = (
            f"On verification failure, the agent attempts rollback via "
            f"the {manifest.rollback_skill_id!r} label -- the actual "
            "rollback logic lives inside the agent's own executor code, "
            "not a separate registered skill (see skills.py's module "
            "docstring)."
        )
    elif manifest.reversible:
        rollback_plan = (
            "This skill is marked reversible but declares no "
            "rollback_skill_id label; rollback, if any, is handled "
            "entirely inside the agent's own executor code."
        )
    else:
        rollback_plan = (
            "This skill is not marked reversible -- no automated rollback "
            "will be attempted on failure; a failure here requires manual "
            "operator follow-up."
        )

    return ActionPreview(
        skill_id=manifest.skill_id,
        skill_version=manifest.version,
        command_type=manifest.command_type.value,
        risk=manifest.risk.value,
        required_privilege=manifest.required_privilege,
        timeout_seconds=manifest.timeout_seconds,
        parameters=parameters,
        preconditions=manifest.preconditions,
        expected_output=manifest.expected_output,
        success_condition=manifest.success_condition,
        failure_condition=manifest.failure_condition,
        side_effects=manifest.side_effects,
        requires_reboot=manifest.requires_reboot,
        reversible=manifest.reversible,
        rollback_skill_id=manifest.rollback_skill_id,
        automation_level=automation_level,
        policy_allowed=policy_decision.allowed,
        approval_required=policy_decision.approval_required,
        policy_reason=policy_decision.reason,
        what_would_execute=what_would_execute,
        verification_plan=verification_plan,
        rollback_plan=rollback_plan,
    )


__all__ = ["ActionPreview", "build_action_preview"]
