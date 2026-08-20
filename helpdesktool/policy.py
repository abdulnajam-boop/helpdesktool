"""Default-deny policy evaluation for deterministic endpoint skills.

Two independent safety gates run here, deliberately never merged into one:
``RiskLevel`` (how risky policy considers a skill — drives whether approval
is required) and ``CommandType`` (what *class* of change a skill makes —
drives whether it can *ever* run autonomously at all, no matter what risk
tier it claims). A ``DESTRUCTIVE`` skill is refused unconditionally here,
before risk/approval is even considered — a future skill mismarked with a
low risk tier can never destructively change an endpoint "by accident"
through a risk-tier misconfiguration alone. See ``models.CommandType``'s
docstring and ``docs/CURRENT_ARCHITECTURE_AUDIT.md`` for the full rationale.
"""

from dataclasses import dataclass

from .models import (
    ActionRequest,
    AutomationLevel,
    CommandType,
    RiskLevel,
    SkillDefinition,
)


@dataclass(frozen=True, slots=True)
class PolicyDecision:
    allowed: bool
    approval_required: bool
    reason: str
    skill: SkillDefinition | None = None
    automation_level: AutomationLevel = AutomationLevel.L0_OBSERVE_ONLY


def automation_level_for(
    skill: SkillDefinition, approval_required: bool
) -> AutomationLevel:
    """Deterministic automation-level classification (Phase 3): read-only
    skills observe only; a skill flagged security-sensitive or targeting
    security containment escalates to L5 regardless of its risk tier;
    admin-approval-required skills are L4; any other approval-required
    skill is L3 (user approval); a reversible, unattended low-risk change
    is L2 (automatic, but still verified with rollback available); genuine
    read-only-adjacent low-risk changes with no rollback story at all are
    L1. This mirrors — but is deliberately a distinct axis from —
    ``RiskLevel``/``CommandType``: a suspicious *event* does not
    automatically imply L5, and this function only ever looks at the
    *skill's own* declared properties, never at incident/security context.
    """
    if (
        skill.risk is RiskLevel.READ_ONLY
        and skill.command_type is CommandType.READ_ONLY
    ):
        return AutomationLevel.L0_OBSERVE_ONLY
    if (
        skill.security_sensitive
        or skill.command_type is CommandType.SECURITY_CONTAINMENT
    ):
        return AutomationLevel.L5_SECURITY_INCIDENT
    if skill.requires_admin_approval:
        return AutomationLevel.L4_ADMIN_APPROVAL
    if approval_required or skill.requires_user_approval:
        return AutomationLevel.L3_USER_APPROVAL
    if skill.reversible and skill.rollback_skill_id:
        return AutomationLevel.L2_AUTOMATIC_VERIFY_ROLLBACK
    return AutomationLevel.L1_SAFE_AUTOMATIC


class PolicyEngine:
    """Evaluates registered skills; unknown and prohibited skills always fail closed."""

    def __init__(self, skills: list[SkillDefinition]) -> None:
        self._skills = {skill.skill_id: skill for skill in skills}
        if len(self._skills) != len(skills):
            raise ValueError("duplicate skill_id")

    def evaluate(self, request: ActionRequest, device_os: str) -> PolicyDecision:
        skill = self._skills.get(request.skill_id)
        if skill is None:
            return PolicyDecision(False, False, "skill is not allowlisted")
        if skill.risk is RiskLevel.PROHIBITED:
            return PolicyDecision(False, False, "skill is prohibited by policy", skill)
        if skill.command_type is CommandType.DESTRUCTIVE:
            return PolicyDecision(
                False,
                False,
                "destructive skills can never execute autonomously",
                skill,
            )
        if device_os.lower() not in {item.lower() for item in skill.supported_os}:
            return PolicyDecision(
                False, False, "skill does not support device OS", skill
            )
        approval = (
            skill.risk in {RiskLevel.MEDIUM, RiskLevel.HIGH}
            or skill.requires_user_approval
            or skill.requires_admin_approval
            or skill.security_sensitive
        )
        return PolicyDecision(
            True,
            approval,
            "allowed by registered skill policy",
            skill,
            automation_level_for(skill, approval),
        )
