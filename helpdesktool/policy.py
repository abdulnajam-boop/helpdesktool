"""Default-deny policy evaluation for deterministic endpoint skills."""

from dataclasses import dataclass

from .models import ActionRequest, RiskLevel, SkillDefinition


@dataclass(frozen=True, slots=True)
class PolicyDecision:
    allowed: bool
    approval_required: bool
    reason: str
    skill: SkillDefinition | None = None


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
        if device_os.lower() not in {item.lower() for item in skill.supported_os}:
            return PolicyDecision(
                False, False, "skill does not support device OS", skill
            )
        approval = skill.risk in {RiskLevel.MEDIUM, RiskLevel.HIGH}
        return PolicyDecision(
            True, approval, "allowed by registered skill policy", skill
        )
