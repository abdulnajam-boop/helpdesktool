import pytest

from helpdesktool.models import ActionRequest, RiskLevel, SkillDefinition
from helpdesktool.policy import PolicyEngine


def test_duplicate_skill_ids_fail_closed_at_startup():
    skill = SkillDefinition(
        "diagnostics.collect", RiskLevel.READ_ONLY, frozenset({"linux"})
    )
    with pytest.raises(ValueError, match="duplicate skill_id"):
        PolicyEngine([skill, skill])


def test_missing_os_support_is_denied():
    skill = SkillDefinition(
        "diagnostics.collect", RiskLevel.READ_ONLY, frozenset({"linux"})
    )
    request = ActionRequest("tenant", "device", skill.skill_id, "user")
    decision = PolicyEngine([skill]).evaluate(request, "windows")
    assert decision.allowed is False
    assert decision.reason == "skill does not support device OS"


def test_service_restart_requires_approval():
    skill = SkillDefinition("service.restart", RiskLevel.MEDIUM, frozenset({"linux"}))
    request = ActionRequest("tenant", "device", skill.skill_id, "user")
    decision = PolicyEngine([skill]).evaluate(request, "linux")
    assert decision.allowed is True
    assert decision.approval_required is True
