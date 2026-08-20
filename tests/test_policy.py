import pytest

from helpdesktool.models import (
    ActionRequest,
    AutomationLevel,
    CommandType,
    RiskLevel,
    SkillDefinition,
)
from helpdesktool.policy import PolicyEngine, automation_level_for


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


# --- Phase 2: destructive skills can never execute autonomously ------------


def test_destructive_command_type_is_refused_even_at_read_only_risk():
    """The core Phase 2 safety property: command_type is an independent
    gate from risk tier. A skill mismarked with a low/read-only risk tier
    must still be refused if its command_type is DESTRUCTIVE.
    """
    skill = SkillDefinition(
        "disk.wipe",
        RiskLevel.READ_ONLY,
        frozenset({"linux"}),
        command_type=CommandType.DESTRUCTIVE,
    )
    request = ActionRequest("tenant", "device", skill.skill_id, "user")
    decision = PolicyEngine([skill]).evaluate(request, "linux")
    assert decision.allowed is False
    assert "destructive" in decision.reason


def test_destructive_command_type_is_refused_even_when_approval_would_otherwise_be_required():
    skill = SkillDefinition(
        "disk.wipe",
        RiskLevel.HIGH,
        frozenset({"linux"}),
        command_type=CommandType.DESTRUCTIVE,
    )
    request = ActionRequest("tenant", "device", skill.skill_id, "user")
    decision = PolicyEngine([skill]).evaluate(request, "linux")
    assert decision.allowed is False
    assert decision.approval_required is False


def test_non_destructive_high_risk_skill_is_still_allowed_with_approval():
    skill = SkillDefinition(
        "config.change",
        RiskLevel.HIGH,
        frozenset({"linux"}),
        command_type=CommandType.PRIVILEGED_CHANGE,
    )
    request = ActionRequest("tenant", "device", skill.skill_id, "user")
    decision = PolicyEngine([skill]).evaluate(request, "linux")
    assert decision.allowed is True
    assert decision.approval_required is True


# --- Phase 3: automation-level classification -------------------------------


def test_read_only_skill_is_automation_level_l0():
    skill = SkillDefinition(
        "diagnostics.collect",
        RiskLevel.READ_ONLY,
        frozenset({"linux"}),
        command_type=CommandType.READ_ONLY,
    )
    assert automation_level_for(skill, approval_required=False) is (
        AutomationLevel.L0_OBSERVE_ONLY
    )


def test_reversible_low_risk_skill_with_rollback_is_l2():
    skill = SkillDefinition(
        "service.restart",
        RiskLevel.LOW,
        frozenset({"linux"}),
        rollback_skill_id="service.restore",
        reversible=True,
    )
    assert automation_level_for(skill, approval_required=False) is (
        AutomationLevel.L2_AUTOMATIC_VERIFY_ROLLBACK
    )


def test_low_risk_skill_with_no_rollback_is_l1():
    skill = SkillDefinition("noop.ping", RiskLevel.LOW, frozenset({"linux"}))
    assert automation_level_for(skill, approval_required=False) is (
        AutomationLevel.L1_SAFE_AUTOMATIC
    )


def test_approval_required_skill_is_l3():
    skill = SkillDefinition("service.restart", RiskLevel.MEDIUM, frozenset({"linux"}))
    assert automation_level_for(skill, approval_required=True) is (
        AutomationLevel.L3_USER_APPROVAL
    )


def test_admin_approval_flag_forces_l4_even_over_l3():
    skill = SkillDefinition(
        "config.change",
        RiskLevel.HIGH,
        frozenset({"linux"}),
        requires_admin_approval=True,
    )
    assert automation_level_for(skill, approval_required=True) is (
        AutomationLevel.L4_ADMIN_APPROVAL
    )


def test_security_sensitive_flag_forces_l5_regardless_of_risk_tier():
    """A suspicious event does not automatically mean L5 -- but a skill the
    *registry itself* declares security_sensitive always does, since that
    is the skill's own declared property, not an inferred event severity.
    """
    skill = SkillDefinition(
        "diagnostics.collect",
        RiskLevel.READ_ONLY,
        frozenset({"linux"}),
        security_sensitive=True,
    )
    assert automation_level_for(skill, approval_required=False) is (
        AutomationLevel.L5_SECURITY_INCIDENT
    )


def test_security_containment_command_type_forces_l5():
    skill = SkillDefinition(
        "network.isolate",
        RiskLevel.HIGH,
        frozenset({"linux"}),
        command_type=CommandType.SECURITY_CONTAINMENT,
        requires_admin_approval=True,
    )
    assert automation_level_for(skill, approval_required=True) is (
        AutomationLevel.L5_SECURITY_INCIDENT
    )


def test_policy_evaluate_populates_automation_level_on_the_decision():
    skill = SkillDefinition("service.restart", RiskLevel.MEDIUM, frozenset({"linux"}))
    request = ActionRequest("tenant", "device", skill.skill_id, "user")
    decision = PolicyEngine([skill]).evaluate(request, "linux")
    assert decision.automation_level is AutomationLevel.L3_USER_APPROVAL
