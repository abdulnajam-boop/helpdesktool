from helpdesktool.audit import InMemoryAuditLog
from helpdesktool.models import (
    ActionRequest,
    ActionStatus,
    ExecutionResult,
    RiskLevel,
    SkillDefinition,
)
from helpdesktool.orchestrator import ActionOrchestrator
from helpdesktool.policy import PolicyEngine


class FakeExecutor:
    def __init__(self, *, success=True, verified=True, rollback_success=True):
        self.success = success
        self.verified = verified
        self.rollback_success = rollback_success
        self.executions = 0

    def execute(self, skill, request):
        self.executions += 1
        return ExecutionResult(
            self.success, {"bounded": "output"}, None if self.success else "failed"
        )

    def verify(self, skill, request, result):
        return self.verified

    def rollback(self, skill, request, result):
        return ExecutionResult(self.rollback_success)


def build(risk=RiskLevel.LOW, **executor_options):
    skill = SkillDefinition(
        "service.restart",
        risk,
        frozenset({"linux", "windows"}),
        rollback_skill_id="service.restore",
    )
    audit = InMemoryAuditLog()
    executor = FakeExecutor(**executor_options)
    return ActionOrchestrator(PolicyEngine([skill]), executor, audit), executor, audit


def request(skill_id="service.restart", **parameters):
    return ActionRequest("tenant-a", "device-1", skill_id, "operator-1", parameters)


def test_unknown_skill_is_denied_without_execution():
    orchestrator, executor, audit = build()
    record = orchestrator.submit(request("shell.arbitrary"), "linux")
    assert record.status is ActionStatus.DENIED
    assert record.risk is RiskLevel.PROHIBITED
    assert executor.executions == 0
    assert audit.verify_chain()


def test_low_risk_action_executes_and_verifies():
    orchestrator, executor, audit = build()
    record = orchestrator.submit(request(), "linux")
    assert record.status is ActionStatus.SUCCEEDED
    assert executor.executions == 1
    assert [event.event_type for event in audit.events] == [
        "policy.evaluated",
        "execution.started",
        "execution.verified",
    ]
    assert audit.verify_chain()


def test_medium_risk_requires_independent_approval():
    orchestrator, executor, _ = build(RiskLevel.MEDIUM)
    record = orchestrator.submit(request(), "linux")
    assert record.status is ActionStatus.PENDING_APPROVAL
    assert executor.executions == 0

    try:
        orchestrator.approve("tenant-a", record.request.correlation_id, "operator-1")
        raise AssertionError("self approval should fail")
    except PermissionError:
        pass

    record = orchestrator.approve(
        "tenant-a", record.request.correlation_id, "approver-2"
    )
    assert record.status is ActionStatus.SUCCEEDED
    assert record.approved_by == "approver-2"


def test_failed_verification_triggers_rollback():
    orchestrator, _, audit = build(verified=False)
    record = orchestrator.submit(request(), "linux")
    assert record.status is ActionStatus.ROLLED_BACK
    assert audit.events[-1].event_type == "rollback.completed"


def test_cross_tenant_approval_is_hidden():
    orchestrator, _, _ = build(RiskLevel.HIGH)
    record = orchestrator.submit(request(), "linux")
    try:
        orchestrator.approve("tenant-b", record.request.correlation_id, "approver-2")
        raise AssertionError("cross-tenant access should fail")
    except KeyError:
        pass
