"""Safety state machine coordinating policy, approval, execution, and rollback."""

from __future__ import annotations

from typing import Protocol

from .audit import AuditSink
from .models import (
    ActionRecord,
    ActionRequest,
    ActionStatus,
    ExecutionResult,
    SkillDefinition,
)
from .policy import PolicyEngine


class SkillExecutor(Protocol):
    def execute(
        self, skill: SkillDefinition, request: ActionRequest
    ) -> ExecutionResult: ...
    def verify(
        self, skill: SkillDefinition, request: ActionRequest, result: ExecutionResult
    ) -> bool: ...
    def rollback(
        self, skill: SkillDefinition, request: ActionRequest, result: ExecutionResult
    ) -> ExecutionResult: ...


class ActionOrchestrator:
    def __init__(
        self, policy: PolicyEngine, executor: SkillExecutor, audit: AuditSink
    ) -> None:
        self._policy = policy
        self._executor = executor
        self._audit = audit
        self._actions: dict[str, ActionRecord] = {}

    def submit(self, request: ActionRequest, device_os: str) -> ActionRecord:
        if request.correlation_id in self._actions:
            raise ValueError("correlation_id already exists")
        decision = self._policy.evaluate(request, device_os)
        status = (
            ActionStatus.PENDING_APPROVAL
            if decision.approval_required
            else ActionStatus.APPROVED
            if decision.allowed
            else ActionStatus.DENIED
        )
        risk = decision.skill.risk if decision.skill else self._unknown_risk()
        record = ActionRecord(request, device_os, risk, status)
        self._actions[request.correlation_id] = record
        self._event(
            record,
            "policy.evaluated",
            request.requested_by,
            {
                "allowed": decision.allowed,
                "approval_required": decision.approval_required,
                "reason": decision.reason,
                "risk": risk.value,
            },
        )
        if status is ActionStatus.APPROVED:
            self._run(record, decision.skill)
        return record

    def approve(
        self, tenant_id: str, correlation_id: str, approver_id: str
    ) -> ActionRecord:
        record = self._get_for_tenant(tenant_id, correlation_id)
        if record.status is not ActionStatus.PENDING_APPROVAL:
            raise ValueError("action is not pending approval")
        if approver_id == record.request.requested_by:
            raise PermissionError("requester cannot approve their own action")
        decision = self._policy.evaluate(record.request, record.device_os)
        if not decision.allowed or decision.skill is None:
            record.status = ActionStatus.DENIED
            self._event(
                record, "approval.invalidated", approver_id, {"reason": decision.reason}
            )
            return record
        record.approved_by = approver_id
        record.status = ActionStatus.APPROVED
        self._event(record, "action.approved", approver_id, {})
        self._run(record, decision.skill)
        return record

    def _run(self, record: ActionRecord, skill: SkillDefinition | None) -> None:
        if skill is None:
            raise RuntimeError("approved action has no registered skill")
        record.status = ActionStatus.RUNNING
        self._event(record, "execution.started", "system", {"skill_id": skill.skill_id})
        result = self._executor.execute(skill, record.request)
        record.result = result
        verified = result.success and self._executor.verify(
            skill, record.request, result
        )
        if verified:
            record.status = ActionStatus.SUCCEEDED
            self._event(record, "execution.verified", "system", {"success": True})
            return
        record.status = ActionStatus.FAILED
        self._event(
            record,
            "execution.failed",
            "system",
            {
                "executor_success": result.success,
                "error": result.error,
            },
        )
        if skill.rollback_skill_id is not None:
            rollback = self._executor.rollback(skill, record.request, result)
            record.status = (
                ActionStatus.ROLLED_BACK
                if rollback.success
                else ActionStatus.ROLLBACK_FAILED
            )
            self._event(
                record,
                "rollback.completed",
                "system",
                {
                    "success": rollback.success,
                    "error": rollback.error,
                },
            )

    def _get_for_tenant(self, tenant_id: str, correlation_id: str) -> ActionRecord:
        record = self._actions.get(correlation_id)
        if record is None or record.request.tenant_id != tenant_id:
            raise KeyError("action not found")
        return record

    def _event(
        self, record: ActionRecord, event_type: str, actor_id: str, details: dict
    ) -> None:
        self._audit.append(
            tenant_id=record.request.tenant_id,
            correlation_id=record.request.correlation_id,
            event_type=event_type,
            actor_id=actor_id,
            details=details,
        )

    @staticmethod
    def _unknown_risk():
        from .models import RiskLevel

        return RiskLevel.PROHIBITED
