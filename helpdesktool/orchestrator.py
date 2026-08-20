"""Safety state machine coordinating policy, approval, execution, and rollback."""

from __future__ import annotations

from typing import Any, Protocol

from .audit import AuditSink
from .models import (
    ActionRecord,
    ActionRequest,
    ActionStatus,
    ExecutionResult,
    RiskLevel,
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


class ActionStore(Protocol):
    def add(self, record: ActionRecord) -> None: ...
    def get(self, tenant_id: str, correlation_id: str) -> ActionRecord | None: ...
    def update(self, record: ActionRecord) -> None: ...


class ActionOrchestrator:
    def __init__(
        self,
        policy: PolicyEngine,
        executor: SkillExecutor,
        audit: AuditSink,
        action_store: ActionStore | None = None,
        execute_immediately: bool = True,
    ) -> None:
        self._policy = policy
        self._executor = executor
        self._audit = audit
        self._actions: dict[str, ActionRecord] = {}
        self._action_store = action_store
        self._execute_immediately = execute_immediately

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
        if self._action_store:
            self._action_store.add(record)
        self._event(
            record,
            "policy.evaluated",
            request.requested_by,
            {
                "allowed": decision.allowed,
                "approval_required": decision.approval_required,
                "reason": decision.reason,
                "risk": risk.value,
                "automation_level": decision.automation_level.value,
            },
        )
        if status is ActionStatus.APPROVED:
            self._execute_or_queue(record, decision.skill)
        self._persist(record)
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
            self._persist(record)
            return record
        record.approved_by = approver_id
        record.status = ActionStatus.APPROVED
        self._event(
            record,
            "action.approved",
            approver_id,
            {
                "previous_status": ActionStatus.PENDING_APPROVAL.value,
                "new_status": ActionStatus.APPROVED.value,
            },
        )
        self._execute_or_queue(record, decision.skill)
        self._persist(record)
        return record

    def _execute_or_queue(
        self, record: ActionRecord, skill: SkillDefinition | None
    ) -> None:
        if self._execute_immediately:
            self._run(record, skill)
            return
        record.status = ActionStatus.QUEUED
        self._event(
            record,
            "execution.queued",
            "system",
            {
                "skill_id": record.request.skill_id,
                "previous_status": ActionStatus.APPROVED.value,
                "new_status": ActionStatus.QUEUED.value,
            },
        )

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
        if record is None and self._action_store:
            record = self._action_store.get(tenant_id, correlation_id)
        if record is None or record.request.tenant_id != tenant_id:
            raise KeyError("action not found")
        return record

    def deny(
        self, tenant_id: str, correlation_id: str, actor_id: str, reason: str
    ) -> ActionRecord:
        record = self._get_for_tenant(tenant_id, correlation_id)
        if record.status is not ActionStatus.PENDING_APPROVAL:
            raise ValueError("action is not pending approval")
        record.status = ActionStatus.DENIED
        self._event(
            record,
            "action.denied",
            actor_id,
            {
                "reason": reason,
                "previous_status": ActionStatus.PENDING_APPROVAL.value,
                "new_status": ActionStatus.DENIED.value,
            },
        )
        self._persist(record)
        return record

    def _persist(self, record: ActionRecord) -> None:
        if self._action_store:
            self._action_store.update(record)

    def _event(
        self,
        record: ActionRecord,
        event_type: str,
        actor_id: str,
        details: dict[str, Any],
    ) -> None:
        self._audit.append(
            tenant_id=record.request.tenant_id,
            correlation_id=record.request.correlation_id,
            event_type=event_type,
            actor_id=actor_id,
            details=details,
        )

    @staticmethod
    def _unknown_risk() -> RiskLevel:
        return RiskLevel.PROHIBITED
