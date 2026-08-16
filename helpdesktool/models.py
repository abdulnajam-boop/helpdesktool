"""Typed domain contracts shared by the control plane and endpoint agents."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from types import MappingProxyType
from typing import Any, Mapping
from uuid import uuid4


class RiskLevel(StrEnum):
    READ_ONLY = "read_only"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    PROHIBITED = "prohibited"


class ActionStatus(StrEnum):
    REQUESTED = "requested"
    PENDING_APPROVAL = "pending_approval"
    APPROVED = "approved"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    ROLLED_BACK = "rolled_back"
    ROLLBACK_FAILED = "rollback_failed"
    DENIED = "denied"


@dataclass(frozen=True, slots=True)
class ActionRequest:
    tenant_id: str
    device_id: str
    skill_id: str
    requested_by: str
    parameters: Mapping[str, Any] = field(default_factory=dict)
    correlation_id: str = field(default_factory=lambda: str(uuid4()))

    def __post_init__(self) -> None:
        for name in ("tenant_id", "device_id", "skill_id", "requested_by"):
            if not getattr(self, name).strip():
                raise ValueError(f"{name} must not be empty")
        object.__setattr__(self, "parameters", MappingProxyType(dict(self.parameters)))


@dataclass(frozen=True, slots=True)
class SkillDefinition:
    skill_id: str
    risk: RiskLevel
    supported_os: frozenset[str]
    timeout_seconds: int = 30
    rollback_skill_id: str | None = None

    def __post_init__(self) -> None:
        if not self.skill_id or not self.supported_os:
            raise ValueError("skill_id and supported_os are required")
        if not 1 <= self.timeout_seconds <= 300:
            raise ValueError("timeout_seconds must be between 1 and 300")


@dataclass(frozen=True, slots=True)
class ExecutionResult:
    success: bool
    output: Mapping[str, Any] = field(default_factory=dict)
    error: str | None = None


@dataclass(slots=True)
class ActionRecord:
    request: ActionRequest
    device_os: str
    risk: RiskLevel
    status: ActionStatus
    approved_by: str | None = None
    result: ExecutionResult | None = None
