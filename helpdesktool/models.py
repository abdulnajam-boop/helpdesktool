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


class CommandType(StrEnum):
    """A second, independent safety dimension from ``RiskLevel``: what
    *class* of change a skill makes, not how risky policy considers it.
    ``PolicyEngine`` hard-blocks ``DESTRUCTIVE`` unconditionally — see its
    module docstring — regardless of what risk tier a manifest claims,
    so a future skill mismarked as low-risk can never make a destructive
    change autonomously "by accident."
    """

    READ_ONLY = "read_only"
    LOW_RISK_CHANGE = "low_risk_change"
    PRIVILEGED_CHANGE = "privileged_change"
    SECURITY_CONTAINMENT = "security_containment"
    DESTRUCTIVE = "destructive"


class AutomationLevel(StrEnum):
    """How much human involvement a given action needs before/while it
    runs -- a distinct concept from ``RiskLevel``/``CommandType`` (how
    risky/what class of change) and from ``SecurityClassification``
    (what the evidence suggests is happening). A suspicious event does not
    automatically mean L5, and a low-risk read-only skill is always L0/L1
    regardless of what triggered it.
    """

    L0_OBSERVE_ONLY = "l0_observe_only"
    L1_SAFE_AUTOMATIC = "l1_safe_automatic"
    L2_AUTOMATIC_VERIFY_ROLLBACK = "l2_automatic_verify_rollback"
    L3_USER_APPROVAL = "l3_user_approval"
    L4_ADMIN_APPROVAL = "l4_admin_approval"
    L5_SECURITY_INCIDENT = "l5_security_incident"


class SecurityClassification(StrEnum):
    """What correlated evidence suggests about an incident/device state.
    Never assigned from a single weak signal alone (high CPU, a port
    number, PowerShell, an unsigned binary, one failed login, ...) -- see
    ``helpdesktool/security_classification.py``'s module docstring for the
    correlation rules that actually assign this.
    """

    NORMAL = "normal"
    UNKNOWN = "unknown"
    MISCONFIGURATION = "misconfiguration"
    POLICY_VIOLATION = "policy_violation"
    SUSPICIOUS = "suspicious"
    LIKELY_COMPROMISED = "likely_compromised"
    CONFIRMED_COMPROMISE = "confirmed_compromise"


class ActionStatus(StrEnum):
    REQUESTED = "requested"
    PENDING_APPROVAL = "pending_approval"
    APPROVED = "approved"
    QUEUED = "queued"
    CLAIMED = "claimed"
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
    command_type: CommandType = CommandType.LOW_RISK_CHANGE
    requires_user_approval: bool = False
    requires_admin_approval: bool = False
    security_sensitive: bool = False
    reversible: bool = True

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
