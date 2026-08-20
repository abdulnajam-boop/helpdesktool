from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field

from .events import EventType


class TenantCreate(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    admin_email: str = Field(min_length=3, max_length=320)


class DeviceEnroll(BaseModel):
    external_id: str = Field(min_length=1, max_length=200)
    hostname: str = Field(min_length=1, max_length=255)
    os: Literal["linux", "windows"]


class DeviceRevoke(BaseModel):
    reason: str = Field(min_length=1, max_length=200)


class EnrollmentTokenCreate(BaseModel):
    label: str = Field(default="", max_length=200)
    ttl_minutes: int = Field(default=60, ge=1, le=10_080)


class HeartbeatCreate(BaseModel):
    status: dict[str, Any] = Field(default_factory=dict)


class InventoryCreate(BaseModel):
    collected_at: datetime
    payload: dict[str, Any]


class LowDiskSimulation(BaseModel):
    device_id: str
    mountpoint: str = Field(default="/", min_length=1, max_length=180)
    used_percent: float = Field(ge=0, le=100)


class TicketCreate(BaseModel):
    title: str = Field(min_length=1, max_length=300)
    description: str = Field(default="", max_length=20_000)
    device_id: str | None = None
    priority: Literal["low", "normal", "high", "critical"] = "normal"


class TicketUpdate(BaseModel):
    title: str | None = Field(default=None, min_length=1, max_length=300)
    description: str | None = Field(default=None, max_length=20_000)
    status: Literal["open", "in_progress", "resolved", "closed"] | None = None
    priority: Literal["low", "normal", "high", "critical"] | None = None


class SkillParameterSpec(BaseModel):
    type: Literal["string", "number", "boolean"]
    required: bool = True


class SkillManifestCreate(BaseModel):
    skill_id: str = Field(min_length=1, max_length=200)
    risk: Literal["read_only", "low", "medium", "high", "prohibited"]
    supported_os: list[Literal["linux", "windows"]] = Field(min_length=1)
    timeout_seconds: int = Field(default=30, ge=1, le=300)
    rollback_skill_id: str | None = Field(default=None, max_length=200)
    parameters: dict[str, SkillParameterSpec] = Field(default_factory=dict)
    # Phase 2 safety metadata -- see helpdesktool/skills.py's SkillManifest
    # docstring for which of these are integrity-hash-covered. A
    # "destructive" command_type is accepted here (it's still meaningful to
    # register and audit one) but PolicyEngine refuses to ever let it
    # execute autonomously, unconditionally, regardless of risk tier.
    command_type: Literal[
        "read_only",
        "low_risk_change",
        "privileged_change",
        "security_containment",
        "destructive",
    ] = "low_risk_change"
    requires_user_approval: bool = False
    requires_admin_approval: bool = False
    security_sensitive: bool = False
    reversible: bool = True
    required_privilege: str = Field(default="", max_length=100)
    preconditions: dict[str, Any] = Field(default_factory=dict)
    expected_output: str = Field(default="", max_length=2000)
    success_condition: str = Field(default="", max_length=2000)
    failure_condition: str = Field(default="", max_length=2000)
    side_effects: str = Field(default="", max_length=2000)
    requires_reboot: bool = False
    allowed_execution_context: str = Field(default="", max_length=100)


class ActionCreate(BaseModel):
    device_id: str
    skill_id: str = Field(min_length=1, max_length=200)
    parameters: dict[str, Any] = Field(default_factory=dict)
    ticket_id: str | None = None


class ApprovalDecision(BaseModel):
    decision: Literal["approve", "deny"]
    reason: str = Field(default="", max_length=2000)


class JobResult(BaseModel):
    success: bool
    verified: bool
    output: dict[str, Any] = Field(default_factory=dict)
    error: str | None = Field(default=None, max_length=4000)
    rollback_attempted: bool = False
    rollback_succeeded: bool | None = None


class ChatMessageCreate(BaseModel):
    message: str = Field(min_length=1, max_length=4000)
    conversation_id: str | None = None


class ConnectorConfigCreate(BaseModel):
    application_id: str = Field(min_length=1, max_length=100, pattern=r"^[a-z0-9_.-]+$")
    display_name: str = Field(min_length=1, max_length=200)
    connector_type: str = Field(min_length=1, max_length=50)
    config: dict[str, Any] = Field(default_factory=dict)
    credential_ref: str = Field(default="", max_length=255)


class ConnectorRequestDecision(BaseModel):
    decision: Literal["approve", "deny"]
    reason: str = Field(default="", max_length=2000)


class WebhookSubscriptionCreate(BaseModel):
    name: str = Field(min_length=1, max_length=100)
    url: str = Field(min_length=1, max_length=2048)
    secret_ref: str = Field(
        pattern=r"^env:HELPDESK_WEBHOOK_SECRET_[A-Z0-9_]+$", max_length=255
    )
    event_types: list[EventType] = Field(min_length=1, max_length=25)
