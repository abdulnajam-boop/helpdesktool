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


class WebhookSubscriptionCreate(BaseModel):
    name: str = Field(min_length=1, max_length=100)
    url: str = Field(min_length=1, max_length=2048)
    secret_ref: str = Field(
        pattern=r"^env:HELPDESK_WEBHOOK_SECRET_[A-Z0-9_]+$", max_length=255
    )
    event_types: list[EventType] = Field(min_length=1, max_length=25)
