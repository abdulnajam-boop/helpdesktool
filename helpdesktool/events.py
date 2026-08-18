"""Canonical domain events and transactional publication helpers."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any, Mapping
from uuid import uuid4


class EventType(StrEnum):
    DEVICE_REGISTERED = "device.registered"
    DEVICE_ONLINE = "device.online"
    DEVICE_OFFLINE = "device.offline"
    DEVICE_HEALTH_WARNING = "device.health.warning"
    INCIDENT_CREATED = "incident.created"
    INCIDENT_UPDATED = "incident.updated"
    INCIDENT_RESOLVED = "incident.resolved"
    INCIDENT_REOPENED = "incident.reopened"
    REMEDIATION_REQUESTED = "remediation.requested"
    REMEDIATION_STARTED = "remediation.started"
    REMEDIATION_SUCCEEDED = "remediation.succeeded"
    REMEDIATION_FAILED = "remediation.failed"
    REMEDIATION_ROLLED_BACK = "remediation.rolled_back"
    APPROVAL_REQUIRED = "approval.required"
    APPROVAL_APPROVED = "approval.approved"
    APPROVAL_DENIED = "approval.denied"
    TICKET_CREATED = "ticket.created"
    TICKET_ESCALATED = "ticket.escalated"
    SECURITY_ALERT = "security.alert"


AUDIT_EVENT_MAPPING: dict[str, EventType] = {
    "device.enrolled": EventType.DEVICE_REGISTERED,
    "policy.evaluated": EventType.REMEDIATION_REQUESTED,
    "action.approved": EventType.APPROVAL_APPROVED,
    "action.denied": EventType.APPROVAL_DENIED,
    "execution.queued": EventType.REMEDIATION_STARTED,
    "execution.verified": EventType.REMEDIATION_SUCCEEDED,
    "execution.failed": EventType.REMEDIATION_FAILED,
    "rollback.completed": EventType.REMEDIATION_ROLLED_BACK,
    "ticket.created": EventType.TICKET_CREATED,
    "incident.created": EventType.INCIDENT_CREATED,
    "incident.updated": EventType.INCIDENT_UPDATED,
    "incident.reopened": EventType.INCIDENT_REOPENED,
    "incident.resolved": EventType.INCIDENT_RESOLVED,
    "action.escalation_required": EventType.TICKET_ESCALATED,
}

SENSITIVE_KEYS = {
    "authorization",
    "password",
    "secret",
    "token",
    "agent_token",
    "claim_token",
}


def sanitize_event_data(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {
            str(key): "[REDACTED]"
            if str(key).lower() in SENSITIVE_KEYS
            else sanitize_event_data(item)
            for key, item in value.items()
        }
    if isinstance(value, (list, tuple)):
        return [sanitize_event_data(item) for item in value]
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    return str(value)


@dataclass(frozen=True, slots=True)
class DomainEvent:
    id: str
    tenant_id: str
    event_type: EventType
    subject_id: str
    occurred_at: datetime
    data: Mapping[str, Any]
    schema_version: int = 1

    @classmethod
    def create(
        cls,
        tenant_id: str,
        event_type: EventType,
        subject_id: str,
        data: Mapping[str, Any],
    ) -> "DomainEvent":
        return cls(
            str(uuid4()),
            tenant_id,
            event_type,
            subject_id,
            datetime.now(UTC),
            dict(data),
        )

    def envelope(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "tenant_id": self.tenant_id,
            "type": self.event_type.value,
            "subject_id": self.subject_id,
            "occurred_at": self.occurred_at.isoformat(),
            "schema_version": self.schema_version,
            "data": dict(self.data),
        }
