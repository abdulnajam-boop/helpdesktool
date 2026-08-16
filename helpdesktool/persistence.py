from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from typing import Any, Mapping

from sqlalchemy import select, text
from sqlalchemy.orm import Session

from .audit import AuditEvent
from .db_models import (
    Action,
    AuditEventRow,
    DomainEventRow,
    ExecutionResultRow,
    WebhookDelivery,
    WebhookSubscription,
)
from .events import AUDIT_EVENT_MAPPING, DomainEvent, EventType, sanitize_event_data
from sqlalchemy import select
from sqlalchemy.orm import Session

from .audit import AuditEvent
from .db_models import Action, AuditEventRow, ExecutionResultRow
from .models import (
    ActionRecord,
    ActionRequest,
    ActionStatus,
    ExecutionResult,
    RiskLevel,
)


class SqlActionStore:
    def __init__(self, session: Session, ticket_id: str | None = None) -> None:
        self.session = session
        self.ticket_id = ticket_id

    def add(self, record: ActionRecord) -> None:
        self.session.add(
            Action(
                id=record.request.correlation_id,
                tenant_id=record.request.tenant_id,
                device_id=record.request.device_id,
                ticket_id=self.ticket_id,
                skill_id=record.request.skill_id,
                requested_by=record.request.requested_by,
                parameters=dict(record.request.parameters),
                device_os=record.device_os,
                risk=record.risk.value,
                status=record.status.value,
            )
        )
        self.session.flush()

    def get(self, tenant_id: str, correlation_id: str) -> ActionRecord | None:
        row = self.session.scalar(
            select(Action).where(
                Action.id == correlation_id, Action.tenant_id == tenant_id
            )
        )
        if row is None:
            return None
        result_row = self.session.scalar(
            select(ExecutionResultRow)
            .where(ExecutionResultRow.action_id == row.id)
            .order_by(ExecutionResultRow.created_at.desc())
        )
        result = (
            None
            if result_row is None
            else ExecutionResult(
                result_row.success, result_row.output, result_row.error
            )
        )
        request = ActionRequest(
            row.tenant_id,
            row.device_id,
            row.skill_id,
            row.requested_by,
            row.parameters,
            row.id,
        )
        return ActionRecord(
            request,
            row.device_os,
            RiskLevel(row.risk),
            ActionStatus(row.status),
            row.approved_by,
            result,
        )

    def update(self, record: ActionRecord) -> None:
        row = self.session.get(Action, record.request.correlation_id)
        if row is None or row.tenant_id != record.request.tenant_id:
            raise KeyError("action not found")
        row.status = record.status.value
        row.approved_by = record.approved_by
        if record.result is not None:
            existing = self.session.scalar(
                select(ExecutionResultRow).where(ExecutionResultRow.action_id == row.id)
            )
            if existing is None:
                self.session.add(
                    ExecutionResultRow(
                        tenant_id=row.tenant_id,
                        action_id=row.id,
                        success=record.result.success,
                        output=dict(record.result.output),
                        error=record.result.error,
                    )
                )
        self.session.flush()


class SqlAuditLog:
    def __init__(self, session: Session) -> None:
        self.session = session

    def append(
        self,
        *,
        tenant_id: str,
        correlation_id: str,
        event_type: str,
        actor_id: str,
        details: Mapping[str, Any],
    ) -> AuditEvent:
        bind = self.session.get_bind()
        if bind.dialect.name == "postgresql":
            # Serialize each tenant's hash-chain head within this transaction.
            self.session.execute(
                text("SELECT pg_advisory_xact_lock(hashtextextended(:tenant_id, 0))"),
                {"tenant_id": tenant_id},
            )
        last = self.session.scalar(
            select(AuditEventRow)
            .where(AuditEventRow.tenant_id == tenant_id)
            .order_by(AuditEventRow.sequence.desc())
            .limit(1)
        )
        sequence = 1 if last is None else last.sequence + 1
        previous_hash = "0" * 64 if last is None else last.event_hash
        occurred_at = datetime.now(UTC)
        payload = {
            "sequence": sequence,
            "occurred_at": occurred_at.isoformat(),
            "tenant_id": tenant_id,
            "correlation_id": correlation_id,
            "event_type": event_type,
            "actor_id": actor_id,
            "details": dict(details),
            "previous_hash": previous_hash,
        }
        event_hash = hashlib.sha256(
            json.dumps(
                payload, sort_keys=True, separators=(",", ":"), default=str
            ).encode()
        ).hexdigest()
        self.session.add(
            AuditEventRow(
                sequence=sequence,
                occurred_at=occurred_at,
                tenant_id=tenant_id,
                correlation_id=correlation_id,
                event_type=event_type,
                actor_id=actor_id,
                details=dict(details),
                previous_hash=previous_hash,
                event_hash=event_hash,
            )
        )
        self.session.flush()
        mapped_type = AUDIT_EVENT_MAPPING.get(event_type)
        if mapped_type is not None:
            self._publish(
                DomainEvent.create(
                    tenant_id,
                    mapped_type,
                    correlation_id,
                    {"actor_id": actor_id, **sanitize_event_data(details)},
                )
            )
        if (
            event_type == "policy.evaluated"
            and details.get("approval_required") is True
        ):
            self._publish(
                DomainEvent.create(
                    tenant_id,
                    EventType.APPROVAL_REQUIRED,
                    correlation_id,
                    {"actor_id": actor_id, **sanitize_event_data(details)},
                )
            )
        return AuditEvent(
            sequence=sequence,
            occurred_at=occurred_at.isoformat(),
            tenant_id=tenant_id,
            correlation_id=correlation_id,
            event_type=event_type,
            actor_id=actor_id,
            details=dict(details),
            previous_hash=previous_hash,
            event_hash=event_hash,
        )

    def _publish(self, event: DomainEvent) -> None:
        self.session.add(
            DomainEventRow(
                id=event.id,
                tenant_id=event.tenant_id,
                event_type=event.event_type.value,
                subject_id=event.subject_id,
                schema_version=event.schema_version,
                data=dict(event.data),
                occurred_at=event.occurred_at,
            )
        )
        subscriptions = self.session.scalars(
            select(WebhookSubscription).where(
                WebhookSubscription.tenant_id == event.tenant_id,
                WebhookSubscription.active.is_(True),
            )
        ).all()
        for subscription in subscriptions:
            if event.event_type.value in subscription.event_types:
                self.session.add(
                    WebhookDelivery(
                        tenant_id=event.tenant_id,
                        event_id=event.id,
                        subscription_id=subscription.id,
                    )
                )
        self.session.flush()
