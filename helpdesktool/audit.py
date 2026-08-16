"""Append-only, hash-chained audit event store contract and in-memory adapter."""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from threading import Lock
from typing import Any, Mapping, Protocol


@dataclass(frozen=True, slots=True)
class AuditEvent:
    sequence: int
    occurred_at: str
    tenant_id: str
    correlation_id: str
    event_type: str
    actor_id: str
    details: Mapping[str, Any]
    previous_hash: str
    event_hash: str


class AuditSink(Protocol):
    def append(
        self,
        *,
        tenant_id: str,
        correlation_id: str,
        event_type: str,
        actor_id: str,
        details: Mapping[str, Any],
    ) -> AuditEvent: ...


class InMemoryAuditLog:
    """Reference adapter. Production must persist these events in append-only storage."""

    def __init__(self) -> None:
        self._events: list[AuditEvent] = []
        self._lock = Lock()

    @property
    def events(self) -> tuple[AuditEvent, ...]:
        return tuple(self._events)

    def append(
        self,
        *,
        tenant_id: str,
        correlation_id: str,
        event_type: str,
        actor_id: str,
        details: Mapping[str, Any],
    ) -> AuditEvent:
        with self._lock:
            sequence = len(self._events) + 1
            occurred_at = datetime.now(UTC).isoformat()
            previous_hash = self._events[-1].event_hash if self._events else "0" * 64
            payload = {
                "sequence": sequence,
                "occurred_at": occurred_at,
                "tenant_id": tenant_id,
                "correlation_id": correlation_id,
                "event_type": event_type,
                "actor_id": actor_id,
                "details": dict(details),
                "previous_hash": previous_hash,
            }
            digest = hashlib.sha256(
                json.dumps(
                    payload, sort_keys=True, separators=(",", ":"), default=str
                ).encode()
            ).hexdigest()
            event = AuditEvent(
                sequence=sequence,
                occurred_at=occurred_at,
                tenant_id=tenant_id,
                correlation_id=correlation_id,
                event_type=event_type,
                actor_id=actor_id,
                details=dict(details),
                previous_hash=previous_hash,
                event_hash=digest,
            )
            event = AuditEvent(**payload, event_hash=digest)
            self._events.append(event)
            return event

    def verify_chain(self) -> bool:
        previous_hash = "0" * 64
        for event in self._events:
            payload = asdict(event)
            event_hash = payload.pop("event_hash")
            if payload["previous_hash"] != previous_hash:
                return False
            digest = hashlib.sha256(
                json.dumps(
                    payload, sort_keys=True, separators=(",", ":"), default=str
                ).encode()
            ).hexdigest()
            if digest != event_hash:
                return False
            previous_hash = event_hash
        return True
