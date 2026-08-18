"""Deterministic, tenant-scoped incident correlation and low-disk detection."""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any, cast

from sqlalchemy import select
from sqlalchemy.orm import Session

from .config import Settings
from .db_models import Incident, Ticket, User
from .persistence import SqlAuditLog


def detect_inventory_incidents(
    session: Session,
    tenant_id: str,
    device_id: str,
    payload: dict[str, Any],
    observed_at: datetime,
    settings: Settings,
) -> list[Incident]:
    incidents: list[Incident] = []
    filesystems = payload.get("filesystems", [])
    if not isinstance(filesystems, list):
        return incidents
    for filesystem in filesystems:
        if not isinstance(filesystem, dict):
            continue
        total = filesystem.get("total_bytes")
        free = filesystem.get("free_bytes")
        if not isinstance(total, (int, float)) or not isinstance(free, (int, float)):
            continue
        if total <= 0 or free < 0 or free > total:
            continue
        used_percent = round((total - free) * 100 / total, 2)
        mountpoint = str(filesystem.get("mountpoint", "unknown"))[:180]
        if used_percent < settings.low_disk_threshold_percent:
            resolve_recovered_incident(
                session,
                tenant_id=tenant_id,
                device_id=device_id,
                correlation_key=f"low_disk_space:{mountpoint}",
                observed_at=observed_at,
                evidence={
                    "device_id": device_id,
                    "filesystem": mountpoint,
                    "used_percent": used_percent,
                    "free_bytes": int(free),
                    "total_bytes": int(total),
                    "threshold_percent": settings.low_disk_threshold_percent,
                    "observed_at": observed_at.isoformat(),
                },
            )
            continue
        evidence = {
            "device_id": device_id,
            "filesystem": mountpoint,
            "used_percent": used_percent,
            "free_bytes": int(free),
            "total_bytes": int(total),
            "threshold_percent": settings.low_disk_threshold_percent,
            "observed_at": observed_at.isoformat(),
        }
        incidents.append(
            correlate_incident(
                session,
                tenant_id=tenant_id,
                device_id=device_id,
                incident_type="low_disk_space",
                severity="critical" if used_percent >= 95 else "high",
                summary=f"Low disk space on {mountpoint}",
                correlation_key=f"low_disk_space:{mountpoint}",
                evidence=evidence,
                observed_at=observed_at,
                correlation_hours=settings.incident_correlation_hours,
            )
        )
    return incidents


def resolve_recovered_incident(
    session: Session,
    *,
    tenant_id: str,
    device_id: str,
    correlation_key: str,
    observed_at: datetime,
    evidence: dict[str, Any],
) -> Incident | None:
    row = cast(
        Incident | None,
        session.scalar(
            select(Incident)
            .where(
                Incident.tenant_id == tenant_id,
                Incident.device_id == device_id,
                Incident.correlation_key == correlation_key,
                Incident.status.in_(["open", "investigating"]),
            )
            .order_by(Incident.last_observed_at.desc())
        ),
    )
    if row is None:
        return None
    row.status = "resolved"
    row.resolved_at = observed_at
    row.last_observed_at = observed_at
    row.evidence = evidence
    if row.ticket_id:
        ticket = session.scalar(
            select(Ticket).where(
                Ticket.id == row.ticket_id, Ticket.tenant_id == tenant_id
            )
        )
        if ticket is not None:
            ticket.status = "resolved"
            SqlAuditLog(session).append(
                tenant_id=tenant_id,
                correlation_id=ticket.id,
                event_type="ticket.resolved",
                actor_id="system:detector",
                details={
                    "device_id": device_id,
                    "incident_id": row.id,
                    "reason": "linked incident recovered",
                },
            )
    SqlAuditLog(session).append(
        tenant_id=tenant_id,
        correlation_id=row.id,
        event_type="incident.resolved",
        actor_id="system:detector",
        details={
            "device_id": device_id,
            "ticket_id": row.ticket_id,
            "reason": "filesystem utilization recovered below threshold",
            "evidence": evidence,
        },
    )
    return row


def correlate_incident(
    session: Session,
    *,
    tenant_id: str,
    device_id: str,
    incident_type: str,
    severity: str,
    summary: str,
    correlation_key: str,
    evidence: dict[str, Any],
    observed_at: datetime,
    correlation_hours: int,
) -> Incident:
    cutoff = observed_at - timedelta(hours=correlation_hours)
    row = cast(
        Incident | None,
        session.scalar(
            select(Incident)
            .where(
                Incident.tenant_id == tenant_id,
                Incident.device_id == device_id,
                Incident.incident_type == incident_type,
                Incident.correlation_key == correlation_key,
                Incident.last_observed_at >= cutoff,
            )
            .order_by(Incident.last_observed_at.desc())
        ),
    )
    audit = SqlAuditLog(session)
    if row is not None:
        previous_status = row.status
        row.last_observed_at = observed_at
        row.occurrence_count += 1
        row.evidence = evidence
        row.severity = severity
        if row.status in {"resolved", "closed"}:
            row.status = "open"
            row.resolved_at = None
            event_type = "incident.reopened"
        else:
            event_type = "incident.updated"
        audit.append(
            tenant_id=tenant_id,
            correlation_id=row.id,
            event_type=event_type,
            actor_id="system:detector",
            details={
                "device_id": device_id,
                "previous_status": previous_status,
                "new_status": row.status,
                "occurrence_count": row.occurrence_count,
                "severity": severity,
                "evidence": evidence,
            },
        )
        return row

    owner = session.scalar(
        select(User)
        .where(User.tenant_id == tenant_id, User.active.is_(True))
        .order_by((User.role == "owner").desc())
    )
    if owner is None:
        raise RuntimeError(
            "incident cannot create a ticket without an active tenant user"
        )
    ticket = Ticket(
        tenant_id=tenant_id,
        device_id=device_id,
        title=summary,
        description="Automatically created from deterministic endpoint telemetry.",
        priority="critical" if severity == "critical" else "high",
        created_by=owner.id,
    )
    session.add(ticket)
    session.flush()
    row = Incident(
        tenant_id=tenant_id,
        device_id=device_id,
        ticket_id=ticket.id,
        incident_type=incident_type,
        severity=severity,
        status="open",
        summary=summary,
        evidence=evidence,
        correlation_key=correlation_key,
        occurrence_count=1,
        first_observed_at=observed_at,
        last_observed_at=observed_at,
    )
    session.add(row)
    session.flush()
    audit.append(
        tenant_id=tenant_id,
        correlation_id=ticket.id,
        event_type="ticket.created",
        actor_id="system:detector",
        details={"device_id": device_id, "title": summary, "priority": ticket.priority},
    )
    audit.append(
        tenant_id=tenant_id,
        correlation_id=row.id,
        event_type="incident.created",
        actor_id="system:detector",
        details={
            "device_id": device_id,
            "ticket_id": ticket.id,
            "severity": severity,
            "evidence": evidence,
        },
    )
    return row


def incident_json(row: Incident) -> dict[str, Any]:
    return {
        "id": row.id,
        "device_id": row.device_id,
        "ticket_id": row.ticket_id,
        "incident_type": row.incident_type,
        "severity": row.severity,
        "status": row.status,
        "summary": row.summary,
        "evidence": row.evidence,
        "correlation_key": row.correlation_key,
        "occurrence_count": row.occurrence_count,
        "first_observed_at": row.first_observed_at.isoformat(),
        "last_observed_at": row.last_observed_at.isoformat(),
        "resolved_at": row.resolved_at.isoformat() if row.resolved_at else None,
        "created_at": row.created_at.isoformat() if row.created_at else None,
        "updated_at": row.updated_at.isoformat() if row.updated_at else None,
    }
