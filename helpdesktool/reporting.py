"""Tenant-scoped operational reporting (Section 8's "autonomous help desk
manager" reporting layer).

Computed on demand from the database for an operator-supplied period,
mirroring ``metrics.py``'s "always recomputed, never incremented at call
sites" rationale: a report is a read over facts that already exist
(incidents, tickets, execution results, approvals), never a separately
maintained running total that could drift from what actually happened.
There is deliberately no scheduled "generate and store a daily snapshot"
worker in this pass -- an operator (or an automation calling this same
endpoint on a cron) asks for a period and gets an answer that is always
exactly consistent with the database, which is a stronger guarantee than a
stored snapshot that ages the moment something is corrected after the
fact.

Every number here is either a plain ``COUNT``/``AVG`` over a real column or
an explicit ratio of two such counts -- nothing is estimated, inferred from
free text, or produced by the AI diagnosis provider. See Section 8's
"AI may summarize but never fabricate metrics": this module has no AI
involvement at all, by design, so that constraint can never be violated by
construction.

Distinguishing a policy-engine denial from an operator (approval) denial
matters for the security-relevant counts below, but ``Action.status``
alone can't tell them apart -- ``PolicyEngine`` and ``ActionOrchestrator.
deny()`` both set the same terminal ``"denied"`` status (see
``orchestrator.py``). The only reliable signal is whether a matching
``Approval`` row exists: an operator denial always has one (the approval
endpoint is what creates a `Approval` row), while a policy denial never
reaches the approval step at all. ``_security_stats`` below uses exactly
that anti-join rather than the ambiguous ``Action.status`` reading.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from .db_models import (
    Action,
    Approval,
    Device,
    ExecutionResultRow,
    Incident,
    Ticket,
)
from .metrics import DEVICE_ONLINE_THRESHOLD


def _mean_seconds(pairs: list[tuple[datetime, datetime]]) -> float | None:
    if not pairs:
        return None
    total = 0.0
    for start, end in pairs:
        s = start if start.tzinfo else start.replace(tzinfo=UTC)
        e = end if end.tzinfo else end.replace(tzinfo=UTC)
        total += (e - s).total_seconds()
    return total / len(pairs)


def _incident_stats(
    session: Session, tenant_id: str, start: datetime, end: datetime
) -> dict[str, Any]:
    detected = (
        session.scalar(
            select(func.count())
            .select_from(Incident)
            .where(
                Incident.tenant_id == tenant_id,
                Incident.created_at >= start,
                Incident.created_at < end,
            )
        )
        or 0
    )
    resolved_pairs = session.execute(
        select(Incident.first_observed_at, Incident.resolved_at).where(
            Incident.tenant_id == tenant_id,
            Incident.resolved_at.is_not(None),
            Incident.resolved_at >= start,
            Incident.resolved_at < end,
        )
    ).all()
    reopened = (
        session.scalar(
            select(func.count())
            .select_from(Incident)
            .where(
                Incident.tenant_id == tenant_id,
                Incident.occurrence_count > 1,
                Incident.last_observed_at >= start,
                Incident.last_observed_at < end,
            )
        )
        or 0
    )
    open_now = (
        session.scalar(
            select(func.count())
            .select_from(Incident)
            .where(Incident.tenant_id == tenant_id, Incident.status != "resolved")
        )
        or 0
    )
    mttr_pairs = [
        (row.first_observed_at, row.resolved_at)
        for row in resolved_pairs
        if row.resolved_at is not None
    ]
    return {
        "detected": detected,
        "resolved": len(resolved_pairs),
        "reopened": reopened,
        "open_now": open_now,
        "mttr_seconds": _mean_seconds(mttr_pairs),
    }


def _ticket_stats(
    session: Session, tenant_id: str, start: datetime, end: datetime
) -> dict[str, Any]:
    opened = (
        session.scalar(
            select(func.count())
            .select_from(Ticket)
            .where(
                Ticket.tenant_id == tenant_id,
                Ticket.created_at >= start,
                Ticket.created_at < end,
            )
        )
        or 0
    )
    resolved = (
        session.scalar(
            select(func.count())
            .select_from(Ticket)
            .where(
                Ticket.tenant_id == tenant_id,
                Ticket.status == "resolved",
                Ticket.updated_at >= start,
                Ticket.updated_at < end,
            )
        )
        or 0
    )
    open_now = (
        session.scalar(
            select(func.count())
            .select_from(Ticket)
            .where(Ticket.tenant_id == tenant_id, Ticket.status != "resolved")
        )
        or 0
    )
    return {"opened": opened, "resolved": resolved, "open_now": open_now}


def _remediation_stats(
    session: Session, tenant_id: str, start: datetime, end: datetime
) -> dict[str, Any]:
    rows = session.execute(
        select(
            ExecutionResultRow.success,
            ExecutionResultRow.rollback_attempted,
            ExecutionResultRow.rollback_succeeded,
        ).where(
            ExecutionResultRow.tenant_id == tenant_id,
            ExecutionResultRow.created_at >= start,
            ExecutionResultRow.created_at < end,
        )
    ).all()
    attempts = len(rows)
    succeeded = sum(1 for r in rows if r.success)
    failed = attempts - succeeded
    rollback_attempted = sum(1 for r in rows if r.rollback_attempted)
    rollback_succeeded = sum(
        1 for r in rows if r.rollback_attempted and r.rollback_succeeded
    )
    return {
        "attempts": attempts,
        "succeeded": succeeded,
        "failed": failed,
        "success_rate": (succeeded / attempts) if attempts else None,
        "rollback_attempted": rollback_attempted,
        "rollback_succeeded": rollback_succeeded,
    }


def _approval_stats(
    session: Session, tenant_id: str, start: datetime, end: datetime
) -> dict[str, Any]:
    rows = session.execute(
        select(Approval.decision, Approval.decided_at, Action.created_at)
        .join(Action, Action.id == Approval.action_id)
        .where(
            Approval.tenant_id == tenant_id,
            Approval.decided_at >= start,
            Approval.decided_at < end,
        )
    ).all()
    approved = sum(1 for r in rows if r.decision == "approve")
    denied = sum(1 for r in rows if r.decision == "deny")
    pairs = [(r.created_at, r.decided_at) for r in rows]
    return {
        "approved": approved,
        "denied": denied,
        "avg_time_to_decision_seconds": _mean_seconds(pairs),
    }


def _device_stats(session: Session, tenant_id: str) -> dict[str, Any]:
    online_cutoff = datetime.now(UTC) - DEVICE_ONLINE_THRESHOLD
    total = (
        session.scalar(
            select(func.count())
            .select_from(Device)
            .where(Device.tenant_id == tenant_id, Device.active.is_(True))
        )
        or 0
    )
    online = (
        session.scalar(
            select(func.count())
            .select_from(Device)
            .where(
                Device.tenant_id == tenant_id,
                Device.active.is_(True),
                Device.last_seen_at.is_not(None),
                Device.last_seen_at >= online_cutoff,
            )
        )
        or 0
    )
    return {"total": total, "online": online, "offline": total - online}


def _security_stats(
    session: Session, tenant_id: str, start: datetime, end: datetime
) -> dict[str, Any]:
    approval_denials = (
        session.scalar(
            select(func.count())
            .select_from(Approval)
            .where(
                Approval.tenant_id == tenant_id,
                Approval.decision == "deny",
                Approval.decided_at >= start,
                Approval.decided_at < end,
            )
        )
        or 0
    )
    approved_action_ids = select(Approval.action_id).where(
        Approval.tenant_id == tenant_id
    )
    policy_denials = (
        session.scalar(
            select(func.count())
            .select_from(Action)
            .where(
                Action.tenant_id == tenant_id,
                Action.status == "denied",
                Action.created_at >= start,
                Action.created_at < end,
                Action.id.not_in(approved_action_ids),
            )
        )
        or 0
    )
    return {"policy_denials": policy_denials, "approval_denials": approval_denials}


def _recurring_incidents(
    session: Session, tenant_id: str, limit: int = 10
) -> list[dict[str, Any]]:
    rows = session.execute(
        select(
            Incident.device_id,
            Incident.incident_type,
            Incident.occurrence_count,
            Incident.status,
            Incident.last_observed_at,
        )
        .where(Incident.tenant_id == tenant_id, Incident.occurrence_count > 1)
        .order_by(Incident.occurrence_count.desc())
        .limit(limit)
    ).all()
    return [
        {
            "device_id": r.device_id,
            "incident_type": r.incident_type,
            "occurrence_count": r.occurrence_count,
            "status": r.status,
            "last_observed_at": r.last_observed_at,
        }
        for r in rows
    ]


def build_report(
    session: Session, tenant_id: str, start: datetime, end: datetime
) -> dict[str, Any]:
    """Assembles the full operational report for ``[start, end)``.

    ``devices`` is a current snapshot (online/offline is inherently "as of
    now", not something that can be re-derived for a past period) --
    everything else is bounded strictly to the requested window.
    """
    if end <= start:
        raise ValueError("end must be after start")
    return {
        "period": {"start": start, "end": end},
        "incidents": _incident_stats(session, tenant_id, start, end),
        "tickets": _ticket_stats(session, tenant_id, start, end),
        "remediation": _remediation_stats(session, tenant_id, start, end),
        "approvals": _approval_stats(session, tenant_id, start, end),
        "devices": _device_stats(session, tenant_id),
        "security": _security_stats(session, tenant_id, start, end),
        "recurring_incidents": _recurring_incidents(session, tenant_id),
    }


__all__ = ["build_report"]
