from __future__ import annotations

import hashlib
import json
import secrets
from datetime import UTC, datetime
from typing import Any

from fastapi import Depends, FastAPI, Header, HTTPException, status
from sqlalchemy import select, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from .auth import Principal, require_agent, require_roles, require_user
from .config import get_settings
from .database import get_session
from .db_models import (
    Action,
    Approval,
    AuditEventRow,
    Device,
    DeviceInventory,
    Heartbeat,
    IdempotencyRecord,
    Tenant,
    Ticket,
    User,
)
from .models import ActionRequest, ExecutionResult, RiskLevel, SkillDefinition
from .orchestrator import ActionOrchestrator
from .persistence import SqlActionStore, SqlAuditLog
from .policy import PolicyEngine
from .schemas import (
    ActionCreate,
    ApprovalDecision,
    DeviceEnroll,
    HeartbeatCreate,
    InventoryCreate,
    TenantCreate,
    TicketCreate,
    TicketUpdate,
)


app = FastAPI(title="Helpdesktool Control Plane", version="0.2.0")

SKILLS = [
    SkillDefinition(
        "diagnostics.collect", RiskLevel.READ_ONLY, frozenset({"linux", "windows"})
    ),
    SkillDefinition(
        "service.restart",
        RiskLevel.MEDIUM,
        frozenset({"linux", "windows"}),
        rollback_skill_id="service.restore",
    ),
]


class NoLocalExecutor:
    """Safety guard: the control plane queues jobs and never executes OS commands locally."""

    def execute(
        self, skill: SkillDefinition, request: ActionRequest
    ) -> ExecutionResult:
        raise RuntimeError("control-plane execution is disabled")

    def verify(
        self, skill: SkillDefinition, request: ActionRequest, result: ExecutionResult
    ) -> bool:
        return False

    def rollback(
        self, skill: SkillDefinition, request: ActionRequest, result: ExecutionResult
    ) -> ExecutionResult:
        raise RuntimeError("control-plane rollback is disabled")


def orchestrator(session: Session, ticket_id: str | None = None) -> ActionOrchestrator:
    return ActionOrchestrator(
        PolicyEngine(SKILLS),
        NoLocalExecutor(),
        SqlAuditLog(session),
        SqlActionStore(session, ticket_id),
        execute_immediately=False,
    )


def audit(
    session: Session,
    tenant_id: str,
    correlation_id: str,
    event_type: str,
    actor_id: str,
    details: dict[str, Any],
) -> None:
    SqlAuditLog(session).append(
        tenant_id=tenant_id,
        correlation_id=correlation_id,
        event_type=event_type,
        actor_id=actor_id,
        details=details,
    )


def idempotency_lookup(
    session: Session, tenant_id: str, scope: str, key: str, payload: dict[str, Any]
) -> dict[str, Any] | None:
    digest = hashlib.sha256(
        json.dumps(payload, sort_keys=True, default=str).encode()
    ).hexdigest()
    record = session.scalar(
        select(IdempotencyRecord).where(
            IdempotencyRecord.tenant_id == tenant_id,
            IdempotencyRecord.scope == scope,
            IdempotencyRecord.key == key,
        )
    )
    if record and record.request_hash != digest:
        raise HTTPException(
            status.HTTP_409_CONFLICT, "idempotency key reused with different payload"
        )
    return None if record is None else record.response


def remember(
    session: Session,
    tenant_id: str,
    scope: str,
    key: str,
    payload: dict[str, Any],
    response: dict[str, Any],
    status_code: int = 200,
) -> None:
    digest = hashlib.sha256(
        json.dumps(payload, sort_keys=True, default=str).encode()
    ).hexdigest()
    session.add(
        IdempotencyRecord(
            tenant_id=tenant_id,
            scope=scope,
            key=key,
            request_hash=digest,
            response=response,
            status_code=status_code,
        )
    )


@app.get("/health/live")
def liveness() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/health/ready")
def readiness(session: Session = Depends(get_session)) -> dict[str, str]:
    session.execute(text("SELECT 1"))
    return {"status": "ready"}


@app.post("/v1/tenants", status_code=201)
def create_tenant(
    body: TenantCreate,
    x_bootstrap_token: str = Header(),
    session: Session = Depends(get_session),
) -> dict[str, str]:
    if not secrets.compare_digest(x_bootstrap_token, get_settings().bootstrap_token):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid bootstrap token")
    tenant = Tenant(name=body.name)
    session.add(tenant)
    session.flush()
    user = User(tenant_id=tenant.id, email=body.admin_email, role="owner")
    session.add(user)
    session.flush()
    audit(
        session,
        tenant.id,
        tenant.id,
        "tenant.created",
        user.id,
        {"name": tenant.name, "admin_user_id": user.id},
    )
    session.commit()
    return {"tenant_id": tenant.id, "admin_user_id": user.id}


@app.post("/v1/devices/enroll", status_code=201)
def enroll_device(
    body: DeviceEnroll,
    principal: Principal = Depends(require_roles("owner", "admin")),
    session: Session = Depends(get_session),
) -> dict[str, str]:
    token = secrets.token_urlsafe(32)
    device = Device(
        tenant_id=principal.tenant_id,
        external_id=body.external_id,
        hostname=body.hostname,
        os=body.os,
        agent_key_hash=hashlib.sha256(token.encode()).hexdigest(),
    )
    session.add(device)
    try:
        session.flush()
    except IntegrityError as exc:
        raise HTTPException(
            status.HTTP_409_CONFLICT, "device already enrolled"
        ) from exc
    audit(
        session,
        principal.tenant_id,
        device.id,
        "device.enrolled",
        principal.actor_id,
        {"hostname": device.hostname, "os": device.os},
    )
    session.commit()
    return {"device_id": device.id, "agent_token": token}


@app.post("/v1/devices/{device_id}/heartbeat")
def heartbeat(
    device_id: str,
    body: HeartbeatCreate,
    idempotency_key: str = Header(alias="Idempotency-Key"),
    principal: Principal = Depends(require_agent),
    session: Session = Depends(get_session),
) -> dict[str, Any]:
    payload = body.model_dump()
    if cached := idempotency_lookup(
        session, principal.tenant_id, "heartbeat", idempotency_key, payload
    ):
        return cached
    device = session.get(Device, device_id)
    now = datetime.now(UTC)
    device.last_seen_at = now
    session.add(
        Heartbeat(
            tenant_id=principal.tenant_id, device_id=device_id, status=body.status
        )
    )
    result = {"accepted": True, "received_at": now.isoformat()}
    remember(
        session, principal.tenant_id, "heartbeat", idempotency_key, payload, result
    )
    session.commit()
    return result


@app.post("/v1/devices/{device_id}/inventory", status_code=202)
def inventory(
    device_id: str,
    body: InventoryCreate,
    idempotency_key: str = Header(alias="Idempotency-Key"),
    principal: Principal = Depends(require_agent),
    session: Session = Depends(get_session),
) -> dict[str, Any]:
    payload = body.model_dump(mode="json")
    if cached := idempotency_lookup(
        session, principal.tenant_id, "inventory", idempotency_key, payload
    ):
        return cached
    row = DeviceInventory(
        tenant_id=principal.tenant_id,
        device_id=device_id,
        collected_at=body.collected_at,
        payload=body.payload,
    )
    session.add(row)
    session.flush()
    result = {"accepted": True, "inventory_id": row.id}
    remember(
        session, principal.tenant_id, "inventory", idempotency_key, payload, result, 202
    )
    session.commit()
    return result


@app.get("/v1/devices")
def list_devices(
    principal: Principal = Depends(require_user),
    session: Session = Depends(get_session),
) -> list[dict[str, Any]]:
    rows = session.scalars(
        select(Device).where(Device.tenant_id == principal.tenant_id)
    ).all()
    return [device_json(row) for row in rows]


@app.get("/v1/devices/{device_id}")
def get_device(
    device_id: str,
    principal: Principal = Depends(require_user),
    session: Session = Depends(get_session),
) -> dict[str, Any]:
    row = tenant_row(session, Device, device_id, principal.tenant_id)
    return device_json(row)


@app.post("/v1/actions", status_code=201)
def create_action(
    body: ActionCreate,
    idempotency_key: str = Header(alias="Idempotency-Key"),
    principal: Principal = Depends(require_roles("owner", "admin", "operator")),
    session: Session = Depends(get_session),
) -> dict[str, Any]:
    payload = body.model_dump(mode="json")
    if cached := idempotency_lookup(
        session, principal.tenant_id, "action", idempotency_key, payload
    ):
        return cached
    device = tenant_row(session, Device, body.device_id, principal.tenant_id)
    if body.ticket_id:
        tenant_row(session, Ticket, body.ticket_id, principal.tenant_id)
    request = ActionRequest(
        principal.tenant_id,
        device.id,
        body.skill_id,
        principal.actor_id,
        body.parameters,
    )
    record = orchestrator(session, body.ticket_id).submit(request, device.os)
    result = action_json(session.get(Action, record.request.correlation_id))
    remember(
        session, principal.tenant_id, "action", idempotency_key, payload, result, 201
    )
    session.commit()
    return result


@app.post("/v1/actions/{action_id}/decision")
def decide_action(
    action_id: str,
    body: ApprovalDecision,
    principal: Principal = Depends(require_roles("owner", "admin")),
    session: Session = Depends(get_session),
) -> dict[str, Any]:
    tenant_row(session, Action, action_id, principal.tenant_id)
    flow = orchestrator(session)
    try:
        if body.decision == "approve":
            record = flow.approve(principal.tenant_id, action_id, principal.actor_id)
        else:
            record = flow.deny(
                principal.tenant_id, action_id, principal.actor_id, body.reason
            )
    except PermissionError as exc:
        raise HTTPException(status.HTTP_403_FORBIDDEN, str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status.HTTP_409_CONFLICT, str(exc)) from exc
    session.add(
        Approval(
            tenant_id=principal.tenant_id,
            action_id=action_id,
            decided_by=principal.actor_id,
            decision=body.decision,
            reason=body.reason or None,
        )
    )
    session.commit()
    return action_json(session.get(Action, record.request.correlation_id))


@app.get("/v1/actions/{action_id}")
def get_action(
    action_id: str,
    principal: Principal = Depends(require_user),
    session: Session = Depends(get_session),
) -> dict[str, Any]:
    return action_json(tenant_row(session, Action, action_id, principal.tenant_id))


@app.get("/v1/audit")
def get_audit(
    limit: int = 100,
    principal: Principal = Depends(require_roles("owner", "admin", "auditor")),
    session: Session = Depends(get_session),
) -> list[dict[str, Any]]:
    limit = max(1, min(limit, 500))
    rows = session.scalars(
        select(AuditEventRow)
        .where(AuditEventRow.tenant_id == principal.tenant_id)
        .order_by(AuditEventRow.sequence.desc())
        .limit(limit)
    ).all()
    return [
        {
            "sequence": r.sequence,
            "occurred_at": r.occurred_at,
            "correlation_id": r.correlation_id,
            "event_type": r.event_type,
            "actor_id": r.actor_id,
            "details": r.details,
            "previous_hash": r.previous_hash,
            "event_hash": r.event_hash,
        }
        for r in rows
    ]


@app.post("/v1/tickets", status_code=201)
def create_ticket(
    body: TicketCreate,
    principal: Principal = Depends(require_roles("owner", "admin", "operator")),
    session: Session = Depends(get_session),
) -> dict[str, Any]:
    if body.device_id:
        tenant_row(session, Device, body.device_id, principal.tenant_id)
    row = Ticket(
        tenant_id=principal.tenant_id,
        device_id=body.device_id,
        title=body.title,
        description=body.description,
        priority=body.priority,
        created_by=principal.actor_id,
    )
    session.add(row)
    session.flush()
    audit(
        session,
        principal.tenant_id,
        row.id,
        "ticket.created",
        principal.actor_id,
        {"title": row.title, "priority": row.priority},
    )
    session.commit()
    return ticket_json(row)


@app.patch("/v1/tickets/{ticket_id}")
def update_ticket(
    ticket_id: str,
    body: TicketUpdate,
    principal: Principal = Depends(require_roles("owner", "admin", "operator")),
    session: Session = Depends(get_session),
) -> dict[str, Any]:
    row = tenant_row(session, Ticket, ticket_id, principal.tenant_id)
    changes = body.model_dump(exclude_unset=True)
    for key, value in changes.items():
        setattr(row, key, value)
    audit(
        session,
        principal.tenant_id,
        row.id,
        "ticket.updated",
        principal.actor_id,
        {"changes": changes},
    )
    session.commit()
    return ticket_json(row)


def tenant_row(session: Session, model: Any, row_id: str, tenant_id: str) -> Any:
    row = session.scalar(
        select(model).where(model.id == row_id, model.tenant_id == tenant_id)
    )
    if row is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "resource not found")
    return row


def device_json(row: Device) -> dict[str, Any]:
    return {
        "id": row.id,
        "external_id": row.external_id,
        "hostname": row.hostname,
        "os": row.os,
        "enrolled_at": row.enrolled_at.isoformat() if row.enrolled_at else None,
        "last_seen_at": row.last_seen_at.isoformat() if row.last_seen_at else None,
    }


def action_json(row: Action) -> dict[str, Any]:
    return {
        "id": row.id,
        "device_id": row.device_id,
        "ticket_id": row.ticket_id,
        "skill_id": row.skill_id,
        "risk": row.risk,
        "status": row.status,
        "requested_by": row.requested_by,
        "approved_by": row.approved_by,
        "created_at": row.created_at.isoformat() if row.created_at else None,
        "updated_at": row.updated_at.isoformat() if row.updated_at else None,
    }


def ticket_json(row: Ticket) -> dict[str, Any]:
    return {
        "id": row.id,
        "device_id": row.device_id,
        "title": row.title,
        "description": row.description,
        "status": row.status,
        "priority": row.priority,
        "created_by": row.created_by,
        "created_at": row.created_at.isoformat() if row.created_at else None,
        "updated_at": row.updated_at.isoformat() if row.updated_at else None,
    }
