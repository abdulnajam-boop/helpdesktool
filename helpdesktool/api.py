from __future__ import annotations

import hashlib
import hmac
import json
import secrets
from datetime import UTC, datetime, timedelta
from typing import Any

from fastapi import Depends, FastAPI, Header, HTTPException, status
from sqlalchemy import select, text, update
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
    ExecutionResultRow,
    Tenant,
    Ticket,
    User,
    WebhookSubscription,
)
from .models import ActionRequest, ExecutionResult, RiskLevel, SkillDefinition
from .integrations import validate_webhook_url
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
    JobResult,
    TenantCreate,
    TicketCreate,
    TicketUpdate,
    WebhookSubscriptionCreate,
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
    payload = {"device_id": device_id, **body.model_dump()}
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
    payload = {"device_id": device_id, **body.model_dump(mode="json")}
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
    if body.skill_id == "service.restart":
        if set(body.parameters) != {"service"} or not isinstance(
            body.parameters.get("service"), str
        ):
            raise HTTPException(
                status.HTTP_422_UNPROCESSABLE_ENTITY,
                "service.restart requires only a string service parameter",
            )
        if body.parameters["service"] not in get_settings().allowed_services:
            raise HTTPException(
                status.HTTP_403_FORBIDDEN, "service is not allowlisted by control plane"
            )
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


@app.get("/v1/devices/{device_id}/jobs")
def poll_jobs(
    device_id: str,
    principal: Principal = Depends(require_agent),
    session: Session = Depends(get_session),
) -> list[dict[str, Any]]:
    rows = session.scalars(
        select(Action)
        .where(
            Action.tenant_id == principal.tenant_id,
            Action.device_id == device_id,
            Action.status == "queued",
        )
        .order_by(Action.created_at)
        .limit(10)
    ).all()
    return [{"id": row.id, "skill_id": row.skill_id, "risk": row.risk} for row in rows]


@app.post("/v1/devices/{device_id}/jobs/{action_id}/claim")
def claim_job(
    device_id: str,
    action_id: str,
    idempotency_key: str = Header(alias="Idempotency-Key"),
    principal: Principal = Depends(require_agent),
    session: Session = Depends(get_session),
) -> dict[str, Any]:
    payload = {"action_id": action_id, "device_id": device_id}
    cached = idempotency_lookup(
        session, principal.tenant_id, "job-claim", idempotency_key, payload
    )
    if cached is not None:
        return {
            **cached,
            "claim_token": _claim_token(action_id, cached["attempt"], idempotency_key),
        }
    current = session.get(Action, action_id)
    next_attempt = 1 if current is None else current.attempt + 1
    token = _claim_token(action_id, next_attempt, idempotency_key)
    now = datetime.now(UTC)
    changed = session.execute(
        update(Action)
        .where(
            Action.id == action_id,
            Action.tenant_id == principal.tenant_id,
            Action.device_id == device_id,
            Action.status == "queued",
        )
        .values(
            status="claimed",
            claim_token_hash=hashlib.sha256(token.encode()).hexdigest(),
            claimed_at=now,
            lease_expires_at=now + timedelta(seconds=60),
            attempt=Action.attempt + 1,
        )
    ).rowcount
    if changed != 1:
        raise HTTPException(status.HTTP_409_CONFLICT, "job is unavailable")
    row = session.get(Action, action_id)
    result = {
        "id": row.id,
        "skill_id": row.skill_id,
        "parameters": row.parameters,
        "device_id": row.device_id,
        "attempt": row.attempt,
        "lease_expires_at": row.lease_expires_at.isoformat(),
        "claim_token": token,
    }
    audit(
        session,
        principal.tenant_id,
        action_id,
        "execution.claimed",
        device_id,
        {
            "attempt": row.attempt,
            "lease_expires_at": result["lease_expires_at"],
            "previous_status": "queued",
            "new_status": "claimed",
        },
    )
    stored_result = {
        key: value for key, value in result.items() if key != "claim_token"
    }
    remember(
        session,
        principal.tenant_id,
        "job-claim",
        idempotency_key,
        payload,
        stored_result,
    )
    session.commit()
    return result


@app.post("/v1/devices/{device_id}/jobs/{action_id}/result")
def report_job_result(
    device_id: str,
    action_id: str,
    body: JobResult,
    claim_token: str = Header(alias="X-Claim-Token"),
    idempotency_key: str = Header(alias="Idempotency-Key"),
    principal: Principal = Depends(require_agent),
    session: Session = Depends(get_session),
) -> dict[str, Any]:
    payload = {
        "action_id": action_id,
        "device_id": device_id,
        **body.model_dump(mode="json"),
    }
    cached = idempotency_lookup(
        session, principal.tenant_id, "job-result", idempotency_key, payload
    )
    if cached is not None:
        return cached
    row = tenant_row(session, Action, action_id, principal.tenant_id)
    supplied = hashlib.sha256(claim_token.encode()).hexdigest()
    if (
        row.device_id != device_id
        or row.status != "claimed"
        or not row.claim_token_hash
    ):
        raise HTTPException(
            status.HTTP_409_CONFLICT, "job is not claimable by this device"
        )
    if not secrets.compare_digest(row.claim_token_hash, supplied):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid claim token")
    expires_at = row.lease_expires_at
    if expires_at and expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=UTC)
    if expires_at and expires_at < datetime.now(UTC):
        raise HTTPException(status.HTTP_409_CONFLICT, "job claim expired")
    previous_status = row.status
    if body.success and body.verified:
        row.status = "succeeded"
    elif body.rollback_attempted and body.rollback_succeeded:
        row.status = "rolled_back"
    elif body.rollback_attempted and not body.rollback_succeeded:
        row.status = "rollback_failed"
    else:
        row.status = "failed"
    session.add(
        ExecutionResultRow(
            tenant_id=principal.tenant_id,
            action_id=action_id,
            success=body.success,
            verified=body.verified,
            output=body.output,
            error=body.error,
            rollback_attempted=body.rollback_attempted,
            rollback_succeeded=body.rollback_succeeded,
        )
    )
    result = {"accepted": True, "action_id": action_id, "status": row.status}
    audit(
        session,
        principal.tenant_id,
        action_id,
        "execution.reported",
        device_id,
        {
            "status": row.status,
            "success": body.success,
            "verified": body.verified,
            "rollback_attempted": body.rollback_attempted,
            "rollback_succeeded": body.rollback_succeeded,
            "previous_status": previous_status,
            "new_status": row.status,
        },
    )
    if body.verified:
        audit(
            session,
            principal.tenant_id,
            action_id,
            "execution.verified",
            device_id,
            {"success": body.success},
        )
    if body.rollback_attempted:
        audit(
            session,
            principal.tenant_id,
            action_id,
            "rollback.completed",
            device_id,
            {"success": body.rollback_succeeded},
        )
    if row.status not in {"succeeded", "rolled_back"}:
        audit(
            session,
            principal.tenant_id,
            action_id,
            "action.escalation_required",
            "system",
            {"status": row.status, "error": body.error},
        )
    remember(
        session, principal.tenant_id, "job-result", idempotency_key, payload, result
    )
    session.commit()
    return result


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


@app.post("/v1/integrations/webhooks", status_code=201)
def create_webhook_subscription(
    body: WebhookSubscriptionCreate,
    principal: Principal = Depends(require_roles("owner", "admin")),
    session: Session = Depends(get_session),
) -> dict[str, Any]:
    try:
        validate_webhook_url(body.url, allow_http=get_settings().webhook_allow_http)
    except ValueError as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, str(exc)) from exc
    row = WebhookSubscription(
        tenant_id=principal.tenant_id,
        name=body.name,
        url=body.url,
        secret_ref=body.secret_ref,
        event_types=sorted({item.value for item in body.event_types}),
        created_by=principal.actor_id,
    )
    session.add(row)
    try:
        session.flush()
    except IntegrityError as exc:
        raise HTTPException(
            status.HTTP_409_CONFLICT, "webhook name already exists"
        ) from exc
    audit(
        session,
        principal.tenant_id,
        row.id,
        "integration.webhook.created",
        principal.actor_id,
        {"name": row.name, "event_types": row.event_types},
    )
    session.commit()
    return webhook_json(row)


@app.get("/v1/integrations/webhooks")
def list_webhook_subscriptions(
    principal: Principal = Depends(require_roles("owner", "admin", "auditor")),
    session: Session = Depends(get_session),
) -> list[dict[str, Any]]:
    rows = session.scalars(
        select(WebhookSubscription)
        .where(WebhookSubscription.tenant_id == principal.tenant_id)
        .order_by(WebhookSubscription.created_at)
    ).all()
    return [webhook_json(row) for row in rows]


@app.delete("/v1/integrations/webhooks/{subscription_id}", status_code=204)
def disable_webhook_subscription(
    subscription_id: str,
    principal: Principal = Depends(require_roles("owner", "admin")),
    session: Session = Depends(get_session),
) -> None:
    row = tenant_row(session, WebhookSubscription, subscription_id, principal.tenant_id)
    row.active = False
    audit(
        session,
        principal.tenant_id,
        row.id,
        "integration.webhook.disabled",
        principal.actor_id,
        {"name": row.name},
    )
    session.commit()


def tenant_row(session: Session, model: Any, row_id: str, tenant_id: str) -> Any:
    row = session.scalar(
        select(model).where(model.id == row_id, model.tenant_id == tenant_id)
    )
    if row is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "resource not found")
    return row


def _claim_token(action_id: str, attempt: int, idempotency_key: str) -> str:
    message = f"{action_id}:{attempt}:{idempotency_key}".encode()
    return hmac.new(
        get_settings().job_claim_secret.encode(), message, hashlib.sha256
    ).hexdigest()


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


def webhook_json(row: WebhookSubscription) -> dict[str, Any]:
    return {
        "id": row.id,
        "name": row.name,
        "url": row.url,
        "event_types": row.event_types,
        "active": row.active,
        "created_at": row.created_at.isoformat() if row.created_at else None,
    }
