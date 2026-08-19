from __future__ import annotations

import hashlib
import hmac
import json
import secrets
from datetime import UTC, datetime, timedelta
from typing import Any, cast

from fastapi import Depends, FastAPI, Header, HTTPException, Query, status
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import CursorResult, func, select, text, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from .auth import (
    Principal,
    require_agent,
    require_roles,
    require_user,
    resolving_identity,
)
from .config import get_settings
from .database import get_session, set_tenant_context
from .db_models import (
    Action,
    Approval,
    AuditEventRow,
    Device,
    DeviceInventory,
    EnrollmentToken,
    ExecutionResultRow,
    Heartbeat,
    IdempotencyRecord,
    Incident,
    Tenant,
    Ticket,
    User,
    WebhookDelivery,
    WebhookSubscription,
)
from .development_auth import issue_session
from .events import EventType
from .incidents import detect_inventory_incidents, incident_json
from .integrations import validate_webhook_url
from .models import ActionRequest, ExecutionResult, RiskLevel, SkillDefinition
from .orchestrator import ActionOrchestrator
from .persistence import SqlActionStore, SqlAuditLog
from .policy import PolicyEngine
from .schemas import (
    ActionCreate,
    ApprovalDecision,
    DeviceEnroll,
    DeviceRevoke,
    EnrollmentTokenCreate,
    HeartbeatCreate,
    InventoryCreate,
    JobResult,
    LowDiskSimulation,
    TenantCreate,
    TicketCreate,
    TicketUpdate,
    WebhookSubscriptionCreate,
)

app = FastAPI(title="Helpdesktool Control Plane", version="0.2.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=get_settings().allowed_cors_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type", "Idempotency-Key"],
)

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


def _require_development_login() -> None:
    settings = get_settings()
    if settings.environment != "development" or not settings.development_login_enabled:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "not found")


@app.get("/v1/auth/development/users")
def development_users(session: Session = Depends(get_session)) -> list[dict[str, str]]:
    _require_development_login()
    # No Principal exists yet for this picker (that is the whole point of a
    # login page) so nothing has bound this session's tenant context; this
    # listing is itself the intended cross-tenant view of demo users, and is
    # already gated to development-only above — see auth.resolving_identity.
    with resolving_identity(session):
        rows = session.execute(
            select(User, Tenant.name)
            .join(Tenant, Tenant.id == User.tenant_id)
            .where(User.active.is_(True))
            .order_by(User.email)
        ).all()
    return [
        {"id": user.id, "email": user.email, "role": user.role, "tenant": tenant}
        for user, tenant in rows
    ]


@app.post("/v1/auth/development/login")
def development_login(
    user_id: str = Query(min_length=1), session: Session = Depends(get_session)
) -> dict[str, Any]:
    _require_development_login()
    with resolving_identity(session):
        user = session.scalar(
            select(User).where(User.id == user_id, User.active.is_(True))
        )
    if user is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid development user")
    settings = get_settings()
    token = issue_session(
        user.id,
        user.tenant_id,
        settings.development_session_secret,
        settings.development_session_minutes,
    )
    return {"access_token": token, "token_type": "bearer", "user": _user_json(user)}


@app.get("/v1/auth/me")
def current_user(
    principal: Principal = Depends(require_user),
    session: Session = Depends(get_session),
) -> dict[str, Any]:
    return _user_json(
        tenant_row(session, User, principal.actor_id, principal.tenant_id)
    )


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
    # No Principal exists yet for a brand-new tenant, so nothing has bound
    # this session's row-level-security context — bind it to the tenant we
    # just created so the owner row below satisfies the tenant_isolation
    # policy's WITH CHECK.
    set_tenant_context(session, tenant.id)
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


@app.post("/v1/devices/enrollment-tokens", status_code=201)
def create_enrollment_token(
    body: EnrollmentTokenCreate,
    principal: Principal = Depends(require_roles("owner", "admin")),
    session: Session = Depends(get_session),
) -> dict[str, Any]:
    token = secrets.token_urlsafe(32)
    expires_at = datetime.now(UTC) + timedelta(minutes=body.ttl_minutes)
    row = EnrollmentToken(
        tenant_id=principal.tenant_id,
        token_hash=hashlib.sha256(token.encode()).hexdigest(),
        created_by=principal.actor_id,
        label=body.label,
        expires_at=expires_at,
    )
    session.add(row)
    session.flush()
    audit(
        session,
        principal.tenant_id,
        row.id,
        "enrollment_token.created",
        principal.actor_id,
        {"label": row.label, "expires_at": expires_at.isoformat()},
    )
    session.commit()
    return {
        "enrollment_token_id": row.id,
        "token": token,
        "expires_at": expires_at.isoformat(),
    }


@app.get("/v1/devices/enrollment-tokens")
def list_enrollment_tokens(
    principal: Principal = Depends(require_roles("owner", "admin")),
    session: Session = Depends(get_session),
) -> list[dict[str, Any]]:
    rows = session.scalars(
        select(EnrollmentToken)
        .where(EnrollmentToken.tenant_id == principal.tenant_id)
        .order_by(EnrollmentToken.created_at.desc())
    ).all()
    now = datetime.now(UTC)
    return [
        {
            "id": row.id,
            "label": row.label,
            "created_by": row.created_by,
            "expires_at": row.expires_at.isoformat(),
            "used_at": row.used_at.isoformat() if row.used_at else None,
            "used_by_device_id": row.used_by_device_id,
            "revoked_at": row.revoked_at.isoformat() if row.revoked_at else None,
            "status": (
                "used"
                if row.used_at
                else "revoked"
                if row.revoked_at
                else "expired"
                if _aware(row.expires_at) < now
                else "active"
            ),
            "created_at": row.created_at.isoformat() if row.created_at else None,
        }
        for row in rows
    ]


@app.delete("/v1/devices/enrollment-tokens/{token_id}", status_code=204)
def revoke_enrollment_token(
    token_id: str,
    principal: Principal = Depends(require_roles("owner", "admin")),
    session: Session = Depends(get_session),
) -> None:
    row = tenant_row(session, EnrollmentToken, token_id, principal.tenant_id)
    row.revoked_at = datetime.now(UTC)
    audit(
        session,
        principal.tenant_id,
        row.id,
        "enrollment_token.revoked",
        principal.actor_id,
        {"label": row.label},
    )
    session.commit()


@app.post("/v1/devices/enroll-with-token", status_code=201)
def enroll_device_with_token(
    body: DeviceEnroll,
    x_enrollment_token: str = Header(alias="X-Enrollment-Token"),
    session: Session = Depends(get_session),
) -> dict[str, str]:
    now = datetime.now(UTC)
    token_hash = hashlib.sha256(x_enrollment_token.encode()).hexdigest()
    # No tenant is known yet — resolving which tenant this token belongs to
    # is exactly what this lookup does, the same pattern require_user's
    # identity-resolution paths use. with_for_update closes the race between
    # two concurrent uses of the same single-use token.
    with resolving_identity(session):
        enrollment = session.scalar(
            select(EnrollmentToken)
            .where(EnrollmentToken.token_hash == token_hash)
            .with_for_update()
        )
    if (
        enrollment is None
        or enrollment.used_at is not None
        or enrollment.revoked_at is not None
        or _aware(enrollment.expires_at) < now
    ):
        raise HTTPException(
            status.HTTP_401_UNAUTHORIZED, "invalid or expired enrollment token"
        )
    set_tenant_context(session, enrollment.tenant_id)
    device_token = secrets.token_urlsafe(32)
    device = Device(
        tenant_id=enrollment.tenant_id,
        external_id=body.external_id,
        hostname=body.hostname,
        os=body.os,
        agent_key_hash=hashlib.sha256(device_token.encode()).hexdigest(),
    )
    session.add(device)
    try:
        session.flush()
    except IntegrityError as exc:
        raise HTTPException(
            status.HTTP_409_CONFLICT, "device already enrolled"
        ) from exc
    enrollment.used_at = now
    enrollment.used_by_device_id = device.id
    audit(
        session,
        enrollment.tenant_id,
        device.id,
        "device.enrolled",
        f"enrollment-token:{enrollment.id}",
        {"hostname": device.hostname, "os": device.os, "via": "enrollment_token"},
    )
    session.commit()
    return {"device_id": device.id, "agent_token": device_token}


@app.post("/v1/devices/{device_id}/rotate-credential")
def rotate_device_credential(
    device_id: str,
    principal: Principal = Depends(require_roles("owner", "admin")),
    session: Session = Depends(get_session),
) -> dict[str, str]:
    device = tenant_row(session, Device, device_id, principal.tenant_id)
    if not device.active:
        raise HTTPException(status.HTTP_409_CONFLICT, "device is revoked")
    token = secrets.token_urlsafe(32)
    device.agent_key_hash = hashlib.sha256(token.encode()).hexdigest()
    device.credential_rotated_at = datetime.now(UTC)
    audit(
        session,
        principal.tenant_id,
        device.id,
        "device.credential_rotated",
        principal.actor_id,
        {"via": "admin"},
    )
    session.commit()
    return {"device_id": device.id, "agent_token": token}


@app.post("/v1/devices/{device_id}/credential/renew")
def renew_device_credential(
    device_id: str,
    principal: Principal = Depends(require_agent),
    session: Session = Depends(get_session),
) -> dict[str, str]:
    # require_agent already authenticated the device's current credential
    # and confirmed it is active before this handler runs.
    device = tenant_row(session, Device, device_id, principal.tenant_id)
    token = secrets.token_urlsafe(32)
    device.agent_key_hash = hashlib.sha256(token.encode()).hexdigest()
    device.credential_rotated_at = datetime.now(UTC)
    audit(
        session,
        principal.tenant_id,
        device.id,
        "device.credential_rotated",
        device.id,
        {"via": "self_service"},
    )
    session.commit()
    return {"device_id": device.id, "agent_token": token}


@app.post("/v1/devices/{device_id}/revoke")
def revoke_device(
    device_id: str,
    body: DeviceRevoke,
    principal: Principal = Depends(require_roles("owner", "admin")),
    session: Session = Depends(get_session),
) -> dict[str, Any]:
    device = tenant_row(session, Device, device_id, principal.tenant_id)
    device.active = False
    device.revoked_at = datetime.now(UTC)
    device.revoked_reason = body.reason
    audit(
        session,
        principal.tenant_id,
        device.id,
        "device.revoked",
        principal.actor_id,
        {"reason": body.reason},
    )
    session.commit()
    return device_json(device)


@app.post("/v1/devices/{device_id}/heartbeat")
def heartbeat(
    device_id: str,
    body: HeartbeatCreate,
    idempotency_key: str = Header(alias="Idempotency-Key"),
    principal: Principal = Depends(require_agent),
    session: Session = Depends(get_session),
) -> dict[str, Any]:
    payload = {"device_id": device_id, **body.model_dump()}
    if cached := idempotency_lookup(
        session, principal.tenant_id, "heartbeat", idempotency_key, payload
    ):
        return cached
    device = session.get(Device, device_id)
    if device is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "device not found")
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
    incidents = detect_inventory_incidents(
        session,
        principal.tenant_id,
        device_id,
        body.payload,
        body.collected_at,
        get_settings(),
    )
    result = {
        "accepted": True,
        "inventory_id": row.id,
        "incident_ids": [incident.id for incident in incidents],
    }
    remember(
        session, principal.tenant_id, "inventory", idempotency_key, payload, result, 202
    )
    session.commit()
    return result


@app.post("/v1/development/simulations/low-disk")
def simulate_low_disk(
    body: LowDiskSimulation,
    principal: Principal = Depends(require_roles("owner", "admin", "operator")),
    session: Session = Depends(get_session),
) -> dict[str, Any]:
    _require_development_login()
    device = tenant_row(session, Device, body.device_id, principal.tenant_id)
    if device.os != "linux":
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY,
            "low-disk simulation requires a Linux device",
        )
    now = datetime.now(UTC)
    total_bytes = 100 * 1024**3
    payload = {
        "simulation": True,
        "filesystems": [
            {
                "device": "/dev/simulated",
                "mountpoint": body.mountpoint,
                "filesystem": "ext4",
                "total_bytes": total_bytes,
                "free_bytes": int(total_bytes * (100 - body.used_percent) / 100),
            }
        ],
    }
    inventory_row = DeviceInventory(
        tenant_id=principal.tenant_id,
        device_id=device.id,
        collected_at=now,
        payload=payload,
    )
    session.add(inventory_row)
    session.flush()
    incidents = detect_inventory_incidents(
        session,
        principal.tenant_id,
        device.id,
        payload,
        now,
        get_settings(),
    )
    audit(
        session,
        principal.tenant_id,
        device.id,
        "development.low_disk.simulated",
        principal.actor_id,
        {
            "inventory_id": inventory_row.id,
            "mountpoint": body.mountpoint,
            "used_percent": body.used_percent,
        },
    )
    session.commit()
    current = session.scalar(
        select(Incident)
        .where(
            Incident.tenant_id == principal.tenant_id,
            Incident.device_id == device.id,
            Incident.correlation_key == f"low_disk_space:{body.mountpoint}",
        )
        .order_by(Incident.last_observed_at.desc())
    )
    return {
        "accepted": True,
        "inventory_id": inventory_row.id,
        "incident_ids": [row.id for row in incidents],
        "incident": incident_json(current) if current else None,
    }


@app.get("/v1/devices")
def list_devices(
    principal: Principal = Depends(require_user),
    session: Session = Depends(get_session),
) -> list[dict[str, Any]]:
    rows = session.scalars(
        select(Device).where(Device.tenant_id == principal.tenant_id)
    ).all()
    return [_device_summary(session, row, principal.tenant_id) for row in rows]


@app.get("/v1/devices/{device_id}")
def get_device(
    device_id: str,
    principal: Principal = Depends(require_user),
    session: Session = Depends(get_session),
) -> dict[str, Any]:
    row = tenant_row(session, Device, device_id, principal.tenant_id)
    result = device_json(row)
    inventory_row = session.scalar(
        select(DeviceInventory)
        .where(
            DeviceInventory.tenant_id == principal.tenant_id,
            DeviceInventory.device_id == device_id,
        )
        .order_by(DeviceInventory.collected_at.desc())
    )
    result["inventory"] = inventory_row.payload if inventory_row else None
    result["incidents"] = [
        incident_json(item)
        for item in session.scalars(
            select(Incident)
            .where(
                Incident.tenant_id == principal.tenant_id,
                Incident.device_id == device_id,
            )
            .order_by(Incident.last_observed_at.desc())
            .limit(10)
        ).all()
    ]
    result["tickets"] = [
        ticket_json(item)
        for item in session.scalars(
            select(Ticket)
            .where(
                Ticket.tenant_id == principal.tenant_id, Ticket.device_id == device_id
            )
            .order_by(Ticket.updated_at.desc())
            .limit(10)
        ).all()
    ]
    result["actions"] = [
        action_json(item)
        for item in session.scalars(
            select(Action)
            .where(
                Action.tenant_id == principal.tenant_id, Action.device_id == device_id
            )
            .order_by(Action.created_at.desc())
            .limit(10)
        ).all()
    ]
    heartbeat_row = session.scalar(
        select(Heartbeat)
        .where(
            Heartbeat.tenant_id == principal.tenant_id,
            Heartbeat.device_id == device_id,
        )
        .order_by(Heartbeat.received_at.desc())
    )
    result["latest_heartbeat"] = (
        {
            "received_at": heartbeat_row.received_at,
            "status": heartbeat_row.status,
        }
        if heartbeat_row
        else None
    )
    correlations = {
        device_id,
        *(item["id"] for item in result["incidents"]),
        *(item["id"] for item in result["tickets"]),
        *(item["id"] for item in result["actions"]),
    }
    result["audit"] = _audit_for(session, principal.tenant_id, correlations)
    return result


@app.get("/v1/dashboard")
def dashboard(
    principal: Principal = Depends(require_user),
    session: Session = Depends(get_session),
) -> dict[str, Any]:
    tenant_id = principal.tenant_id
    devices = session.scalars(select(Device).where(Device.tenant_id == tenant_id)).all()
    online_cutoff = datetime.now(UTC) - timedelta(minutes=5)
    recent_incidents = session.scalars(
        select(Incident)
        .where(Incident.tenant_id == tenant_id)
        .order_by(Incident.last_observed_at.desc())
        .limit(5)
    ).all()
    recent_tickets = session.scalars(
        select(Ticket)
        .where(Ticket.tenant_id == tenant_id)
        .order_by(Ticket.updated_at.desc())
        .limit(5)
    ).all()
    recent_actions = session.scalars(
        select(Action)
        .where(Action.tenant_id == tenant_id)
        .order_by(Action.created_at.desc())
        .limit(5)
    ).all()
    return {
        "counts": {
            "devices": len(devices),
            "online_devices": sum(
                1
                for row in devices
                if row.last_seen_at and _aware(row.last_seen_at) >= online_cutoff
            ),
            "offline_devices": sum(
                1
                for row in devices
                if not row.last_seen_at or _aware(row.last_seen_at) < online_cutoff
            ),
            "open_tickets": _count(
                session, Ticket, tenant_id, Ticket.status.in_(["open", "in_progress"])
            ),
            "open_incidents": _count(
                session,
                Incident,
                tenant_id,
                Incident.status.in_(["open", "investigating"]),
            ),
            "pending_approvals": _count(
                session, Action, tenant_id, Action.status == "pending_approval"
            ),
            "failed_actions": _count(
                session,
                Action,
                tenant_id,
                Action.status.in_(["failed", "rollback_failed"]),
            ),
        },
        "recent_incidents": [incident_json(row) for row in recent_incidents],
        "recent_tickets": [ticket_json(row) for row in recent_tickets],
        "recent_actions": [action_json(row) for row in recent_actions],
    }


@app.get("/v1/incidents")
def list_incidents(
    principal: Principal = Depends(require_user),
    session: Session = Depends(get_session),
) -> list[dict[str, Any]]:
    return [
        incident_json(row)
        for row in session.scalars(
            select(Incident)
            .where(Incident.tenant_id == principal.tenant_id)
            .order_by(Incident.last_observed_at.desc())
        ).all()
    ]


@app.get("/v1/incidents/{incident_id}")
def get_incident(
    incident_id: str,
    principal: Principal = Depends(require_user),
    session: Session = Depends(get_session),
) -> dict[str, Any]:
    row = tenant_row(session, Incident, incident_id, principal.tenant_id)
    result = incident_json(row)
    result["ticket"] = (
        ticket_json(tenant_row(session, Ticket, row.ticket_id, principal.tenant_id))
        if row.ticket_id
        else None
    )
    result["actions"] = [
        action_json(item)
        for item in session.scalars(
            select(Action).where(
                Action.tenant_id == principal.tenant_id,
                Action.ticket_id == row.ticket_id,
            )
        ).all()
    ]
    correlations = {row.id}
    if row.ticket_id:
        correlations.add(row.ticket_id)
    correlations.update(item["id"] for item in result["actions"])
    result["timeline"] = _audit_for(session, principal.tenant_id, correlations)
    return result


@app.get("/v1/tickets")
def list_tickets(
    principal: Principal = Depends(require_user),
    session: Session = Depends(get_session),
) -> list[dict[str, Any]]:
    return [
        ticket_json(row)
        for row in session.scalars(
            select(Ticket)
            .where(Ticket.tenant_id == principal.tenant_id)
            .order_by(Ticket.updated_at.desc())
        ).all()
    ]


@app.get("/v1/tickets/{ticket_id}")
def get_ticket(
    ticket_id: str,
    principal: Principal = Depends(require_user),
    session: Session = Depends(get_session),
) -> dict[str, Any]:
    row = tenant_row(session, Ticket, ticket_id, principal.tenant_id)
    result = ticket_json(row)
    incident = session.scalar(
        select(Incident).where(
            Incident.tenant_id == principal.tenant_id,
            Incident.ticket_id == row.id,
        )
    )
    actions = session.scalars(
        select(Action).where(
            Action.tenant_id == principal.tenant_id, Action.ticket_id == row.id
        )
    ).all()
    result["incident"] = incident_json(incident) if incident else None
    result["actions"] = [action_json(item) for item in actions]
    correlations = {row.id, *(item.id for item in actions)}
    if incident:
        correlations.add(incident.id)
    result["timeline"] = _audit_for(session, principal.tenant_id, correlations)
    return result


@app.get("/v1/actions")
def list_actions(
    principal: Principal = Depends(require_user),
    session: Session = Depends(get_session),
) -> list[dict[str, Any]]:
    return [
        action_json(row)
        for row in session.scalars(
            select(Action)
            .where(Action.tenant_id == principal.tenant_id)
            .order_by(Action.created_at.desc())
        ).all()
    ]


@app.get("/v1/approvals")
def list_approvals(
    principal: Principal = Depends(require_user),
    session: Session = Depends(get_session),
) -> list[dict[str, Any]]:
    rows = session.scalars(
        select(Action)
        .where(
            Action.tenant_id == principal.tenant_id, Action.status == "pending_approval"
        )
        .order_by(Action.created_at)
    ).all()
    return [action_json(row) for row in rows]


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
    action_row = session.get(Action, record.request.correlation_id)
    if action_row is None:
        raise HTTPException(
            status.HTTP_500_INTERNAL_SERVER_ERROR, "action was not persisted"
        )
    result = action_json(action_row)
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
    action_row = session.get(Action, record.request.correlation_id)
    if action_row is None:
        raise HTTPException(
            status.HTTP_500_INTERNAL_SERVER_ERROR, "action was not persisted"
        )
    return action_json(action_row)


@app.get("/v1/actions/{action_id}")
def get_action(
    action_id: str,
    principal: Principal = Depends(require_user),
    session: Session = Depends(get_session),
) -> dict[str, Any]:
    row = tenant_row(session, Action, action_id, principal.tenant_id)
    result = action_json(row)
    approvals = session.scalars(
        select(Approval).where(
            Approval.tenant_id == principal.tenant_id,
            Approval.action_id == row.id,
        )
    ).all()
    executions = session.scalars(
        select(ExecutionResultRow).where(
            ExecutionResultRow.tenant_id == principal.tenant_id,
            ExecutionResultRow.action_id == row.id,
        )
    ).all()
    result["approvals"] = [
        {
            "decision": item.decision,
            "decided_by": item.decided_by,
            "reason": item.reason,
            "decided_at": item.decided_at,
        }
        for item in approvals
    ]
    result["execution_results"] = [
        {
            "success": item.success,
            "verified": item.verified,
            "output": item.output,
            "error": item.error,
            "rollback_attempted": item.rollback_attempted,
            "rollback_succeeded": item.rollback_succeeded,
            "created_at": item.created_at,
        }
        for item in executions
    ]
    correlations = {row.id, *(filter(None, [row.ticket_id]))}
    if row.ticket_id:
        incident_id = session.scalar(
            select(Incident.id).where(
                Incident.tenant_id == principal.tenant_id,
                Incident.ticket_id == row.ticket_id,
            )
        )
        if incident_id:
            correlations.add(incident_id)
    result["timeline"] = _audit_for(session, principal.tenant_id, correlations)
    return result


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
    changed = cast(
        CursorResult[Any],
        session.execute(
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
        ),
    ).rowcount
    if changed != 1:
        raise HTTPException(status.HTTP_409_CONFLICT, "job is unavailable")
    row = session.get(Action, action_id)
    if row is None or row.lease_expires_at is None:
        raise HTTPException(
            status.HTTP_500_INTERNAL_SERVER_ERROR, "claimed job vanished unexpectedly"
        )
    result = {
        "id": row.id,
        "skill_id": row.skill_id,
        "parameters": row.parameters,
        "device_os": row.device_os,
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
    event_type: str | None = None,
    correlation_id: str | None = None,
    principal: Principal = Depends(require_user),
    session: Session = Depends(get_session),
) -> list[dict[str, Any]]:
    limit = max(1, min(limit, 500))
    query = select(AuditEventRow).where(AuditEventRow.tenant_id == principal.tenant_id)
    if event_type:
        query = query.where(AuditEventRow.event_type == event_type)
    if correlation_id:
        query = query.where(AuditEventRow.correlation_id == correlation_id)
    rows = session.scalars(
        query.order_by(AuditEventRow.sequence.desc()).limit(limit)
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
    principal: Principal = Depends(require_user),
    session: Session = Depends(get_session),
) -> list[dict[str, Any]]:
    rows = session.scalars(
        select(WebhookSubscription)
        .where(WebhookSubscription.tenant_id == principal.tenant_id)
        .order_by(WebhookSubscription.created_at)
    ).all()
    return [webhook_json(row) for row in rows]


@app.get("/v1/integrations/webhooks/deliveries")
def list_webhook_deliveries(
    principal: Principal = Depends(require_user),
    session: Session = Depends(get_session),
) -> list[dict[str, Any]]:
    rows = session.scalars(
        select(WebhookDelivery)
        .where(WebhookDelivery.tenant_id == principal.tenant_id)
        .order_by(WebhookDelivery.next_attempt_at.desc())
        .limit(100)
    ).all()
    return [
        {
            "id": row.id,
            "event_id": row.event_id,
            "subscription_id": row.subscription_id,
            "status": row.status,
            "attempt_count": row.attempt_count,
            "last_attempt_at": row.last_attempt_at,
            "delivered_at": row.delivered_at,
            "response_status": row.response_status,
            "last_error": row.last_error,
        }
        for row in rows
    ]


@app.get("/v1/settings")
def settings_summary(
    principal: Principal = Depends(require_user),
    session: Session = Depends(get_session),
) -> dict[str, Any]:
    tenant = session.get(Tenant, principal.tenant_id)
    if tenant is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "tenant not found")
    users = session.scalars(
        select(User).where(User.tenant_id == principal.tenant_id).order_by(User.email)
    ).all()
    settings = get_settings()
    return {
        "tenant": {"id": tenant.id, "name": tenant.name},
        "users": [_user_json(row) for row in users],
        "environment": settings.environment,
        "development_login_enabled": settings.development_login_enabled,
        "low_disk_threshold_percent": settings.low_disk_threshold_percent,
        "allowed_services": sorted(settings.allowed_services),
        "supported_events": [item.value for item in EventType],
    }


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


def _audit_for(
    session: Session, tenant_id: str, correlation_ids: set[str], limit: int = 50
) -> list[dict[str, Any]]:
    if not correlation_ids:
        return []
    rows = session.scalars(
        select(AuditEventRow)
        .where(
            AuditEventRow.tenant_id == tenant_id,
            AuditEventRow.correlation_id.in_(correlation_ids),
        )
        .order_by(AuditEventRow.sequence.desc())
        .limit(limit)
    ).all()
    return [_audit_json(row) for row in rows]


def _audit_json(row: AuditEventRow) -> dict[str, Any]:
    return {
        "sequence": row.sequence,
        "occurred_at": row.occurred_at,
        "correlation_id": row.correlation_id,
        "event_type": row.event_type,
        "actor_id": row.actor_id,
        "details": row.details,
        "previous_hash": row.previous_hash,
        "event_hash": row.event_hash,
    }


def _count(session: Session, model: Any, tenant_id: str, condition: Any) -> int:
    return int(
        session.scalar(
            select(func.count())
            .select_from(model)
            .where(model.tenant_id == tenant_id, condition)
        )
        or 0
    )


def _aware(value: datetime) -> datetime:
    return value if value.tzinfo else value.replace(tzinfo=UTC)


def _claim_token(action_id: str, attempt: int, idempotency_key: str) -> str:
    message = f"{action_id}:{attempt}:{idempotency_key}".encode()
    return hmac.new(
        get_settings().job_claim_secret.encode(), message, hashlib.sha256
    ).hexdigest()


def device_json(row: Device) -> dict[str, Any]:
    online = bool(
        row.last_seen_at
        and _aware(row.last_seen_at) >= datetime.now(UTC) - timedelta(minutes=5)
    )
    return {
        "id": row.id,
        "external_id": row.external_id,
        "hostname": row.hostname,
        "os": row.os,
        "enrolled_at": row.enrolled_at.isoformat() if row.enrolled_at else None,
        "last_seen_at": row.last_seen_at.isoformat() if row.last_seen_at else None,
        "status": "online" if online else "offline",
        "agent_status": "connected" if online else "disconnected",
        "active": row.active,
        "revoked_at": row.revoked_at.isoformat() if row.revoked_at else None,
        "revoked_reason": row.revoked_reason,
        "credential_rotated_at": (
            row.credential_rotated_at.isoformat() if row.credential_rotated_at else None
        ),
    }


def _device_summary(session: Session, row: Device, tenant_id: str) -> dict[str, Any]:
    result = device_json(row)
    result["open_incidents"] = _count(
        session,
        Incident,
        tenant_id,
        (Incident.device_id == row.id) & Incident.status.in_(["open", "investigating"]),
    )
    return result


def action_json(row: Action) -> dict[str, Any]:
    return {
        "id": row.id,
        "device_id": row.device_id,
        "ticket_id": row.ticket_id,
        "skill_id": row.skill_id,
        "parameters": row.parameters,
        "device_os": row.device_os,
        "risk": row.risk,
        "status": row.status,
        "requested_by": row.requested_by,
        "approved_by": row.approved_by,
        "attempt": row.attempt,
        "claimed_at": row.claimed_at.isoformat() if row.claimed_at else None,
        "lease_expires_at": (
            row.lease_expires_at.isoformat() if row.lease_expires_at else None
        ),
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


def _user_json(row: User) -> dict[str, Any]:
    return {
        "id": row.id,
        "tenant_id": row.tenant_id,
        "email": row.email,
        "role": row.role,
        "active": row.active,
    }
