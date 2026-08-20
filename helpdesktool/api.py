from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import time
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any, cast

from fastapi import Depends, FastAPI, Header, HTTPException, Query, Response, status
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import CursorResult, func, select, text, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request

from .action_preview import build_action_preview
from .ai.provider import diagnose_with_fallback, get_ai_provider
from .auth import (
    Principal,
    require_agent,
    require_roles,
    require_user,
    resolving_identity,
)
from .baseline import BaselineEntry, BaselineValidationError, resolve_known_good
from .channels import ChannelSigningError
from .channels.google_chat import (
    build_google_chat_reply,
    build_google_chat_verifier,
    parse_google_chat_event,
    verify_google_chat_request,
)
from .channels.slack import (
    NullSlackReplySender,
    parse_slack_event,
    resolve_slack_signing_secret,
    verify_slack_signature,
)
from .confidence import ConfidenceInput, compute_confidence
from .config import get_settings
from .connectors import ConnectorRegistry
from .connectors.mock import MockApplicationConnector
from .conversation import handle_message
from .database import get_session, set_tenant_context
from .db_models import (
    Action,
    ApplicationConnectorConfig,
    Approval,
    AuditEventRow,
    ChannelIdentityLink,
    ChannelWorkspaceLink,
    ConnectorRequest,
    Conversation,
    ConversationMessage,
    Device,
    DeviceInventory,
    Diagnosis,
    DiagnosticStepRow,
    DiagnosticWorkflowRow,
    EnrollmentToken,
    ExecutionResultRow,
    Heartbeat,
    IdempotencyRecord,
    Incident,
    IssueDefinitionRow,
    KnowledgeSourceRow,
    OrganizationalBaselineRow,
    SkillManifestRow,
    Tenant,
    Ticket,
    User,
    WebhookDelivery,
    WebhookSubscription,
)
from .development_auth import issue_session
from .events import EventType
from .hardening import (
    RateLimitMiddleware,
    RequestSizeLimitMiddleware,
    SecurityHeadersMiddleware,
)
from .incidents import detect_inventory_incidents, incident_json
from .integrations import validate_webhook_url
from .job_signing import active_public_keys, sign_envelope
from .knowledge import (
    CveReference,
    DiagnosticStep,
    EscalationPolicy,
    EvidenceRequirement,
    IssueDefinition,
    KnowledgeValidationError,
    MitreMapping,
    validate_remediation_skill_references,
)
from .logging_config import configure_logging, set_request_id
from .metrics import (
    DEVICE_ONLINE_THRESHOLD,
    HTTP_REQUEST_DURATION_SECONDS,
    HTTP_REQUESTS_TOTAL,
    render_metrics,
)
from .models import (
    ActionRequest,
    CommandType,
    ExecutionResult,
    RiskLevel,
    SkillDefinition,
)
from .orchestrator import ActionOrchestrator
from .persistence import SqlActionStore, SqlAuditLog
from .policy import PolicyEngine, automation_level_for
from .reporting import build_report
from .schemas import (
    ActionCreate,
    ApprovalDecision,
    ChannelIdentityLinkCreate,
    ChannelWorkspaceLinkCreate,
    ChatMessageCreate,
    ConnectorConfigCreate,
    ConnectorRequestDecision,
    DeviceEnroll,
    DeviceRevoke,
    DiagnosticWorkflowCreate,
    EnrollmentTokenCreate,
    HeartbeatCreate,
    InventoryCreate,
    IssueDefinitionCreate,
    JobResult,
    KnowledgeSourceCreate,
    LowDiskSimulation,
    OrganizationalBaselineCreate,
    SkillManifestCreate,
    TenantCreate,
    TicketCreate,
    TicketUpdate,
    WebhookSubscriptionCreate,
)
from .skills import ParameterSpec, SkillManifest, validate_parameters

configure_logging()

_settings = get_settings()
# FastAPI's built-in Swagger/ReDoc UI and raw OpenAPI schema are
# development-only, matching every other dev-only surface in this codebase
# (dev login, insecure header auth) — publicly exposing the full endpoint/
# field-name schema of a multi-tenant SaaS API by default isn't a
# necessary tradeoff, and nothing in this app's own operation depends on
# them being reachable outside development.
_docs_enabled = _settings.environment == "development"
app = FastAPI(
    title="Helpdesktool Control Plane",
    version="0.2.0",
    docs_url="/docs" if _docs_enabled else None,
    redoc_url="/redoc" if _docs_enabled else None,
    openapi_url="/openapi.json" if _docs_enabled else None,
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=_settings.allowed_cors_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type", "Idempotency-Key"],
)


class RequestIdMiddleware(BaseHTTPMiddleware):
    """Propagates/generates a per-request correlation id (``X-Request-ID``),
    binds it to every structured log line emitted while handling this
    request (``helpdesktool.logging_config``), echoes it back in the
    response, and records the two HTTP-level Prometheus metrics
    (``helpdesktool.metrics``) against the matched route *template* — never
    the raw path, which would blow up label cardinality with every distinct
    device/action/incident id ever requested.
    """

    async def dispatch(
        self, request: Request, call_next: RequestResponseEndpoint
    ) -> Response:
        request_id = request.headers.get("X-Request-ID") or str(uuid.uuid4())
        set_request_id(request_id)
        started = time.monotonic()
        try:
            response = await call_next(request)
        finally:
            set_request_id(None)
        duration = time.monotonic() - started
        route = request.scope.get("route")
        path_template = getattr(route, "path", request.url.path)
        HTTP_REQUESTS_TOTAL.labels(
            method=request.method, path=path_template, status=str(response.status_code)
        ).inc()
        HTTP_REQUEST_DURATION_SECONDS.labels(
            method=request.method, path=path_template
        ).observe(duration)
        response.headers["X-Request-ID"] = request_id
        return response


app.add_middleware(RequestIdMiddleware)
app.add_middleware(
    RequestSizeLimitMiddleware, max_bytes=_settings.request_max_body_bytes
)
app.add_middleware(
    RateLimitMiddleware,
    max_requests=_settings.rate_limit_max_requests,
    window_seconds=_settings.rate_limit_window_seconds,
    enabled=_settings.environment != "development",
)
app.add_middleware(
    SecurityHeadersMiddleware, hsts=_settings.environment != "development"
)


def _manifest_from_row(row: SkillManifestRow) -> SkillManifest:
    return SkillManifest(
        skill_id=row.skill_id,
        version=row.version,
        risk=RiskLevel(row.risk),
        supported_os=frozenset(row.supported_os),
        timeout_seconds=row.timeout_seconds,
        rollback_skill_id=row.rollback_skill_id,
        parameters={
            name: ParameterSpec(spec["type"], spec["required"])
            for name, spec in row.parameters.items()
        },
        command_type=CommandType(row.command_type),
        requires_user_approval=row.requires_user_approval,
        requires_admin_approval=row.requires_admin_approval,
        security_sensitive=row.security_sensitive,
        reversible=row.reversible,
        required_privilege=row.required_privilege,
        preconditions=row.preconditions,
        expected_output=row.expected_output,
        success_condition=row.success_condition,
        failure_condition=row.failure_condition,
        side_effects=row.side_effects,
        requires_reboot=row.requires_reboot,
        allowed_execution_context=row.allowed_execution_context,
    )


def load_active_skill_manifests(session: Session) -> list[SkillManifest]:
    """The active version of every registered skill, integrity-verified.

    See ``helpdesktool/skills.py``'s module docstring: a manifest whose
    stored ``content_hash`` no longer matches its recomputed hash (e.g. a
    row edited directly in the database) fails the whole request closed
    rather than being silently trusted or silently dropped.
    """
    rows = session.scalars(
        select(SkillManifestRow).where(SkillManifestRow.active.is_(True))
    ).all()
    manifests = []
    for row in rows:
        manifest = _manifest_from_row(row)
        if manifest.content_hash() != row.content_hash:
            raise HTTPException(
                status.HTTP_500_INTERNAL_SERVER_ERROR,
                f"skill registry integrity check failed for {row.skill_id!r}",
            )
        manifests.append(manifest)
    return manifests


def get_active_manifest(session: Session, skill_id: str) -> SkillManifest | None:
    row = session.scalar(
        select(SkillManifestRow).where(
            SkillManifestRow.skill_id == skill_id, SkillManifestRow.active.is_(True)
        )
    )
    if row is None:
        return None
    manifest = _manifest_from_row(row)
    if manifest.content_hash() != row.content_hash:
        raise HTTPException(
            status.HTTP_500_INTERNAL_SERVER_ERROR,
            f"skill registry integrity check failed for {skill_id!r}",
        )
    return manifest


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
    skills = [m.to_skill_definition() for m in load_active_skill_manifests(session)]
    return ActionOrchestrator(
        PolicyEngine(skills),
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


# The application connector registry (helpdesktool/connectors/__init__.py).
# "mock" is always registered -- the dev-safe default with no external
# credentials required, same role as ai/provider.py's
# DeterministicFallbackProvider. A real connector (Salesforce, Microsoft
# 365, ...) registers here too once implemented; nothing about the API
# layer above changes to add one.
CONNECTOR_REGISTRY = ConnectorRegistry()
CONNECTOR_REGISTRY.register("mock", MockApplicationConnector)


@app.get("/health/live")
def liveness() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/health/ready")
def readiness(session: Session = Depends(get_session)) -> dict[str, str]:
    session.execute(text("SELECT 1"))
    return {"status": "ready"}


@app.get("/metrics")
def metrics_endpoint(
    authorization: str | None = Header(default=None),
    session: Session = Depends(get_session),
) -> Response:
    token = get_settings().metrics_token
    if token:
        supplied = (authorization or "").removeprefix("Bearer ")
        if (
            not authorization
            or not authorization.startswith("Bearer ")
            or not (secrets.compare_digest(supplied, token))
        ):
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid metrics token")
    body, content_type = render_metrics(session)
    return Response(content=body, media_type=content_type)


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


def _active_signing_keys() -> dict[int, str]:
    """The version -> PEM map every agent-facing endpoint that hands out
    signing keys should return -- one place expressing the current
    rotation window (``helpdesktool.job_signing``'s module docstring),
    consumed identically by device enrollment and the dedicated
    signing-key refresh endpoint.
    """
    settings = get_settings()
    return active_public_keys(
        settings.job_signing_seed,
        settings.job_signing_key_version,
        settings.job_signing_key_rotation_window,
    )


@app.post("/v1/devices/enroll", status_code=201)
def enroll_device(
    body: DeviceEnroll,
    principal: Principal = Depends(require_roles("owner", "admin")),
    session: Session = Depends(get_session),
) -> dict[str, Any]:
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
    return {
        "device_id": device.id,
        "agent_token": token,
        "signing_public_keys": _active_signing_keys(),
    }


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
) -> dict[str, Any]:
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
    return {
        "device_id": device.id,
        "tenant_id": enrollment.tenant_id,
        "agent_token": device_token,
        "signing_public_keys": _active_signing_keys(),
    }


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
    limit: int = 100,
    offset: int = 0,
    principal: Principal = Depends(require_user),
    session: Session = Depends(get_session),
) -> list[dict[str, Any]]:
    limit, offset = _clamp_pagination(limit, offset)
    rows = session.scalars(
        select(Device)
        .where(Device.tenant_id == principal.tenant_id)
        .order_by(Device.enrolled_at.desc())
        .offset(offset)
        .limit(limit)
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
    online_cutoff = datetime.now(UTC) - DEVICE_ONLINE_THRESHOLD
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


@app.get("/v1/reports/summary")
def report_summary(
    start: datetime | None = None,
    end: datetime | None = None,
    principal: Principal = Depends(require_user),
    session: Session = Depends(get_session),
) -> dict[str, Any]:
    """Operational report for a period -- see ``reporting.py``'s module
    docstring for exactly what each figure means and where it comes from.
    Defaults to the trailing 7 days when ``start``/``end`` are omitted; pass
    both explicitly (e.g. midnight-to-midnight) to generate a daily report.
    """
    period_end = _aware(end) if end else datetime.now(UTC)
    period_start = _aware(start) if start else period_end - timedelta(days=7)
    try:
        return build_report(session, principal.tenant_id, period_start, period_end)
    except ValueError as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc)) from exc


@app.get("/v1/incidents")
def list_incidents(
    limit: int = 100,
    offset: int = 0,
    principal: Principal = Depends(require_user),
    session: Session = Depends(get_session),
) -> list[dict[str, Any]]:
    limit, offset = _clamp_pagination(limit, offset)
    return [
        incident_json(row)
        for row in session.scalars(
            select(Incident)
            .where(Incident.tenant_id == principal.tenant_id)
            .order_by(Incident.last_observed_at.desc())
            .offset(offset)
            .limit(limit)
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
    result["diagnoses"] = [
        diagnosis_json(item)
        for item in session.scalars(
            select(Diagnosis)
            .where(
                Diagnosis.tenant_id == principal.tenant_id,
                Diagnosis.incident_id == row.id,
            )
            .order_by(Diagnosis.created_at.desc())
        ).all()
    ]
    return result


@app.post("/v1/incidents/{incident_id}/diagnose", status_code=201)
def diagnose_incident(
    incident_id: str,
    principal: Principal = Depends(require_roles("owner", "admin", "operator")),
    session: Session = Depends(get_session),
) -> dict[str, Any]:
    incident = tenant_row(session, Incident, incident_id, principal.tenant_id)
    settings = get_settings()
    evidence = {
        "incident_type": incident.incident_type,
        "severity": incident.severity,
        "status": incident.status,
        "device_id": incident.device_id,
        "occurrence_count": incident.occurrence_count,
        "summary": incident.summary,
        "evidence": incident.evidence,
    }
    provider = get_ai_provider(
        base_url=settings.ai_provider_base_url,
        api_key=settings.ai_provider_api_key,
        model=settings.ai_provider_model,
        allowed_skill_ids=tuple(
            m.skill_id for m in load_active_skill_manifests(session)
        ),
        timeout_seconds=settings.ai_timeout_seconds,
        max_retries=settings.ai_max_retries,
    )
    diagnosis = diagnose_with_fallback(provider, evidence)
    proposal = diagnosis.proposal

    # Confidence is never trusted from the AI provider -- computed
    # deterministically from real, inspectable evidence instead. See
    # helpdesktool/confidence.py's module docstring for why.
    device = session.get(Device, incident.device_id)
    telemetry_reliability = 1.0
    missing_signals = 0
    if device is not None and device.last_seen_at is not None:
        staleness = datetime.now(UTC) - _aware(device.last_seen_at)
        if staleness > DEVICE_ONLINE_THRESHOLD:
            telemetry_reliability = 0.5
            missing_signals = 1
    elif device is None or device.last_seen_at is None:
        telemetry_reliability = 0.5
        missing_signals = 1
    supporting_signals = sum(
        [
            incident.occurrence_count > 1,
            incident.severity in {"high", "critical"},
        ]
    )
    confidence_result = compute_confidence(
        ConfidenceInput(
            required_signals_present=1,
            required_signals_total=1,
            supporting_signals=supporting_signals,
            contradicting_signals=0,
            missing_signals=missing_signals,
            source_reliability=1.0,
            telemetry_reliability=telemetry_reliability,
            historical_baseline_matches=0,
            evidence_notes=(
                f"incident observed {incident.occurrence_count} time(s)",
                f"severity={incident.severity}",
            ),
        )
    )

    row = Diagnosis(
        tenant_id=principal.tenant_id,
        incident_id=incident.id,
        requested_by=principal.actor_id,
        provider_name=diagnosis.provider_name,
        model=diagnosis.model,
        fallback_used=diagnosis.fallback_used,
        summary=proposal.summary,
        likely_root_cause=proposal.likely_root_cause,
        confidence=confidence_result.score,
        suggested_skill_id=proposal.suggested_skill_id,
        suggested_parameters=proposal.suggested_parameters,
        escalate=proposal.escalate,
        escalation_reason=proposal.escalation_reason,
        latency_ms=diagnosis.latency_ms,
    )
    session.add(row)
    session.flush()
    audit(
        session,
        principal.tenant_id,
        incident.id,
        "incident.diagnosed",
        principal.actor_id,
        {
            "diagnosis_id": row.id,
            "provider": diagnosis.provider_name,
            "fallback_used": diagnosis.fallback_used,
            "suggested_skill_id": proposal.suggested_skill_id,
            "escalate": proposal.escalate,
            "confidence_score": confidence_result.score,
            "confidence_band": confidence_result.band,
            "confidence_evidence_summary": confidence_result.evidence_summary,
        },
    )
    result = diagnosis_json(row)
    session.commit()
    return result


@app.get("/v1/tickets")
def list_tickets(
    limit: int = 100,
    offset: int = 0,
    principal: Principal = Depends(require_user),
    session: Session = Depends(get_session),
) -> list[dict[str, Any]]:
    limit, offset = _clamp_pagination(limit, offset)
    return [
        ticket_json(row)
        for row in session.scalars(
            select(Ticket)
            .where(Ticket.tenant_id == principal.tenant_id)
            .order_by(Ticket.updated_at.desc())
            .offset(offset)
            .limit(limit)
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


@app.get("/v1/skills")
def list_skills(
    active_only: bool = Query(default=True),
    principal: Principal = Depends(require_user),
    session: Session = Depends(get_session),
) -> list[dict[str, Any]]:
    query = select(SkillManifestRow).order_by(
        SkillManifestRow.skill_id, SkillManifestRow.version.desc()
    )
    if active_only:
        query = query.where(SkillManifestRow.active.is_(True))
    return [skill_manifest_json(row) for row in session.scalars(query).all()]


@app.post("/v1/skills", status_code=201)
def create_skill_manifest(
    body: SkillManifestCreate,
    principal: Principal = Depends(require_roles("owner", "admin")),
    session: Session = Depends(get_session),
) -> dict[str, Any]:
    risk = RiskLevel(body.risk)
    parameters = {
        name: ParameterSpec(spec.type, spec.required)
        for name, spec in body.parameters.items()
    }
    previous = session.scalar(
        select(SkillManifestRow)
        .where(SkillManifestRow.skill_id == body.skill_id)
        .order_by(SkillManifestRow.version.desc())
        .limit(1)
    )
    next_version = 1 if previous is None else previous.version + 1
    manifest = SkillManifest(
        skill_id=body.skill_id,
        version=next_version,
        risk=risk,
        supported_os=frozenset(body.supported_os),
        timeout_seconds=body.timeout_seconds,
        rollback_skill_id=body.rollback_skill_id,
        parameters=parameters,
        command_type=CommandType(body.command_type),
        requires_user_approval=body.requires_user_approval,
        requires_admin_approval=body.requires_admin_approval,
        security_sensitive=body.security_sensitive,
        reversible=body.reversible,
    )
    if previous is not None and previous.active:
        previous.active = False
    row = SkillManifestRow(
        skill_id=body.skill_id,
        version=next_version,
        risk=str(manifest.risk),
        supported_os=sorted(body.supported_os),
        timeout_seconds=body.timeout_seconds,
        rollback_skill_id=body.rollback_skill_id,
        parameters={
            name: {"type": spec.type, "required": spec.required}
            for name, spec in body.parameters.items()
        },
        command_type=body.command_type,
        requires_user_approval=body.requires_user_approval,
        requires_admin_approval=body.requires_admin_approval,
        security_sensitive=body.security_sensitive,
        reversible=body.reversible,
        required_privilege=body.required_privilege,
        preconditions=body.preconditions,
        expected_output=body.expected_output,
        success_condition=body.success_condition,
        failure_condition=body.failure_condition,
        side_effects=body.side_effects,
        requires_reboot=body.requires_reboot,
        allowed_execution_context=body.allowed_execution_context,
        content_hash=manifest.content_hash(),
        active=True,
        created_by=principal.actor_id,
    )
    session.add(row)
    session.flush()
    audit(
        session,
        principal.tenant_id,
        row.id,
        "skill.registered",
        principal.actor_id,
        {"skill_id": row.skill_id, "version": row.version, "risk": row.risk},
    )
    result = skill_manifest_json(row)
    session.commit()
    return result


def knowledge_source_json(row: KnowledgeSourceRow) -> dict[str, Any]:
    return {
        "id": row.id,
        "source_organization": row.source_organization,
        "source_url": row.source_url,
        "retrieval_date": row.retrieval_date,
        "last_verified_date": row.last_verified_date,
        "source_reliability": row.source_reliability,
        "deprecated": row.deprecated,
        "superseded_by": row.superseded_by,
        "created_by": row.created_by,
        "created_at": row.created_at,
    }


@app.post("/v1/knowledge/sources", status_code=201)
def create_knowledge_source(
    body: KnowledgeSourceCreate,
    principal: Principal = Depends(require_roles("owner", "admin")),
    session: Session = Depends(get_session),
) -> dict[str, Any]:
    row = KnowledgeSourceRow(
        source_organization=body.source_organization,
        source_url=body.source_url,
        retrieval_date=body.retrieval_date,
        last_verified_date=body.last_verified_date,
        source_reliability=body.source_reliability,
        created_by=principal.actor_id,
    )
    session.add(row)
    session.flush()
    audit(
        session,
        principal.tenant_id,
        row.id,
        "knowledge_source.registered",
        principal.actor_id,
        {"source_organization": row.source_organization},
    )
    result = knowledge_source_json(row)
    session.commit()
    return result


@app.get("/v1/knowledge/sources")
def list_knowledge_sources(
    principal: Principal = Depends(require_user),
    session: Session = Depends(get_session),
) -> list[dict[str, Any]]:
    rows = session.scalars(
        select(KnowledgeSourceRow).order_by(KnowledgeSourceRow.created_at.desc())
    ).all()
    return [knowledge_source_json(row) for row in rows]


def _issue_definition_from_row(row: IssueDefinitionRow) -> IssueDefinition:
    return IssueDefinition(
        issue_key=row.issue_key,
        version=row.version,
        title=row.title,
        description=row.description,
        category=row.category,
        applicable_os=frozenset(row.applicable_os),
        source_id=row.source_id,
        applicable_software_versions=row.applicable_software_versions,
        evidence_requirements=tuple(
            EvidenceRequirement(
                item["name"], item.get("description", ""), item["required"]
            )
            for item in row.evidence_requirements
        ),
        mitre_mappings=tuple(
            MitreMapping(
                item["technique_id"],
                item.get("tactic", ""),
                item.get("mapping_confidence", 0.5),
                item.get("mapping_evidence", ""),
            )
            for item in row.mitre_mappings
        ),
        cve_references=tuple(
            CveReference(item["cve_id"], item.get("applicable_versions", ""))
            for item in row.cve_references
        ),
        escalation_policy=(
            EscalationPolicy(**row.escalation_policy) if row.escalation_policy else None
        ),
    )


def issue_definition_json(row: IssueDefinitionRow) -> dict[str, Any]:
    return {
        "id": row.id,
        "issue_key": row.issue_key,
        "version": row.version,
        "title": row.title,
        "description": row.description,
        "category": row.category,
        "applicable_os": row.applicable_os,
        "applicable_software_versions": row.applicable_software_versions,
        "evidence_requirements": row.evidence_requirements,
        "mitre_mappings": row.mitre_mappings,
        "cve_references": row.cve_references,
        "escalation_policy": row.escalation_policy,
        "source_id": row.source_id,
        "validated": row.validated,
        "content_hash": row.content_hash,
        "active": row.active,
        "created_by": row.created_by,
        "created_at": row.created_at,
    }


@app.post("/v1/knowledge/issues", status_code=201)
def create_issue_definition(
    body: IssueDefinitionCreate,
    principal: Principal = Depends(require_roles("owner", "admin")),
    session: Session = Depends(get_session),
) -> dict[str, Any]:
    """Registers a new (or new-version) issue definition. ``validated``
    means this record passed structural validation (well-formed MITRE/CVE
    ids, non-empty required fields, ...) — it does NOT mean any referenced
    remediation has been reviewed for correctness; that remains a human
    judgment call. See ``helpdesktool/knowledge.py``'s module docstring:
    this is reference data, never itself executable, regardless of
    ``validated``.
    """
    try:
        evidence_requirements = tuple(
            EvidenceRequirement(item.name, item.description, item.required)
            for item in body.evidence_requirements
        )
        mitre_mappings = tuple(
            MitreMapping(
                item.technique_id,
                item.tactic,
                item.mapping_confidence,
                item.mapping_evidence,
            )
            for item in body.mitre_mappings
        )
        cve_references = tuple(
            CveReference(item.cve_id, item.applicable_versions)
            for item in body.cve_references
        )
        escalation_policy = (
            EscalationPolicy(
                body.escalation_policy.condition,
                body.escalation_policy.escalate_to_role,
                body.escalation_policy.priority,
            )
            if body.escalation_policy
            else None
        )
        previous = session.scalar(
            select(IssueDefinitionRow)
            .where(IssueDefinitionRow.issue_key == body.issue_key)
            .order_by(IssueDefinitionRow.version.desc())
            .limit(1)
        )
        next_version = 1 if previous is None else previous.version + 1
        definition = IssueDefinition(
            issue_key=body.issue_key,
            version=next_version,
            title=body.title,
            description=body.description,
            category=body.category,
            applicable_os=frozenset(body.applicable_os),
            source_id=body.source_id,
            applicable_software_versions=body.applicable_software_versions,
            evidence_requirements=evidence_requirements,
            mitre_mappings=mitre_mappings,
            cve_references=cve_references,
            escalation_policy=escalation_policy,
        )
    except KnowledgeValidationError as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, str(exc)) from exc
    if previous is not None and previous.active:
        previous.active = False
    row = IssueDefinitionRow(
        issue_key=body.issue_key,
        version=next_version,
        title=body.title,
        description=body.description,
        category=body.category,
        applicable_os=body.applicable_os,
        applicable_software_versions=body.applicable_software_versions,
        evidence_requirements=[
            item.model_dump() for item in body.evidence_requirements
        ],
        mitre_mappings=[item.model_dump() for item in body.mitre_mappings],
        cve_references=[item.model_dump() for item in body.cve_references],
        escalation_policy=(
            body.escalation_policy.model_dump() if body.escalation_policy else None
        ),
        source_id=body.source_id,
        validated=True,
        content_hash=definition.content_hash(),
        active=True,
        created_by=principal.actor_id,
    )
    session.add(row)
    session.flush()
    audit(
        session,
        principal.tenant_id,
        row.id,
        "issue_definition.registered",
        principal.actor_id,
        {"issue_key": row.issue_key, "version": row.version, "category": row.category},
    )
    result = issue_definition_json(row)
    session.commit()
    return result


@app.get("/v1/knowledge/issues")
def list_issue_definitions(
    active_only: bool = Query(default=True),
    principal: Principal = Depends(require_user),
    session: Session = Depends(get_session),
) -> list[dict[str, Any]]:
    query = select(IssueDefinitionRow).order_by(
        IssueDefinitionRow.issue_key, IssueDefinitionRow.version.desc()
    )
    if active_only:
        query = query.where(IssueDefinitionRow.active.is_(True))
    return [issue_definition_json(row) for row in session.scalars(query).all()]


@app.get("/v1/knowledge/issues/{issue_definition_id}")
def get_issue_definition(
    issue_definition_id: str,
    principal: Principal = Depends(require_user),
    session: Session = Depends(get_session),
) -> dict[str, Any]:
    row = session.get(IssueDefinitionRow, issue_definition_id)
    if row is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "issue definition not found")
    definition = _issue_definition_from_row(row)
    if definition.content_hash() != row.content_hash:
        raise HTTPException(
            status.HTTP_500_INTERNAL_SERVER_ERROR,
            f"knowledge integrity check failed for {row.issue_key!r}",
        )
    result = issue_definition_json(row)
    workflows = session.scalars(
        select(DiagnosticWorkflowRow).where(
            DiagnosticWorkflowRow.issue_definition_id == issue_definition_id
        )
    ).all()
    result["workflows"] = []
    for workflow in workflows:
        steps = session.scalars(
            select(DiagnosticStepRow)
            .where(DiagnosticStepRow.workflow_id == workflow.id)
            .order_by(DiagnosticStepRow.step_order)
        ).all()
        result["workflows"].append(
            {
                "id": workflow.id,
                "version": workflow.version,
                "active": workflow.active,
                "steps": [
                    {
                        "id": step.id,
                        "step_order": step.step_order,
                        "step_type": step.step_type,
                        "description": step.description,
                        "remediation_skill_id": step.remediation_skill_id,
                        "verification_description": step.verification_description,
                        "rollback_skill_id": step.rollback_skill_id,
                        "reference_description": step.reference_description,
                    }
                    for step in steps
                ],
            }
        )
    return result


@app.post("/v1/knowledge/issues/{issue_definition_id}/workflows", status_code=201)
def create_diagnostic_workflow(
    issue_definition_id: str,
    body: DiagnosticWorkflowCreate,
    principal: Principal = Depends(require_roles("owner", "admin")),
    session: Session = Depends(get_session),
) -> dict[str, Any]:
    """Registers a diagnostic workflow for an issue definition. Every
    ``remediation_skill_id``/``rollback_skill_id`` referenced by any step
    is checked against the *actual, currently active* skill registry —
    fails closed (422) if any step references a skill id that isn't
    really registered, per ``knowledge.py``'s core safety invariant:
    knowledge may reference an existing trusted skill, never invent one.
    """
    issue_row = session.get(IssueDefinitionRow, issue_definition_id)
    if issue_row is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "issue definition not found")
    known_skill_ids = frozenset(
        m.skill_id for m in load_active_skill_manifests(session)
    )
    try:
        steps = tuple(
            DiagnosticStep(
                step.step_order,
                step.step_type,
                step.description,
                step.remediation_skill_id,
                step.verification_description,
                step.rollback_skill_id,
                step.reference_description,
            )
            for step in body.steps
        )
        validate_remediation_skill_references(steps, known_skill_ids)
    except KnowledgeValidationError as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, str(exc)) from exc

    previous = session.scalar(
        select(DiagnosticWorkflowRow)
        .where(DiagnosticWorkflowRow.issue_definition_id == issue_definition_id)
        .order_by(DiagnosticWorkflowRow.version.desc())
        .limit(1)
    )
    next_version = 1 if previous is None else previous.version + 1
    if previous is not None and previous.active:
        previous.active = False
    workflow = DiagnosticWorkflowRow(
        issue_definition_id=issue_definition_id,
        version=next_version,
        active=True,
        created_by=principal.actor_id,
    )
    session.add(workflow)
    session.flush()
    for step in body.steps:
        session.add(
            DiagnosticStepRow(
                workflow_id=workflow.id,
                step_order=step.step_order,
                step_type=step.step_type,
                description=step.description,
                remediation_skill_id=step.remediation_skill_id,
                verification_description=step.verification_description,
                rollback_skill_id=step.rollback_skill_id,
                reference_description=step.reference_description,
            )
        )
    audit(
        session,
        principal.tenant_id,
        workflow.id,
        "diagnostic_workflow.registered",
        principal.actor_id,
        {
            "issue_definition_id": issue_definition_id,
            "version": workflow.version,
            "step_count": len(body.steps),
        },
    )
    session.commit()
    return {
        "id": workflow.id,
        "issue_definition_id": issue_definition_id,
        "version": workflow.version,
    }


def baseline_json(row: OrganizationalBaselineRow) -> dict[str, Any]:
    return {
        "id": row.id,
        "scope": row.scope,
        "key": row.key,
        "value": row.value,
        "device_id": row.device_id,
        "user_id": row.user_id,
        "description": row.description,
        "active": row.active,
        "created_by": row.created_by,
        "created_at": row.created_at,
    }


@app.post("/v1/baselines", status_code=201)
def create_organizational_baseline(
    body: OrganizationalBaselineCreate,
    principal: Principal = Depends(require_roles("owner", "admin")),
    session: Session = Depends(get_session),
) -> dict[str, Any]:
    """Registers this tenant's own declared "known good" value for a
    configuration key (Phase 6) -- see ``helpdesktool/baseline.py``'s
    module docstring. A device_baseline/user_baseline entry's device_id/
    user_id must belong to this tenant (checked the same way any other
    tenant-scoped foreign reference is -- ``tenant_row`` fails closed with
    404 rather than trusting a client-supplied id from another tenant).
    """
    if body.device_id is not None:
        tenant_row(session, Device, body.device_id, principal.tenant_id)
    if body.user_id is not None:
        tenant_row(session, User, body.user_id, principal.tenant_id)
    try:
        BaselineEntry(
            scope=body.scope,  # type: ignore[arg-type]
            key=body.key,
            value=body.value,
            device_id=body.device_id,
            user_id=body.user_id,
            description=body.description,
        )
    except BaselineValidationError as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, str(exc)) from exc

    row = OrganizationalBaselineRow(
        tenant_id=principal.tenant_id,
        scope=body.scope,
        key=body.key,
        value=body.value,
        device_id=body.device_id,
        user_id=body.user_id,
        description=body.description,
        created_by=principal.actor_id,
    )
    session.add(row)
    session.flush()
    audit(
        session,
        principal.tenant_id,
        row.id,
        "baseline.registered",
        principal.actor_id,
        {"scope": row.scope, "key": row.key},
    )
    result = baseline_json(row)
    session.commit()
    return result


@app.get("/v1/baselines")
def list_organizational_baselines(
    key: str | None = None,
    active_only: bool = Query(default=True),
    principal: Principal = Depends(require_user),
    session: Session = Depends(get_session),
) -> list[dict[str, Any]]:
    query = select(OrganizationalBaselineRow).where(
        OrganizationalBaselineRow.tenant_id == principal.tenant_id
    )
    if key is not None:
        query = query.where(OrganizationalBaselineRow.key == key)
    if active_only:
        query = query.where(OrganizationalBaselineRow.active.is_(True))
    rows = session.scalars(query.order_by(OrganizationalBaselineRow.key)).all()
    return [baseline_json(row) for row in rows]


@app.get("/v1/baselines/resolve")
def resolve_organizational_baseline(
    key: str,
    device_id: str | None = None,
    user_id: str | None = None,
    principal: Principal = Depends(require_user),
    session: Session = Depends(get_session),
) -> dict[str, Any]:
    """Resolves the single most authoritative known-good value for ``key``
    for this tenant (Phase 6) -- see ``helpdesktool.baseline.resolve_known_good``.
    Returns ``{"resolved": null}`` when nothing at all is declared for this
    key; callers must never invent a fallback (e.g. a public DNS resolver)
    on a null result themselves.
    """
    rows = session.scalars(
        select(OrganizationalBaselineRow).where(
            OrganizationalBaselineRow.tenant_id == principal.tenant_id,
            OrganizationalBaselineRow.key == key,
            OrganizationalBaselineRow.active.is_(True),
        )
    ).all()
    entries = [
        BaselineEntry(
            scope=row.scope,  # type: ignore[arg-type]
            key=row.key,
            value=row.value,
            device_id=row.device_id,
            user_id=row.user_id,
            description=row.description,
        )
        for row in rows
    ]
    resolved = resolve_known_good(entries, key, device_id=device_id, user_id=user_id)
    if resolved is None:
        return {"resolved": None}
    return {
        "resolved": {
            "scope": resolved.scope,
            "key": resolved.key,
            "value": resolved.value,
            "device_id": resolved.device_id,
            "user_id": resolved.user_id,
            "description": resolved.description,
        }
    }


@app.get("/v1/actions")
def list_actions(
    limit: int = 100,
    offset: int = 0,
    principal: Principal = Depends(require_user),
    session: Session = Depends(get_session),
) -> list[dict[str, Any]]:
    limit, offset = _clamp_pagination(limit, offset)
    return [
        action_json(row)
        for row in session.scalars(
            select(Action)
            .where(Action.tenant_id == principal.tenant_id)
            .order_by(Action.created_at.desc())
            .offset(offset)
            .limit(limit)
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


def conversation_json(
    row: Conversation, messages: list[ConversationMessage]
) -> dict[str, Any]:
    return {
        "id": row.id,
        "channel": row.channel,
        "status": row.status,
        "ticket_id": row.ticket_id,
        "created_at": row.created_at,
        "updated_at": row.updated_at,
        "messages": [
            {
                "id": m.id,
                "role": m.role,
                "content": m.content,
                "intent": m.intent,
                "created_at": m.created_at,
            }
            for m in messages
        ],
    }


def connector_request_json(row: ConnectorRequest) -> dict[str, Any]:
    return {
        "id": row.id,
        "conversation_id": row.conversation_id,
        "connector_id": row.connector_id,
        "operation": row.operation,
        "target_email": row.target_email,
        "requested_by": row.requested_by,
        "risk": row.risk,
        "status": row.status,
        "decided_by": row.decided_by,
        "decision_reason": row.decision_reason,
        "decided_at": row.decided_at,
        "result_success": row.result_success,
        "result_detail": row.result_detail,
        "verified": row.verified,
        # Never the hash or the raw code -- just whether one is currently
        # outstanding, so an operator UI can show "waiting on requester" vs.
        # "ready for approval".
        "step_up_code_pending": row.step_up_code_hash is not None,
        "created_at": row.created_at,
    }


@app.post("/v1/chat/message", status_code=201)
def send_chat_message(
    body: ChatMessageCreate,
    principal: Principal = Depends(require_user),
    session: Session = Depends(get_session),
) -> dict[str, Any]:
    """The web channel adapter: the caller's already-authenticated session
    *is* the resolved channel identity (no separate identity-resolution
    step needed here, unlike a future Slack/Teams/Google Chat adapter,
    which would call ``identity_resolution.resolve_channel_identity``
    against its own signature-verified provider identity first).
    """
    user = session.get(User, principal.actor_id)
    if user is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "user not found")
    if body.conversation_id:
        tenant_row(session, Conversation, body.conversation_id, principal.tenant_id)
    result = handle_message(
        session,
        principal.tenant_id,
        user,
        channel="web",
        channel_thread_id=body.conversation_id or "",
        message=body.message,
        conversation_id=body.conversation_id,
    )
    session.commit()
    return {
        "conversation_id": result.conversation_id,
        "reply": result.reply,
        "ticket_id": result.ticket_id,
        "connector_request_id": result.connector_request_id,
    }


def channel_workspace_link_json(row: ChannelWorkspaceLink) -> dict[str, Any]:
    return {
        "id": row.id,
        "channel": row.channel,
        "workspace_id": row.workspace_id,
        "signing_secret_ref": row.signing_secret_ref,
        "active": row.active,
        "created_by": row.created_by,
        "created_at": row.created_at,
    }


@app.post("/v1/channels/workspace-links", status_code=201)
def create_channel_workspace_link(
    body: ChannelWorkspaceLinkCreate,
    principal: Principal = Depends(require_roles("owner", "admin")),
    session: Session = Depends(get_session),
) -> dict[str, Any]:
    """Registers which external chat workspace (e.g. a Slack ``team_id``)
    belongs to this tenant (Phase 18). The returned ``id`` is the
    ``link_id`` path segment the provider's webhook Request URL must be
    configured with -- see ``slack_events`` below for why a per-link URL,
    not one shared endpoint, is what makes multi-tenant signature
    verification possible at all.
    """
    row = ChannelWorkspaceLink(
        tenant_id=principal.tenant_id,
        channel=body.channel,
        workspace_id=body.workspace_id,
        signing_secret_ref=body.signing_secret_ref,
        created_by=principal.actor_id,
    )
    session.add(row)
    try:
        session.flush()
    except IntegrityError as exc:
        raise HTTPException(
            status.HTTP_409_CONFLICT, "this workspace is already linked to a tenant"
        ) from exc
    audit(
        session,
        principal.tenant_id,
        row.id,
        "channel_workspace_link.registered",
        principal.actor_id,
        {"channel": row.channel, "workspace_id": row.workspace_id},
    )
    result = channel_workspace_link_json(row)
    session.commit()
    return result


@app.get("/v1/channels/workspace-links")
def list_channel_workspace_links(
    principal: Principal = Depends(require_user),
    session: Session = Depends(get_session),
) -> list[dict[str, Any]]:
    rows = session.scalars(
        select(ChannelWorkspaceLink).where(
            ChannelWorkspaceLink.tenant_id == principal.tenant_id
        )
    ).all()
    return [channel_workspace_link_json(row) for row in rows]


def channel_identity_link_json(row: ChannelIdentityLink) -> dict[str, Any]:
    return {
        "id": row.id,
        "channel": row.channel,
        "provider_user_id": row.provider_user_id,
        "user_id": row.user_id,
        "created_by": row.created_by,
        "created_at": row.created_at,
    }


@app.post("/v1/channels/identity-links", status_code=201)
def create_channel_identity_link(
    body: ChannelIdentityLinkCreate,
    principal: Principal = Depends(require_roles("owner", "admin")),
    session: Session = Depends(get_session),
) -> dict[str, Any]:
    """Maps an external chat provider's already-authenticated user id to a
    Helpdesktool user (Phase 18) -- see
    ``helpdesktool/identity_resolution.py``'s trust-model docstring: the
    provider user id must come from the provider's own signed payload,
    never from message text.
    """
    tenant_row(session, User, body.user_id, principal.tenant_id)
    row = ChannelIdentityLink(
        tenant_id=principal.tenant_id,
        channel=body.channel,
        provider_user_id=body.provider_user_id,
        user_id=body.user_id,
        created_by=principal.actor_id,
    )
    session.add(row)
    try:
        session.flush()
    except IntegrityError as exc:
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            "this provider identity is already linked for this tenant",
        ) from exc
    audit(
        session,
        principal.tenant_id,
        row.id,
        "channel_identity_link.registered",
        principal.actor_id,
        {"channel": row.channel, "provider_user_id": row.provider_user_id},
    )
    result = channel_identity_link_json(row)
    session.commit()
    return result


@app.get("/v1/channels/identity-links")
def list_channel_identity_links(
    principal: Principal = Depends(require_user),
    session: Session = Depends(get_session),
) -> list[dict[str, Any]]:
    rows = session.scalars(
        select(ChannelIdentityLink).where(
            ChannelIdentityLink.tenant_id == principal.tenant_id
        )
    ).all()
    return [channel_identity_link_json(row) for row in rows]


@app.post("/v1/channels/slack/events/{link_id}")
async def slack_events(
    link_id: str,
    request: Request,
    session: Session = Depends(get_session),
) -> Any:
    """The Slack Events API webhook target. Unauthenticated by design --
    like any real Slack app's Request URL -- trust comes entirely from
    Slack's own request signature, verified below against the signing
    secret the matching ``ChannelWorkspaceLink`` references. The link id
    in the URL (rather than one shared endpoint for every tenant) is what
    lets a multi-tenant control plane resolve *which* tenant's signing
    secret applies before even parsing the body -- required for Slack's
    ``url_verification`` handshake, whose payload carries no ``team_id``
    at all. Always acknowledges with 2xx/204 once the request is
    authentic, per Slack's own retry semantics, even when the event ends
    up not actionable (unresolved identity, inactive user, non-message
    event) -- returning an error there would just cause Slack to retry a
    request that will never become actionable.
    """
    # No Principal/tenant context exists yet for this unauthenticated
    # webhook request -- which tenant this is even depends on the row
    # we're about to look up. Same narrow, documented exception as
    # auth.resolving_identity (see rls.py's module docstring): bypass RLS
    # for exactly this one lookup, then bind the session to the resolved
    # tenant for everything else in the request, exactly as get_session()
    # does automatically for an authenticated request.
    with resolving_identity(session):
        link = session.get(ChannelWorkspaceLink, link_id)
    if link is None or not link.active:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "unknown channel link")
    set_tenant_context(session, link.tenant_id)

    body = await request.body()
    timestamp = request.headers.get("X-Slack-Request-Timestamp", "")
    signature = request.headers.get("X-Slack-Signature", "")
    try:
        signing_secret = resolve_slack_signing_secret(
            dict(os.environ), link.signing_secret_ref
        )
        verify_slack_signature(signing_secret, timestamp, body, signature)
    except ChannelSigningError as exc:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, str(exc)) from exc

    payload = json.loads(body)
    if payload.get("type") == "url_verification":
        return {"challenge": payload.get("challenge", "")}

    envelope = parse_slack_event(payload)
    if envelope is None:
        return Response(status_code=204)
    if envelope.team_id != link.workspace_id:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "workspace mismatch")

    # is not None, not a truthy check: the stored response for a processed
    # Slack event is deliberately an empty dict (this endpoint always
    # replies 204/no body), and an empty dict is falsy -- a truthy check
    # here would silently treat every replay as a brand-new event and then
    # crash on the idempotency table's own unique constraint.
    if (
        idempotency_lookup(
            session, link.tenant_id, "slack_event", envelope.event_id, payload
        )
        is not None
    ):
        return Response(status_code=204)

    identity_link = session.scalar(
        select(ChannelIdentityLink).where(
            ChannelIdentityLink.tenant_id == link.tenant_id,
            ChannelIdentityLink.channel == "slack",
            ChannelIdentityLink.provider_user_id == envelope.user_id,
        )
    )
    user = (
        session.get(User, identity_link.user_id) if identity_link is not None else None
    )
    if user is None or not user.active:
        audit(
            session,
            link.tenant_id,
            link.id,
            "channel_message.unresolved_identity",
            "system:slack_adapter",
            {"provider_user_id": envelope.user_id, "channel": "slack"},
        )
        remember(session, link.tenant_id, "slack_event", envelope.event_id, payload, {})
        session.commit()
        return Response(status_code=204)

    result = handle_message(
        session,
        link.tenant_id,
        user,
        channel="slack",
        channel_thread_id=envelope.channel_id,
        message=envelope.text,
    )
    remember(session, link.tenant_id, "slack_event", envelope.event_id, payload, {})
    session.commit()
    NullSlackReplySender().send(
        channel_id=envelope.channel_id, thread_ts=envelope.thread_ts, text=result.reply
    )
    return Response(status_code=204)


@app.post("/v1/channels/google-chat/events/{link_id}")
async def google_chat_events(
    link_id: str,
    request: Request,
    session: Session = Depends(get_session),
) -> Any:
    """The Google Chat HTTP endpoint app's webhook target. Unauthenticated
    by design, like ``slack_events`` above -- trust comes entirely from
    Google's own signed Bearer ID token, verified against the audience
    (Cloud project number) the matching ``ChannelWorkspaceLink`` declares.
    Unlike Slack, this app replies **synchronously in the HTTP response
    body itself** -- see ``channels/google_chat.py``'s module docstring
    for why that closes the reply loop without a BLOCKED-EXTERNAL bot
    token dependency.
    """
    with resolving_identity(session):
        link = session.get(ChannelWorkspaceLink, link_id)
    if link is None or not link.active or link.channel != "google_chat":
        raise HTTPException(status.HTTP_404_NOT_FOUND, "unknown channel link")
    set_tenant_context(session, link.tenant_id)

    try:
        verify_google_chat_request(
            build_google_chat_verifier(link.workspace_id),
            request.headers.get("Authorization", ""),
        )
    except ChannelSigningError as exc:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, str(exc)) from exc

    payload = await request.json()
    envelope = parse_google_chat_event(payload)
    if envelope is None:
        return Response(status_code=204)

    cached = idempotency_lookup(
        session, link.tenant_id, "google_chat_event", envelope.event_id, payload
    )
    if cached is not None:
        return cached

    identity_link = session.scalar(
        select(ChannelIdentityLink).where(
            ChannelIdentityLink.tenant_id == link.tenant_id,
            ChannelIdentityLink.channel == "google_chat",
            ChannelIdentityLink.provider_user_id == envelope.user_name,
        )
    )
    user = (
        session.get(User, identity_link.user_id) if identity_link is not None else None
    )
    if user is None or not user.active:
        audit(
            session,
            link.tenant_id,
            link.id,
            "channel_message.unresolved_identity",
            "system:google_chat_adapter",
            {"provider_user_id": envelope.user_name, "channel": "google_chat"},
        )
        reply_body = build_google_chat_reply(
            "I couldn't match your Google Chat account to a Helpdesktool user. "
            "Please ask an administrator to link your account."
        )
        remember(
            session,
            link.tenant_id,
            "google_chat_event",
            envelope.event_id,
            payload,
            reply_body,
        )
        session.commit()
        return reply_body

    result = handle_message(
        session,
        link.tenant_id,
        user,
        channel="google_chat",
        channel_thread_id=envelope.space_name,
        message=envelope.text,
    )
    reply_body = build_google_chat_reply(result.reply)
    remember(
        session,
        link.tenant_id,
        "google_chat_event",
        envelope.event_id,
        payload,
        reply_body,
    )
    session.commit()
    return reply_body


@app.get("/v1/conversations")
def list_conversations(
    limit: int = 100,
    offset: int = 0,
    principal: Principal = Depends(require_user),
    session: Session = Depends(get_session),
) -> list[dict[str, Any]]:
    limit, offset = _clamp_pagination(limit, offset)
    query = select(Conversation).where(Conversation.tenant_id == principal.tenant_id)
    if principal.role not in {"owner", "admin"}:
        query = query.where(Conversation.user_id == principal.actor_id)
    rows = session.scalars(
        query.order_by(Conversation.updated_at.desc()).offset(offset).limit(limit)
    ).all()
    return [conversation_json(row, []) for row in rows]


@app.get("/v1/conversations/{conversation_id}")
def get_conversation(
    conversation_id: str,
    principal: Principal = Depends(require_user),
    session: Session = Depends(get_session),
) -> dict[str, Any]:
    row = tenant_row(session, Conversation, conversation_id, principal.tenant_id)
    if principal.role not in {"owner", "admin"} and row.user_id != principal.actor_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "resource not found")
    messages = session.scalars(
        select(ConversationMessage)
        .where(ConversationMessage.conversation_id == conversation_id)
        .order_by(ConversationMessage.created_at)
    ).all()
    return conversation_json(row, list(messages))


@app.post("/v1/connectors", status_code=201)
def create_connector(
    body: ConnectorConfigCreate,
    principal: Principal = Depends(require_roles("owner", "admin")),
    session: Session = Depends(get_session),
) -> dict[str, Any]:
    if body.connector_type not in CONNECTOR_REGISTRY.known_types():
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY,
            f"unknown connector_type; must be one of {sorted(CONNECTOR_REGISTRY.known_types())}",
        )
    row = ApplicationConnectorConfig(
        tenant_id=principal.tenant_id,
        application_id=body.application_id,
        display_name=body.display_name,
        connector_type=body.connector_type,
        config=body.config,
        credential_ref=body.credential_ref,
        created_by=principal.actor_id,
    )
    session.add(row)
    try:
        session.flush()
    except IntegrityError as exc:
        raise HTTPException(
            status.HTTP_409_CONFLICT, "a connector for this application already exists"
        ) from exc
    audit(
        session,
        principal.tenant_id,
        row.id,
        "connector.registered",
        principal.actor_id,
        {"application_id": row.application_id, "connector_type": row.connector_type},
    )
    result = {
        "id": row.id,
        "application_id": row.application_id,
        "display_name": row.display_name,
        "connector_type": row.connector_type,
        "active": row.active,
        "created_at": row.created_at,
    }
    session.commit()
    return result


@app.get("/v1/connectors")
def list_connectors(
    principal: Principal = Depends(require_user),
    session: Session = Depends(get_session),
) -> list[dict[str, Any]]:
    rows = session.scalars(
        select(ApplicationConnectorConfig).where(
            ApplicationConnectorConfig.tenant_id == principal.tenant_id
        )
    ).all()
    return [
        {
            "id": row.id,
            "application_id": row.application_id,
            "display_name": row.display_name,
            "connector_type": row.connector_type,
            "active": row.active,
            "created_at": row.created_at,
        }
        for row in rows
    ]


@app.get("/v1/connector-requests")
def list_connector_requests(
    principal: Principal = Depends(require_user),
    session: Session = Depends(get_session),
) -> list[dict[str, Any]]:
    rows = session.scalars(
        select(ConnectorRequest)
        .where(
            ConnectorRequest.tenant_id == principal.tenant_id,
            ConnectorRequest.status == "pending_approval",
        )
        .order_by(ConnectorRequest.created_at)
    ).all()
    return [connector_request_json(row) for row in rows]


_STEP_UP_CODE_TTL_MINUTES = 10


def _verify_connector_request_step_up_code(
    row: ConnectorRequest, supplied: str | None
) -> None:
    """Fails closed on every path: no code generated yet, expired, or
    wrong -- all 403, never a silent pass-through. Consumes the code on
    success so it can never be replayed against a second decision attempt.
    """
    if row.step_up_code_hash is None:
        raise HTTPException(
            status.HTTP_403_FORBIDDEN,
            "requester has not generated a step-up verification code yet",
        )
    if row.step_up_code_expires_at is None or _aware(
        row.step_up_code_expires_at
    ) < datetime.now(UTC):
        raise HTTPException(
            status.HTTP_403_FORBIDDEN, "step-up verification code has expired"
        )
    if not supplied or not secrets.compare_digest(
        hashlib.sha256(supplied.encode()).hexdigest(), row.step_up_code_hash
    ):
        raise HTTPException(
            status.HTTP_403_FORBIDDEN, "incorrect step-up verification code"
        )
    row.step_up_code_hash = None
    row.step_up_code_expires_at = None


@app.get("/v1/connector-requests/{request_id}/step-up-code", status_code=201)
def generate_connector_request_step_up_code(
    request_id: str,
    principal: Principal = Depends(require_user),
    session: Session = Depends(get_session),
) -> dict[str, Any]:
    """Mints a fresh, short-lived step-up verification code for a
    high-risk connector request -- only the request's own original
    requester may call this (never an approver, and never anyone else),
    and only through whatever authenticated session this endpoint is
    reached with. The point is exactly that: reaching this endpoint at all
    requires an independently authenticated call, separate from however
    the original request was created (a Slack/Google Chat message, for
    instance) -- see migration 0018's docstring for the trust model this
    closes. Only the SHA-256 hash is stored; the raw code is returned in
    this one response and nowhere else.
    """
    row = tenant_row(session, ConnectorRequest, request_id, principal.tenant_id)
    if row.requested_by != principal.actor_id:
        raise HTTPException(
            status.HTTP_403_FORBIDDEN,
            "only the requester can generate their own step-up code",
        )
    if row.risk != "high":
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            "step-up verification only applies to high-risk requests",
        )
    if row.status != "pending_approval":
        raise HTTPException(status.HTTP_409_CONFLICT, "request is not pending approval")
    code = f"{secrets.randbelow(900_000_000) + 100_000_000}"
    expires_at = datetime.now(UTC) + timedelta(minutes=_STEP_UP_CODE_TTL_MINUTES)
    row.step_up_code_hash = hashlib.sha256(code.encode()).hexdigest()
    row.step_up_code_expires_at = expires_at
    audit(
        session,
        principal.tenant_id,
        row.id,
        "connector_request.step_up_code_generated",
        principal.actor_id,
        {"expires_at": expires_at.isoformat()},
    )
    session.commit()
    return {"step_up_code": code, "expires_at": expires_at}


@app.post("/v1/connector-requests/{request_id}/decision")
def decide_connector_request(
    request_id: str,
    body: ConnectorRequestDecision,
    principal: Principal = Depends(require_roles("owner", "admin")),
    session: Session = Depends(get_session),
) -> dict[str, Any]:
    row = tenant_row(session, ConnectorRequest, request_id, principal.tenant_id)
    if row.status != "pending_approval":
        raise HTTPException(status.HTTP_409_CONFLICT, "request is not pending approval")
    if row.requested_by == principal.actor_id:
        raise HTTPException(
            status.HTTP_403_FORBIDDEN, "requester cannot decide their own request"
        )
    if body.decision == "approve" and row.risk == "high":
        _verify_connector_request_step_up_code(row, body.step_up_code)
    row.decided_by = principal.actor_id
    row.decision_reason = body.reason
    row.decided_at = datetime.now(UTC)
    if body.decision == "deny":
        row.status = "denied"
        audit(
            session,
            principal.tenant_id,
            row.id,
            "connector_request.denied",
            principal.actor_id,
            {"reason": body.reason},
        )
        session.commit()
        return connector_request_json(row)

    connector_config = tenant_row(
        session, ApplicationConnectorConfig, row.connector_id, principal.tenant_id
    )
    connector = CONNECTOR_REGISTRY.create(connector_config.connector_type)
    resolved = connector.resolve_user(row.target_email)
    if not resolved.success:
        row.status = "failed"
        row.result_success = False
        row.result_detail = resolved.detail
        audit(
            session,
            principal.tenant_id,
            row.id,
            "connector_request.failed",
            principal.actor_id,
            {"reason": resolved.detail, "stage": "resolve_user"},
        )
        session.commit()
        return connector_request_json(row)

    external_user_id = str(resolved.data["external_user_id"])
    operation_method = getattr(connector, row.operation)
    execution = operation_method(external_user_id)
    verification = connector.verify_result(external_user_id, row.operation)
    row.status = "succeeded" if execution.success else "failed"
    row.result_success = execution.success
    row.result_detail = execution.detail
    row.verified = verification.success
    audit(
        session,
        principal.tenant_id,
        row.id,
        "connector_request.executed"
        if execution.success
        else "connector_request.failed",
        principal.actor_id,
        {
            "operation": row.operation,
            "success": execution.success,
            "verified": verification.success,
        },
    )
    session.commit()
    return connector_request_json(row)


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
    manifest = get_active_manifest(session, body.skill_id)
    if manifest is not None:
        shape_error = validate_parameters(manifest, body.parameters)
        if shape_error is not None:
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, shape_error)
    # service.restart's *shape* (a single required "service" string) is
    # covered generically above by the registry's parameter schema; which
    # service names are actually allowed to be restarted is a separate,
    # tenant-independent business policy (Settings.service_allowlist), not
    # something the skill registry's shape-only schema is meant to express.
    if body.skill_id == "service.restart":
        if body.parameters.get("service") not in get_settings().allowed_services:
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


@app.get("/v1/actions/{action_id}/preview")
def preview_action(
    action_id: str,
    principal: Principal = Depends(require_user),
    session: Session = Depends(get_session),
) -> dict[str, Any]:
    """Phase 14: "show exactly what this specific action would do, without
    running it" as one explicit, structured answer, computed fresh from
    the current active skill manifest every call -- see
    ``action_preview.py``'s module docstring. Works regardless of the
    action's current status; the preview always reflects what *would*
    happen if it ran against the manifest as currently registered, which
    may have changed version since this action was originally requested.
    """
    row = tenant_row(session, Action, action_id, principal.tenant_id)
    manifest = get_active_manifest(session, row.skill_id)
    if manifest is None:
        raise HTTPException(
            status.HTTP_404_NOT_FOUND,
            f"skill {row.skill_id!r} is no longer an active registered skill",
        )
    skill_definition = manifest.to_skill_definition()
    policy_decision = PolicyEngine([skill_definition]).evaluate(
        ActionRequest(
            tenant_id=principal.tenant_id,
            device_id=row.device_id,
            skill_id=row.skill_id,
            requested_by=row.requested_by,
            parameters=row.parameters,
        ),
        row.device_os,
    )
    automation_level = automation_level_for(
        skill_definition, policy_decision.approval_required
    )
    preview = build_action_preview(
        manifest=manifest,
        parameters=row.parameters,
        policy_decision=policy_decision,
        automation_level=automation_level,
    )
    return {
        "action_id": row.id,
        "action_status": row.status,
        "skill_id": preview.skill_id,
        "skill_version": preview.skill_version,
        "command_type": preview.command_type,
        "risk": preview.risk,
        "required_privilege": preview.required_privilege,
        "timeout_seconds": preview.timeout_seconds,
        "parameters": preview.parameters,
        "preconditions": preview.preconditions,
        "expected_output": preview.expected_output,
        "success_condition": preview.success_condition,
        "failure_condition": preview.failure_condition,
        "side_effects": preview.side_effects,
        "requires_reboot": preview.requires_reboot,
        "reversible": preview.reversible,
        "rollback_skill_id": preview.rollback_skill_id,
        "automation_level": preview.automation_level.value,
        "policy_allowed": preview.policy_allowed,
        "approval_required": preview.approval_required,
        "policy_reason": preview.policy_reason,
        "what_would_execute": preview.what_would_execute,
        "verification_plan": preview.verification_plan,
        "rollback_plan": preview.rollback_plan,
    }


@app.get("/v1/devices/{device_id}/signing-key")
def agent_signing_key(
    device_id: str,
    principal: Principal = Depends(require_agent),
) -> dict[str, Any]:
    """Lets an already-enrolled agent refresh its locally-trusted
    signing-key set via trust-on-first-use. Called every agent cycle now
    (``linux_agent``/``windows_agent``'s ``ensure_signing_key``), not just
    once, so a key rotated on the control plane (bumping
    ``Settings.job_signing_key_version``) is picked up automatically within
    one heartbeat interval -- see ``helpdesktool/job_signing.py``'s module
    docstring for the rotation model. New enrollments get the same
    ``signing_public_keys`` map directly in their enrollment response
    instead -- see ``enroll_device``/``enroll_device_with_token``.
    """
    return {"signing_public_keys": _active_signing_keys()}


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
    if current is not None and current.tenant_id == principal.tenant_id:
        manifest = get_active_manifest(session, current.skill_id)
        if manifest is None:
            raise HTTPException(
                status.HTTP_409_CONFLICT,
                "skill is no longer registered; job cannot be claimed",
            )
        skill_version = manifest.version
    else:
        skill_version = 0
    next_attempt = 1 if current is None else current.attempt + 1
    token = _claim_token(action_id, next_attempt, idempotency_key)
    now = datetime.now(UTC)
    expires_at = now + timedelta(seconds=60)
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
                lease_expires_at=expires_at,
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
    envelope: dict[str, Any] = {
        "job_id": f"{row.id}:{row.attempt}",
        "action_id": row.id,
        "device_id": row.device_id,
        "tenant_id": principal.tenant_id,
        "skill_id": row.skill_id,
        "skill_version": skill_version,
        "parameters": row.parameters,
        "device_os": row.device_os,
        "issued_at": now.isoformat(),
        "expires_at": row.lease_expires_at.isoformat(),
        "nonce": secrets.token_hex(16),
        "key_version": get_settings().job_signing_key_version,
    }
    envelope["signature"] = sign_envelope(
        envelope,
        get_settings().job_signing_seed,
        get_settings().job_signing_key_version,
    )
    result: dict[str, Any] = {
        **envelope,
        "id": row.id,
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
            "job_id": envelope["job_id"],
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


def _clamp_pagination(limit: int, offset: int) -> tuple[int, int]:
    """Every unbounded list endpoint clamps through this so none of them can
    be made to return an unlimited result set — a genuinely large tenant
    (or a malicious one) can no longer force an arbitrarily large query/
    response just by not passing ``limit``. ``limit`` defaults generously
    (100) so this is invisible to any caller that was already implicitly
    relying on "give me everything" for a normal-sized tenant.
    """
    return max(1, min(limit, 500)), max(0, offset)


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
        and _aware(row.last_seen_at) >= datetime.now(UTC) - DEVICE_ONLINE_THRESHOLD
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


def skill_manifest_json(row: SkillManifestRow) -> dict[str, Any]:
    return {
        "id": row.id,
        "skill_id": row.skill_id,
        "version": row.version,
        "risk": row.risk,
        "supported_os": row.supported_os,
        "timeout_seconds": row.timeout_seconds,
        "rollback_skill_id": row.rollback_skill_id,
        "parameters": row.parameters,
        "command_type": row.command_type,
        "requires_user_approval": row.requires_user_approval,
        "requires_admin_approval": row.requires_admin_approval,
        "security_sensitive": row.security_sensitive,
        "reversible": row.reversible,
        "required_privilege": row.required_privilege,
        "preconditions": row.preconditions,
        "expected_output": row.expected_output,
        "success_condition": row.success_condition,
        "failure_condition": row.failure_condition,
        "side_effects": row.side_effects,
        "requires_reboot": row.requires_reboot,
        "allowed_execution_context": row.allowed_execution_context,
        "content_hash": row.content_hash,
        "active": row.active,
        "created_by": row.created_by,
        "created_at": row.created_at.isoformat() if row.created_at else None,
    }


def diagnosis_json(row: Diagnosis) -> dict[str, Any]:
    return {
        "id": row.id,
        "incident_id": row.incident_id,
        "requested_by": row.requested_by,
        "provider_name": row.provider_name,
        "model": row.model,
        "fallback_used": row.fallback_used,
        "summary": row.summary,
        "likely_root_cause": row.likely_root_cause,
        "confidence": row.confidence,
        "suggested_skill_id": row.suggested_skill_id,
        "suggested_parameters": row.suggested_parameters,
        "escalate": row.escalate,
        "escalation_reason": row.escalation_reason,
        "latency_ms": row.latency_ms,
        "created_at": row.created_at.isoformat() if row.created_at else None,
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
