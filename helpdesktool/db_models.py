from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import uuid4

from sqlalchemy import (
    JSON,
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy.orm import Mapped, mapped_column

from .database import Base


def new_id() -> str:
    return str(uuid4())


class Tenant(Base):
    __tablename__ = "tenants"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    name: Mapped[str] = mapped_column(String(200), unique=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )


class SkillManifestRow(Base):
    """A versioned remediation skill manifest. Global/platform-wide, not
    tenant-owned (like ``tenants`` itself) — the set of skills that exist is
    the same across every tenant; what varies per tenant is which ones a
    policy allows and which devices they run on. See
    ``helpdesktool/skills.py``'s module docstring for the full trust model,
    in particular why this is policy metadata only and never a way to ship
    new execution logic to an agent.
    """

    __tablename__ = "skills"
    __table_args__ = (UniqueConstraint("skill_id", "version"),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    skill_id: Mapped[str] = mapped_column(String(200), index=True)
    version: Mapped[int] = mapped_column(Integer)
    risk: Mapped[str] = mapped_column(String(30))
    supported_os: Mapped[list[str]] = mapped_column(JSON)
    timeout_seconds: Mapped[int] = mapped_column(Integer, default=30)
    rollback_skill_id: Mapped[str | None] = mapped_column(String(200))
    parameters: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    # Phase 2 safety metadata (helpdesktool/skills.py's SkillManifest
    # docstring explains exactly which of these are hash-covered and why).
    command_type: Mapped[str] = mapped_column(String(30), default="low_risk_change")
    requires_user_approval: Mapped[bool] = mapped_column(Boolean, default=False)
    requires_admin_approval: Mapped[bool] = mapped_column(Boolean, default=False)
    security_sensitive: Mapped[bool] = mapped_column(Boolean, default=False)
    reversible: Mapped[bool] = mapped_column(Boolean, default=True)
    required_privilege: Mapped[str] = mapped_column(String(100), default="")
    preconditions: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    expected_output: Mapped[str] = mapped_column(Text, default="")
    success_condition: Mapped[str] = mapped_column(Text, default="")
    failure_condition: Mapped[str] = mapped_column(Text, default="")
    side_effects: Mapped[str] = mapped_column(Text, default="")
    requires_reboot: Mapped[bool] = mapped_column(Boolean, default=False)
    allowed_execution_context: Mapped[str] = mapped_column(String(100), default="")
    content_hash: Mapped[str] = mapped_column(String(64))
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_by: Mapped[str] = mapped_column(String(36))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )


class WorkerHeartbeatRow(Base):
    """One row per background worker process (``webhook_worker``,
    ``lease_reaper``), upserted at the end of every batch iteration.
    Platform-wide/unscoped like ``tenants``/``skills`` — a worker's
    liveness isn't owned by any tenant. Consumed by ``GET /metrics`` (a
    stale heartbeat surfaces as a Prometheus gauge an alert rule can fire
    on) and ``GET /v1/system/health`` for human/operator consumption.
    """

    __tablename__ = "worker_heartbeats"
    worker_name: Mapped[str] = mapped_column(String(100), primary_key=True)
    last_heartbeat_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    last_batch_size: Mapped[int] = mapped_column(Integer, default=0)


class User(Base):
    __tablename__ = "users"
    __table_args__ = (UniqueConstraint("tenant_id", "email"),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    tenant_id: Mapped[str] = mapped_column(
        ForeignKey("tenants.id", ondelete="CASCADE"), index=True
    )
    email: Mapped[str] = mapped_column(String(320))
    role: Mapped[str] = mapped_column(String(30))
    active: Mapped[bool] = mapped_column(Boolean, default=True)


class Device(Base):
    __tablename__ = "devices"
    __table_args__ = (UniqueConstraint("tenant_id", "external_id"),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    tenant_id: Mapped[str] = mapped_column(
        ForeignKey("tenants.id", ondelete="CASCADE"), index=True
    )
    external_id: Mapped[str] = mapped_column(String(200))
    hostname: Mapped[str] = mapped_column(String(255))
    os: Mapped[str] = mapped_column(String(30))
    agent_key_hash: Mapped[str] = mapped_column(String(64))
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    revoked_reason: Mapped[str | None] = mapped_column(String(200))
    credential_rotated_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True)
    )
    enrolled_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    last_seen_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class EnrollmentToken(Base):
    """A short-lived, single-use token an admin generates out-of-band and
    hands to whoever is installing an agent, so the agent can self-enroll
    without an authenticated human session at enrollment time. Only the
    hash is stored; the raw token is returned exactly once, at creation.
    """

    __tablename__ = "enrollment_tokens"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    tenant_id: Mapped[str] = mapped_column(
        ForeignKey("tenants.id", ondelete="CASCADE"), index=True
    )
    token_hash: Mapped[str] = mapped_column(String(64), unique=True)
    created_by: Mapped[str] = mapped_column(ForeignKey("users.id"))
    label: Mapped[str] = mapped_column(String(200), default="")
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    used_by_device_id: Mapped[str | None] = mapped_column(
        ForeignKey("devices.id", ondelete="SET NULL")
    )
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )


class DeviceInventory(Base):
    __tablename__ = "device_inventory"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    tenant_id: Mapped[str] = mapped_column(
        ForeignKey("tenants.id", ondelete="CASCADE"), index=True
    )
    device_id: Mapped[str] = mapped_column(
        ForeignKey("devices.id", ondelete="CASCADE"), index=True
    )
    collected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    payload: Mapped[dict[str, Any]] = mapped_column(JSON)


class Heartbeat(Base):
    __tablename__ = "heartbeats"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    tenant_id: Mapped[str] = mapped_column(
        ForeignKey("tenants.id", ondelete="CASCADE"), index=True
    )
    device_id: Mapped[str] = mapped_column(
        ForeignKey("devices.id", ondelete="CASCADE"), index=True
    )
    received_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    status: Mapped[dict[str, Any]] = mapped_column(JSON)


class Ticket(Base):
    __tablename__ = "tickets"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    tenant_id: Mapped[str] = mapped_column(
        ForeignKey("tenants.id", ondelete="CASCADE"), index=True
    )
    device_id: Mapped[str | None] = mapped_column(
        ForeignKey("devices.id", ondelete="SET NULL")
    )
    title: Mapped[str] = mapped_column(String(300))
    description: Mapped[str] = mapped_column(Text, default="")
    status: Mapped[str] = mapped_column(String(30), default="open")
    priority: Mapped[str] = mapped_column(String(30), default="normal")
    created_by: Mapped[str] = mapped_column(ForeignKey("users.id"))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )


class Incident(Base):
    __tablename__ = "incidents"
    __table_args__ = (
        Index(
            "ix_incidents_tenant_device_correlation",
            "tenant_id",
            "device_id",
            "correlation_key",
        ),
    )
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    tenant_id: Mapped[str] = mapped_column(
        ForeignKey("tenants.id", ondelete="CASCADE"), index=True
    )
    device_id: Mapped[str] = mapped_column(
        ForeignKey("devices.id", ondelete="CASCADE"), index=True
    )
    ticket_id: Mapped[str | None] = mapped_column(
        ForeignKey("tickets.id", ondelete="SET NULL"), index=True
    )
    incident_type: Mapped[str] = mapped_column(String(100), index=True)
    severity: Mapped[str] = mapped_column(String(30))
    status: Mapped[str] = mapped_column(String(30), default="open", index=True)
    summary: Mapped[str] = mapped_column(String(300))
    evidence: Mapped[dict[str, Any]] = mapped_column(JSON)
    correlation_key: Mapped[str] = mapped_column(String(255))
    occurrence_count: Mapped[int] = mapped_column(Integer, default=1)
    first_observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    last_observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )


class Action(Base):
    __tablename__ = "actions"
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(
        ForeignKey("tenants.id", ondelete="CASCADE"), index=True
    )
    device_id: Mapped[str] = mapped_column(ForeignKey("devices.id"), index=True)
    ticket_id: Mapped[str | None] = mapped_column(
        ForeignKey("tickets.id", ondelete="SET NULL")
    )
    skill_id: Mapped[str] = mapped_column(String(200))
    requested_by: Mapped[str] = mapped_column(ForeignKey("users.id"))
    parameters: Mapped[dict[str, Any]] = mapped_column(JSON)
    device_os: Mapped[str] = mapped_column(String(30))
    risk: Mapped[str] = mapped_column(String(30))
    status: Mapped[str] = mapped_column(String(30))
    approved_by: Mapped[str | None] = mapped_column(ForeignKey("users.id"))
    claim_token_hash: Mapped[str | None] = mapped_column(String(64))
    claimed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    lease_expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    attempt: Mapped[int] = mapped_column(Integer, default=0)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )


class Approval(Base):
    __tablename__ = "approvals"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    tenant_id: Mapped[str] = mapped_column(
        ForeignKey("tenants.id", ondelete="CASCADE"), index=True
    )
    action_id: Mapped[str] = mapped_column(
        ForeignKey("actions.id", ondelete="CASCADE"), index=True
    )
    decided_by: Mapped[str] = mapped_column(ForeignKey("users.id"))
    decision: Mapped[str] = mapped_column(String(20))
    reason: Mapped[str | None] = mapped_column(Text)
    decided_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )


class Diagnosis(Base):
    """A stored AI (or deterministic-fallback) diagnosis proposal for an
    incident. Advisory only: a row here is never turned into an ``Action``
    automatically — see ``helpdesktool/ai/provider.py``'s module docstring
    for the full trust model.
    """

    __tablename__ = "diagnoses"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    tenant_id: Mapped[str] = mapped_column(
        ForeignKey("tenants.id", ondelete="CASCADE"), index=True
    )
    incident_id: Mapped[str] = mapped_column(
        ForeignKey("incidents.id", ondelete="CASCADE"), index=True
    )
    requested_by: Mapped[str] = mapped_column(ForeignKey("users.id"))
    provider_name: Mapped[str] = mapped_column(String(100))
    model: Mapped[str] = mapped_column(String(200))
    fallback_used: Mapped[bool] = mapped_column(Boolean, default=False)
    summary: Mapped[str] = mapped_column(Text)
    likely_root_cause: Mapped[str] = mapped_column(Text, default="")
    confidence: Mapped[float] = mapped_column(Float, default=0.0)
    suggested_skill_id: Mapped[str | None] = mapped_column(String(200))
    suggested_parameters: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    escalate: Mapped[bool] = mapped_column(Boolean, default=False)
    escalation_reason: Mapped[str] = mapped_column(Text, default="")
    latency_ms: Mapped[int] = mapped_column(Integer, default=0)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )


class ExecutionResultRow(Base):
    __tablename__ = "execution_results"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    tenant_id: Mapped[str] = mapped_column(
        ForeignKey("tenants.id", ondelete="CASCADE"), index=True
    )
    action_id: Mapped[str] = mapped_column(
        ForeignKey("actions.id", ondelete="CASCADE"), index=True
    )
    success: Mapped[bool] = mapped_column(Boolean)
    output: Mapped[dict[str, Any]] = mapped_column(JSON)
    error: Mapped[str | None] = mapped_column(Text)
    verified: Mapped[bool] = mapped_column(Boolean, default=False)
    rollback_attempted: Mapped[bool] = mapped_column(Boolean, default=False)
    rollback_succeeded: Mapped[bool | None] = mapped_column(Boolean)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )


class AuditEventRow(Base):
    __tablename__ = "audit_events"
    __table_args__ = (
        Index("ix_audit_tenant_sequence", "tenant_id", "sequence", unique=True),
    )
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    sequence: Mapped[int] = mapped_column(Integer)
    occurred_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    tenant_id: Mapped[str] = mapped_column(
        ForeignKey("tenants.id", ondelete="CASCADE"), index=True
    )
    correlation_id: Mapped[str] = mapped_column(String(100), index=True)
    event_type: Mapped[str] = mapped_column(String(100))
    actor_id: Mapped[str] = mapped_column(String(100))
    details: Mapped[dict[str, Any]] = mapped_column(JSON)
    previous_hash: Mapped[str] = mapped_column(String(64))
    event_hash: Mapped[str] = mapped_column(String(64), unique=True)


class IdempotencyRecord(Base):
    __tablename__ = "idempotency_records"
    __table_args__ = (UniqueConstraint("tenant_id", "scope", "key"),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    tenant_id: Mapped[str] = mapped_column(
        ForeignKey("tenants.id", ondelete="CASCADE"), index=True
    )
    scope: Mapped[str] = mapped_column(String(100))
    key: Mapped[str] = mapped_column(String(200))
    request_hash: Mapped[str] = mapped_column(String(64))
    response: Mapped[dict[str, Any]] = mapped_column(JSON)
    status_code: Mapped[int] = mapped_column(Integer)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )


class DomainEventRow(Base):
    __tablename__ = "domain_events"
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(
        ForeignKey("tenants.id", ondelete="CASCADE"), index=True
    )
    event_type: Mapped[str] = mapped_column(String(100), index=True)
    subject_id: Mapped[str] = mapped_column(String(100), index=True)
    schema_version: Mapped[int] = mapped_column(Integer, default=1)
    data: Mapped[dict[str, Any]] = mapped_column(JSON)
    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class WebhookSubscription(Base):
    __tablename__ = "webhook_subscriptions"
    __table_args__ = (UniqueConstraint("tenant_id", "name"),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    tenant_id: Mapped[str] = mapped_column(
        ForeignKey("tenants.id", ondelete="CASCADE"), index=True
    )
    name: Mapped[str] = mapped_column(String(100))
    url: Mapped[str] = mapped_column(String(2048))
    secret_ref: Mapped[str] = mapped_column(String(255))
    event_types: Mapped[list[str]] = mapped_column(JSON)
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_by: Mapped[str] = mapped_column(ForeignKey("users.id"))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )


class WebhookDelivery(Base):
    __tablename__ = "webhook_deliveries"
    __table_args__ = (UniqueConstraint("event_id", "subscription_id"),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    tenant_id: Mapped[str] = mapped_column(
        ForeignKey("tenants.id", ondelete="CASCADE"), index=True
    )
    event_id: Mapped[str] = mapped_column(
        ForeignKey("domain_events.id", ondelete="CASCADE"), index=True
    )
    subscription_id: Mapped[str] = mapped_column(
        ForeignKey("webhook_subscriptions.id", ondelete="CASCADE"), index=True
    )
    status: Mapped[str] = mapped_column(String(30), default="pending", index=True)
    attempt_count: Mapped[int] = mapped_column(Integer, default=0)
    next_attempt_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), index=True
    )
    last_attempt_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    delivered_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    response_status: Mapped[int | None] = mapped_column(Integer)
    last_error: Mapped[str | None] = mapped_column(Text)


class ApplicationConnectorConfig(Base):
    """A tenant's configured connector for one third-party application
    (Salesforce, Microsoft 365, ...). ``credential_ref`` follows the exact
    same environment-reference pattern as ``WebhookSubscription.secret_ref``
    (see ``integrations.py``'s ``EnvironmentSecretsProvider``) -- never a
    literal secret value in the database.
    """

    __tablename__ = "application_connectors"
    __table_args__ = (UniqueConstraint("tenant_id", "application_id"),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    tenant_id: Mapped[str] = mapped_column(
        ForeignKey("tenants.id", ondelete="CASCADE"), index=True
    )
    application_id: Mapped[str] = mapped_column(String(100))
    display_name: Mapped[str] = mapped_column(String(200))
    connector_type: Mapped[str] = mapped_column(String(50))
    config: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    credential_ref: Mapped[str] = mapped_column(String(255), default="")
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_by: Mapped[str] = mapped_column(ForeignKey("users.id"))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )


class Conversation(Base):
    """One chat thread across any channel (web, and future Slack/Teams/
    Google Chat adapters) -- the shared orchestration record every channel
    adapter feeds into, per CLAUDE.md's channel-adapter architecture.
    """

    __tablename__ = "conversations"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    tenant_id: Mapped[str] = mapped_column(
        ForeignKey("tenants.id", ondelete="CASCADE"), index=True
    )
    channel: Mapped[str] = mapped_column(String(30), index=True)
    channel_thread_id: Mapped[str] = mapped_column(String(255), default="")
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id"), index=True)
    status: Mapped[str] = mapped_column(String(30), default="open", index=True)
    ticket_id: Mapped[str | None] = mapped_column(
        ForeignKey("tickets.id", ondelete="SET NULL")
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )


class ConversationMessage(Base):
    __tablename__ = "conversation_messages"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    tenant_id: Mapped[str] = mapped_column(
        ForeignKey("tenants.id", ondelete="CASCADE"), index=True
    )
    conversation_id: Mapped[str] = mapped_column(
        ForeignKey("conversations.id", ondelete="CASCADE"), index=True
    )
    role: Mapped[str] = mapped_column(String(20))
    content: Mapped[str] = mapped_column(Text)
    intent: Mapped[str | None] = mapped_column(String(50))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )


class ConnectorRequest(Base):
    """A single proposed connector operation, gated by policy exactly like
    ``Action`` gates endpoint skills (``orchestrator.py``) -- read-only
    operations (see ``connectors.READ_ONLY_OPERATIONS``) execute
    immediately; high-risk ones (``connectors.HIGH_RISK_OPERATIONS``) sit
    ``pending_approval`` until an independent approver (never the
    requester -- enforced in ``api.py`` exactly like action approval)
    decides. Decision fields are inline here rather than reusing the
    ``approvals`` table, which is keyed to ``actions`` specifically.
    """

    __tablename__ = "connector_requests"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    tenant_id: Mapped[str] = mapped_column(
        ForeignKey("tenants.id", ondelete="CASCADE"), index=True
    )
    conversation_id: Mapped[str | None] = mapped_column(
        ForeignKey("conversations.id", ondelete="SET NULL")
    )
    connector_id: Mapped[str] = mapped_column(
        ForeignKey("application_connectors.id", ondelete="CASCADE")
    )
    operation: Mapped[str] = mapped_column(String(50))
    target_email: Mapped[str] = mapped_column(String(320))
    requested_by: Mapped[str] = mapped_column(ForeignKey("users.id"))
    risk: Mapped[str] = mapped_column(String(30))
    status: Mapped[str] = mapped_column(String(30), default="pending_approval")
    decided_by: Mapped[str | None] = mapped_column(ForeignKey("users.id"))
    decision_reason: Mapped[str | None] = mapped_column(Text)
    decided_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    result_success: Mapped[bool | None] = mapped_column(Boolean)
    result_detail: Mapped[str | None] = mapped_column(Text)
    verified: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )


class KnowledgeSourceRow(Base):
    """Provenance for an imported knowledge record (Phase 12). Platform-
    wide/unscoped like ``skills`` — a source's provenance isn't owned by
    any one tenant.
    """

    __tablename__ = "knowledge_sources"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    source_organization: Mapped[str] = mapped_column(String(200))
    source_url: Mapped[str] = mapped_column(String(2048), default="")
    retrieval_date: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    last_verified_date: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    source_reliability: Mapped[float] = mapped_column(Float, default=0.5)
    deprecated: Mapped[bool] = mapped_column(Boolean, default=False)
    superseded_by: Mapped[str | None] = mapped_column(
        ForeignKey("knowledge_sources.id", ondelete="SET NULL")
    )
    created_by: Mapped[str] = mapped_column(String(36))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )


class IssueDefinitionRow(Base):
    """A versioned, integrity-checked description of a recognizable IT
    issue (Phase 1). Platform-wide/unscoped like ``skills`` — see
    ``helpdesktool/knowledge.py``'s module docstring for the full trust
    model, in particular why this can never itself describe *how* a
    remediation executes, only which already-registered skill (if any) is
    relevant.
    """

    __tablename__ = "issue_definitions"
    __table_args__ = (UniqueConstraint("issue_key", "version"),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    issue_key: Mapped[str] = mapped_column(String(200), index=True)
    version: Mapped[int] = mapped_column(Integer)
    title: Mapped[str] = mapped_column(String(300))
    description: Mapped[str] = mapped_column(Text, default="")
    category: Mapped[str] = mapped_column(String(50))
    applicable_os: Mapped[list[str]] = mapped_column(JSON)
    applicable_software_versions: Mapped[dict[str, Any]] = mapped_column(
        JSON, default=dict
    )
    evidence_requirements: Mapped[list[dict[str, Any]]] = mapped_column(
        JSON, default=list
    )
    mitre_mappings: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list)
    cve_references: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list)
    escalation_policy: Mapped[dict[str, Any] | None] = mapped_column(JSON)
    source_id: Mapped[str | None] = mapped_column(
        ForeignKey("knowledge_sources.id", ondelete="SET NULL")
    )
    validated: Mapped[bool] = mapped_column(Boolean, default=False)
    content_hash: Mapped[str] = mapped_column(String(64))
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_by: Mapped[str] = mapped_column(String(36))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )


class DiagnosticWorkflowRow(Base):
    __tablename__ = "diagnostic_workflows"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    issue_definition_id: Mapped[str] = mapped_column(
        ForeignKey("issue_definitions.id", ondelete="CASCADE"), index=True
    )
    version: Mapped[int] = mapped_column(Integer, default=1)
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_by: Mapped[str] = mapped_column(String(36))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )


class DiagnosticStepRow(Base):
    __tablename__ = "diagnostic_steps"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    workflow_id: Mapped[str] = mapped_column(
        ForeignKey("diagnostic_workflows.id", ondelete="CASCADE"), index=True
    )
    step_order: Mapped[int] = mapped_column(Integer)
    step_type: Mapped[str] = mapped_column(String(30))
    description: Mapped[str] = mapped_column(Text, default="")
    remediation_skill_id: Mapped[str | None] = mapped_column(String(200))
    verification_description: Mapped[str] = mapped_column(Text, default="")
    rollback_skill_id: Mapped[str | None] = mapped_column(String(200))
    reference_description: Mapped[str] = mapped_column(Text, default="")


class OrganizationalBaselineRow(Base):
    """A tenant's declared "known good" value for some configuration key,
    at a given scope (Phase 6) -- see ``helpdesktool/baseline.py``'s module
    docstring. Tenant-scoped/RLS-protected, unlike the platform-wide
    knowledge tables above, since an organizational baseline is inherently
    specific to one tenant's own environment.
    """

    __tablename__ = "organizational_baselines"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    tenant_id: Mapped[str] = mapped_column(
        ForeignKey("tenants.id", ondelete="CASCADE"), index=True
    )
    scope: Mapped[str] = mapped_column(String(30))
    key: Mapped[str] = mapped_column(String(200), index=True)
    value: Mapped[Any] = mapped_column(JSON)
    device_id: Mapped[str | None] = mapped_column(
        ForeignKey("devices.id", ondelete="CASCADE")
    )
    user_id: Mapped[str | None] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE")
    )
    description: Mapped[str] = mapped_column(Text, default="")
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_by: Mapped[str] = mapped_column(String(36))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
