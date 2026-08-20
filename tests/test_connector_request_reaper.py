"""Tests for helpdesktool.connector_request_reaper: recovering
ConnectorRequest rows stuck pending_approval past the stale window
(Phase 8 -- the connector-request pipeline's equivalent of
lease_reaper.py, but for staleness rather than a crashed agent claim)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from sqlalchemy import select

from helpdesktool.config import Settings
from helpdesktool.connector_request_reaper import ConnectorRequestReaper
from helpdesktool.db_models import (
    ApplicationConnectorConfig,
    AuditEventRow,
    ConnectorRequest,
    Tenant,
    User,
)


def _make_pending_request(session, *, created_at) -> ConnectorRequest:
    tenant = Tenant(name=f"tenant-{created_at}")
    session.add(tenant)
    session.flush()
    user = User(
        tenant_id=tenant.id, email=f"owner-{tenant.id}@example.com", role="owner"
    )
    session.add(user)
    session.flush()
    connector = ApplicationConnectorConfig(
        tenant_id=tenant.id,
        application_id="entra",
        display_name="Entra ID",
        connector_type="mock",
        created_by=user.id,
    )
    session.add(connector)
    session.flush()
    request = ConnectorRequest(
        id=f"req-{tenant.id}",
        tenant_id=tenant.id,
        connector_id=connector.id,
        operation="reset_password",
        target_email="user@example.com",
        requested_by=user.id,
        risk="high",
        status="pending_approval",
        created_at=created_at,
        updated_at=created_at,
    )
    session.add(request)
    session.commit()
    return request


def test_stale_pending_request_is_expired(client):
    _, factory = client
    with factory() as session:
        request = _make_pending_request(
            session, created_at=datetime.now(UTC) - timedelta(hours=48)
        )
        request_id = request.id

    reaper = ConnectorRequestReaper(Settings(connector_request_stale_after_hours=24.0))
    with factory() as session:
        processed = reaper.process_batch(session)
    assert processed == 1

    with factory() as session:
        row = session.get(ConnectorRequest, request_id)
        assert row.status == "expired"
        assert row.decided_at is not None
        assert "auto-expired" in row.decision_reason
        events = session.scalars(
            select(AuditEventRow).where(AuditEventRow.correlation_id == request_id)
        ).all()
        assert any(
            e.event_type == "connector_request.escalation_required" for e in events
        )


def test_recent_pending_request_is_left_alone(client):
    _, factory = client
    with factory() as session:
        request = _make_pending_request(
            session, created_at=datetime.now(UTC) - timedelta(hours=1)
        )
        request_id = request.id

    reaper = ConnectorRequestReaper(Settings(connector_request_stale_after_hours=24.0))
    with factory() as session:
        processed = reaper.process_batch(session)
    assert processed == 0

    with factory() as session:
        row = session.get(ConnectorRequest, request_id)
        assert row.status == "pending_approval"


def test_non_pending_requests_are_ignored(client):
    _, factory = client
    with factory() as session:
        request = _make_pending_request(
            session, created_at=datetime.now(UTC) - timedelta(hours=48)
        )
        request.status = "approved"
        request_id = request.id
        session.commit()

    reaper = ConnectorRequestReaper(Settings(connector_request_stale_after_hours=24.0))
    with factory() as session:
        processed = reaper.process_batch(session)
    assert processed == 0

    with factory() as session:
        row = session.get(ConnectorRequest, request_id)
        assert row.status == "approved"
