"""Tests for helpdesktool.lease_reaper: recovering abandoned job claims."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from sqlalchemy import select

from helpdesktool.config import Settings
from helpdesktool.db_models import Action, AuditEventRow, Device, Tenant, User
from helpdesktool.lease_reaper import LeaseReaper


def _make_claimed_action(session, *, attempt: int, lease_expires_at) -> Action:
    tenant = Tenant(name=f"tenant-{attempt}-{lease_expires_at}")
    session.add(tenant)
    session.flush()
    user = User(
        tenant_id=tenant.id, email=f"owner-{tenant.id}@example.com", role="owner"
    )
    session.add(user)
    session.flush()
    device = Device(
        tenant_id=tenant.id,
        external_id=f"device-{tenant.id}",
        hostname="host",
        os="linux",
        agent_key_hash="x" * 64,
    )
    session.add(device)
    session.flush()
    action = Action(
        id=f"action-{tenant.id}",
        tenant_id=tenant.id,
        device_id=device.id,
        skill_id="service.restart",
        requested_by=user.id,
        parameters={"service": "demo.service"},
        device_os="linux",
        risk="medium",
        status="claimed",
        claim_token_hash="y" * 64,
        claimed_at=datetime.now(UTC) - timedelta(minutes=5),
        lease_expires_at=lease_expires_at,
        attempt=attempt,
    )
    session.add(action)
    session.commit()
    return action


def test_expired_claim_is_requeued_when_attempts_remain(client):
    _, factory = client
    with factory() as session:
        action = _make_claimed_action(
            session,
            attempt=1,
            lease_expires_at=datetime.now(UTC) - timedelta(minutes=1),
        )
        action_id = action.id

    reaper = LeaseReaper(Settings(lease_reaper_max_attempts=3))
    with factory() as session:
        processed = reaper.process_batch(session)
    assert processed == 1

    with factory() as session:
        row = session.get(Action, action_id)
        assert row.status == "queued"
        assert row.claim_token_hash is None
        assert row.claimed_at is None
        assert row.lease_expires_at is None
        events = session.scalars(
            select(AuditEventRow).where(AuditEventRow.correlation_id == action_id)
        ).all()
        assert any(e.event_type == "execution.lease_expired_requeued" for e in events)


def test_expired_claim_escalates_after_max_attempts(client):
    _, factory = client
    with factory() as session:
        action = _make_claimed_action(
            session,
            attempt=3,
            lease_expires_at=datetime.now(UTC) - timedelta(minutes=1),
        )
        action_id = action.id

    reaper = LeaseReaper(Settings(lease_reaper_max_attempts=3))
    with factory() as session:
        processed = reaper.process_batch(session)
    assert processed == 1

    with factory() as session:
        row = session.get(Action, action_id)
        assert row.status == "failed"
        events = session.scalars(
            select(AuditEventRow).where(AuditEventRow.correlation_id == action_id)
        ).all()
        assert any(e.event_type == "action.escalation_required" for e in events)


def test_unexpired_claim_is_left_alone(client):
    _, factory = client
    with factory() as session:
        action = _make_claimed_action(
            session,
            attempt=1,
            lease_expires_at=datetime.now(UTC) + timedelta(minutes=5),
        )
        action_id = action.id

    reaper = LeaseReaper(Settings(lease_reaper_max_attempts=3))
    with factory() as session:
        processed = reaper.process_batch(session)
    assert processed == 0

    with factory() as session:
        row = session.get(Action, action_id)
        assert row.status == "claimed"


def test_non_claimed_actions_are_ignored(client):
    _, factory = client
    with factory() as session:
        action = _make_claimed_action(
            session,
            attempt=1,
            lease_expires_at=datetime.now(UTC) - timedelta(minutes=1),
        )
        action.status = "succeeded"
        action_id = action.id
        session.commit()

    reaper = LeaseReaper(Settings(lease_reaper_max_attempts=3))
    with factory() as session:
        processed = reaper.process_batch(session)
    assert processed == 0

    with factory() as session:
        row = session.get(Action, action_id)
        assert row.status == "succeeded"
