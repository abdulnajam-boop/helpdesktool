"""Tests for helpdesktool.retention_worker: bounded cleanup of expired
heartbeats, device inventory snapshots, and idempotency records -- and the
explicit guarantee that audit_events is never touched.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from sqlalchemy import select

from helpdesktool.config import Settings
from helpdesktool.db_models import (
    AuditEventRow,
    Device,
    DeviceInventory,
    Heartbeat,
    IdempotencyRecord,
    Tenant,
    User,
)
from helpdesktool.retention_worker import RetentionWorker


def _seed_tenant(session) -> tuple[str, str, str]:
    tenant = Tenant(name=f"tenant-{datetime.now(UTC).timestamp()}")
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
    session.commit()
    return tenant.id, user.id, device.id


def test_purges_expired_heartbeats_and_inventory_but_keeps_recent_ones(client):
    _, factory = client
    with factory() as session:
        tenant_id, _, device_id = _seed_tenant(session)
        old = datetime.now(UTC) - timedelta(days=60)
        recent = datetime.now(UTC) - timedelta(days=1)
        session.add(
            Heartbeat(
                tenant_id=tenant_id, device_id=device_id, received_at=old, status={}
            )
        )
        session.add(
            Heartbeat(
                tenant_id=tenant_id, device_id=device_id, received_at=recent, status={}
            )
        )
        session.add(
            DeviceInventory(
                tenant_id=tenant_id, device_id=device_id, collected_at=old, payload={}
            )
        )
        session.add(
            DeviceInventory(
                tenant_id=tenant_id,
                device_id=device_id,
                collected_at=recent,
                payload={},
            )
        )
        session.commit()

    worker = RetentionWorker(
        Settings(heartbeat_retention_days=30, inventory_retention_days=30)
    )
    with factory() as session:
        deleted = worker.process_batch(session)
    assert deleted == 2

    with factory() as session:
        from helpdesktool.database import set_tenant_context

        set_tenant_context(session, tenant_id)
        remaining_heartbeats = session.scalars(select(Heartbeat)).all()
        remaining_inventory = session.scalars(select(DeviceInventory)).all()
        assert len(remaining_heartbeats) == 1
        assert remaining_heartbeats[0].received_at.replace(tzinfo=UTC) > datetime.now(
            UTC
        ) - timedelta(days=2)
        assert len(remaining_inventory) == 1


def test_purges_expired_idempotency_records(client):
    _, factory = client
    with factory() as session:
        tenant_id, _, _ = _seed_tenant(session)
        old = datetime.now(UTC) - timedelta(days=10)
        session.add(
            IdempotencyRecord(
                tenant_id=tenant_id,
                scope="action",
                key="old-key",
                request_hash="a" * 64,
                response={},
                status_code=201,
                created_at=old,
            )
        )
        session.add(
            IdempotencyRecord(
                tenant_id=tenant_id,
                scope="action",
                key="new-key",
                request_hash="b" * 64,
                response={},
                status_code=201,
            )
        )
        session.commit()

    worker = RetentionWorker(Settings(idempotency_record_retention_days=7))
    with factory() as session:
        deleted = worker.process_batch(session)
    assert deleted == 1

    with factory() as session:
        from helpdesktool.database import set_tenant_context

        set_tenant_context(session, tenant_id)
        remaining = session.scalars(select(IdempotencyRecord)).all()
        assert len(remaining) == 1
        assert remaining[0].key == "new-key"


def test_never_touches_audit_events_regardless_of_age(client):
    """The core safety property: audit_events is hash-chained, so this
    worker must never delete from it, no matter how old a row is.
    """
    from helpdesktool.persistence import SqlAuditLog

    _, factory = client
    with factory() as session:
        tenant_id, user_id, device_id = _seed_tenant(session)
        from helpdesktool.database import set_tenant_context

        set_tenant_context(session, tenant_id)
        SqlAuditLog(session).append(
            tenant_id=tenant_id,
            correlation_id=device_id,
            event_type="device.enrolled",
            actor_id=user_id,
            details={},
        )
        session.commit()
        # Backdate it far beyond every retention window configured below.
        row = session.scalars(select(AuditEventRow)).one()
        row.occurred_at = datetime.now(UTC) - timedelta(days=3650)
        session.commit()

    worker = RetentionWorker(
        Settings(
            heartbeat_retention_days=1,
            inventory_retention_days=1,
            idempotency_record_retention_days=1,
        )
    )
    with factory() as session:
        worker.process_batch(session)

    with factory() as session:
        from helpdesktool.database import set_tenant_context

        set_tenant_context(session, tenant_id)
        assert session.scalars(select(AuditEventRow)).all()


def test_process_batch_clears_rls_bypass_after_running(client):
    """Symmetric with webhook_worker/lease_reaper: never leave the
    cross-tenant bypass GUC set on a connection once a batch is done.
    """
    from sqlalchemy import text

    _, factory = client
    with factory() as session:
        RetentionWorker(Settings()).process_batch(session)
        bind = session.get_bind()
        if bind.dialect.name == "postgresql":
            value = session.execute(
                text("SELECT current_setting('app.rls_bypass', true)")
            ).scalar()
            assert value in (None, "", "off")
