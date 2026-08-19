"""Tests for PostgreSQL-only behavior in helpdesktool.persistence.

These tests use the ``postgres_session_factory`` fixture (see tests/conftest.py)
and are skipped unless HELPDESK_TEST_DATABASE_URL points at a real, disposable
PostgreSQL database. SQLite (used by the ``client`` fixture in every other test)
silently no-ops the ``pg_advisory_xact_lock`` branch in SqlAuditLog.append, so the
tenant-serialized audit sequence guarantee it exists to provide was previously
untested anywhere in this repository.
"""

from __future__ import annotations

import threading
from uuid import uuid4

from sqlalchemy import select

from helpdesktool.db_models import AuditEventRow, Tenant
from helpdesktool.persistence import SqlAuditLog


def test_advisory_lock_serializes_concurrent_audit_appends(postgres_session_factory):
    factory = postgres_session_factory
    worker_count = 20

    with factory() as session:
        tenant = Tenant(name=f"advisory-lock-test-{uuid4()}")
        session.add(tenant)
        session.commit()
        tenant_id = tenant.id

    errors: list[BaseException] = []

    def append_event(index: int) -> None:
        try:
            with factory() as session:
                SqlAuditLog(session).append(
                    tenant_id=tenant_id,
                    correlation_id=f"correlation-{index}",
                    event_type="test.concurrent_append",
                    actor_id="test-worker",
                    details={"index": index},
                )
                session.commit()
        except BaseException as exc:  # noqa: BLE001 - captured for the assertion below
            errors.append(exc)

    threads = [
        threading.Thread(target=append_event, args=(index,))
        for index in range(worker_count)
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert not errors, f"concurrent audit appends raised: {errors}"

    with factory() as session:
        rows = session.scalars(
            select(AuditEventRow)
            .where(AuditEventRow.tenant_id == tenant_id)
            .order_by(AuditEventRow.sequence)
        ).all()

    # The advisory lock must serialize appends into a gap-free, duplicate-free
    # sequence even though every worker committed concurrently on its own session.
    assert [row.sequence for row in rows] == list(range(1, worker_count + 1))

    # And the hash chain itself must be intact end to end.
    previous_hash = "0" * 64
    for row in rows:
        assert row.previous_hash == previous_hash
        previous_hash = row.event_hash


def test_advisory_lock_keeps_separate_tenants_independent(postgres_session_factory):
    factory = postgres_session_factory
    with factory() as session:
        tenant_a = Tenant(name=f"tenant-a-{uuid4()}")
        tenant_b = Tenant(name=f"tenant-b-{uuid4()}")
        session.add_all([tenant_a, tenant_b])
        session.commit()
        tenant_a_id, tenant_b_id = tenant_a.id, tenant_b.id

    with factory() as session:
        log = SqlAuditLog(session)
        log.append(
            tenant_id=tenant_a_id,
            correlation_id="a-1",
            event_type="test.independent",
            actor_id="test",
            details={},
        )
        log.append(
            tenant_id=tenant_b_id,
            correlation_id="b-1",
            event_type="test.independent",
            actor_id="test",
            details={},
        )
        session.commit()

    with factory() as session:
        for tenant_id in (tenant_a_id, tenant_b_id):
            rows = session.scalars(
                select(AuditEventRow).where(AuditEventRow.tenant_id == tenant_id)
            ).all()
            assert [row.sequence for row in rows] == [1]
