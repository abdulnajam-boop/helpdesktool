"""Direct database-layer tests for PostgreSQL row-level security.

These bypass the API entirely and exercise the RLS policies themselves
(``helpdesktool.rls``, applied here with the identical DDL migration 0005
uses), proving the isolation guarantee holds even if some future API
handler forgets a ``WHERE tenant_id = ...`` filter. API-level tests that
prove the same thing through real HTTP requests live in
``test_auth_tenant_isolation_api_postgres.py``.
"""

from __future__ import annotations

from uuid import uuid4

import pytest
from sqlalchemy import select
from sqlalchemy.exc import DBAPIError

from helpdesktool.database import (
    reset_tenant_context,
    set_rls_bypass,
    set_tenant_context,
)
from helpdesktool.db_models import AuditEventRow, Tenant, User


def _make_tenant(session, name: str) -> Tenant:
    tenant = Tenant(name=name)
    session.add(tenant)
    session.commit()
    return tenant


def test_session_with_no_tenant_context_sees_nothing(postgres_rls_session_factory):
    factory = postgres_rls_session_factory
    with factory() as setup:
        tenant_a = _make_tenant(setup, f"tenant-a-{uuid4()}")
        set_tenant_context(setup, tenant_a.id)
        setup.add(User(tenant_id=tenant_a.id, email="owner@a.example", role="owner"))
        setup.commit()
        # set_tenant_context uses is_local=false so it survives the commit
        # above (see its docstring); reset it explicitly here to simulate
        # what helpdesktool.database.get_session's real teardown does at the
        # end of every request, rather than leaving it to leak onto whatever
        # connection this session's pool hands back next.
        reset_tenant_context(setup)

    # A fresh session that never calls set_tenant_context at all must see
    # zero rows, across every tenant — true default deny, not "deny unless
    # someone forgets to filter."
    with factory() as blind:
        assert blind.scalars(select(User)).all() == []
        assert (
            blind.scalars(select(Tenant)).all() != []
        )  # tenants itself isn't RLS-scoped


def test_tenant_sees_only_its_own_rows(postgres_rls_session_factory):
    factory = postgres_rls_session_factory
    with factory() as setup:
        tenant_a = _make_tenant(setup, f"tenant-a-{uuid4()}")
        tenant_b = _make_tenant(setup, f"tenant-b-{uuid4()}")
        set_tenant_context(setup, tenant_a.id)
        setup.add(User(tenant_id=tenant_a.id, email="owner@a.example", role="owner"))
        setup.commit()
        set_tenant_context(setup, tenant_b.id)
        setup.add(User(tenant_id=tenant_b.id, email="owner@b.example", role="owner"))
        setup.commit()

    with factory() as as_a:
        set_tenant_context(as_a, tenant_a.id)
        rows = as_a.scalars(select(User)).all()
        assert [row.email for row in rows] == ["owner@a.example"]

    with factory() as as_b:
        set_tenant_context(as_b, tenant_b.id)
        rows = as_b.scalars(select(User)).all()
        assert [row.email for row in rows] == ["owner@b.example"]


def test_cannot_fetch_another_tenants_row_by_id(postgres_rls_session_factory):
    factory = postgres_rls_session_factory
    with factory() as setup:
        tenant_a = _make_tenant(setup, f"tenant-a-{uuid4()}")
        tenant_b = _make_tenant(setup, f"tenant-b-{uuid4()}")
        set_tenant_context(setup, tenant_b.id)
        victim = User(tenant_id=tenant_b.id, email="victim@b.example", role="owner")
        setup.add(victim)
        setup.commit()
        victim_id = victim.id

    with factory() as attacker_session:
        set_tenant_context(attacker_session, tenant_a.id)
        # Even a direct primary-key lookup for a row that indisputably
        # exists (in tenant B) returns nothing while scoped to tenant A.
        assert attacker_session.get(User, victim_id) is None
        assert attacker_session.scalar(select(User).where(User.id == victim_id)) is None


def test_cannot_insert_a_row_claiming_a_different_tenant(postgres_rls_session_factory):
    factory = postgres_rls_session_factory
    with factory() as setup:
        tenant_a = _make_tenant(setup, f"tenant-a-{uuid4()}")
        tenant_b = _make_tenant(setup, f"tenant-b-{uuid4()}")

    with factory() as session:
        set_tenant_context(session, tenant_a.id)
        # Session is scoped to tenant A but this row claims tenant B — the
        # WITH CHECK clause must reject it, not silently accept it.
        session.add(User(tenant_id=tenant_b.id, email="forged@b.example", role="owner"))
        with pytest.raises(DBAPIError):
            session.commit()


def test_isolation_holds_on_a_second_table_not_just_users(postgres_rls_session_factory):
    factory = postgres_rls_session_factory
    with factory() as setup:
        tenant_a = _make_tenant(setup, f"tenant-a-{uuid4()}")
        tenant_b = _make_tenant(setup, f"tenant-b-{uuid4()}")
        set_tenant_context(setup, tenant_a.id)
        setup.add(
            AuditEventRow(
                sequence=1,
                tenant_id=tenant_a.id,
                correlation_id="corr-a",
                event_type="test.event",
                actor_id="tester",
                details={},
                previous_hash="0" * 64,
                event_hash="a" * 64,
            )
        )
        setup.commit()
        set_tenant_context(setup, tenant_b.id)
        setup.add(
            AuditEventRow(
                sequence=1,
                tenant_id=tenant_b.id,
                correlation_id="corr-b",
                event_type="test.event",
                actor_id="tester",
                details={},
                previous_hash="0" * 64,
                event_hash="b" * 64,
            )
        )
        setup.commit()

    with factory() as as_a:
        set_tenant_context(as_a, tenant_a.id)
        rows = as_a.scalars(select(AuditEventRow)).all()
        assert [row.correlation_id for row in rows] == ["corr-a"]


def test_rls_bypass_grants_cross_tenant_visibility_only_when_set(
    postgres_rls_session_factory,
):
    factory = postgres_rls_session_factory
    with factory() as setup:
        tenant_a = _make_tenant(setup, f"tenant-a-{uuid4()}")
        tenant_b = _make_tenant(setup, f"tenant-b-{uuid4()}")
        set_tenant_context(setup, tenant_a.id)
        setup.add(User(tenant_id=tenant_a.id, email="a@example.com", role="owner"))
        setup.commit()
        set_tenant_context(setup, tenant_b.id)
        setup.add(User(tenant_id=tenant_b.id, email="b@example.com", role="owner"))
        setup.commit()
        reset_tenant_context(setup)

    with factory() as bypass_session:
        set_rls_bypass(bypass_session, enabled=True)
        emails = {row.email for row in bypass_session.scalars(select(User)).all()}
        assert emails == {"a@example.com", "b@example.com"}
        reset_tenant_context(bypass_session)

    with factory() as no_bypass_session:
        assert no_bypass_session.scalars(select(User)).all() == []


def test_connection_reset_clears_tenant_context_between_sessions(
    postgres_rls_single_connection_factory,
):
    """Simulates helpdesktool.database.get_session's teardown behavior on a
    pool pinned to a single connection, proving a pooled connection can never
    hand one request's tenant context to the next.
    """
    factory = postgres_rls_single_connection_factory
    with factory() as setup:
        tenant_a = _make_tenant(setup, f"tenant-a-{uuid4()}")
        set_tenant_context(setup, tenant_a.id)
        setup.add(User(tenant_id=tenant_a.id, email="owner@a.example", role="owner"))
        setup.commit()

    first = factory()
    try:
        set_tenant_context(first, tenant_a.id)
        assert len(first.scalars(select(User)).all()) == 1
    finally:
        reset_tenant_context(first)
        first.close()

    # A brand-new session, reusing the same (pool-pinned) physical
    # connection, that never calls set_tenant_context must see nothing —
    # if the reset above hadn't run, this would incorrectly still see
    # tenant A's row.
    second = factory()
    try:
        assert second.scalars(select(User)).all() == []
    finally:
        second.close()
