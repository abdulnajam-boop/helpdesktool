"""Regression test: the development login picker must keep working once
PostgreSQL row-level security is enabled.

``development_users``/``development_login`` in api.py run before any
Principal exists (that is the whole point of a login picker), so they have
no tenant context to be scoped by — an earlier draft of Milestone 2 missed
this and RLS silently made both endpoints return nothing/401 for every valid
demo user, breaking the exact `docker compose up` -> "select a user" flow
described in README.md. Caught by an independent adversarial review; this
test exists so a future change can't reintroduce it silently.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import sessionmaker

from helpdesktool.api import app
from helpdesktool.config import get_settings
from helpdesktool.database import (
    Base,
    get_session,
    reset_tenant_context,
    set_tenant_context,
)
from helpdesktool.db_models import Tenant, User
from tests.conftest import (
    TEST_APP_ROLE_PASSWORD,
    _connect_or_skip,
    _provision_rls_schema_and_role,
    _require_test_database_url,
)


@pytest.fixture
def dev_login_client(monkeypatch):
    """Development-mode API client (dev login enabled, RLS applied) backed
    by the real restricted app role — distinct from `postgres_client`, which
    deliberately runs in production mode with dev login disabled.
    """
    superuser_engine = _connect_or_skip(_require_test_database_url())
    Base.metadata.drop_all(superuser_engine)
    Base.metadata.create_all(superuser_engine)
    app_role_url = _provision_rls_schema_and_role(superuser_engine)
    app_engine = _connect_or_skip(app_role_url)
    factory = sessionmaker(app_engine, expire_on_commit=False)

    def override_session():
        with factory() as session:
            try:
                yield session
            finally:
                reset_tenant_context(session)

    monkeypatch.setenv("HELPDESK_BOOTSTRAP_TOKEN", "test-bootstrap-token")
    monkeypatch.setenv("HELPDESK_APP_ROLE_PASSWORD", TEST_APP_ROLE_PASSWORD)
    get_settings.cache_clear()
    app.dependency_overrides[get_session] = override_session
    with TestClient(app) as test_client:
        yield test_client, factory
    app.dependency_overrides.clear()
    get_settings.cache_clear()
    app_engine.dispose()
    Base.metadata.drop_all(superuser_engine)
    superuser_engine.dispose()


def test_development_login_picker_works_under_rls(dev_login_client):
    http, factory = dev_login_client
    with factory() as session:
        tenant = Tenant(name="Dev Demo Tenant")
        session.add(tenant)
        session.flush()
        set_tenant_context(session, tenant.id)
        user = User(tenant_id=tenant.id, email="owner@demo.example", role="owner")
        session.add(user)
        session.commit()
        tenant_id = tenant.id
        user_id = user.id

    listing = http.get("/v1/auth/development/users")
    assert listing.status_code == 200
    assert any(row["id"] == user_id for row in listing.json())

    login = http.post(f"/v1/auth/development/login?user_id={user_id}")
    assert login.status_code == 200
    assert login.json()["user"]["id"] == user_id

    me = http.get(
        "/v1/auth/me",
        headers={"Authorization": f"Bearer {login.json()['access_token']}"},
    )
    assert me.status_code == 200
    assert me.json()["tenant_id"] == tenant_id
