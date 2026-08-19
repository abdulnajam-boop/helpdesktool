"""Shared pytest fixtures for the backend test suite."""

from __future__ import annotations

import os
from collections.abc import Iterator

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, text
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from helpdesktool.api import app
from helpdesktool.config import Settings, get_settings
from helpdesktool.database import Base, get_session, reset_tenant_context
from helpdesktool.db_models import SkillManifestRow
from helpdesktool.models import RiskLevel
from helpdesktool.oidc import OIDCVerifier
from helpdesktool.rls import (
    TENANT_SCOPED_TABLES,
    UNSCOPED_APPLICATION_TABLES,
    clear_staged_app_role_password_statement,
    enable_statements,
    provision_app_role_statements,
    stage_app_role_password_statement,
)
from helpdesktool.skills import compute_manifest_hash
from tests.support import StaticKeyResolver, generate_test_keypair

TEST_OIDC_ISSUER = "https://idp.test.internal/"
TEST_OIDC_AUDIENCE = "https://api.test.internal"
TEST_OIDC_JWKS_URL = "https://idp.test.internal/.well-known/jwks.json"
TEST_APP_ROLE_PASSWORD = "test-app-role-password"

_DEFAULT_SKILL_SEEDS = (
    {
        "skill_id": "diagnostics.collect",
        "risk": RiskLevel.READ_ONLY,
        "rollback_skill_id": None,
        "parameters": {},
    },
    {
        "skill_id": "service.restart",
        "risk": RiskLevel.MEDIUM,
        "rollback_skill_id": "service.restore",
        "parameters": {"service": {"type": "string", "required": True}},
    },
)


def _seed_default_skills(engine: Engine) -> None:
    """Mirrors migration ``0008``'s seed data. Fixtures build the schema
    directly from ``Base.metadata`` rather than running Alembic (the same
    shortcut they already take for RLS — see ``_provision_rls_schema_and_role``
    below), so without this the skill registry a freshly built test schema
    starts with is empty and every ``service.restart`` action in the test
    suite would be rejected as "not allowlisted" — this keeps test schemas
    equivalent to a real migrated database for the two built-in skills.
    """
    with sessionmaker(engine)() as session:
        for seed in _DEFAULT_SKILL_SEEDS:
            content_hash = compute_manifest_hash(
                skill_id=seed["skill_id"],
                version=1,
                risk=seed["risk"],
                supported_os=frozenset({"linux", "windows"}),
                timeout_seconds=30,
                rollback_skill_id=seed["rollback_skill_id"],
                parameters=seed["parameters"],
            )
            session.add(
                SkillManifestRow(
                    skill_id=seed["skill_id"],
                    version=1,
                    risk=str(seed["risk"]),
                    supported_os=["linux", "windows"],
                    timeout_seconds=30,
                    rollback_skill_id=seed["rollback_skill_id"],
                    parameters=seed["parameters"],
                    content_hash=content_hash,
                    active=True,
                    created_by="00000000-0000-0000-0000-000000000000",
                )
            )
        session.commit()


@pytest.fixture
def client(monkeypatch) -> Iterator[tuple[TestClient, sessionmaker[Session]]]:
    """In-memory SQLite-backed API client for fast, DB-independent endpoint tests."""
    engine = create_engine(
        "sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool
    )
    Base.metadata.create_all(engine)
    _seed_default_skills(engine)
    factory = sessionmaker(engine, expire_on_commit=False)

    def override_session() -> Iterator[Session]:
        with factory() as session:
            yield session

    monkeypatch.setenv("HELPDESK_BOOTSTRAP_TOKEN", "test-bootstrap-token")
    monkeypatch.setenv("HELPDESK_SERVICE_ALLOWLIST", "demo.service")
    get_settings.cache_clear()
    app.dependency_overrides[get_session] = override_session
    with TestClient(app) as test_client:
        yield test_client, factory
    app.dependency_overrides.clear()
    get_settings.cache_clear()


def _connect_or_skip(database_url: str) -> Engine:
    engine = create_engine(database_url)
    try:
        with engine.connect():
            return engine
    except Exception as exc:  # pragma: no cover - environment-dependent
        engine.dispose()
        pytest.skip(f"PostgreSQL test database is unreachable: {exc}")


def _require_test_database_url() -> str:
    database_url = os.environ.get("HELPDESK_TEST_DATABASE_URL")
    if not database_url:
        pytest.skip(
            "HELPDESK_TEST_DATABASE_URL is not set; skipping PostgreSQL-only test"
        )
    return database_url


def _provision_rls_schema_and_role(superuser_engine: Engine) -> str:
    """Applies migration 0005's DDL (RLS policies + the restricted app role)
    directly against a disposable test database, and returns the connection
    URL for the restricted role.

    Runs the identical statement sequence the real migration runs, against
    the superuser connection (only a superuser/owner can run CREATE POLICY
    and CREATE ROLE) — this is deliberately not a shortcut past migration
    0005, it *is* migration 0005, applied without going through Alembic's
    bookkeeping since these fixtures also bypass Alembic for the base schema
    (see ``Base.metadata.create_all`` below).
    """
    with superuser_engine.begin() as connection:
        for table in TENANT_SCOPED_TABLES:
            for statement in enable_statements(table):
                connection.execute(text(statement))
        connection.execute(
            text(stage_app_role_password_statement()),
            {"password": TEST_APP_ROLE_PASSWORD},
        )
        for statement in provision_app_role_statements(
            (*TENANT_SCOPED_TABLES, *UNSCOPED_APPLICATION_TABLES)
        ):
            connection.execute(text(statement))
        connection.execute(text(clear_staged_app_role_password_statement()))
    return Settings(
        database_url=str(superuser_engine.url),
        app_role_password=TEST_APP_ROLE_PASSWORD,
    ).runtime_database_url


@pytest.fixture
def postgres_session_factory() -> Iterator[sessionmaker[Session]]:
    """Real-PostgreSQL fixture for code paths that only run on PostgreSQL, such as
    the tenant-serializing advisory lock in ``helpdesktool.persistence.SqlAuditLog``.

    SQLite silently no-ops that branch, so it must be exercised against a real
    PostgreSQL database to mean anything. Set ``HELPDESK_TEST_DATABASE_URL`` to a
    disposable PostgreSQL database to run tests using this fixture; CI points it at
    the `postgres` service container. Locally, without that variable (or with an
    unreachable database), tests using this fixture are skipped rather than failed.

    Row-level security is deliberately NOT applied here — this fixture is for
    tests that don't want RLS's default-deny behavior in their way, and it
    connects as the schema-owning role (fine for that purpose: with no RLS
    applied there is nothing for role separation to matter to). Use
    ``postgres_rls_session_factory`` for row-level-security tests.
    """
    engine = _connect_or_skip(_require_test_database_url())
    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)
    _seed_default_skills(engine)
    factory = sessionmaker(engine, expire_on_commit=False)
    try:
        yield factory
    finally:
        Base.metadata.drop_all(engine)
        engine.dispose()


@pytest.fixture
def postgres_rls_session_factory() -> Iterator[sessionmaker[Session]]:
    """Real-PostgreSQL fixture with row-level security applied to every
    tenant-scoped table and a real, restricted (non-superuser, non-BYPASSRLS)
    ``helpdesk_app`` role provisioned, using the exact DDL migration 0005
    applies. The returned session factory connects as that restricted role —
    connecting as the schema owner would silently bypass every RLS policy
    (PostgreSQL exempts superusers/table owners from RLS unconditionally),
    which would make every assertion in a test using this fixture meaningless
    regardless of whether the policies themselves are correct.

    A session obtained from the returned factory starts with no tenant
    context bound (``app.current_tenant_id`` unset) — tests must call
    ``helpdesktool.database.set_tenant_context`` explicitly to simulate an
    authenticated request, which is the point: a session that never does so
    should see zero rows across every tenant.
    """
    superuser_engine = _connect_or_skip(_require_test_database_url())
    Base.metadata.drop_all(superuser_engine)
    Base.metadata.create_all(superuser_engine)
    _seed_default_skills(superuser_engine)
    app_role_url = _provision_rls_schema_and_role(superuser_engine)
    app_engine = _connect_or_skip(app_role_url)
    factory = sessionmaker(app_engine, expire_on_commit=False)
    try:
        yield factory
    finally:
        app_engine.dispose()
        Base.metadata.drop_all(superuser_engine)
        superuser_engine.dispose()


@pytest.fixture
def postgres_rls_single_connection_factory() -> Iterator[sessionmaker[Session]]:
    """Same as ``postgres_rls_session_factory``, but the app-role engine's
    pool is pinned to exactly one connection (``pool_size=1,
    max_overflow=0``), so two sequential sessions are guaranteed to reuse the
    identical physical connection. Used only to test that tenant-context
    GUCs never survive a session handoff on a reused pooled connection.
    """
    superuser_engine = _connect_or_skip(_require_test_database_url())
    Base.metadata.drop_all(superuser_engine)
    Base.metadata.create_all(superuser_engine)
    _seed_default_skills(superuser_engine)
    app_role_url = _provision_rls_schema_and_role(superuser_engine)
    app_engine = create_engine(app_role_url, pool_size=1, max_overflow=0)
    try:
        with app_engine.connect():
            pass
    except Exception as exc:  # pragma: no cover - environment-dependent
        app_engine.dispose()
        superuser_engine.dispose()
        pytest.skip(f"PostgreSQL test database is unreachable: {exc}")
    factory = sessionmaker(app_engine, expire_on_commit=False)
    try:
        yield factory
    finally:
        app_engine.dispose()
        Base.metadata.drop_all(superuser_engine)
        superuser_engine.dispose()


@pytest.fixture
def oidc_test_keypair():
    return generate_test_keypair()


@pytest.fixture
def postgres_client(
    monkeypatch, oidc_test_keypair
) -> Iterator[tuple[TestClient, sessionmaker[Session]]]:
    """Full API client backed by real PostgreSQL with row-level security
    applied, a real (non-superuser) ``helpdesk_app`` connection for all
    request traffic, and a real (test-keyed) OIDC verifier wired in — the
    strongest available test double for "a real production-mode deployment":
    human authentication only via signed OIDC bearer tokens, no insecure
    header auth, no development login, RLS enforced at the database layer
    against the exact role the API actually connects as at runtime.
    """
    superuser_engine = _connect_or_skip(_require_test_database_url())
    Base.metadata.drop_all(superuser_engine)
    Base.metadata.create_all(superuser_engine)
    _seed_default_skills(superuser_engine)
    app_role_url = _provision_rls_schema_and_role(superuser_engine)
    app_engine = _connect_or_skip(app_role_url)
    factory = sessionmaker(app_engine, expire_on_commit=False)

    def override_session() -> Iterator[Session]:
        # Mirrors helpdesktool.database.get_session's teardown exactly:
        # without this, a stale app.current_tenant_id from one request can
        # survive on a reused pooled connection and corrupt the *next*
        # request's cross-tenant candidate lookup in
        # auth._resolve_oidc_principal (which must see across every tenant
        # for an as-yet-unresolved identity — that's the one query in this
        # codebase that legitimately runs before any tenant context is set).
        with factory() as session:
            try:
                yield session
            finally:
                reset_tenant_context(session)

    _, public_key = oidc_test_keypair
    test_verifier = OIDCVerifier(
        TEST_OIDC_ISSUER,
        TEST_OIDC_AUDIENCE,
        TEST_OIDC_JWKS_URL,
        key_resolver=StaticKeyResolver(public_key),
    )

    monkeypatch.setenv("HELPDESK_ENVIRONMENT", "production")
    monkeypatch.setenv("HELPDESK_ALLOW_INSECURE_HEADER_AUTH", "false")
    monkeypatch.setenv("HELPDESK_DEVELOPMENT_LOGIN_ENABLED", "false")
    monkeypatch.setenv("HELPDESK_BOOTSTRAP_TOKEN", "test-bootstrap-token")
    monkeypatch.setenv("HELPDESK_JOB_CLAIM_SECRET", "test-job-claim-secret")
    monkeypatch.setenv("HELPDESK_DEVELOPMENT_SESSION_SECRET", "test-session-secret")
    monkeypatch.setenv("HELPDESK_APP_ROLE_PASSWORD", TEST_APP_ROLE_PASSWORD)
    monkeypatch.setenv("HELPDESK_SERVICE_ALLOWLIST", "demo.service")
    monkeypatch.setenv("HELPDESK_OIDC_ISSUER", TEST_OIDC_ISSUER)
    monkeypatch.setenv("HELPDESK_OIDC_AUDIENCE", TEST_OIDC_AUDIENCE)
    monkeypatch.setenv("HELPDESK_OIDC_JWKS_URL", TEST_OIDC_JWKS_URL)
    get_settings.cache_clear()
    # get_oidc_verifier is called as a plain function inside auth.py, not
    # wired in via FastAPI Depends(), so app.dependency_overrides can't
    # intercept it — replace it directly in the auth module's namespace
    # instead. This avoids ever needing a real network call to a JWKS
    # endpoint and avoids constructing a mandatory Depends() that would fire
    # (and fail closed) on every request, including dev-mode ones that don't
    # use OIDC at all.
    monkeypatch.setattr("helpdesktool.auth.get_oidc_verifier", lambda: test_verifier)
    app.dependency_overrides[get_session] = override_session
    with TestClient(app) as test_client:
        yield test_client, factory
    app.dependency_overrides.clear()
    get_settings.cache_clear()
    app_engine.dispose()
    Base.metadata.drop_all(superuser_engine)
    superuser_engine.dispose()
