"""Shared pytest fixtures for the backend test suite."""

from __future__ import annotations

import os
from collections.abc import Iterator

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from helpdesktool.api import app
from helpdesktool.config import get_settings
from helpdesktool.database import Base, get_session


@pytest.fixture
def client(monkeypatch) -> Iterator[tuple[TestClient, sessionmaker[Session]]]:
    """In-memory SQLite-backed API client for fast, DB-independent endpoint tests."""
    engine = create_engine(
        "sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool
    )
    Base.metadata.create_all(engine)
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


@pytest.fixture
def postgres_session_factory() -> Iterator[sessionmaker[Session]]:
    """Real-PostgreSQL fixture for code paths that only run on PostgreSQL, such as
    the tenant-serializing advisory lock in ``helpdesktool.persistence.SqlAuditLog``.

    SQLite silently no-ops that branch, so it must be exercised against a real
    PostgreSQL database to mean anything. Set ``HELPDESK_TEST_DATABASE_URL`` to a
    disposable PostgreSQL database to run tests using this fixture; CI points it at
    the `postgres` service container. Locally, without that variable (or with an
    unreachable database), tests using this fixture are skipped rather than failed.
    """
    database_url = os.environ.get("HELPDESK_TEST_DATABASE_URL")
    if not database_url:
        pytest.skip(
            "HELPDESK_TEST_DATABASE_URL is not set; skipping PostgreSQL-only test"
        )
    engine = create_engine(database_url)
    try:
        with engine.connect():
            pass
    except Exception as exc:  # pragma: no cover - environment-dependent
        engine.dispose()
        pytest.skip(f"PostgreSQL test database is unreachable: {exc}")
    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)
    factory = sessionmaker(engine, expire_on_commit=False)
    try:
        yield factory
    finally:
        Base.metadata.drop_all(engine)
        engine.dispose()
