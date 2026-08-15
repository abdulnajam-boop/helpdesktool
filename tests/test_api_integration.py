import pytest

pytest.importorskip("fastapi")
pytest.importorskip("sqlalchemy")
pytest.importorskip("httpx")

from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from helpdesktool.api import app
from helpdesktool.config import get_settings
from helpdesktool.database import Base, get_session
from helpdesktool.db_models import User


@pytest.fixture
def client(monkeypatch):
    engine = create_engine(
        "sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool
    )
    Base.metadata.create_all(engine)
    factory = sessionmaker(engine, expire_on_commit=False)

    def override_session():
        with factory() as session:
            yield session

    monkeypatch.setenv("HELPDESK_BOOTSTRAP_TOKEN", "test-bootstrap-token")
    get_settings.cache_clear()
    app.dependency_overrides[get_session] = override_session
    with TestClient(app) as test_client:
        yield test_client, factory
    app.dependency_overrides.clear()
    get_settings.cache_clear()


def test_tenant_device_telemetry_ticket_and_approval_workflow(client):
    http, factory = client
    response = http.post(
        "/v1/tenants",
        headers={"X-Bootstrap-Token": "test-bootstrap-token"},
        json={"name": "Acme", "admin_email": "owner@example.com"},
    )
    assert response.status_code == 201
    identity = response.json()
    owner_headers = {
        "X-Tenant-ID": identity["tenant_id"],
        "X-User-ID": identity["admin_user_id"],
    }

    enrolled = http.post(
        "/v1/devices/enroll",
        headers=owner_headers,
        json={"external_id": "agent-1", "hostname": "server-1", "os": "linux"},
    )
    assert enrolled.status_code == 201
    device = enrolled.json()
    agent_headers = {
        "Authorization": f"Bearer {device['agent_token']}",
        "Idempotency-Key": "heartbeat-1",
    }
    heartbeat = http.post(
        f"/v1/devices/{device['device_id']}/heartbeat",
        headers=agent_headers,
        json={"status": {"load": 0.2}},
    )
    assert heartbeat.status_code == 200
    assert (
        http.post(
            f"/v1/devices/{device['device_id']}/heartbeat",
            headers=agent_headers,
            json={"status": {"load": 0.2}},
        ).json()
        == heartbeat.json()
    )

    ticket = http.post(
        "/v1/tickets",
        headers=owner_headers,
        json={"title": "Restart web service", "device_id": device["device_id"]},
    )
    assert ticket.status_code == 201
    action = http.post(
        "/v1/actions",
        headers={**owner_headers, "Idempotency-Key": "action-1"},
        json={
            "device_id": device["device_id"],
            "ticket_id": ticket.json()["id"],
            "skill_id": "service.restart",
        },
    )
    assert action.status_code == 201
    assert action.json()["status"] == "pending_approval"
    self_approval = http.post(
        f"/v1/actions/{action.json()['id']}/decision",
        headers=owner_headers,
        json={"decision": "approve", "reason": "should fail"},
    )
    assert self_approval.status_code == 403

    with factory() as session:
        approver = User(
            tenant_id=identity["tenant_id"], email="admin@example.com", role="admin"
        )
        session.add(approver)
        session.commit()
        approver_id = approver.id
    approved = http.post(
        f"/v1/actions/{action.json()['id']}/decision",
        headers={"X-Tenant-ID": identity["tenant_id"], "X-User-ID": approver_id},
        json={"decision": "approve", "reason": "maintenance window"},
    )
    assert approved.status_code == 200
    assert approved.json()["status"] == "queued"
    audit = http.get("/v1/audit", headers=owner_headers)
    assert audit.status_code == 200
    assert {event["event_type"] for event in audit.json()} >= {
        "tenant.created",
        "device.enrolled",
        "ticket.created",
        "policy.evaluated",
        "action.approved",
        "execution.queued",
    }
