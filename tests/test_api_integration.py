import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from helpdesktool.api import app
from helpdesktool.config import get_settings
from helpdesktool.database import Base, get_session
from helpdesktool.db_models import User, WebhookDelivery
from helpdesktool.integrations import DeliveryResponse
from helpdesktool.webhook_worker import WebhookWorker
from linux_agent.executor import ServiceRestartExecutor


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
    monkeypatch.setenv("HELPDESK_SERVICE_ALLOWLIST", "demo.service")
    get_settings.cache_clear()
    app.dependency_overrides[get_session] = override_session
    with TestClient(app) as test_client:
        yield test_client, factory
    app.dependency_overrides.clear()
    get_settings.cache_clear()


def test_tenant_device_telemetry_ticket_and_approval_workflow(client, monkeypatch):
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
    demo_login = http.post(
        f"/v1/auth/development/login?user_id={identity['admin_user_id']}"
    )
    assert demo_login.status_code == 200
    browser_headers = {"Authorization": f"Bearer {demo_login.json()['access_token']}"}
    assert http.get("/v1/auth/me", headers=browser_headers).json()["role"] == "owner"
    monkeypatch.setattr(
        "helpdesktool.api.validate_webhook_url", lambda *args, **kwargs: None
    )
    webhook = http.post(
        "/v1/integrations/webhooks",
        headers=owner_headers,
        json={
            "name": "n8n",
            "url": "https://example.com/webhook",
            "secret_ref": "env:HELPDESK_WEBHOOK_SECRET_N8N",
            "event_types": ["ticket.created", "remediation.requested"],
        },
    )
    assert webhook.status_code == 201

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
    low_disk = http.post(
        f"/v1/devices/{device['device_id']}/inventory",
        headers={
            "Authorization": f"Bearer {device['agent_token']}",
            "Idempotency-Key": "inventory-low-disk-1",
        },
        json={
            "collected_at": "2026-08-18T12:00:00Z",
            "payload": {
                "filesystems": [
                    {
                        "mountpoint": "/",
                        "total_bytes": 1000,
                        "free_bytes": 50,
                    }
                ]
            },
        },
    )
    assert low_disk.status_code == 202
    assert len(low_disk.json()["incident_ids"]) == 1
    repeated = http.post(
        f"/v1/devices/{device['device_id']}/inventory",
        headers={
            "Authorization": f"Bearer {device['agent_token']}",
            "Idempotency-Key": "inventory-low-disk-2",
        },
        json={
            "collected_at": "2026-08-18T12:05:00Z",
            "payload": {
                "filesystems": [
                    {"mountpoint": "/", "total_bytes": 1000, "free_bytes": 40}
                ]
            },
        },
    )
    assert repeated.json()["incident_ids"] == low_disk.json()["incident_ids"]
    incidents = http.get("/v1/incidents", headers=browser_headers).json()
    assert incidents[0]["occurrence_count"] == 2
    assert incidents[0]["ticket_id"]
    dashboard = http.get("/v1/dashboard", headers=browser_headers).json()
    assert dashboard["counts"]["open_incidents"] == 1
    assert dashboard["counts"]["devices"] == 1

    with factory() as session:
        viewer = User(
            tenant_id=identity["tenant_id"], email="viewer@example.com", role="viewer"
        )
        session.add(viewer)
        session.commit()
        viewer_id = viewer.id
    viewer_login = http.post(f"/v1/auth/development/login?user_id={viewer_id}")
    viewer_headers = {"Authorization": f"Bearer {viewer_login.json()['access_token']}"}
    assert http.get("/v1/devices", headers=viewer_headers).status_code == 200
    assert (
        http.post(
            "/v1/tickets", headers=viewer_headers, json={"title": "not allowed"}
        ).status_code
        == 403
    )
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
            "parameters": {"service": "demo.service"},
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
    jobs = http.get(
        f"/v1/devices/{device['device_id']}/jobs",
        headers={"Authorization": f"Bearer {device['agent_token']}"},
    )
    assert [job["id"] for job in jobs.json()] == [action.json()["id"]]
    assert (
        http.get(
            f"/v1/devices/{device['device_id']}/jobs",
            headers={"Authorization": "Bearer wrong-device-token"},
        ).status_code
        == 401
    )
    claim = http.post(
        f"/v1/devices/{device['device_id']}/jobs/{action.json()['id']}/claim",
        headers={
            "Authorization": f"Bearer {device['agent_token']}",
            "Idempotency-Key": "claim-1",
        },
        json={},
    )
    assert claim.status_code == 200
    assert (
        http.post(
            f"/v1/devices/{device['device_id']}/jobs/{action.json()['id']}/claim",
            headers={
                "Authorization": f"Bearer {device['agent_token']}",
                "Idempotency-Key": "claim-1",
            },
            json={},
        ).json()
        == claim.json()
    )

    class Runner:
        responses = iter(
            [
                "LoadState=loaded\nActiveState=active\nSubState=running\n",
                "",
                "LoadState=loaded\nActiveState=active\nSubState=running\n",
            ]
        )

        def __call__(self, command, *, timeout):
            import subprocess

            return subprocess.CompletedProcess(command, 0, next(self.responses), "")

    execution = ServiceRestartExecutor(("demo.service",), runner=Runner()).execute(
        {"service": "demo.service"}
    )
    result = http.post(
        f"/v1/devices/{device['device_id']}/jobs/{action.json()['id']}/result",
        headers={
            "Authorization": f"Bearer {device['agent_token']}",
            "Idempotency-Key": "result-1",
            "X-Claim-Token": claim.json()["claim_token"],
        },
        json=execution,
    )
    assert result.json()["status"] == "succeeded"
    audit = http.get("/v1/audit", headers=owner_headers)
    assert audit.status_code == 200
    assert {event["event_type"] for event in audit.json()} >= {
        "tenant.created",
        "device.enrolled",
        "ticket.created",
        "policy.evaluated",
        "action.approved",
        "execution.queued",
        "execution.claimed",
        "execution.reported",
    }

    class Provider:
        def deliver(self, url, event_id, payload, secret, timeout_seconds):
            assert secret == "integration-secret"
            return DeliveryResponse(204, "")

    monkeypatch.setattr(
        "helpdesktool.webhook_worker.validate_webhook_url", lambda *args, **kwargs: None
    )
    with factory() as session:
        settings = get_settings()
        processed = WebhookWorker(
            Provider(),
            settings,
            {"HELPDESK_WEBHOOK_SECRET_N8N": "integration-secret"},
        ).process_batch(session)
        assert processed >= 2
        assert {row.status for row in session.query(WebhookDelivery).all()} == {
            "delivered"
        }
