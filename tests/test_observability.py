"""Tests for helpdesktool's observability surface: structured JSON logging,
the per-request correlation id middleware, worker heartbeats, and the
Prometheus /metrics endpoint.
"""

from __future__ import annotations

import json
import logging

from helpdesktool.logging_config import JsonFormatter, get_request_id, set_request_id
from helpdesktool.metrics import render_metrics
from helpdesktool.persistence import record_worker_heartbeat


def _bootstrap_owner(http) -> dict:
    response = http.post(
        "/v1/tenants",
        headers={"X-Bootstrap-Token": "test-bootstrap-token"},
        json={"name": "Acme", "admin_email": "owner@example.com"},
    )
    assert response.status_code == 201, response.text
    return response.json()


def test_json_formatter_produces_valid_json_with_expected_fields():
    formatter = JsonFormatter()
    record = logging.LogRecord(
        name="helpdesktool.test",
        level=logging.INFO,
        pathname=__file__,
        lineno=1,
        msg="something happened",
        args=(),
        exc_info=None,
    )
    parsed = json.loads(formatter.format(record))
    assert parsed["level"] == "INFO"
    assert parsed["logger"] == "helpdesktool.test"
    assert parsed["message"] == "something happened"
    assert "timestamp" in parsed


def test_json_formatter_includes_bound_request_id():
    formatter = JsonFormatter()
    set_request_id("req-123")
    try:
        record = logging.LogRecord(
            name="helpdesktool.test",
            level=logging.INFO,
            pathname=__file__,
            lineno=1,
            msg="inside a request",
            args=(),
            exc_info=None,
        )
        parsed = json.loads(formatter.format(record))
        assert parsed["request_id"] == "req-123"
    finally:
        set_request_id(None)


def test_get_request_id_defaults_to_none():
    assert get_request_id() is None


def test_request_id_is_generated_and_echoed_when_absent(client):
    http, _ = client
    response = http.get("/health/live")
    assert response.status_code == 200
    assert response.headers.get("X-Request-ID")


def test_supplied_request_id_is_propagated_back(client):
    http, _ = client
    response = http.get("/health/live", headers={"X-Request-ID": "caller-supplied-id"})
    assert response.headers["X-Request-ID"] == "caller-supplied-id"


def test_metrics_endpoint_exposes_prometheus_text_format(client):
    http, _ = client
    response = http.get("/metrics")
    assert response.status_code == 200
    assert "text/plain" in response.headers["content-type"]
    body = response.text
    assert "helpdesk_actions_total" in body
    assert "helpdesk_incidents_total" in body
    assert "helpdesk_devices_total" in body
    assert "helpdesk_http_requests_total" in body


def test_metrics_reflect_real_action_and_device_counts(client):
    http, factory = client
    identity = _bootstrap_owner(http)
    owner_headers = {
        "X-Tenant-ID": identity["tenant_id"],
        "X-User-ID": identity["admin_user_id"],
    }
    enrolled = http.post(
        "/v1/devices/enroll",
        headers=owner_headers,
        json={"external_id": "d1", "hostname": "d1", "os": "linux"},
    )
    assert enrolled.status_code == 201, enrolled.text
    device_id = enrolled.json()["device_id"]

    action = http.post(
        "/v1/actions",
        headers={**owner_headers, "Idempotency-Key": "action-1"},
        json={
            "device_id": device_id,
            "skill_id": "diagnostics.collect",
            "parameters": {},
        },
    )
    assert action.status_code == 201, action.text

    with factory() as session:
        body, _ = render_metrics(session)
    text = body.decode()
    assert 'helpdesk_actions_total{status="queued"} 1.0' in text
    assert 'helpdesk_devices_total{status="offline"} 1.0' in text


def test_metrics_endpoint_requires_token_when_configured(client, monkeypatch):
    from helpdesktool.config import get_settings

    http, _ = client
    monkeypatch.setenv("HELPDESK_METRICS_TOKEN", "secret-scrape-token")
    get_settings.cache_clear()
    try:
        denied = http.get("/metrics")
        assert denied.status_code == 401

        allowed = http.get(
            "/metrics", headers={"Authorization": "Bearer secret-scrape-token"}
        )
        assert allowed.status_code == 200
    finally:
        get_settings.cache_clear()


def test_worker_heartbeat_is_recorded_and_reflected_in_metrics(client):
    http, factory = client
    with factory() as session:
        record_worker_heartbeat(session, "lease_reaper", 3)
        record_worker_heartbeat(session, "webhook_worker", 0)

    with factory() as session:
        body, _ = render_metrics(session)
    text = body.decode()
    assert 'helpdesk_worker_heartbeat_age_seconds{worker="lease_reaper"}' in text
    assert 'helpdesk_worker_heartbeat_age_seconds{worker="webhook_worker"}' in text


def test_worker_heartbeat_upsert_updates_existing_row(client):
    from helpdesktool.db_models import WorkerHeartbeatRow

    http, factory = client
    with factory() as session:
        record_worker_heartbeat(session, "lease_reaper", 1)
        first_timestamp = session.get(
            WorkerHeartbeatRow, "lease_reaper"
        ).last_heartbeat_at

    with factory() as session:
        record_worker_heartbeat(session, "lease_reaper", 7)
        row = session.get(WorkerHeartbeatRow, "lease_reaper")
        assert row.last_batch_size == 7
        assert row.last_heartbeat_at >= first_timestamp
