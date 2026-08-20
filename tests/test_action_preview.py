"""API-level tests for GET /v1/actions/{id}/preview (Phase 14): proves
the standalone "what would this action do" surface is computed correctly
from the real active skill manifest, not from stale/cached data.
"""

from __future__ import annotations


def _bootstrap_owner(http) -> dict:
    response = http.post(
        "/v1/tenants",
        headers={"X-Bootstrap-Token": "test-bootstrap-token"},
        json={"name": "Acme", "admin_email": "owner@example.com"},
    )
    assert response.status_code == 201, response.text
    return response.json()


def _enroll_device(http, headers) -> dict:
    enrolled = http.post(
        "/v1/devices/enroll",
        headers=headers,
        json={"external_id": "agent-1", "hostname": "server-1", "os": "linux"},
    )
    assert enrolled.status_code == 201, enrolled.text
    return enrolled.json()


def test_preview_reflects_the_real_registered_manifest(client):
    http, _ = client
    identity = _bootstrap_owner(http)
    owner_headers = {
        "X-Tenant-ID": identity["tenant_id"],
        "X-User-ID": identity["admin_user_id"],
    }
    device = _enroll_device(http, owner_headers)
    action = http.post(
        "/v1/actions",
        headers={**owner_headers, "Idempotency-Key": "preview-action-1"},
        json={
            "device_id": device["device_id"],
            "skill_id": "service.restart",
            "parameters": {"service": "demo.service"},
        },
    )
    assert action.status_code == 201, action.text
    action_id = action.json()["id"]

    preview = http.get(f"/v1/actions/{action_id}/preview", headers=owner_headers)
    assert preview.status_code == 200, preview.text
    body = preview.json()
    assert body["action_id"] == action_id
    assert body["action_status"] == "pending_approval"
    assert body["skill_id"] == "service.restart"
    assert body["rollback_skill_id"] == "service.restore"
    assert body["parameters"] == {"service": "demo.service"}
    assert body["approval_required"] is True
    assert body["policy_allowed"] is True
    assert "service.restart" in body["what_would_execute"]
    assert body["rollback_plan"]
    assert body["verification_plan"]


def test_preview_for_read_only_skill_needs_no_approval(client):
    http, _ = client
    identity = _bootstrap_owner(http)
    owner_headers = {
        "X-Tenant-ID": identity["tenant_id"],
        "X-User-ID": identity["admin_user_id"],
    }
    device = _enroll_device(http, owner_headers)
    action = http.post(
        "/v1/actions",
        headers={**owner_headers, "Idempotency-Key": "preview-action-2"},
        json={
            "device_id": device["device_id"],
            "skill_id": "diagnostics.collect",
            "parameters": {},
        },
    )
    assert action.status_code == 201, action.text
    action_id = action.json()["id"]

    preview = http.get(f"/v1/actions/{action_id}/preview", headers=owner_headers).json()
    assert preview["approval_required"] is False
    assert preview["automation_level"] in {"l0_observe_only", "l1_safe_automatic"}
    assert preview["reversible"] is True or preview["rollback_skill_id"] is None


def test_preview_for_nonexistent_action_is_404(client):
    http, _ = client
    identity = _bootstrap_owner(http)
    owner_headers = {
        "X-Tenant-ID": identity["tenant_id"],
        "X-User-ID": identity["admin_user_id"],
    }
    response = http.get(
        "/v1/actions/00000000-0000-0000-0000-000000000000/preview",
        headers=owner_headers,
    )
    assert response.status_code == 404


def test_preview_is_tenant_isolated(client):
    http, _ = client
    identity_a = _bootstrap_owner(http)
    identity_b = http.post(
        "/v1/tenants",
        headers={"X-Bootstrap-Token": "test-bootstrap-token"},
        json={"name": "Globex", "admin_email": "owner2@example.com"},
    ).json()
    owner_a_headers = {
        "X-Tenant-ID": identity_a["tenant_id"],
        "X-User-ID": identity_a["admin_user_id"],
    }
    owner_b_headers = {
        "X-Tenant-ID": identity_b["tenant_id"],
        "X-User-ID": identity_b["admin_user_id"],
    }
    device = _enroll_device(http, owner_a_headers)
    action = http.post(
        "/v1/actions",
        headers={**owner_a_headers, "Idempotency-Key": "preview-action-3"},
        json={
            "device_id": device["device_id"],
            "skill_id": "service.restart",
            "parameters": {"service": "demo.service"},
        },
    )
    action_id = action.json()["id"]

    response = http.get(f"/v1/actions/{action_id}/preview", headers=owner_b_headers)
    assert response.status_code == 404
