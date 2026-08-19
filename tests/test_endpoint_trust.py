"""Tests for device credential rotation/revocation and enrollment tokens."""

from __future__ import annotations


def _bootstrap_owner(http) -> dict:
    response = http.post(
        "/v1/tenants",
        headers={"X-Bootstrap-Token": "test-bootstrap-token"},
        json={"name": "Acme", "admin_email": "owner@example.com"},
    )
    assert response.status_code == 201
    return response.json()


def test_enrollment_token_workflow(client):
    http, _ = client
    identity = _bootstrap_owner(http)
    owner_headers = {
        "X-Tenant-ID": identity["tenant_id"],
        "X-User-ID": identity["admin_user_id"],
    }

    created = http.post(
        "/v1/devices/enrollment-tokens",
        headers=owner_headers,
        json={"label": "new laptop batch"},
    )
    assert created.status_code == 201
    token = created.json()["token"]

    listing = http.get("/v1/devices/enrollment-tokens", headers=owner_headers)
    assert listing.status_code == 200
    assert listing.json()[0]["status"] == "active"
    assert listing.json()[0]["label"] == "new laptop batch"

    enrolled = http.post(
        "/v1/devices/enroll-with-token",
        headers={"X-Enrollment-Token": token},
        json={"external_id": "laptop-1", "hostname": "laptop-1", "os": "linux"},
    )
    assert enrolled.status_code == 201
    assert "agent_token" in enrolled.json()
    # tenant_id must be present so a self-enrolling agent (which never
    # authenticates as an admin and so never otherwise learns its tenant)
    # can populate its own config and correctly verify signed job envelopes
    # -- see linux_agent.agent.LinuxAgent.enroll_with_token.
    assert enrolled.json()["tenant_id"] == identity["tenant_id"]

    # Single-use: the same token cannot enroll a second device.
    reuse = http.post(
        "/v1/devices/enroll-with-token",
        headers={"X-Enrollment-Token": token},
        json={"external_id": "laptop-2", "hostname": "laptop-2", "os": "linux"},
    )
    assert reuse.status_code == 401

    listing_after = http.get("/v1/devices/enrollment-tokens", headers=owner_headers)
    assert listing_after.json()[0]["status"] == "used"
    assert listing_after.json()[0]["used_by_device_id"] == enrolled.json()["device_id"]


def test_enrollment_token_rejects_unknown_or_garbage_token(client):
    http, _ = client
    enrolled = http.post(
        "/v1/devices/enroll-with-token",
        headers={"X-Enrollment-Token": "not-a-real-token"},
        json={"external_id": "laptop-1", "hostname": "laptop-1", "os": "linux"},
    )
    assert enrolled.status_code == 401


def test_enrollment_token_can_be_revoked_before_use(client):
    http, _ = client
    identity = _bootstrap_owner(http)
    owner_headers = {
        "X-Tenant-ID": identity["tenant_id"],
        "X-User-ID": identity["admin_user_id"],
    }
    created = http.post("/v1/devices/enrollment-tokens", headers=owner_headers, json={})
    token_id = created.json()["enrollment_token_id"]
    token = created.json()["token"]

    revoked = http.delete(
        f"/v1/devices/enrollment-tokens/{token_id}", headers=owner_headers
    )
    assert revoked.status_code == 204

    enrolled = http.post(
        "/v1/devices/enroll-with-token",
        headers={"X-Enrollment-Token": token},
        json={"external_id": "laptop-1", "hostname": "laptop-1", "os": "linux"},
    )
    assert enrolled.status_code == 401


def test_only_admin_or_owner_can_create_enrollment_tokens(client):
    http, factory = client
    from helpdesktool.db_models import User

    identity = _bootstrap_owner(http)
    with factory() as session:
        viewer = User(
            tenant_id=identity["tenant_id"], email="viewer@example.com", role="viewer"
        )
        session.add(viewer)
        session.commit()
        viewer_id = viewer.id
    viewer_headers = {"X-Tenant-ID": identity["tenant_id"], "X-User-ID": viewer_id}
    denied = http.post("/v1/devices/enrollment-tokens", headers=viewer_headers, json={})
    assert denied.status_code == 403


def test_device_credential_rotation_by_admin(client):
    http, _ = client
    identity = _bootstrap_owner(http)
    owner_headers = {
        "X-Tenant-ID": identity["tenant_id"],
        "X-User-ID": identity["admin_user_id"],
    }
    enrolled = http.post(
        "/v1/devices/enroll",
        headers=owner_headers,
        json={"external_id": "server-1", "hostname": "server-1", "os": "linux"},
    )
    device_id = enrolled.json()["device_id"]
    old_token = enrolled.json()["agent_token"]

    rotated = http.post(
        f"/v1/devices/{device_id}/rotate-credential", headers=owner_headers
    )
    assert rotated.status_code == 200
    new_token = rotated.json()["agent_token"]
    assert new_token != old_token

    # Old credential no longer authenticates.
    old_auth_headers = {
        "Authorization": f"Bearer {old_token}",
        "Idempotency-Key": "hb-old",
    }
    assert (
        http.post(
            f"/v1/devices/{device_id}/heartbeat",
            headers=old_auth_headers,
            json={"status": {}},
        ).status_code
        == 401
    )
    # New credential works.
    new_auth_headers = {
        "Authorization": f"Bearer {new_token}",
        "Idempotency-Key": "hb-new",
    }
    assert (
        http.post(
            f"/v1/devices/{device_id}/heartbeat",
            headers=new_auth_headers,
            json={"status": {}},
        ).status_code
        == 200
    )


def test_device_self_service_credential_renewal(client):
    http, _ = client
    identity = _bootstrap_owner(http)
    owner_headers = {
        "X-Tenant-ID": identity["tenant_id"],
        "X-User-ID": identity["admin_user_id"],
    }
    enrolled = http.post(
        "/v1/devices/enroll",
        headers=owner_headers,
        json={"external_id": "server-1", "hostname": "server-1", "os": "linux"},
    )
    device_id = enrolled.json()["device_id"]
    old_token = enrolled.json()["agent_token"]

    renewed = http.post(
        f"/v1/devices/{device_id}/credential/renew",
        headers={"Authorization": f"Bearer {old_token}"},
    )
    assert renewed.status_code == 200
    new_token = renewed.json()["agent_token"]
    assert new_token != old_token

    assert (
        http.post(
            f"/v1/devices/{device_id}/heartbeat",
            headers={
                "Authorization": f"Bearer {old_token}",
                "Idempotency-Key": "hb-1",
            },
            json={"status": {}},
        ).status_code
        == 401
    )
    assert (
        http.post(
            f"/v1/devices/{device_id}/heartbeat",
            headers={
                "Authorization": f"Bearer {new_token}",
                "Idempotency-Key": "hb-2",
            },
            json={"status": {}},
        ).status_code
        == 200
    )


def test_revoked_device_cannot_authenticate(client):
    http, _ = client
    identity = _bootstrap_owner(http)
    owner_headers = {
        "X-Tenant-ID": identity["tenant_id"],
        "X-User-ID": identity["admin_user_id"],
    }
    enrolled = http.post(
        "/v1/devices/enroll",
        headers=owner_headers,
        json={"external_id": "server-1", "hostname": "server-1", "os": "linux"},
    )
    device_id = enrolled.json()["device_id"]
    token = enrolled.json()["agent_token"]

    revoked = http.post(
        f"/v1/devices/{device_id}/revoke",
        headers=owner_headers,
        json={"reason": "device reported lost"},
    )
    assert revoked.status_code == 200
    assert revoked.json()["active"] is False
    assert revoked.json()["revoked_reason"] == "device reported lost"

    assert (
        http.post(
            f"/v1/devices/{device_id}/heartbeat",
            headers={
                "Authorization": f"Bearer {token}",
                "Idempotency-Key": "hb-1",
            },
            json={"status": {}},
        ).status_code
        == 401
    )
    # And a revoked device cannot rotate/renew its own credential either.
    assert (
        http.post(
            f"/v1/devices/{device_id}/credential/renew",
            headers={"Authorization": f"Bearer {token}"},
        ).status_code
        == 401
    )


def test_revoking_a_device_does_not_affect_others(client):
    http, _ = client
    identity = _bootstrap_owner(http)
    owner_headers = {
        "X-Tenant-ID": identity["tenant_id"],
        "X-User-ID": identity["admin_user_id"],
    }
    a = http.post(
        "/v1/devices/enroll",
        headers=owner_headers,
        json={"external_id": "server-a", "hostname": "server-a", "os": "linux"},
    ).json()
    b = http.post(
        "/v1/devices/enroll",
        headers=owner_headers,
        json={"external_id": "server-b", "hostname": "server-b", "os": "linux"},
    ).json()
    http.post(
        f"/v1/devices/{a['device_id']}/revoke",
        headers=owner_headers,
        json={"reason": "lost"},
    )
    assert (
        http.post(
            f"/v1/devices/{b['device_id']}/heartbeat",
            headers={
                "Authorization": f"Bearer {b['agent_token']}",
                "Idempotency-Key": "hb-1",
            },
            json={"status": {}},
        ).status_code
        == 200
    )
