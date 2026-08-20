"""API-level tests for POST/GET /v1/baselines and GET /v1/baselines/resolve
(Phase 6). Proves the precedence resolution actually runs at the API
boundary against real tenant-scoped rows, and that role/tenant boundaries
hold, not just the pure-function unit tests in tests/test_baseline.py.
"""

from __future__ import annotations

from helpdesktool.db_models import Device, User


def _bootstrap_owner(http) -> dict:
    response = http.post(
        "/v1/tenants",
        headers={"X-Bootstrap-Token": "test-bootstrap-token"},
        json={"name": "Acme", "admin_email": "owner@example.com"},
    )
    assert response.status_code == 201, response.text
    return response.json()


def test_create_and_list_baseline(client):
    http, _ = client
    identity = _bootstrap_owner(http)
    owner_headers = {
        "X-Tenant-ID": identity["tenant_id"],
        "X-User-ID": identity["admin_user_id"],
    }
    created = http.post(
        "/v1/baselines",
        headers=owner_headers,
        json={
            "scope": "organizational_policy",
            "key": "dns_servers",
            "value": ["10.0.0.1", "10.0.0.2"],
        },
    )
    assert created.status_code == 201, created.text
    listed = http.get(
        "/v1/baselines", headers=owner_headers, params={"key": "dns_servers"}
    ).json()
    assert len(listed) == 1
    assert listed[0]["scope"] == "organizational_policy"
    assert listed[0]["value"] == ["10.0.0.1", "10.0.0.2"]


def test_malformed_scope_combination_is_rejected_with_422(client):
    http, _ = client
    identity = _bootstrap_owner(http)
    owner_headers = {
        "X-Tenant-ID": identity["tenant_id"],
        "X-User-ID": identity["admin_user_id"],
    }
    response = http.post(
        "/v1/baselines",
        headers=owner_headers,
        json={
            "scope": "device_baseline",
            "key": "dns_servers",
            "value": ["10.0.5.9"],
            # missing device_id -- a device_baseline entry requires one.
        },
    )
    assert response.status_code == 422


def test_viewer_cannot_register_a_baseline(client):
    http, factory = client
    identity = _bootstrap_owner(http)
    with factory() as session:
        viewer = User(
            tenant_id=identity["tenant_id"], email="viewer@example.com", role="viewer"
        )
        session.add(viewer)
        session.commit()
        viewer_id = viewer.id
    viewer_headers = {"X-Tenant-ID": identity["tenant_id"], "X-User-ID": viewer_id}
    response = http.post(
        "/v1/baselines",
        headers=viewer_headers,
        json={
            "scope": "organizational_policy",
            "key": "dns_servers",
            "value": ["10.0.0.1"],
        },
    )
    assert response.status_code == 403


def test_device_id_from_another_tenant_is_rejected(client):
    http, factory = client
    identity_a = _bootstrap_owner(http)
    tenants_b = http.post(
        "/v1/tenants",
        headers={"X-Bootstrap-Token": "test-bootstrap-token"},
        json={"name": "Globex", "admin_email": "owner2@example.com"},
    ).json()
    with factory() as session:
        foreign_device = Device(
            tenant_id=tenants_b["tenant_id"],
            external_id="foreign-device",
            hostname="host",
            os="linux",
            agent_key_hash="x" * 64,
        )
        session.add(foreign_device)
        session.commit()
        foreign_device_id = foreign_device.id
    owner_a_headers = {
        "X-Tenant-ID": identity_a["tenant_id"],
        "X-User-ID": identity_a["admin_user_id"],
    }
    response = http.post(
        "/v1/baselines",
        headers=owner_a_headers,
        json={
            "scope": "device_baseline",
            "key": "dns_servers",
            "value": ["10.0.5.9"],
            "device_id": foreign_device_id,
        },
    )
    assert response.status_code == 404


def test_resolve_prefers_device_baseline_over_organizational_policy(client):
    http, factory = client
    identity = _bootstrap_owner(http)
    owner_headers = {
        "X-Tenant-ID": identity["tenant_id"],
        "X-User-ID": identity["admin_user_id"],
    }
    with factory() as session:
        device = Device(
            tenant_id=identity["tenant_id"],
            external_id="device-1",
            hostname="host-1",
            os="linux",
            agent_key_hash="x" * 64,
        )
        session.add(device)
        session.commit()
        device_id = device.id

    http.post(
        "/v1/baselines",
        headers=owner_headers,
        json={
            "scope": "organizational_policy",
            "key": "dns_servers",
            "value": ["10.0.0.1"],
        },
    )
    http.post(
        "/v1/baselines",
        headers=owner_headers,
        json={
            "scope": "device_baseline",
            "key": "dns_servers",
            "value": ["10.0.5.9"],
            "device_id": device_id,
        },
    )

    resolved = http.get(
        "/v1/baselines/resolve",
        headers=owner_headers,
        params={"key": "dns_servers", "device_id": device_id},
    ).json()
    assert resolved["resolved"]["scope"] == "device_baseline"
    assert resolved["resolved"]["value"] == ["10.0.5.9"]

    resolved_other_device = http.get(
        "/v1/baselines/resolve",
        headers=owner_headers,
        params={"key": "dns_servers", "device_id": "some-other-device"},
    ).json()
    assert resolved_other_device["resolved"]["scope"] == "organizational_policy"


def test_resolve_returns_null_when_nothing_is_declared(client):
    http, _ = client
    identity = _bootstrap_owner(http)
    owner_headers = {
        "X-Tenant-ID": identity["tenant_id"],
        "X-User-ID": identity["admin_user_id"],
    }
    resolved = http.get(
        "/v1/baselines/resolve",
        headers=owner_headers,
        params={"key": "never_declared_key"},
    ).json()
    assert resolved["resolved"] is None


def test_baselines_are_tenant_isolated(client):
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
    http.post(
        "/v1/baselines",
        headers=owner_a_headers,
        json={
            "scope": "organizational_policy",
            "key": "dns_servers",
            "value": ["10.0.0.1"],
        },
    )
    resolved_for_b = http.get(
        "/v1/baselines/resolve",
        headers=owner_b_headers,
        params={"key": "dns_servers"},
    ).json()
    assert resolved_for_b["resolved"] is None
    listed_for_b = http.get(
        "/v1/baselines", headers=owner_b_headers, params={"key": "dns_servers"}
    ).json()
    assert listed_for_b == []
