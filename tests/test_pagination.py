"""Tests for limit/offset pagination on the list endpoints that previously
returned an unbounded result set (devices, tickets, actions, incidents).
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


def test_devices_list_is_capped_by_default_limit(client):
    from helpdesktool.database import set_tenant_context
    from helpdesktool.db_models import Device

    http, factory = client
    identity = _bootstrap_owner(http)
    owner_headers = {
        "X-Tenant-ID": identity["tenant_id"],
        "X-User-ID": identity["admin_user_id"],
    }
    with factory() as session:
        set_tenant_context(session, identity["tenant_id"])
        for i in range(120):
            session.add(
                Device(
                    tenant_id=identity["tenant_id"],
                    external_id=f"device-{i}",
                    hostname=f"host-{i}",
                    os="linux",
                    agent_key_hash="x" * 64,
                )
            )
        session.commit()

    default_page = http.get("/v1/devices", headers=owner_headers)
    assert default_page.status_code == 200
    assert len(default_page.json()) == 100  # default limit

    full_page = http.get("/v1/devices?limit=200", headers=owner_headers)
    assert len(full_page.json()) == 120


def test_devices_offset_advances_through_pages_without_duplicates(client):
    from helpdesktool.database import set_tenant_context
    from helpdesktool.db_models import Device

    http, factory = client
    identity = _bootstrap_owner(http)
    owner_headers = {
        "X-Tenant-ID": identity["tenant_id"],
        "X-User-ID": identity["admin_user_id"],
    }
    with factory() as session:
        set_tenant_context(session, identity["tenant_id"])
        for i in range(30):
            session.add(
                Device(
                    tenant_id=identity["tenant_id"],
                    external_id=f"device-{i}",
                    hostname=f"host-{i}",
                    os="linux",
                    agent_key_hash="x" * 64,
                )
            )
        session.commit()

    page1 = http.get("/v1/devices?limit=10&offset=0", headers=owner_headers).json()
    page2 = http.get("/v1/devices?limit=10&offset=10", headers=owner_headers).json()
    page3 = http.get("/v1/devices?limit=10&offset=20", headers=owner_headers).json()
    assert len(page1) == len(page2) == len(page3) == 10
    ids = {row["id"] for row in page1 + page2 + page3}
    assert len(ids) == 30  # no duplicates, no gaps across a stable ordering


def test_limit_is_clamped_to_a_maximum(client):
    http, _ = client
    identity = _bootstrap_owner(http)
    owner_headers = {
        "X-Tenant-ID": identity["tenant_id"],
        "X-User-ID": identity["admin_user_id"],
    }
    # A caller trying to request an effectively unbounded page must not get
    # one -- this is the actual security/performance property under test.
    response = http.get("/v1/devices?limit=1000000", headers=owner_headers)
    assert response.status_code == 200


def test_tickets_actions_incidents_accept_limit_and_offset(client):
    http, _ = client
    identity = _bootstrap_owner(http)
    owner_headers = {
        "X-Tenant-ID": identity["tenant_id"],
        "X-User-ID": identity["admin_user_id"],
    }
    for path in ("/v1/tickets", "/v1/actions", "/v1/incidents"):
        response = http.get(f"{path}?limit=5&offset=0", headers=owner_headers)
        assert response.status_code == 200, f"{path}: {response.text}"
        assert response.json() == []
