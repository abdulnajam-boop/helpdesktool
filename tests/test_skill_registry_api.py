"""API-level tests for the data-driven skill registry (GET/POST /v1/skills)
and its integration into action creation and AI diagnosis's allowed-skill
enforcement — Milestone 4.
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


def test_list_skills_includes_the_two_seeded_defaults(client):
    http, _ = client
    identity = _bootstrap_owner(http)
    headers = {
        "X-Tenant-ID": identity["tenant_id"],
        "X-User-ID": identity["admin_user_id"],
    }
    response = http.get("/v1/skills", headers=headers)
    assert response.status_code == 200, response.text
    skill_ids = {row["skill_id"] for row in response.json()}
    assert skill_ids == {"diagnostics.collect", "service.restart"}
    for row in response.json():
        assert row["active"] is True
        assert row["version"] == 1
        assert len(row["content_hash"]) == 64


def test_create_skill_manifest_requires_owner_or_admin(client):
    http, factory = client
    identity = _bootstrap_owner(http)
    # Seed an operator via the low-level DB, mirroring other tests' pattern.
    from helpdesktool.db_models import User

    with factory() as session:
        session.add(
            User(
                tenant_id=identity["tenant_id"],
                email="operator@example.com",
                role="operator",
            )
        )
        session.commit()
        operator_id = (
            session.query(User).filter_by(email="operator@example.com").one().id
        )
    denied = http.post(
        "/v1/skills",
        headers={
            "X-Tenant-ID": identity["tenant_id"],
            "X-User-ID": operator_id,
        },
        json={
            "skill_id": "diagnostics.network",
            "risk": "read_only",
            "supported_os": ["linux"],
        },
    )
    assert denied.status_code == 403


def test_create_skill_manifest_registers_a_new_versioned_skill(client):
    http, _ = client
    identity = _bootstrap_owner(http)
    headers = {
        "X-Tenant-ID": identity["tenant_id"],
        "X-User-ID": identity["admin_user_id"],
    }
    created = http.post(
        "/v1/skills",
        headers=headers,
        json={
            "skill_id": "diagnostics.network",
            "risk": "read_only",
            "supported_os": ["linux", "windows"],
            "parameters": {},
        },
    )
    assert created.status_code == 201, created.text
    body = created.json()
    assert body["version"] == 1
    assert body["active"] is True

    listing = http.get("/v1/skills", headers=headers)
    skill_ids = {row["skill_id"] for row in listing.json()}
    assert "diagnostics.network" in skill_ids


def test_registering_a_new_version_deactivates_the_previous_one(client):
    http, _ = client
    identity = _bootstrap_owner(http)
    headers = {
        "X-Tenant-ID": identity["tenant_id"],
        "X-User-ID": identity["admin_user_id"],
    }
    v2 = http.post(
        "/v1/skills",
        headers=headers,
        json={
            "skill_id": "service.restart",
            "risk": "high",
            "supported_os": ["linux", "windows"],
            "rollback_skill_id": "service.restore",
            "parameters": {"service": {"type": "string", "required": True}},
        },
    )
    assert v2.status_code == 201, v2.text
    assert v2.json()["version"] == 2
    assert v2.json()["risk"] == "high"

    all_versions = http.get("/v1/skills?active_only=false", headers=headers).json()
    restart_versions = {
        row["version"]: row["active"]
        for row in all_versions
        if row["skill_id"] == "service.restart"
    }
    assert restart_versions == {1: False, 2: True}


def test_unknown_skill_id_in_action_create_is_rejected_not_silently_allowed(client):
    http, _ = client
    identity = _bootstrap_owner(http)
    headers = {
        "X-Tenant-ID": identity["tenant_id"],
        "X-User-ID": identity["admin_user_id"],
    }
    device = http.post(
        "/v1/devices/enroll",
        headers=headers,
        json={"external_id": "d1", "hostname": "d1", "os": "linux"},
    )
    assert device.status_code == 201, device.text
    response = http.post(
        "/v1/actions",
        headers={**headers, "Idempotency-Key": "key-1"},
        json={
            "device_id": device.json()["device_id"],
            "skill_id": "shell.execute",
            "parameters": {"command": "rm -rf /"},
        },
    )
    # No registered manifest matches this skill_id, so PolicyEngine denies it
    # at evaluation time; the action is still recorded (for audit/visibility)
    # with status "denied" rather than ever executing — it never raises an
    # HTTP error, since "policy denied this" is a normal, auditable outcome
    # distinct from a malformed request.
    assert response.status_code == 201, response.text
    assert response.json()["status"] == "denied"


def test_action_create_rejects_parameters_outside_the_registered_schema(client):
    http, _ = client
    identity = _bootstrap_owner(http)
    headers = {
        "X-Tenant-ID": identity["tenant_id"],
        "X-User-ID": identity["admin_user_id"],
    }
    device = http.post(
        "/v1/devices/enroll",
        headers=headers,
        json={"external_id": "d1", "hostname": "d1", "os": "linux"},
    )
    assert device.status_code == 201, device.text
    response = http.post(
        "/v1/actions",
        headers={**headers, "Idempotency-Key": "key-1"},
        json={
            "device_id": device.json()["device_id"],
            "skill_id": "service.restart",
            "parameters": {"service": "demo.service", "extra_param": "x"},
        },
    )
    assert response.status_code == 422
    assert "unexpected parameter" in response.json()["detail"]


def test_manifest_integrity_tampering_fails_closed_on_action_create(client):
    """Directly editing a stored manifest's policy fields without updating
    its content_hash (bypassing POST /v1/skills, e.g. a compromised/errant
    direct database write) must be detected and block the endpoint, not be
    silently trusted.
    """
    from helpdesktool.db_models import SkillManifestRow

    http, factory = client
    identity = _bootstrap_owner(http)
    headers = {
        "X-Tenant-ID": identity["tenant_id"],
        "X-User-ID": identity["admin_user_id"],
    }
    device = http.post(
        "/v1/devices/enroll",
        headers=headers,
        json={"external_id": "d1", "hostname": "d1", "os": "linux"},
    )
    assert device.status_code == 201, device.text

    with factory() as session:
        row = (
            session.query(SkillManifestRow)
            .filter_by(skill_id="service.restart", active=True)
            .one()
        )
        row.risk = "prohibited"  # tampered without recomputing content_hash
        session.commit()

    response = http.post(
        "/v1/actions",
        headers={**headers, "Idempotency-Key": "key-1"},
        json={
            "device_id": device.json()["device_id"],
            "skill_id": "service.restart",
            "parameters": {"service": "demo.service"},
        },
    )
    assert response.status_code == 500
    assert "integrity" in response.json()["detail"]
