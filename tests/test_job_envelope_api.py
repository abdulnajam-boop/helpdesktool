"""API-level test proving POST /v1/devices/{id}/jobs/{action_id}/claim
returns a genuinely signed, verifiable job envelope wired to the real
skill registry -- not just a plausible-looking dict.
"""

from __future__ import annotations

from agent_common.signing import verify_envelope
from helpdesktool.job_signing import public_key_pem


def _bootstrap_owner(http) -> dict:
    response = http.post(
        "/v1/tenants",
        headers={"X-Bootstrap-Token": "test-bootstrap-token"},
        json={"name": "Acme", "admin_email": "owner@example.com"},
    )
    assert response.status_code == 201, response.text
    return response.json()


def test_claimed_job_envelope_is_signed_and_verifies(client):
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
    agent_token = enrolled.json()["agent_token"]
    assert enrolled.json()["signing_key_version"] == 1
    assert "BEGIN PUBLIC KEY" in enrolled.json()["signing_public_key_pem"]

    action = http.post(
        "/v1/actions",
        headers={**owner_headers, "Idempotency-Key": "action-1"},
        json={
            "device_id": device_id,
            "skill_id": "service.restart",
            "parameters": {"service": "demo.service"},
        },
    )
    assert action.status_code == 201, action.text
    action_id = action.json()["id"]

    from helpdesktool.db_models import User

    with factory() as session:
        approver = User(
            tenant_id=identity["tenant_id"], email="admin@example.com", role="admin"
        )
        session.add(approver)
        session.commit()
        approver_id = approver.id
    approved = http.post(
        f"/v1/actions/{action_id}/decision",
        headers={"X-Tenant-ID": identity["tenant_id"], "X-User-ID": approver_id},
        json={"decision": "approve", "reason": "test"},
    )
    assert approved.status_code == 200, approved.text

    agent_headers = {"Authorization": f"Bearer {agent_token}"}
    claim = http.post(
        f"/v1/devices/{device_id}/jobs/{action_id}/claim",
        headers={**agent_headers, "Idempotency-Key": "claim-1"},
        json={},
    )
    assert claim.status_code == 200, claim.text
    envelope = claim.json()

    assert envelope["action_id"] == action_id
    assert envelope["device_id"] == device_id
    assert envelope["tenant_id"] == identity["tenant_id"]
    assert envelope["skill_id"] == "service.restart"
    assert envelope["skill_version"] == 1
    assert envelope["job_id"] == f"{action_id}:1"
    assert envelope["parameters"] == {"service": "demo.service"}

    # The core assertion: the control plane's own derivation from the
    # configured signing seed independently verifies this exact envelope --
    # proving claim_job actually signed it correctly, not just attached a
    # plausible-looking "signature" field.
    from helpdesktool.config import get_settings

    verify_envelope(
        envelope,
        public_key_pem=public_key_pem(get_settings().job_signing_seed),
        expected_device_id=device_id,
        expected_tenant_id=identity["tenant_id"],
        supported_skill_versions={"service.restart": frozenset({1})},
    )


def test_agent_signing_key_endpoint_matches_enrollment_key(client):
    http, _ = client
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
    agent_token = enrolled.json()["agent_token"]

    device_id = enrolled.json()["device_id"]
    fetched = http.get(
        f"/v1/devices/{device_id}/signing-key",
        headers={"Authorization": f"Bearer {agent_token}"},
    )
    assert fetched.status_code == 200, fetched.text
    assert fetched.json()["public_key_pem"] == enrolled.json()["signing_public_key_pem"]
    assert fetched.json()["key_version"] == enrolled.json()["signing_key_version"]
