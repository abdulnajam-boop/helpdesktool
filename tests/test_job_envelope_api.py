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
    assert "BEGIN PUBLIC KEY" in enrolled.json()["signing_public_keys"]["1"]

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
        public_keys={1: public_key_pem(get_settings().job_signing_seed, 1)},
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
    assert (
        fetched.json()["signing_public_keys"] == enrolled.json()["signing_public_keys"]
    )


def test_signing_key_rotation_keeps_the_old_version_verifiable(client, monkeypatch):
    """The real rotation contract (Milestone 27): bumping
    Settings.job_signing_key_version alone (no new secret, no code deploy)
    signs *new* envelopes with a different key, while the signing-key
    endpoint keeps exposing the previous version too -- an envelope
    claimed before the rotation still verifies against that same
    endpoint's response after it.
    """
    from helpdesktool.config import get_settings

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
    device_id = enrolled.json()["device_id"]
    agent_token = enrolled.json()["agent_token"]
    agent_headers = {"Authorization": f"Bearer {agent_token}"}

    from helpdesktool.db_models import User

    with factory() as session:
        approver = User(
            tenant_id=identity["tenant_id"], email="admin@example.com", role="admin"
        )
        session.add(approver)
        session.commit()
        approver_id = approver.id
    admin_headers = {"X-Tenant-ID": identity["tenant_id"], "X-User-ID": approver_id}

    def _claim_a_job(idempotency_key: str) -> dict:
        action = http.post(
            "/v1/actions",
            headers={**owner_headers, "Idempotency-Key": idempotency_key},
            json={
                "device_id": device_id,
                "skill_id": "service.restart",
                "parameters": {"service": "demo.service"},
            },
        )
        action_id = action.json()["id"]
        http.post(
            f"/v1/actions/{action_id}/decision",
            headers=admin_headers,
            json={"decision": "approve", "reason": "test"},
        )
        claim = http.post(
            f"/v1/devices/{device_id}/jobs/{action_id}/claim",
            headers={**agent_headers, "Idempotency-Key": f"claim-{idempotency_key}"},
            json={},
        )
        assert claim.status_code == 200, claim.text
        return claim.json()

    envelope_v1 = _claim_a_job("action-v1")
    assert envelope_v1["key_version"] == 1

    # Rotate: bump the active version, same seed, no code change.
    monkeypatch.setenv("HELPDESK_JOB_SIGNING_KEY_VERSION", "2")
    get_settings.cache_clear()

    fetched = http.get(f"/v1/devices/{device_id}/signing-key", headers=agent_headers)
    trusted_keys = {
        int(version): pem
        for version, pem in fetched.json()["signing_public_keys"].items()
    }
    assert set(trusted_keys) == {1, 2}

    envelope_v2 = _claim_a_job("action-v2")
    assert envelope_v2["key_version"] == 2

    from agent_common.signing import verify_envelope

    # Both the pre-rotation and post-rotation envelopes verify against the
    # same refreshed key set -- the transition window in action.
    for envelope in (envelope_v1, envelope_v2):
        verify_envelope(
            envelope,
            public_keys=trusted_keys,
            expected_device_id=device_id,
            expected_tenant_id=identity["tenant_id"],
            supported_skill_versions={"service.restart": frozenset({1})},
        )
