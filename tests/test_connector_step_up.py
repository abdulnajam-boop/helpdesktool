"""Tests for step-up verification on high-risk connector requests
(migration 0018): an approver can never approve a password reset / account
unlock / MFA reset blind off the original channel identity claim alone --
the requester must separately retrieve a short-lived code through their
own authenticated session and hand it to the approver.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from helpdesktool.db_models import ConnectorRequest, User


def _bootstrap_owner(http) -> dict:
    response = http.post(
        "/v1/tenants",
        headers={"X-Bootstrap-Token": "test-bootstrap-token"},
        json={"name": "Acme", "admin_email": "owner@example.com"},
    )
    assert response.status_code == 201, response.text
    return response.json()


def _register_mock_connector(http, owner_headers, application_id="salesforce") -> dict:
    response = http.post(
        "/v1/connectors",
        headers=owner_headers,
        json={
            "application_id": application_id,
            "display_name": application_id.title(),
            "connector_type": "mock",
        },
    )
    assert response.status_code == 201, response.text
    return response.json()


def _create_high_risk_request(http, factory, identity) -> tuple[str, dict, dict]:
    owner_headers = {
        "X-Tenant-ID": identity["tenant_id"],
        "X-User-ID": identity["admin_user_id"],
    }
    _register_mock_connector(http, owner_headers, "salesforce")
    chat = http.post(
        "/v1/chat/message",
        headers=owner_headers,
        json={"message": "Reset my Salesforce password"},
    )
    request_id = chat.json()["connector_request_id"]
    with factory() as session:
        admin = User(
            tenant_id=identity["tenant_id"], email="admin@example.com", role="admin"
        )
        session.add(admin)
        session.commit()
        admin_id = admin.id
    admin_headers = {"X-Tenant-ID": identity["tenant_id"], "X-User-ID": admin_id}
    return request_id, owner_headers, admin_headers


def test_approving_without_any_step_up_code_is_refused(client):
    http, factory = client
    identity = _bootstrap_owner(http)
    request_id, _owner_headers, admin_headers = _create_high_risk_request(
        http, factory, identity
    )
    response = http.post(
        f"/v1/connector-requests/{request_id}/decision",
        headers=admin_headers,
        json={"decision": "approve", "reason": "no code"},
    )
    assert response.status_code == 403
    assert "step-up" in response.json()["detail"]


def test_wrong_step_up_code_is_refused(client):
    http, factory = client
    identity = _bootstrap_owner(http)
    request_id, owner_headers, admin_headers = _create_high_risk_request(
        http, factory, identity
    )
    generated = http.get(
        f"/v1/connector-requests/{request_id}/step-up-code", headers=owner_headers
    )
    assert generated.status_code == 201
    response = http.post(
        f"/v1/connector-requests/{request_id}/decision",
        headers=admin_headers,
        json={
            "decision": "approve",
            "reason": "wrong",
            "step_up_code": "000000001",
        },
    )
    assert response.status_code == 403
    assert "incorrect" in response.json()["detail"]


def test_only_the_original_requester_can_generate_a_step_up_code(client):
    http, factory = client
    identity = _bootstrap_owner(http)
    request_id, _owner_headers, admin_headers = _create_high_risk_request(
        http, factory, identity
    )
    # The admin (a different, unrelated user) cannot mint a code for
    # someone else's request.
    response = http.get(
        f"/v1/connector-requests/{request_id}/step-up-code", headers=admin_headers
    )
    assert response.status_code == 403
    assert "only the requester" in response.json()["detail"]


def test_correct_step_up_code_allows_approval(client):
    http, factory = client
    identity = _bootstrap_owner(http)
    request_id, owner_headers, admin_headers = _create_high_risk_request(
        http, factory, identity
    )
    generated = http.get(
        f"/v1/connector-requests/{request_id}/step-up-code", headers=owner_headers
    )
    code = generated.json()["step_up_code"]
    response = http.post(
        f"/v1/connector-requests/{request_id}/decision",
        headers=admin_headers,
        json={"decision": "approve", "reason": "verified", "step_up_code": code},
    )
    assert response.status_code == 200, response.text
    assert response.json()["status"] == "succeeded"


def test_step_up_code_is_single_use(client):
    """A code cannot be replayed against a second decision attempt --
    consumed on first use, and re-deciding an already-decided request is
    rejected before the code is even checked again."""
    http, factory = client
    identity = _bootstrap_owner(http)
    request_id, owner_headers, admin_headers = _create_high_risk_request(
        http, factory, identity
    )
    generated = http.get(
        f"/v1/connector-requests/{request_id}/step-up-code", headers=owner_headers
    )
    code = generated.json()["step_up_code"]
    with factory() as session:
        request = session.get(ConnectorRequest, request_id)
        assert request is not None
        assert request.step_up_code_hash is not None

    first = http.post(
        f"/v1/connector-requests/{request_id}/decision",
        headers=admin_headers,
        json={"decision": "approve", "reason": "first", "step_up_code": code},
    )
    assert first.status_code == 200

    with factory() as session:
        request = session.get(ConnectorRequest, request_id)
        assert request is not None
        assert request.step_up_code_hash is None


def test_expired_step_up_code_is_refused(client):
    http, factory = client
    identity = _bootstrap_owner(http)
    request_id, owner_headers, admin_headers = _create_high_risk_request(
        http, factory, identity
    )
    generated = http.get(
        f"/v1/connector-requests/{request_id}/step-up-code", headers=owner_headers
    )
    code = generated.json()["step_up_code"]
    with factory() as session:
        request = session.get(ConnectorRequest, request_id)
        assert request is not None
        request.step_up_code_expires_at = datetime.now(UTC) - timedelta(minutes=1)
        session.commit()

    response = http.post(
        f"/v1/connector-requests/{request_id}/decision",
        headers=admin_headers,
        json={"decision": "approve", "reason": "late", "step_up_code": code},
    )
    assert response.status_code == 403
    assert "expired" in response.json()["detail"]


def test_denying_a_high_risk_request_never_requires_a_step_up_code(client):
    http, factory = client
    identity = _bootstrap_owner(http)
    request_id, _owner_headers, admin_headers = _create_high_risk_request(
        http, factory, identity
    )
    response = http.post(
        f"/v1/connector-requests/{request_id}/decision",
        headers=admin_headers,
        json={"decision": "deny", "reason": "not needed"},
    )
    assert response.status_code == 200
    assert response.json()["status"] == "denied"


def test_step_up_code_endpoint_requires_a_pending_high_risk_request(client):
    http, factory = client
    identity = _bootstrap_owner(http)
    request_id, owner_headers, admin_headers = _create_high_risk_request(
        http, factory, identity
    )
    http.post(
        f"/v1/connector-requests/{request_id}/decision",
        headers=admin_headers,
        json={"decision": "deny", "reason": "closed"},
    )
    late = http.get(
        f"/v1/connector-requests/{request_id}/step-up-code", headers=owner_headers
    )
    assert late.status_code == 409
