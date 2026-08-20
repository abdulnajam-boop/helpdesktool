"""Tests for the omnichannel help-desk foundation: identity resolution,
the Application Connector Framework (against the mock connector), the
Conversation Service's deterministic intent classification, and the full
chat -> policy -> connector -> ticket -> audit pipeline via the real HTTP
API (the web channel adapter).
"""

from __future__ import annotations

from helpdesktool.connectors.mock import MockApplicationConnector
from helpdesktool.conversation import classify_intent
from helpdesktool.db_models import User


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


# --- classify_intent (unit) -------------------------------------------------


def test_classify_intent_recognizes_password_reset():
    result = classify_intent("Can you reset my password please?", frozenset())
    assert result.intent == "password_reset"


def test_classify_intent_recognizes_application_hint():
    result = classify_intent("Reset my Salesforce password", frozenset({"salesforce"}))
    assert result.intent == "password_reset"
    assert result.application_hint == "salesforce"


def test_classify_intent_recognizes_unlock():
    result = classify_intent("I'm locked out of my account", frozenset())
    assert result.intent == "unlock_account"


def test_classify_intent_recognizes_mfa_reset():
    result = classify_intent("please reset my MFA / authenticator", frozenset())
    assert result.intent == "mfa_reset"


def test_classify_intent_falls_back_to_general_inquiry():
    result = classify_intent("My laptop is really slow today", frozenset())
    assert result.intent == "general_inquiry"


# --- MockApplicationConnector (unit) ----------------------------------------


def test_mock_connector_full_reset_password_lifecycle():
    connector = MockApplicationConnector()
    resolved = connector.resolve_user("owner@example.com")
    assert resolved.success
    external_id = resolved.data["external_user_id"]
    reset = connector.reset_password(external_id)
    assert reset.success
    verified = connector.verify_result(external_id, "reset_password")
    assert verified.success


def test_mock_connector_unresolvable_email_fails_closed():
    connector = MockApplicationConnector()
    result = connector.resolve_user("nobody@nowhere.example")
    assert not result.success


# --- Full pipeline via the real HTTP API ------------------------------------


def test_general_inquiry_creates_a_ticket(client):
    http, _ = client
    identity = _bootstrap_owner(http)
    owner_headers = {
        "X-Tenant-ID": identity["tenant_id"],
        "X-User-ID": identity["admin_user_id"],
    }
    response = http.post(
        "/v1/chat/message",
        headers=owner_headers,
        json={"message": "My laptop is really slow"},
    )
    assert response.status_code == 201, response.text
    body = response.json()
    assert body["ticket_id"] is not None
    assert body["connector_request_id"] is None
    ticket = http.get(f"/v1/tickets/{body['ticket_id']}", headers=owner_headers).json()
    assert ticket["title"]


def test_password_reset_creates_a_pending_connector_request(client):
    http, _ = client
    identity = _bootstrap_owner(http)
    owner_headers = {
        "X-Tenant-ID": identity["tenant_id"],
        "X-User-ID": identity["admin_user_id"],
    }
    _register_mock_connector(http, owner_headers, "salesforce")
    response = http.post(
        "/v1/chat/message",
        headers=owner_headers,
        json={"message": "Please reset my Salesforce password"},
    )
    assert response.status_code == 201, response.text
    body = response.json()
    assert body["connector_request_id"] is not None
    assert body["ticket_id"] is not None

    pending = http.get("/v1/connector-requests", headers=owner_headers).json()
    assert any(r["id"] == body["connector_request_id"] for r in pending)
    request = pending[0]
    assert request["operation"] == "reset_password"
    assert request["status"] == "pending_approval"
    assert request["target_email"] == "owner@example.com"


def test_full_password_reset_pipeline_end_to_end(client):
    """Chat -> policy (pending approval) -> independent admin approves ->
    mock connector executes -> verified -> ticket/audit trail exists.
    Mirrors this project's existing full-lifecycle integration tests
    (test_api_integration.py) but for the chat/connector pipeline.
    """
    http, factory = client
    identity = _bootstrap_owner(http)
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

    # Owner cannot approve their own request (separation of duties, same
    # rule as action approval).
    self_approve = http.post(
        f"/v1/connector-requests/{request_id}/decision",
        headers=owner_headers,
        json={"decision": "approve", "reason": "should be rejected"},
    )
    assert self_approve.status_code == 403

    with factory() as session:
        admin = User(
            tenant_id=identity["tenant_id"], email="admin@example.com", role="admin"
        )
        session.add(admin)
        session.commit()
        admin_id = admin.id
    admin_headers = {"X-Tenant-ID": identity["tenant_id"], "X-User-ID": admin_id}

    approved = http.post(
        f"/v1/connector-requests/{request_id}/decision",
        headers=admin_headers,
        json={"decision": "approve", "reason": "confirmed identity"},
    )
    assert approved.status_code == 200, approved.text
    body = approved.json()
    assert body["status"] == "succeeded"
    assert body["result_success"] is True
    assert body["verified"] is True

    # Re-deciding an already-decided request is rejected, same as actions.
    replay = http.post(
        f"/v1/connector-requests/{request_id}/decision",
        headers=admin_headers,
        json={"decision": "approve", "reason": "replay"},
    )
    assert replay.status_code == 409

    audit_events = http.get("/v1/audit", headers=owner_headers).json()
    event_types = {e["event_type"] for e in audit_events}
    assert {
        "conversation.started",
        "connector_request.created",
        "connector_request.executed",
    }.issubset(event_types)


def test_denied_connector_request_never_touches_the_connector(client):
    http, factory = client
    identity = _bootstrap_owner(http)
    owner_headers = {
        "X-Tenant-ID": identity["tenant_id"],
        "X-User-ID": identity["admin_user_id"],
    }
    _register_mock_connector(http, owner_headers, "salesforce")
    chat = http.post(
        "/v1/chat/message",
        headers=owner_headers,
        json={"message": "unlock my Salesforce account"},
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

    denied = http.post(
        f"/v1/connector-requests/{request_id}/decision",
        headers=admin_headers,
        json={"decision": "deny", "reason": "not verified"},
    )
    assert denied.status_code == 200
    assert denied.json()["status"] == "denied"
    assert denied.json()["result_success"] is None


def test_unresolved_application_asks_for_clarification(client):
    http, _ = client
    identity = _bootstrap_owner(http)
    owner_headers = {
        "X-Tenant-ID": identity["tenant_id"],
        "X-User-ID": identity["admin_user_id"],
    }
    _register_mock_connector(http, owner_headers, "salesforce")
    _register_mock_connector(http, owner_headers, "github")
    response = http.post(
        "/v1/chat/message",
        headers=owner_headers,
        json={"message": "reset my password"},
    )
    assert response.status_code == 201
    body = response.json()
    assert body["connector_request_id"] is None
    assert "couldn't tell which application" in body["reply"]


def test_viewer_can_message_but_cannot_decide_connector_requests(client):
    http, factory = client
    identity = _bootstrap_owner(http)
    owner_headers = {
        "X-Tenant-ID": identity["tenant_id"],
        "X-User-ID": identity["admin_user_id"],
    }
    _register_mock_connector(http, owner_headers, "salesforce")
    with factory() as session:
        viewer = User(
            tenant_id=identity["tenant_id"], email="viewer@example.com", role="viewer"
        )
        session.add(viewer)
        session.commit()
        viewer_id = viewer.id
    viewer_headers = {"X-Tenant-ID": identity["tenant_id"], "X-User-ID": viewer_id}

    chat = http.post(
        "/v1/chat/message",
        headers=viewer_headers,
        json={"message": "reset my Salesforce password"},
    )
    assert chat.status_code == 201
    request_id = chat.json()["connector_request_id"]

    denied = http.post(
        f"/v1/connector-requests/{request_id}/decision",
        headers=viewer_headers,
        json={"decision": "approve", "reason": "n/a"},
    )
    assert denied.status_code == 403


def test_cross_tenant_connector_request_is_not_found(client):
    http, factory = client
    tenant_a = _bootstrap_owner(http)
    owner_a_headers = {
        "X-Tenant-ID": tenant_a["tenant_id"],
        "X-User-ID": tenant_a["admin_user_id"],
    }
    _register_mock_connector(http, owner_a_headers, "salesforce")
    chat = http.post(
        "/v1/chat/message",
        headers=owner_a_headers,
        json={"message": "reset my Salesforce password"},
    )
    request_id = chat.json()["connector_request_id"]

    tenant_b = http.post(
        "/v1/tenants",
        headers={"X-Bootstrap-Token": "test-bootstrap-token"},
        json={"name": "Other Co", "admin_email": "owner@other.example"},
    ).json()
    owner_b_headers = {
        "X-Tenant-ID": tenant_b["tenant_id"],
        "X-User-ID": tenant_b["admin_user_id"],
    }
    forged = http.post(
        f"/v1/connector-requests/{request_id}/decision",
        headers=owner_b_headers,
        json={"decision": "approve", "reason": "cross-tenant forgery"},
    )
    assert forged.status_code == 404


def test_unresolvable_target_account_fails_closed(client):
    """If the connector can't resolve the requester's own email (e.g. the
    mock roster doesn't have them), execution fails closed rather than
    silently succeeding.
    """
    http, factory = client
    identity = _bootstrap_owner(http)
    owner_headers = {
        "X-Tenant-ID": identity["tenant_id"],
        "X-User-ID": identity["admin_user_id"],
    }
    _register_mock_connector(http, owner_headers, "salesforce")
    with factory() as session:
        requester = User(
            tenant_id=identity["tenant_id"],
            email="unknown-to-connector@example.com",
            role="operator",
        )
        session.add(requester)
        session.commit()
        requester_id = requester.id
    requester_headers = {
        "X-Tenant-ID": identity["tenant_id"],
        "X-User-ID": requester_id,
    }
    chat = http.post(
        "/v1/chat/message",
        headers=requester_headers,
        json={"message": "reset my Salesforce password"},
    )
    request_id = chat.json()["connector_request_id"]

    with factory() as session:
        admin = User(
            tenant_id=identity["tenant_id"], email="admin2@example.com", role="admin"
        )
        session.add(admin)
        session.commit()
        admin_id = admin.id
    admin_headers = {"X-Tenant-ID": identity["tenant_id"], "X-User-ID": admin_id}
    decided = http.post(
        f"/v1/connector-requests/{request_id}/decision",
        headers=admin_headers,
        json={"decision": "approve", "reason": "ok"},
    )
    assert decided.status_code == 200
    assert decided.json()["status"] == "failed"
    assert decided.json()["result_success"] is False
