"""API-level tests for the Slack channel adapter: workspace/identity link
registration and POST /v1/channels/slack/events/{link_id}, proving the
full identity -> conversation -> ticket pipeline runs against a real,
self-signed Slack-shaped request -- not just the pure-function unit tests
in tests/test_channels_slack.py.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import time

SECRET = "acme-slack-signing-secret"


def _sign(secret: str, timestamp: str, body: bytes) -> str:
    basestring = b"v0:" + timestamp.encode() + b":" + body
    return "v0=" + hmac.new(secret.encode(), basestring, hashlib.sha256).hexdigest()


def _slack_headers(secret: str, body: bytes) -> dict:
    timestamp = str(int(time.time()))
    return {
        "X-Slack-Request-Timestamp": timestamp,
        "X-Slack-Signature": _sign(secret, timestamp, body),
        "Content-Type": "application/json",
    }


def _bootstrap_owner(http) -> dict:
    response = http.post(
        "/v1/tenants",
        headers={"X-Bootstrap-Token": "test-bootstrap-token"},
        json={"name": "Acme", "admin_email": "owner@example.com"},
    )
    assert response.status_code == 201, response.text
    return response.json()


def _link_workspace(http, owner_headers, monkeypatch) -> str:
    monkeypatch.setenv("HELPDESK_SLACK_SIGNING_SECRET_ACME", SECRET)
    created = http.post(
        "/v1/channels/workspace-links",
        headers=owner_headers,
        json={
            "channel": "slack",
            "workspace_id": "T123",
            "signing_secret_ref": "env:HELPDESK_SLACK_SIGNING_SECRET_ACME",
        },
    )
    assert created.status_code == 201, created.text
    return created.json()["id"]


def test_url_verification_challenge_is_echoed_back(client, monkeypatch):
    http, _ = client
    identity = _bootstrap_owner(http)
    owner_headers = {
        "X-Tenant-ID": identity["tenant_id"],
        "X-User-ID": identity["admin_user_id"],
    }
    link_id = _link_workspace(http, owner_headers, monkeypatch)
    body = json.dumps({"type": "url_verification", "challenge": "xyz123"}).encode()
    response = http.post(
        f"/v1/channels/slack/events/{link_id}",
        headers=_slack_headers(SECRET, body),
        content=body,
    )
    assert response.status_code == 200
    assert response.json() == {"challenge": "xyz123"}


def test_invalid_signature_is_rejected(client, monkeypatch):
    http, _ = client
    identity = _bootstrap_owner(http)
    owner_headers = {
        "X-Tenant-ID": identity["tenant_id"],
        "X-User-ID": identity["admin_user_id"],
    }
    link_id = _link_workspace(http, owner_headers, monkeypatch)
    body = json.dumps({"type": "url_verification", "challenge": "xyz"}).encode()
    headers = _slack_headers("wrong-secret", body)
    response = http.post(
        f"/v1/channels/slack/events/{link_id}", headers=headers, content=body
    )
    assert response.status_code == 401


def test_unknown_link_id_is_rejected(client):
    http, _ = client
    body = json.dumps({"type": "url_verification", "challenge": "xyz"}).encode()
    response = http.post(
        "/v1/channels/slack/events/00000000-0000-0000-0000-000000000000",
        headers=_slack_headers(SECRET, body),
        content=body,
    )
    assert response.status_code == 404


def test_event_from_an_unmapped_workspace_is_rejected(client, monkeypatch):
    http, _ = client
    identity = _bootstrap_owner(http)
    owner_headers = {
        "X-Tenant-ID": identity["tenant_id"],
        "X-User-ID": identity["admin_user_id"],
    }
    link_id = _link_workspace(http, owner_headers, monkeypatch)
    payload = {
        "type": "event_callback",
        "team_id": "T999",  # not the linked workspace_id (T123)
        "event_id": "Ev1",
        "event": {
            "type": "message",
            "user": "U1",
            "text": "reset my password",
            "channel": "C1",
        },
    }
    body = json.dumps(payload).encode()
    response = http.post(
        f"/v1/channels/slack/events/{link_id}",
        headers=_slack_headers(SECRET, body),
        content=body,
    )
    assert response.status_code == 401


def test_message_from_an_unmapped_slack_user_is_acknowledged_but_not_processed(
    client, monkeypatch
):
    http, _ = client
    identity = _bootstrap_owner(http)
    owner_headers = {
        "X-Tenant-ID": identity["tenant_id"],
        "X-User-ID": identity["admin_user_id"],
    }
    link_id = _link_workspace(http, owner_headers, monkeypatch)
    payload = {
        "type": "event_callback",
        "team_id": "T123",
        "event_id": "Ev2",
        "event": {
            "type": "message",
            "user": "U-unmapped",
            "text": "reset my password",
            "channel": "C1",
        },
    }
    body = json.dumps(payload).encode()
    response = http.post(
        f"/v1/channels/slack/events/{link_id}",
        headers=_slack_headers(SECRET, body),
        content=body,
    )
    assert response.status_code == 204
    tickets = http.get("/v1/tickets", headers=owner_headers).json()
    assert tickets == []


def test_message_from_a_mapped_slack_user_creates_a_ticket(client, monkeypatch):
    http, _ = client
    identity = _bootstrap_owner(http)
    owner_headers = {
        "X-Tenant-ID": identity["tenant_id"],
        "X-User-ID": identity["admin_user_id"],
    }
    link_id = _link_workspace(http, owner_headers, monkeypatch)
    linked = http.post(
        "/v1/channels/identity-links",
        headers=owner_headers,
        json={
            "channel": "slack",
            "provider_user_id": "U-owner",
            "user_id": identity["admin_user_id"],
        },
    )
    assert linked.status_code == 201, linked.text

    payload = {
        "type": "event_callback",
        "team_id": "T123",
        "event_id": "Ev3",
        "event": {
            "type": "message",
            "user": "U-owner",
            "text": "my laptop is broken",
            "channel": "C1",
        },
    }
    body = json.dumps(payload).encode()
    response = http.post(
        f"/v1/channels/slack/events/{link_id}",
        headers=_slack_headers(SECRET, body),
        content=body,
    )
    assert response.status_code == 204
    tickets = http.get("/v1/tickets", headers=owner_headers).json()
    assert len(tickets) == 1
    assert tickets[0]["description"] == "my laptop is broken"


def test_replayed_event_id_is_processed_only_once(client, monkeypatch):
    http, _ = client
    identity = _bootstrap_owner(http)
    owner_headers = {
        "X-Tenant-ID": identity["tenant_id"],
        "X-User-ID": identity["admin_user_id"],
    }
    link_id = _link_workspace(http, owner_headers, monkeypatch)
    http.post(
        "/v1/channels/identity-links",
        headers=owner_headers,
        json={
            "channel": "slack",
            "provider_user_id": "U-owner",
            "user_id": identity["admin_user_id"],
        },
    )
    payload = {
        "type": "event_callback",
        "team_id": "T123",
        "event_id": "Ev-dup",
        "event": {
            "type": "message",
            "user": "U-owner",
            "text": "repeated ticket please",
            "channel": "C1",
        },
    }
    body = json.dumps(payload).encode()
    headers = _slack_headers(SECRET, body)
    first = http.post(
        f"/v1/channels/slack/events/{link_id}", headers=headers, content=body
    )
    second = http.post(
        f"/v1/channels/slack/events/{link_id}", headers=headers, content=body
    )
    assert first.status_code == 204
    assert second.status_code == 204
    tickets = http.get("/v1/tickets", headers=owner_headers).json()
    assert len(tickets) == 1


def test_bot_messages_are_acknowledged_but_never_processed(client, monkeypatch):
    """The Phase 8 loop-prevention proof: a bot-authored message must never
    itself trigger conversation handling."""
    http, _ = client
    identity = _bootstrap_owner(http)
    owner_headers = {
        "X-Tenant-ID": identity["tenant_id"],
        "X-User-ID": identity["admin_user_id"],
    }
    link_id = _link_workspace(http, owner_headers, monkeypatch)
    http.post(
        "/v1/channels/identity-links",
        headers=owner_headers,
        json={
            "channel": "slack",
            "provider_user_id": "U-owner",
            "user_id": identity["admin_user_id"],
        },
    )
    payload = {
        "type": "event_callback",
        "team_id": "T123",
        "event_id": "Ev-bot",
        "event": {
            "type": "message",
            "user": "U-owner",
            "text": "I am a bot loop",
            "channel": "C1",
            "bot_id": "B1",
        },
    }
    body = json.dumps(payload).encode()
    response = http.post(
        f"/v1/channels/slack/events/{link_id}",
        headers=_slack_headers(SECRET, body),
        content=body,
    )
    assert response.status_code == 204
    tickets = http.get("/v1/tickets", headers=owner_headers).json()
    assert tickets == []
