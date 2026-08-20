"""API-level tests for the Google Chat channel adapter: workspace/identity
link registration and POST /v1/channels/google-chat/events/{link_id},
proving the full identity -> conversation -> ticket pipeline runs against
a real, self-signed Google-Chat-shaped Bearer token -- not just the
pure-function unit tests in tests/test_channels_google_chat.py. Also
proves the synchronous-reply contract: unlike Slack, a successful call
returns the actual reply text in the HTTP response body.
"""

from __future__ import annotations

import json

import helpdesktool.api as api_module
from helpdesktool.channels.google_chat import (
    GOOGLE_CHAT_ISSUER,
    build_google_chat_verifier,
)
from tests.support import StaticKeyResolver, generate_test_keypair, mint_token

PROJECT_NUMBER = "123456789012"


def _install_fake_verifier(monkeypatch, public_key):
    def _fake_build_verifier(audience: str, **kwargs):
        return build_google_chat_verifier(
            audience, key_resolver=StaticKeyResolver(public_key)
        )

    monkeypatch.setattr(api_module, "build_google_chat_verifier", _fake_build_verifier)


def _bearer_headers(private_key, **claim_overrides) -> dict:
    kwargs = dict(
        issuer=GOOGLE_CHAT_ISSUER,
        audience=PROJECT_NUMBER,
        subject="chat@system.gserviceaccount.com",
    )
    kwargs.update(claim_overrides)
    token = mint_token(private_key, **kwargs)
    return {"Authorization": f"Bearer {token}"}


def _bootstrap_owner(http) -> dict:
    response = http.post(
        "/v1/tenants",
        headers={"X-Bootstrap-Token": "test-bootstrap-token"},
        json={"name": "Acme", "admin_email": "owner@example.com"},
    )
    assert response.status_code == 201, response.text
    return response.json()


def _link_workspace(http, owner_headers) -> str:
    created = http.post(
        "/v1/channels/workspace-links",
        headers=owner_headers,
        json={
            "channel": "google_chat",
            "workspace_id": PROJECT_NUMBER,
            "signing_secret_ref": "",
        },
    )
    assert created.status_code == 201, created.text
    return created.json()["id"]


def test_invalid_bearer_token_is_rejected(client, monkeypatch):
    http, _ = client
    _, public_key = generate_test_keypair()
    _install_fake_verifier(monkeypatch, public_key)
    identity = _bootstrap_owner(http)
    owner_headers = {
        "X-Tenant-ID": identity["tenant_id"],
        "X-User-ID": identity["admin_user_id"],
    }
    link_id = _link_workspace(http, owner_headers)
    payload = {"type": "ADDED_TO_SPACE"}
    response = http.post(
        f"/v1/channels/google-chat/events/{link_id}",
        headers={"Authorization": "Bearer not-a-real-token"},
        content=json.dumps(payload).encode(),
    )
    assert response.status_code == 401


def test_unknown_link_id_is_rejected(client):
    http, _ = client
    response = http.post(
        "/v1/channels/google-chat/events/00000000-0000-0000-0000-000000000000",
        headers={"Authorization": "Bearer whatever"},
        content=b"{}",
    )
    assert response.status_code == 404


def test_non_message_event_is_acknowledged_without_processing(client, monkeypatch):
    http, _ = client
    private_key, public_key = generate_test_keypair()
    _install_fake_verifier(monkeypatch, public_key)
    identity = _bootstrap_owner(http)
    owner_headers = {
        "X-Tenant-ID": identity["tenant_id"],
        "X-User-ID": identity["admin_user_id"],
    }
    link_id = _link_workspace(http, owner_headers)
    payload = {"type": "ADDED_TO_SPACE", "space": {"name": "spaces/AAAA"}}
    response = http.post(
        f"/v1/channels/google-chat/events/{link_id}",
        headers=_bearer_headers(private_key),
        content=json.dumps(payload).encode(),
    )
    assert response.status_code == 204


def test_message_from_an_unmapped_user_gets_a_synchronous_reply_but_no_ticket(
    client, monkeypatch
):
    http, _ = client
    private_key, public_key = generate_test_keypair()
    _install_fake_verifier(monkeypatch, public_key)
    identity = _bootstrap_owner(http)
    owner_headers = {
        "X-Tenant-ID": identity["tenant_id"],
        "X-User-ID": identity["admin_user_id"],
    }
    link_id = _link_workspace(http, owner_headers)
    payload = {
        "type": "MESSAGE",
        "space": {"name": "spaces/AAAA"},
        "message": {
            "name": "spaces/AAAA/messages/1",
            "text": "reset my password",
            "sender": {"name": "users/unmapped"},
        },
    }
    response = http.post(
        f"/v1/channels/google-chat/events/{link_id}",
        headers=_bearer_headers(private_key),
        content=json.dumps(payload).encode(),
    )
    assert response.status_code == 200
    assert "couldn't match" in response.json()["text"]
    tickets = http.get("/v1/tickets", headers=owner_headers).json()
    assert tickets == []


def test_message_from_a_mapped_user_creates_a_ticket_and_replies_synchronously(
    client, monkeypatch
):
    http, _ = client
    private_key, public_key = generate_test_keypair()
    _install_fake_verifier(monkeypatch, public_key)
    identity = _bootstrap_owner(http)
    owner_headers = {
        "X-Tenant-ID": identity["tenant_id"],
        "X-User-ID": identity["admin_user_id"],
    }
    link_id = _link_workspace(http, owner_headers)
    linked = http.post(
        "/v1/channels/identity-links",
        headers=owner_headers,
        json={
            "channel": "google_chat",
            "provider_user_id": "users/owner",
            "user_id": identity["admin_user_id"],
        },
    )
    assert linked.status_code == 201, linked.text

    payload = {
        "type": "MESSAGE",
        "space": {"name": "spaces/AAAA"},
        "message": {
            "name": "spaces/AAAA/messages/2",
            "text": "my laptop is broken",
            "sender": {"name": "users/owner"},
        },
    }
    response = http.post(
        f"/v1/channels/google-chat/events/{link_id}",
        headers=_bearer_headers(private_key),
        content=json.dumps(payload).encode(),
    )
    assert response.status_code == 200
    assert response.json()["text"]
    tickets = http.get("/v1/tickets", headers=owner_headers).json()
    assert len(tickets) == 1
    assert tickets[0]["description"] == "my laptop is broken"


def test_replayed_event_id_is_processed_only_once_and_returns_the_same_reply(
    client, monkeypatch
):
    http, _ = client
    private_key, public_key = generate_test_keypair()
    _install_fake_verifier(monkeypatch, public_key)
    identity = _bootstrap_owner(http)
    owner_headers = {
        "X-Tenant-ID": identity["tenant_id"],
        "X-User-ID": identity["admin_user_id"],
    }
    link_id = _link_workspace(http, owner_headers)
    http.post(
        "/v1/channels/identity-links",
        headers=owner_headers,
        json={
            "channel": "google_chat",
            "provider_user_id": "users/owner",
            "user_id": identity["admin_user_id"],
        },
    )
    payload = {
        "type": "MESSAGE",
        "space": {"name": "spaces/AAAA"},
        "message": {
            "name": "spaces/AAAA/messages/dup",
            "text": "repeated ticket please",
            "sender": {"name": "users/owner"},
        },
    }
    headers = _bearer_headers(private_key)
    first = http.post(
        f"/v1/channels/google-chat/events/{link_id}",
        headers=headers,
        content=json.dumps(payload).encode(),
    )
    second = http.post(
        f"/v1/channels/google-chat/events/{link_id}",
        headers=headers,
        content=json.dumps(payload).encode(),
    )
    assert first.status_code == 200
    assert second.status_code == 200
    assert first.json() == second.json()
    tickets = http.get("/v1/tickets", headers=owner_headers).json()
    assert len(tickets) == 1
