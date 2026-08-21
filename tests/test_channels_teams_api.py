"""API-level tests for the Microsoft Teams channel adapter: workspace/
identity link registration and POST /v1/channels/teams/events/{link_id},
proving the full identity -> conversation -> ticket pipeline runs against
a real, self-signed Bot-Framework-shaped Bearer token -- not just the
pure-function unit tests in tests/test_channels_teams.py.
"""

from __future__ import annotations

import json

import helpdesktool.api as api_module
from helpdesktool.channels.teams import (
    BOT_FRAMEWORK_ISSUER,
    verify_teams_bot_framework_token,
)
from tests.support import StaticKeyResolver, generate_test_keypair, mint_token

APP_ID = "11111111-2222-3333-4444-555555555555"
TENANT_ID = "m365-tenant-1"
SERVICE_URL = "https://smba.trafficmanager.net/amer/"


def _install_fake_verifier(monkeypatch, public_key):
    real = verify_teams_bot_framework_token

    def _fake(*args, **kwargs):
        kwargs["key_resolver"] = StaticKeyResolver(public_key)
        return real(*args, **kwargs)

    monkeypatch.setattr(api_module, "verify_teams_bot_framework_token", _fake)


def _configure_bot_app_id(monkeypatch):
    monkeypatch.setenv("HELPDESK_TEAMS_BOT_APP_ID", APP_ID)
    api_module.get_settings.cache_clear()


def _bearer_headers(private_key, **claim_overrides) -> dict:
    kwargs: dict = dict(
        issuer=BOT_FRAMEWORK_ISSUER,
        audience=APP_ID,
        subject="bot-framework-connector",
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
            "channel": "teams",
            "workspace_id": TENANT_ID,
            "signing_secret_ref": "",
        },
    )
    assert created.status_code == 201, created.text
    return created.json()["id"]


def _activity(**overrides) -> dict:
    payload = {
        "type": "message",
        "id": "activity-1",
        "serviceUrl": SERVICE_URL,
        "text": "reset my Outlook password",
        "conversation": {"id": "conversation-1"},
        "from": {"id": "29:channel-user-1", "aadObjectId": "aad-owner"},
        "channelData": {"tenant": {"id": TENANT_ID}},
    }
    payload.update(overrides)
    return payload


def test_unconfigured_bot_app_id_fails_closed(client, monkeypatch):
    http, _ = client
    identity = _bootstrap_owner(http)
    owner_headers = {
        "X-Tenant-ID": identity["tenant_id"],
        "X-User-ID": identity["admin_user_id"],
    }
    link_id = _link_workspace(http, owner_headers)
    monkeypatch.delenv("HELPDESK_TEAMS_BOT_APP_ID", raising=False)
    api_module.get_settings.cache_clear()
    payload = _activity()
    response = http.post(
        f"/v1/channels/teams/events/{link_id}",
        headers={"Authorization": "Bearer whatever"},
        content=json.dumps(payload).encode(),
    )
    assert response.status_code == 503


def test_invalid_bearer_token_is_rejected(client, monkeypatch):
    http, _ = client
    _configure_bot_app_id(monkeypatch)
    _, public_key = generate_test_keypair()
    _install_fake_verifier(monkeypatch, public_key)
    identity = _bootstrap_owner(http)
    owner_headers = {
        "X-Tenant-ID": identity["tenant_id"],
        "X-User-ID": identity["admin_user_id"],
    }
    link_id = _link_workspace(http, owner_headers)
    payload = _activity()
    response = http.post(
        f"/v1/channels/teams/events/{link_id}",
        headers={"Authorization": "Bearer not-a-real-token"},
        content=json.dumps(payload).encode(),
    )
    assert response.status_code == 401


def test_unknown_link_id_is_rejected(client, monkeypatch):
    http, _ = client
    _configure_bot_app_id(monkeypatch)
    response = http.post(
        "/v1/channels/teams/events/00000000-0000-0000-0000-000000000000",
        headers={"Authorization": "Bearer whatever"},
        content=b"{}",
    )
    assert response.status_code == 404


def test_event_from_an_unmapped_workspace_is_rejected(client, monkeypatch):
    http, _ = client
    _configure_bot_app_id(monkeypatch)
    private_key, public_key = generate_test_keypair()
    _install_fake_verifier(monkeypatch, public_key)
    identity = _bootstrap_owner(http)
    owner_headers = {
        "X-Tenant-ID": identity["tenant_id"],
        "X-User-ID": identity["admin_user_id"],
    }
    link_id = _link_workspace(http, owner_headers)
    payload = _activity(channelData={"tenant": {"id": "a-different-tenant"}})
    response = http.post(
        f"/v1/channels/teams/events/{link_id}",
        headers=_bearer_headers(private_key),
        content=json.dumps(payload).encode(),
    )
    assert response.status_code == 401


def test_non_message_activity_is_acknowledged_without_processing(client, monkeypatch):
    http, _ = client
    _configure_bot_app_id(monkeypatch)
    private_key, public_key = generate_test_keypair()
    _install_fake_verifier(monkeypatch, public_key)
    identity = _bootstrap_owner(http)
    owner_headers = {
        "X-Tenant-ID": identity["tenant_id"],
        "X-User-ID": identity["admin_user_id"],
    }
    link_id = _link_workspace(http, owner_headers)
    payload = _activity(type="conversationUpdate")
    response = http.post(
        f"/v1/channels/teams/events/{link_id}",
        headers=_bearer_headers(private_key),
        content=json.dumps(payload).encode(),
    )
    assert response.status_code == 204


def test_message_from_an_unmapped_teams_user_is_acknowledged_but_not_processed(
    client, monkeypatch
):
    http, _ = client
    _configure_bot_app_id(monkeypatch)
    private_key, public_key = generate_test_keypair()
    _install_fake_verifier(monkeypatch, public_key)
    identity = _bootstrap_owner(http)
    owner_headers = {
        "X-Tenant-ID": identity["tenant_id"],
        "X-User-ID": identity["admin_user_id"],
    }
    link_id = _link_workspace(http, owner_headers)
    payload = _activity(
        **{"from": {"id": "29:unmapped", "aadObjectId": "aad-unmapped"}}
    )
    response = http.post(
        f"/v1/channels/teams/events/{link_id}",
        headers=_bearer_headers(private_key),
        content=json.dumps(payload).encode(),
    )
    assert response.status_code == 204
    tickets = http.get("/v1/tickets", headers=owner_headers).json()
    assert tickets == []


def test_message_from_a_mapped_teams_user_creates_a_ticket(client, monkeypatch):
    http, _ = client
    _configure_bot_app_id(monkeypatch)
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
            "channel": "teams",
            "provider_user_id": "aad-owner",
            "user_id": identity["admin_user_id"],
        },
    )
    assert linked.status_code == 201, linked.text

    payload = _activity(text="my laptop is broken")
    response = http.post(
        f"/v1/channels/teams/events/{link_id}",
        headers=_bearer_headers(private_key),
        content=json.dumps(payload).encode(),
    )
    assert response.status_code == 204
    tickets = http.get("/v1/tickets", headers=owner_headers).json()
    assert len(tickets) == 1
    assert tickets[0]["description"] == "my laptop is broken"


def test_replayed_activity_id_is_processed_only_once(client, monkeypatch):
    http, _ = client
    _configure_bot_app_id(monkeypatch)
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
            "channel": "teams",
            "provider_user_id": "aad-owner",
            "user_id": identity["admin_user_id"],
        },
    )
    payload = _activity(id="activity-dup", text="repeated ticket please")
    headers = _bearer_headers(private_key)
    first = http.post(
        f"/v1/channels/teams/events/{link_id}",
        headers=headers,
        content=json.dumps(payload).encode(),
    )
    second = http.post(
        f"/v1/channels/teams/events/{link_id}",
        headers=headers,
        content=json.dumps(payload).encode(),
    )
    assert first.status_code == 204
    assert second.status_code == 204
    tickets = http.get("/v1/tickets", headers=owner_headers).json()
    assert len(tickets) == 1
