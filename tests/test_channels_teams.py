"""Unit tests for helpdesktool.channels.teams: Bot Framework Bearer-token
verification, Activity parsing, and the (BLOCKED-EXTERNAL) reply sender --
no live Bot Framework/Teams app registration required, since verification
uses the same self-generated-RSA-keypair pattern that proved
helpdesktool.oidc/channels.google_chat, standing in for the real
published JWKS.
"""

from __future__ import annotations

import pytest

from helpdesktool.channels import ChannelSigningError
from helpdesktool.channels.teams import (
    BOT_FRAMEWORK_ISSUER,
    NullTeamsReplySender,
    parse_teams_activity,
    verify_teams_bot_framework_token,
)
from tests.support import StaticKeyResolver, generate_test_keypair, mint_token

APP_ID = (
    "11111111-2222-3333-4444-555555555555"  # stands in for a bot's Microsoft App ID
)
SERVICE_URL = "https://smba.trafficmanager.net/amer/"


@pytest.fixture(scope="module")
def keypair():
    return generate_test_keypair()


def _token(private_key, **overrides) -> str:
    kwargs: dict = dict(
        issuer=BOT_FRAMEWORK_ISSUER,
        audience=APP_ID,
        subject="bot-framework-connector",
    )
    kwargs.update(overrides)
    return mint_token(private_key, **kwargs)


def test_valid_bearer_token_is_accepted(keypair):
    private_key, public_key = keypair
    token = _token(private_key, serviceurl=SERVICE_URL)
    verify_teams_bot_framework_token(
        f"Bearer {token}",
        app_id=APP_ID,
        activity_service_url=SERVICE_URL,
        key_resolver=StaticKeyResolver(public_key),
    )


def test_valid_token_with_no_serviceurl_claim_is_still_accepted(keypair):
    """The serviceUrl check is conditional -- a Bot Framework token that
    doesn't carry the claim at all must not be rejected just for that,
    since this codebase doesn't assert every token always includes it."""
    private_key, public_key = keypair
    token = _token(private_key)
    verify_teams_bot_framework_token(
        f"Bearer {token}",
        app_id=APP_ID,
        activity_service_url=SERVICE_URL,
        key_resolver=StaticKeyResolver(public_key),
    )


def test_missing_bearer_prefix_is_rejected(keypair):
    _, public_key = keypair
    with pytest.raises(ChannelSigningError, match="missing bearer token"):
        verify_teams_bot_framework_token(
            "not-a-bearer-header",
            app_id=APP_ID,
            activity_service_url=SERVICE_URL,
            key_resolver=StaticKeyResolver(public_key),
        )


def test_empty_bearer_token_is_rejected(keypair):
    _, public_key = keypair
    with pytest.raises(ChannelSigningError, match="missing bearer token"):
        verify_teams_bot_framework_token(
            "Bearer ",
            app_id=APP_ID,
            activity_service_url=SERVICE_URL,
            key_resolver=StaticKeyResolver(public_key),
        )


def test_wrong_audience_is_rejected(keypair):
    private_key, public_key = keypair
    token = _token(private_key, audience="a-different-app-id")
    with pytest.raises(ChannelSigningError):
        verify_teams_bot_framework_token(
            f"Bearer {token}",
            app_id=APP_ID,
            activity_service_url=SERVICE_URL,
            key_resolver=StaticKeyResolver(public_key),
        )


def test_wrong_issuer_is_rejected(keypair):
    private_key, public_key = keypair
    token = _token(private_key, issuer="https://not-api.botframework.com")
    with pytest.raises(ChannelSigningError):
        verify_teams_bot_framework_token(
            f"Bearer {token}",
            app_id=APP_ID,
            activity_service_url=SERVICE_URL,
            key_resolver=StaticKeyResolver(public_key),
        )


def test_token_signed_by_a_different_key_is_rejected(keypair):
    _, public_key = keypair
    other_private_key, _ = generate_test_keypair()
    token = _token(other_private_key)
    with pytest.raises(ChannelSigningError):
        verify_teams_bot_framework_token(
            f"Bearer {token}",
            app_id=APP_ID,
            activity_service_url=SERVICE_URL,
            key_resolver=StaticKeyResolver(public_key),
        )


def test_mismatched_serviceurl_claim_is_rejected(keypair):
    private_key, public_key = keypair
    token = _token(private_key, serviceurl="https://attacker.example/")
    with pytest.raises(ChannelSigningError, match="serviceUrl"):
        verify_teams_bot_framework_token(
            f"Bearer {token}",
            app_id=APP_ID,
            activity_service_url=SERVICE_URL,
            key_resolver=StaticKeyResolver(public_key),
        )


def test_matching_serviceurl_with_trailing_slash_difference_is_accepted(keypair):
    private_key, public_key = keypair
    token = _token(private_key, serviceurl=SERVICE_URL.rstrip("/"))
    verify_teams_bot_framework_token(
        f"Bearer {token}",
        app_id=APP_ID,
        activity_service_url=SERVICE_URL,
        key_resolver=StaticKeyResolver(public_key),
    )


def _message_activity(**overrides) -> dict:
    payload = {
        "type": "message",
        "id": "activity-1",
        "serviceUrl": SERVICE_URL,
        "text": "reset my password",
        "conversation": {"id": "conversation-1"},
        "from": {"id": "29:channel-user-1", "aadObjectId": "aad-object-1"},
        "channelData": {"tenant": {"id": "m365-tenant-1"}},
    }
    payload.update(overrides)
    return payload


def test_parse_teams_activity_extracts_a_message_activity():
    envelope = parse_teams_activity(_message_activity())
    assert envelope is not None
    assert envelope.activity_id == "activity-1"
    assert envelope.tenant_id == "m365-tenant-1"
    assert envelope.user_id == "aad-object-1"
    assert envelope.conversation_id == "conversation-1"
    assert envelope.text == "reset my password"
    assert envelope.service_url == SERVICE_URL


def test_parse_teams_activity_falls_back_to_channel_user_id_without_aad_object_id():
    payload = _message_activity(**{"from": {"id": "29:channel-user-1"}})
    envelope = parse_teams_activity(payload)
    assert envelope is not None
    assert envelope.user_id == "29:channel-user-1"


def test_parse_teams_activity_ignores_non_message_types():
    payload = _message_activity(type="conversationUpdate")
    assert parse_teams_activity(payload) is None


def test_parse_teams_activity_ignores_incomplete_activities():
    payload = _message_activity()
    del payload["text"]
    assert parse_teams_activity(payload) is None


def test_parse_teams_activity_requires_a_tenant_id():
    payload = _message_activity(channelData={})
    assert parse_teams_activity(payload) is None


def test_null_teams_reply_sender_does_not_raise():
    NullTeamsReplySender().send(
        service_url=SERVICE_URL,
        conversation_id="conversation-1",
        activity_id="activity-1",
        text="hello",
    )
