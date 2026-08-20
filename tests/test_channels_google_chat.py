"""Unit tests for helpdesktool.channels.google_chat: Bearer ID-token
verification, event parsing, and the synchronous reply body -- no live
Google Chat required, since verification reuses the exact same
OIDCVerifier code path tests/test_oidc.py already exercises with a
self-generated RSA key pair standing in for Google's JWKS.
"""

from __future__ import annotations

import pytest

from helpdesktool.channels import ChannelSigningError
from helpdesktool.channels.google_chat import (
    GOOGLE_CHAT_ISSUER,
    build_google_chat_reply,
    build_google_chat_verifier,
    parse_google_chat_event,
    verify_google_chat_request,
)
from tests.support import StaticKeyResolver, generate_test_keypair, mint_token

AUDIENCE = "123456789012"  # stands in for a Google Cloud project number


@pytest.fixture(scope="module")
def keypair():
    return generate_test_keypair()


def _verifier(public_key):
    return build_google_chat_verifier(
        AUDIENCE, key_resolver=StaticKeyResolver(public_key)
    )


def _token(private_key, **overrides) -> str:
    kwargs = dict(
        issuer=GOOGLE_CHAT_ISSUER,
        audience=AUDIENCE,
        subject="chat@system.gserviceaccount.com",
    )
    kwargs.update(overrides)
    return mint_token(private_key, **kwargs)


def test_valid_bearer_token_is_accepted(keypair):
    private_key, public_key = keypair
    token = _token(private_key)
    verify_google_chat_request(_verifier(public_key), f"Bearer {token}")


def test_missing_bearer_prefix_is_rejected(keypair):
    _, public_key = keypair
    with pytest.raises(ChannelSigningError, match="missing bearer token"):
        verify_google_chat_request(_verifier(public_key), "not-a-bearer-header")


def test_empty_bearer_token_is_rejected(keypair):
    _, public_key = keypair
    with pytest.raises(ChannelSigningError, match="missing bearer token"):
        verify_google_chat_request(_verifier(public_key), "Bearer ")


def test_wrong_audience_is_rejected(keypair):
    private_key, public_key = keypair
    token = _token(private_key, audience="a-different-project")
    with pytest.raises(ChannelSigningError):
        verify_google_chat_request(_verifier(public_key), f"Bearer {token}")


def test_wrong_issuer_is_rejected(keypair):
    private_key, public_key = keypair
    token = _token(private_key, issuer="not-chat@system.gserviceaccount.com")
    with pytest.raises(ChannelSigningError):
        verify_google_chat_request(_verifier(public_key), f"Bearer {token}")


def test_token_signed_by_a_different_key_is_rejected(keypair):
    _, public_key = keypair
    other_private_key, _ = generate_test_keypair()
    token = _token(other_private_key)
    with pytest.raises(ChannelSigningError):
        verify_google_chat_request(_verifier(public_key), f"Bearer {token}")


def _message_event(**overrides) -> dict:
    payload = {
        "type": "MESSAGE",
        "space": {"name": "spaces/AAAA"},
        "message": {
            "name": "spaces/AAAA/messages/BBBB",
            "text": "reset my password",
            "sender": {"name": "users/12345"},
        },
    }
    payload.update(overrides)
    return payload


def test_parse_google_chat_event_extracts_a_message_event():
    envelope = parse_google_chat_event(_message_event())
    assert envelope is not None
    assert envelope.event_id == "spaces/AAAA/messages/BBBB"
    assert envelope.space_name == "spaces/AAAA"
    assert envelope.user_name == "users/12345"
    assert envelope.text == "reset my password"


def test_parse_google_chat_event_ignores_non_message_types():
    payload = _message_event(type="ADDED_TO_SPACE")
    assert parse_google_chat_event(payload) is None


def test_parse_google_chat_event_ignores_incomplete_events():
    payload = _message_event()
    del payload["message"]["text"]
    assert parse_google_chat_event(payload) is None


def test_build_google_chat_reply_shape():
    assert build_google_chat_reply("hello") == {"text": "hello"}
