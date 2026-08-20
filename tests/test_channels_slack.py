"""Unit tests for helpdesktool.channels.slack: signature verification,
replay protection, secret resolution, and event parsing -- no live Slack
required, since these are pure functions over self-generated signatures
computed with the same documented algorithm Slack itself uses."""

from __future__ import annotations

import hashlib
import hmac
import time
from datetime import UTC, datetime

import pytest

from helpdesktool.channels import ChannelSigningError
from helpdesktool.channels.slack import (
    parse_slack_event,
    resolve_slack_signing_secret,
    verify_slack_signature,
)

SECRET = "test-signing-secret"


def _sign(secret: str, timestamp: str, body: bytes) -> str:
    basestring = b"v0:" + timestamp.encode() + b":" + body
    return "v0=" + hmac.new(secret.encode(), basestring, hashlib.sha256).hexdigest()


def test_valid_signature_is_accepted():
    body = b'{"type":"url_verification","challenge":"abc"}'
    timestamp = str(int(time.time()))
    signature = _sign(SECRET, timestamp, body)
    verify_slack_signature(SECRET, timestamp, body, signature)


def test_tampered_body_is_rejected():
    body = b'{"type":"url_verification","challenge":"abc"}'
    timestamp = str(int(time.time()))
    signature = _sign(SECRET, timestamp, body)
    with pytest.raises(ChannelSigningError, match="signature mismatch"):
        verify_slack_signature(SECRET, timestamp, b"tampered body", signature)


def test_wrong_secret_is_rejected():
    body = b'{"type":"url_verification"}'
    timestamp = str(int(time.time()))
    signature = _sign("a-different-secret", timestamp, body)
    with pytest.raises(ChannelSigningError, match="signature mismatch"):
        verify_slack_signature(SECRET, timestamp, body, signature)


def test_expired_timestamp_is_rejected():
    body = b'{"type":"url_verification"}'
    old_timestamp = str(int(time.time()) - 600)
    signature = _sign(SECRET, old_timestamp, body)
    with pytest.raises(ChannelSigningError, match="skew"):
        verify_slack_signature(SECRET, old_timestamp, body, signature)


def test_malformed_timestamp_is_rejected():
    with pytest.raises(ChannelSigningError, match="malformed"):
        verify_slack_signature(SECRET, "not-a-number", b"{}", "v0=whatever")


def test_replayed_but_still_fresh_signature_is_accepted_at_the_boundary():
    body = b'{"type":"url_verification"}'
    now = datetime(2026, 1, 1, tzinfo=UTC)
    timestamp = str(int(now.timestamp()) - 299)
    signature = _sign(SECRET, timestamp, body)
    verify_slack_signature(SECRET, timestamp, body, signature, now=now)


def test_resolve_signing_secret_rejects_non_env_reference():
    with pytest.raises(ChannelSigningError, match="unsupported"):
        resolve_slack_signing_secret({}, "literal-value")


def test_resolve_signing_secret_rejects_wrong_prefix():
    with pytest.raises(ChannelSigningError, match="prefix"):
        resolve_slack_signing_secret(
            {"HELPDESK_WEBHOOK_SECRET_N8N": "x"}, "env:HELPDESK_WEBHOOK_SECRET_N8N"
        )


def test_resolve_signing_secret_rejects_missing_value():
    with pytest.raises(ChannelSigningError, match="unavailable"):
        resolve_slack_signing_secret({}, "env:HELPDESK_SLACK_SIGNING_SECRET_ACME")


def test_resolve_signing_secret_returns_the_configured_value():
    value = resolve_slack_signing_secret(
        {"HELPDESK_SLACK_SIGNING_SECRET_ACME": "s3cr3t"},
        "env:HELPDESK_SLACK_SIGNING_SECRET_ACME",
    )
    assert value == "s3cr3t"


def _message_event(**overrides) -> dict:
    payload = {
        "type": "event_callback",
        "team_id": "T123",
        "event_id": "Ev123",
        "event": {
            "type": "message",
            "user": "U123",
            "text": "reset my password",
            "channel": "C123",
        },
    }
    payload.update(overrides)
    return payload


def test_parse_slack_event_extracts_a_message_event():
    envelope = parse_slack_event(_message_event())
    assert envelope is not None
    assert envelope.event_id == "Ev123"
    assert envelope.team_id == "T123"
    assert envelope.user_id == "U123"
    assert envelope.channel_id == "C123"
    assert envelope.text == "reset my password"


def test_parse_slack_event_ignores_bot_messages():
    payload = _message_event()
    payload["event"]["bot_id"] = "B999"
    assert parse_slack_event(payload) is None


def test_parse_slack_event_ignores_bot_message_subtype():
    payload = _message_event()
    payload["event"]["subtype"] = "bot_message"
    assert parse_slack_event(payload) is None


def test_parse_slack_event_ignores_non_message_events():
    payload = _message_event()
    payload["event"]["type"] = "reaction_added"
    assert parse_slack_event(payload) is None


def test_parse_slack_event_ignores_non_event_callback_types():
    assert parse_slack_event({"type": "url_verification"}) is None


def test_parse_slack_event_ignores_incomplete_events():
    payload = _message_event()
    del payload["event"]["text"]
    assert parse_slack_event(payload) is None
