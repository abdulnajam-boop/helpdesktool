import hashlib
import hmac
import json
import socket

import pytest

from helpdesktool.integrations import (
    EnvironmentSecretsProvider,
    SignedWebhookProvider,
    canonical_payload,
    validate_webhook_url,
)


def test_secret_provider_restricts_namespace_and_missing_values():
    provider = EnvironmentSecretsProvider({"HELPDESK_WEBHOOK_SECRET_N8N": "value"})
    assert provider.get("env:HELPDESK_WEBHOOK_SECRET_N8N") == "value"
    with pytest.raises(ValueError):
        provider.get("env:AWS_SECRET_ACCESS_KEY")
    with pytest.raises(KeyError):
        provider.get("env:HELPDESK_WEBHOOK_SECRET_MISSING")


def test_webhook_url_rejects_credentials_private_network_and_http(monkeypatch):
    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        lambda *args, **kwargs: [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.0.0.10", 443))
        ],
    )
    with pytest.raises(ValueError, match="public IP"):
        validate_webhook_url("https://n8n.internal/webhook")
    with pytest.raises(ValueError, match="HTTPS"):
        validate_webhook_url("http://example.com/hook")
    with pytest.raises(ValueError, match="prohibited"):
        validate_webhook_url("https://user:pass@example.com/hook")


def test_webhook_url_accepts_public_https(monkeypatch):
    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        lambda *args, **kwargs: [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 443))
        ],
    )
    validate_webhook_url("https://example.com/n8n/webhook")


def test_signed_webhook_uses_canonical_payload_and_hmac(monkeypatch):
    captured = {}

    class Response:
        status = 202

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return None

        def read(self, limit):
            return b"accepted"

    def fake_urlopen(request, timeout):
        captured["request"] = request
        captured["timeout"] = timeout
        return Response()

    monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)
    payload = canonical_payload({"type": "ticket.created", "id": "event-1"})
    response = SignedWebhookProvider().deliver(
        "https://example.com/hook", "event-1", payload, "signing-secret", 4.0
    )
    expected = hmac.new(b"signing-secret", payload, hashlib.sha256).hexdigest()
    assert response.status_code == 202
    assert captured["timeout"] == 4.0
    assert (
        captured["request"].get_header("X-helpdesk-signature-256")
        == f"sha256={expected}"
    )
    assert json.loads(captured["request"].data)["type"] == "ticket.created"
