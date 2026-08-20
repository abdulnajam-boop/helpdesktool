import hashlib
import hmac
import ipaddress
import json
import socket
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

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


@pytest.mark.parametrize(
    "attacker_ip",
    [
        "127.0.0.1",  # loopback
        "169.254.169.254",  # cloud instance metadata endpoint
        "169.254.0.1",  # link-local, general
        "10.0.0.5",  # RFC1918 private
        "172.16.0.5",  # RFC1918 private
        "192.168.1.5",  # RFC1918 private
        "0.0.0.0",  # unspecified
    ],
)
def test_webhook_url_rejects_every_non_global_ip_class(monkeypatch, attacker_ip):
    assert not ipaddress.ip_address(attacker_ip).is_global  # sanity-check the fixture
    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        lambda *args, **kwargs: [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", (attacker_ip, 443))
        ],
    )
    with pytest.raises(ValueError, match="public IP"):
        validate_webhook_url("https://attacker-controlled.example/hook")


def test_webhook_delivery_refuses_to_follow_a_redirect_to_a_private_address():
    """The real SSRF bypass this closes: validate_webhook_url only ever
    checks the URL a subscription is registered with -- a webhook target
    that returns a 3xx redirect could otherwise point the actual delivery
    request anywhere (cloud metadata, localhost, an internal service) with
    zero re-validation, since the default urllib opener follows redirects
    transparently. Uses a real local HTTP server, not a mock, so this
    proves the actual network behavior rather than an assumption about it.
    """

    class RedirectingHandler(BaseHTTPRequestHandler):
        def do_POST(self):  # noqa: N802 - stdlib method name
            self.send_response(302)
            self.send_header(
                "Location", "http://169.254.169.254/latest/meta-data/secret"
            )
            self.end_headers()

        def log_message(self, *args):  # silence test output
            pass

    server = HTTPServer(("127.0.0.1", 0), RedirectingHandler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        result = SignedWebhookProvider().deliver(
            f"http://127.0.0.1:{port}/hook", "event-1", b"{}", "secret", 3.0
        )
        # The redirect must be surfaced as-is (a 302 "delivery"), never
        # silently followed to the attacker-chosen Location.
        assert result.status_code == 302
    finally:
        server.shutdown()
        thread.join(timeout=5)


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

    def fake_open(request, timeout):
        captured["request"] = request
        captured["timeout"] = timeout
        return Response()

    # SignedWebhookProvider deliberately uses its own no-redirect opener
    # rather than the module-level urlopen (see _NoRedirectHandler's
    # docstring) -- patch that opener's .open, matching what the code
    # actually calls.
    monkeypatch.setattr("helpdesktool.integrations._NO_REDIRECT_OPENER.open", fake_open)
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
