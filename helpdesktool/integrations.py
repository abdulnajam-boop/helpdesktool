"""Provider-neutral integration contracts and signed webhook delivery."""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
import json
import socket
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Mapping, Protocol


class SecretsProvider(Protocol):
    def get(self, reference: str) -> str: ...


class EnvironmentSecretsProvider:
    def __init__(self, environment: Mapping[str, str]) -> None:
        self.environment = environment

    def get(self, reference: str) -> str:
        if not reference.startswith("env:"):
            raise ValueError("unsupported secret reference")
        name = reference.removeprefix("env:")
        if not name.startswith("HELPDESK_WEBHOOK_SECRET_"):
            raise ValueError("webhook secret environment variable has invalid prefix")
        value = self.environment.get(name)
        if not value:
            raise KeyError("webhook signing secret is unavailable")
        return value


def validate_webhook_url(url: str, *, allow_http: bool = False) -> None:
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme not in ({"https", "http"} if allow_http else {"https"}):
        raise ValueError("webhook URL must use HTTPS")
    if not parsed.hostname or parsed.username or parsed.password or parsed.fragment:
        raise ValueError("webhook URL contains prohibited components")
    try:
        addresses = socket.getaddrinfo(
            parsed.hostname, parsed.port or 443, type=socket.SOCK_STREAM
        )
    except socket.gaierror as exc:
        raise ValueError("webhook hostname cannot be resolved") from exc
    for address in addresses:
        ip = ipaddress.ip_address(address[4][0])
        if not ip.is_global:
            raise ValueError("webhook destination must resolve to public IP addresses")


@dataclass(frozen=True, slots=True)
class DeliveryResponse:
    status_code: int
    body: str


class IntegrationProvider(Protocol):
    def deliver(
        self,
        url: str,
        event_id: str,
        payload: bytes,
        secret: str,
        timeout_seconds: float,
    ) -> DeliveryResponse: ...


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Refuses every HTTP redirect rather than following it.

    ``validate_webhook_url`` only ever checks the URL a subscription is
    registered/re-validated with -- the default ``urlopen`` opener follows
    3xx redirects to *any* destination the remote server names, completely
    bypassing that check. A webhook target an attacker controls (or a
    legitimate one later compromised) could 302 a delivery to
    ``http://169.254.169.254/...`` (cloud instance metadata) or
    ``http://localhost:6379/`` and this code would happily follow it with
    no further validation. Returning ``None`` here tells urllib not to
    follow the redirect; the 3xx response is surfaced to the caller as an
    ordinary (non-2xx) delivery outcome instead, same as any other HTTP
    error status.
    """

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[no-untyped-def]
        return None


_NO_REDIRECT_OPENER = urllib.request.build_opener(_NoRedirectHandler)


class SignedWebhookProvider:
    """Generic webhook adapter compatible with n8n and other HTTP consumers."""

    def deliver(
        self,
        url: str,
        event_id: str,
        payload: bytes,
        secret: str,
        timeout_seconds: float,
    ) -> DeliveryResponse:
        signature = hmac.new(secret.encode(), payload, hashlib.sha256).hexdigest()
        request = urllib.request.Request(
            url,
            data=payload,
            method="POST",
            headers={
                "Content-Type": "application/json",
                "User-Agent": "helpdesktool-webhook/1",
                "X-Helpdesk-Event-ID": event_id,
                "X-Helpdesk-Signature-256": f"sha256={signature}",
            },
        )
        try:
            with _NO_REDIRECT_OPENER.open(request, timeout=timeout_seconds) as response:
                return DeliveryResponse(
                    response.status, response.read(4096).decode(errors="replace")
                )
        except urllib.error.HTTPError as exc:
            return DeliveryResponse(exc.code, exc.read(4096).decode(errors="replace"))


def canonical_payload(envelope: Mapping[str, object]) -> bytes:
    return json.dumps(
        envelope, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode()
