"""Explicitly development-only signed browser sessions."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
from datetime import UTC, datetime, timedelta
from typing import Any


class InvalidDevelopmentSession(ValueError):
    """Raised when a development session is malformed, invalid, or expired."""


def issue_session(user_id: str, tenant_id: str, secret: str, minutes: int) -> str:
    claims = {
        "exp": int((datetime.now(UTC) + timedelta(minutes=minutes)).timestamp()),
        "sub": user_id,
        "tenant": tenant_id,
    }
    payload = base64.urlsafe_b64encode(
        json.dumps(claims, separators=(",", ":"), sort_keys=True).encode()
    ).rstrip(b"=")
    signature = hmac.new(secret.encode(), payload, hashlib.sha256).digest()
    encoded_signature = base64.urlsafe_b64encode(signature).rstrip(b"=")
    return f"{payload.decode()}.{encoded_signature.decode()}"


def verify_session(token: str, secret: str) -> dict[str, Any]:
    try:
        payload_text, signature_text = token.split(".", 1)
        payload = payload_text.encode()
        supplied = _decode(signature_text)
        expected = hmac.new(secret.encode(), payload, hashlib.sha256).digest()
        if not hmac.compare_digest(expected, supplied):
            raise InvalidDevelopmentSession("invalid development session")
        claims = json.loads(_decode(payload_text))
        if not isinstance(claims, dict):
            raise InvalidDevelopmentSession("invalid development session")
        if int(claims["exp"]) <= int(datetime.now(UTC).timestamp()):
            raise InvalidDevelopmentSession("development session expired")
        if not isinstance(claims.get("sub"), str) or not isinstance(
            claims.get("tenant"), str
        ):
            raise InvalidDevelopmentSession("invalid development session")
        return claims
    except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
        if isinstance(exc, InvalidDevelopmentSession):
            raise
        raise InvalidDevelopmentSession("invalid development session") from exc


def _decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
