"""Shared test doubles and helpers, used by more than one test module."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

import jwt
from cryptography.hazmat.primitives.asymmetric import rsa


@dataclass(frozen=True)
class StaticSigningKey:
    key: object


class StaticKeyResolver:
    """Test double for PyJWKClient: always returns the same fixed public key."""

    def __init__(self, key: object) -> None:
        self._key = key

    def get_signing_key_from_jwt(self, token: str) -> StaticSigningKey:
        return StaticSigningKey(self._key)


def generate_test_keypair() -> tuple[Any, Any]:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return private_key, private_key.public_key()


def mint_token(
    private_key: Any,
    *,
    issuer: str,
    audience: str,
    subject: str,
    email: str | None = None,
    ttl_minutes: int = 5,
    issued_at: datetime | None = None,
    expires_at: datetime | None = None,
    **extra_claims: Any,
) -> str:
    now = datetime.now(UTC)
    claims: dict[str, Any] = {
        "iss": issuer,
        "aud": audience,
        "sub": subject,
        "iat": issued_at or now,
        "exp": expires_at or (now + timedelta(minutes=ttl_minutes)),
        **extra_claims,
    }
    if email is not None:
        claims["email"] = email
    return jwt.encode(claims, private_key, algorithm="RS256")
