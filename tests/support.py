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


TEST_JOB_SIGNING_SEED = "test-job-signing-seed"


def agent_signing_public_key_pem(version: int = 1) -> str:
    from helpdesktool.job_signing import public_key_pem

    return public_key_pem(TEST_JOB_SIGNING_SEED, version)


def agent_signing_public_keys(*versions: int) -> dict[int, str]:
    """The ``AgentConfig.signing_public_keys`` shape a test agent needs --
    defaults to just version 1 if none are given."""
    return {v: agent_signing_public_key_pem(v) for v in (versions or (1,))}


def build_signed_job_envelope(
    *,
    action_id: str = "action-1",
    device_id: str = "device-1",
    tenant_id: str = "tenant-1",
    skill_id: str = "service.restart",
    skill_version: int = 1,
    parameters: dict[str, Any] | None = None,
    device_os: str = "linux",
    attempt: int = 1,
    claim_token: str = "claim-token",
    issued_at: datetime | None = None,
    expires_at: datetime | None = None,
    nonce: str = "test-nonce",
    key_version: int = 1,
    seed_secret: str = TEST_JOB_SIGNING_SEED,
) -> dict[str, Any]:
    """Builds a genuinely-signed job envelope for agent-side unit tests, so
    those tests exercise the real ``agent_common.signing.verify_envelope``
    path rather than a hand-rolled stand-in.
    """
    from helpdesktool.job_signing import sign_envelope

    now = datetime.now(UTC)
    envelope: dict[str, Any] = {
        "job_id": f"{action_id}:{attempt}",
        "action_id": action_id,
        "device_id": device_id,
        "tenant_id": tenant_id,
        "skill_id": skill_id,
        "skill_version": skill_version,
        "parameters": parameters or {},
        "device_os": device_os,
        "issued_at": (issued_at or now).isoformat(),
        "expires_at": (expires_at or now + timedelta(minutes=1)).isoformat(),
        "nonce": nonce,
        "key_version": key_version,
    }
    envelope["signature"] = sign_envelope(envelope, seed_secret, key_version)
    envelope["claim_token"] = claim_token
    envelope["attempt"] = attempt
    envelope["lease_expires_at"] = envelope["expires_at"]
    return envelope


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
