"""Unit tests for OIDC token verification.

No network access and no real identity provider: a local RSA key pair signs
test tokens, and a fake key resolver (matching PyJWKClient's interface)
injects the public key directly, exercising the exact verification path
production uses without depending on any provider being reachable.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import jwt
import pytest

from helpdesktool.oidc import InvalidIdentityToken, OIDCVerifier
from tests.support import StaticKeyResolver, generate_test_keypair, mint_token

ISSUER = "https://idp.example.com/"
AUDIENCE = "https://api.example.com"
JWKS_URL = "https://idp.example.com/.well-known/jwks.json"


@pytest.fixture(scope="module")
def keypair():
    return generate_test_keypair()


@pytest.fixture
def verifier(keypair):
    _, public_key = keypair
    return OIDCVerifier(
        ISSUER, AUDIENCE, JWKS_URL, key_resolver=StaticKeyResolver(public_key)
    )


def _mint(
    private_key,
    *,
    iss: str = ISSUER,
    aud: str = AUDIENCE,
    sub: str = "user-subject-1",
    email: str | None = "person@example.com",
    iat: datetime | None = None,
    exp: datetime | None = None,
) -> str:
    return mint_token(
        private_key,
        issuer=iss,
        audience=aud,
        subject=sub,
        email=email,
        issued_at=iat,
        expires_at=exp,
    )


def test_valid_token_is_accepted(keypair, verifier):
    private_key, _ = keypair
    identity = verifier.verify(_mint(private_key))
    assert identity.subject == "user-subject-1"
    assert identity.issuer == ISSUER
    assert identity.email == "person@example.com"


def test_token_without_email_claim_has_no_email(keypair, verifier):
    private_key, _ = keypair
    token = mint_token(
        private_key, issuer=ISSUER, audience=AUDIENCE, subject="user-subject-1"
    )
    identity = verifier.verify(token)
    assert identity.email is None


def test_expired_token_is_rejected(keypair, verifier):
    private_key, _ = keypair
    now = datetime.now(UTC)
    token = _mint(
        private_key, iat=now - timedelta(hours=2), exp=now - timedelta(hours=1)
    )
    with pytest.raises(InvalidIdentityToken):
        verifier.verify(token)


def test_wrong_audience_is_rejected(keypair, verifier):
    private_key, _ = keypair
    token = _mint(private_key, aud="https://someone-elses-api.example.com")
    with pytest.raises(InvalidIdentityToken):
        verifier.verify(token)


def test_wrong_issuer_is_rejected(keypair, verifier):
    private_key, _ = keypair
    token = _mint(private_key, iss="https://a-different-idp.example.com/")
    with pytest.raises(InvalidIdentityToken):
        verifier.verify(token)


def test_missing_subject_is_rejected(keypair, verifier):
    private_key, _ = keypair
    now = datetime.now(UTC)
    claims = {
        "iss": ISSUER,
        "aud": AUDIENCE,
        "iat": now,
        "exp": now + timedelta(minutes=5),
    }
    token = jwt.encode(claims, private_key, algorithm="RS256")
    with pytest.raises(InvalidIdentityToken):
        verifier.verify(token)


def test_tampered_signature_is_rejected(keypair, verifier):
    private_key, _ = keypair
    token = _mint(private_key)
    header, payload, signature = token.split(".")
    tampered_signature = ("A" if signature[0] != "A" else "B") + signature[1:]
    tampered = f"{header}.{payload}.{tampered_signature}"
    with pytest.raises(InvalidIdentityToken):
        verifier.verify(tampered)


def test_token_signed_by_a_different_key_is_rejected(keypair):
    private_key, _ = keypair
    other_private_key, _ = generate_test_keypair()
    token = _mint(other_private_key)
    _, public_key = keypair
    verifier = OIDCVerifier(
        ISSUER, AUDIENCE, JWKS_URL, key_resolver=StaticKeyResolver(public_key)
    )
    with pytest.raises(InvalidIdentityToken):
        verifier.verify(token)


def test_construction_requires_issuer_audience_and_jwks_url():
    with pytest.raises(ValueError):
        OIDCVerifier("", AUDIENCE, JWKS_URL)
    with pytest.raises(ValueError):
        OIDCVerifier(ISSUER, "", JWKS_URL)
    with pytest.raises(ValueError):
        OIDCVerifier(ISSUER, AUDIENCE, "")
