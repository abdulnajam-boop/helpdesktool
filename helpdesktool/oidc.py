"""Provider-neutral OpenID Connect access-token verification.

This module knows nothing about any specific identity provider. It works
with any standards-compliant OIDC provider (Auth0, Okta, Keycloak, AWS
Cognito, Authentik, Google, a self-hosted one, ...) that publishes a JWKS
endpoint and issues RS256/ES256-signed JWT access tokens with standard
``iss``/``aud``/``exp``/``sub`` claims. Swapping providers is a configuration
change (issuer, audience, JWKS URL), never a code change.

Deliberately not included here: any notion of tenant_id or role. Those are
resolved by ``helpdesktool.auth`` from this module's verified, trustworthy
output (the token's cryptographically-checked subject/email), never from
anything the caller supplies directly — see the module docstring there.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Protocol

import jwt
from jwt import PyJWKClient


class InvalidIdentityToken(ValueError):
    """Raised when a bearer token fails OIDC verification for any reason."""


@dataclass(frozen=True, slots=True)
class VerifiedIdentity:
    """The result of successfully verifying a token's signature and claims.

    Nothing on this object is trusted-but-unverified; every field comes from
    a claim inside a token whose signature, issuer, audience, and expiry have
    already been checked against the configured identity provider.
    """

    subject: str
    issuer: str
    email: str | None
    claims: dict[str, Any]


class SigningKeyResolver(Protocol):
    """Resolves the public key that signed a given (still-unverified) JWT.

    Production uses ``PyJWKClient``, which fetches and caches keys from the
    provider's JWKS endpoint over HTTPS. Tests inject a resolver backed by a
    locally generated key pair so verification is deterministic and requires
    no network access.
    """

    def get_signing_key_from_jwt(self, token: str) -> Any: ...


class OIDCVerifier:
    """Verifies OIDC access tokens against one configured identity provider."""

    def __init__(
        self,
        issuer: str,
        audience: str,
        jwks_url: str,
        *,
        algorithms: tuple[str, ...] = ("RS256", "ES256"),
        leeway_seconds: int = 30,
        key_resolver: SigningKeyResolver | None = None,
    ) -> None:
        if not issuer or not audience or not jwks_url:
            raise ValueError("issuer, audience, and jwks_url are all required")
        self.issuer = issuer
        self.audience = audience
        self.jwks_url = jwks_url
        self.algorithms = list(algorithms)
        self.leeway_seconds = leeway_seconds
        self._key_resolver: SigningKeyResolver = key_resolver or PyJWKClient(jwks_url)

    def verify(self, token: str) -> VerifiedIdentity:
        try:
            signing_key = self._key_resolver.get_signing_key_from_jwt(token)
            claims = jwt.decode(
                token,
                signing_key.key,
                algorithms=self.algorithms,
                audience=self.audience,
                issuer=self.issuer,
                leeway=self.leeway_seconds,
                options={"require": ["exp", "iat", "sub"]},
            )
        except jwt.PyJWTError as exc:
            raise InvalidIdentityToken(str(exc)) from exc
        subject = claims.get("sub")
        if not isinstance(subject, str) or not subject.strip():
            raise InvalidIdentityToken("token is missing a subject claim")
        email = claims.get("email")
        return VerifiedIdentity(
            subject=subject,
            issuer=self.issuer,
            email=email if isinstance(email, str) and email.strip() else None,
            claims=claims,
        )
