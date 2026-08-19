"""Request authentication and tenant-context binding.

Trust model
-----------
``tenant_id`` is never trusted when it arrives as a raw, unverified value
from the client (an ``X-Tenant-ID`` header, a query parameter, a JSON body
field). Every path in this module that ends in a ``Principal`` derives its
``tenant_id`` from something the server itself has already verified:

- the development browser session's HMAC signature (dev-only, see
  ``development_auth.py``),
- the OIDC access token's cryptographic signature plus a database lookup
  keyed on the token's verified ``email`` claim (production), or
- the agent device's hashed bearer credential (existing device-scoped path).

The one exception — and the only place a client-supplied tenant identifier
is read at all — is OIDC login when a single verified email is provisioned
into more than one tenant: there, an ``X-Tenant-ID`` header is used only to
*select among* a candidate set the server already computed from the verified
identity, never as a raw lookup key. See ``_resolve_oidc_principal``.

Every successful resolution also binds the request's database session to
that tenant for PostgreSQL row-level security (``set_tenant_context``), so a
missing or incorrect authorization check in some future endpoint fails
closed at the database layer too, not only here.

Resolving identity before a tenant is known
--------------------------------------------
Every path above has to look a credential up *before* any tenant context
exists — that lookup is exactly what establishes the tenant, so it cannot
itself be scoped by ``app.current_tenant_id`` (which is, correctly, unset at
that point). Under default-deny row-level security an unscoped SELECT
against ``users``/``devices`` returns nothing, credential or not — so each
of these lookups runs inside ``resolving_identity``, which grants the
session cross-tenant visibility only for that one query and unconditionally
revokes it again (even on exception) before any code that runs afterward.
This is safe because none of these lookups grants access on its own: the
insecure-header path still requires an exact ``(tenant_id, user_id)`` match
in the query itself, the OIDC path keys the lookup on an email that was just
cryptographically verified (not client input), and the agent path still
requires the caller to know a secret whose hash matches — this bypass only
lets the server *find* the candidate row to check a credential against, the
same way a login form looks up a username before checking a password.
"""

from __future__ import annotations

import hashlib
import hmac
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from functools import lru_cache

from fastapi import Depends, Header, HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from .config import get_settings
from .database import get_session, set_rls_bypass, set_tenant_context
from .db_models import Device, User
from .development_auth import InvalidDevelopmentSession, verify_session
from .oidc import InvalidIdentityToken, OIDCVerifier


@dataclass(frozen=True)
class Principal:
    tenant_id: str
    actor_id: str
    role: str


@contextmanager
def resolving_identity(session: Session) -> Iterator[None]:
    set_rls_bypass(session, enabled=True)
    try:
        yield
    finally:
        set_rls_bypass(session, enabled=False)


@lru_cache
def get_oidc_verifier() -> OIDCVerifier:
    settings = get_settings()
    if not settings.oidc_configured:
        raise HTTPException(
            status.HTTP_503_SERVICE_UNAVAILABLE,
            "identity provider is not configured",
        )
    return OIDCVerifier(
        settings.oidc_issuer, settings.oidc_audience, settings.oidc_jwks_url
    )


def _load_principal(session: Session, tenant_id: str, user_id: str) -> Principal:
    with resolving_identity(session):
        user = session.scalar(
            select(User).where(
                User.id == user_id, User.tenant_id == tenant_id, User.active.is_(True)
            )
        )
    if user is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid tenant or user")
    set_tenant_context(session, user.tenant_id)
    return Principal(user.tenant_id, user.id, user.role)


def _resolve_oidc_principal(
    session: Session, token: str, requested_tenant_id: str | None
) -> Principal:
    try:
        identity = get_oidc_verifier().verify(token)
    except InvalidIdentityToken as exc:
        raise HTTPException(
            status.HTTP_401_UNAUTHORIZED, "invalid identity token"
        ) from exc
    if not identity.email:
        raise HTTPException(
            status.HTTP_401_UNAUTHORIZED, "identity token is missing an email claim"
        )
    # The email claim just came out of a signature we verified above, so this
    # lookup is keyed on server-verified data — it is not client input.
    with resolving_identity(session):
        candidates = session.scalars(
            select(User).where(User.email == identity.email, User.active.is_(True))
        ).all()
    if not candidates:
        raise HTTPException(
            status.HTTP_403_FORBIDDEN, "identity is not provisioned in any tenant"
        )
    if len(candidates) == 1:
        user = candidates[0]
    else:
        # Multiple tenants share this verified email. The client may supply
        # X-Tenant-ID to disambiguate, but only as a filter over the set of
        # tenants this verified identity is already a member of — never as a
        # raw lookup key an attacker could point at an arbitrary tenant.
        if not requested_tenant_id:
            raise HTTPException(
                status.HTTP_409_CONFLICT,
                "identity belongs to multiple tenants; specify X-Tenant-ID",
            )
        matches = [row for row in candidates if row.tenant_id == requested_tenant_id]
        if not matches:
            raise HTTPException(
                status.HTTP_403_FORBIDDEN,
                "identity is not provisioned in the requested tenant",
            )
        user = matches[0]
    set_tenant_context(session, user.tenant_id)
    return Principal(user.tenant_id, user.id, user.role)


def require_user(
    tenant_id: str | None = Header(default=None, alias="X-Tenant-ID"),
    user_id: str | None = Header(default=None, alias="X-User-ID"),
    authorization: str | None = Header(default=None),
    session: Session = Depends(get_session),
) -> Principal:
    settings = get_settings()
    if authorization and authorization.startswith("Bearer "):
        token = authorization[7:]
        if settings.environment == "development" and settings.development_login_enabled:
            try:
                claims = verify_session(token, settings.development_session_secret)
            except InvalidDevelopmentSession as exc:
                raise HTTPException(status.HTTP_401_UNAUTHORIZED, str(exc)) from exc
            return _load_principal(session, str(claims["tenant"]), str(claims["sub"]))
        return _resolve_oidc_principal(session, token, tenant_id)
    if not settings.allow_insecure_header_auth:
        raise HTTPException(
            status.HTTP_503_SERVICE_UNAVAILABLE,
            "human authentication is not configured",
        )
    if not tenant_id or not user_id:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "authentication required")
    return _load_principal(session, tenant_id, user_id)


def require_roles(*roles: str) -> Callable[..., Principal]:
    def dependency(principal: Principal = Depends(require_user)) -> Principal:
        if principal.role not in roles:
            raise HTTPException(status.HTTP_403_FORBIDDEN, "insufficient role")
        return principal

    return dependency


def require_agent(
    device_id: str,
    authorization: str = Header(),
    session: Session = Depends(get_session),
) -> Principal:
    if not authorization.startswith("Bearer "):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "missing agent bearer token")
    with resolving_identity(session):
        device = session.get(Device, device_id)
    supplied = hashlib.sha256(authorization[7:].encode()).hexdigest()
    if device is None or not hmac.compare_digest(device.agent_key_hash, supplied):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid agent credentials")
    set_tenant_context(session, device.tenant_id)
    return Principal(device.tenant_id, device.id, "agent")
