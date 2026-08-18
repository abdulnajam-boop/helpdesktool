import hashlib
import hmac
from collections.abc import Callable
from dataclasses import dataclass

from fastapi import Depends, Header, HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from .config import get_settings
from .database import get_session
from .db_models import Device, User
from .development_auth import InvalidDevelopmentSession, verify_session


@dataclass(frozen=True)
class Principal:
    tenant_id: str
    actor_id: str
    role: str


def require_user(
    tenant_id: str | None = Header(default=None, alias="X-Tenant-ID"),
    user_id: str | None = Header(default=None, alias="X-User-ID"),
    authorization: str | None = Header(default=None),
    session: Session = Depends(get_session),
) -> Principal:
    settings = get_settings()
    if authorization and authorization.startswith("Bearer "):
        if (
            settings.environment != "development"
            or not settings.development_login_enabled
        ):
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid browser session")
        try:
            claims = verify_session(
                authorization[7:], settings.development_session_secret
            )
        except InvalidDevelopmentSession as exc:
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, str(exc)) from exc
        tenant_id = str(claims["tenant"])
        user_id = str(claims["sub"])
    elif not settings.allow_insecure_header_auth:
        raise HTTPException(
            status.HTTP_503_SERVICE_UNAVAILABLE,
            "human authentication is not configured",
        )
    elif not tenant_id or not user_id:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "authentication required")
    user = session.scalar(
        select(User).where(
            User.id == user_id, User.tenant_id == tenant_id, User.active.is_(True)
        )
    )
    if user is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid tenant or user")
    return Principal(user.tenant_id, user.id, user.role)


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
    device = session.get(Device, device_id)
    supplied = hashlib.sha256(authorization[7:].encode()).hexdigest()
    if device is None or not hmac.compare_digest(device.agent_key_hash, supplied):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid agent credentials")
    return Principal(device.tenant_id, device.id, "agent")
