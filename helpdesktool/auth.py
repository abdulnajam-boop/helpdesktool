import hashlib
import hmac
from collections.abc import Callable
from dataclasses import dataclass

from fastapi import Depends, Header, HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from .database import get_session
from .db_models import Device, User


@dataclass(frozen=True)
class Principal:
    tenant_id: str
    actor_id: str
    role: str


def require_user(
    tenant_id: str = Header(alias="X-Tenant-ID"),
    user_id: str = Header(alias="X-User-ID"),
    session: Session = Depends(get_session),
) -> Principal:
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
