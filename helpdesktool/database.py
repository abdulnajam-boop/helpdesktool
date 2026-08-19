from collections.abc import Generator

from sqlalchemy import create_engine, text
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

from .config import get_settings


class Base(DeclarativeBase):
    pass


engine = create_engine(get_settings().runtime_database_url, pool_pre_ping=True)
SessionLocal = sessionmaker(engine, expire_on_commit=False)


def _is_postgresql(session: Session) -> bool:
    return session.get_bind().dialect.name == "postgresql"


def set_tenant_context(session: Session, tenant_id: str) -> None:
    """Bind ``session`` to a tenant for PostgreSQL row-level security.

    Every row-level security policy (see ``helpdesktool.rls``) permits a row
    only when this session-level GUC matches the row's ``tenant_id``. Callers
    must pass a ``tenant_id`` that has already been derived from verified
    authentication (see ``helpdesktool.auth``) — never a raw, unverified
    value taken directly from client input — since this is the value the
    database will trust for the rest of the session's tenant-scoped access.

    Uses ``set_config(..., is_local=false)`` (session-scoped, not
    transaction-scoped) deliberately: several request handlers call
    ``session.commit()`` partway through and then continue issuing
    tenant-scoped queries on the same session afterward, and a transaction-
    scoped ``SET LOCAL`` would be cleared by that intermediate commit. The
    session-level value set here is unconditionally cleared when the session
    is torn down (see ``get_session`` below), so it can never outlive the
    request that set it.
    """
    if not _is_postgresql(session):
        return
    session.execute(
        text("SELECT set_config('app.current_tenant_id', :tenant_id, false)"),
        {"tenant_id": tenant_id},
    )


def set_rls_bypass(session: Session, *, enabled: bool) -> None:
    """Grant or revoke cross-tenant row visibility for ``session``.

    Reserved for trusted, non-request-driven internal processes that must
    legitimately operate across every tenant by design (currently only the
    webhook delivery worker). Must never be called from any code path that
    handles an inbound HTTP request.
    """
    if not _is_postgresql(session):
        return
    session.execute(
        text("SELECT set_config('app.rls_bypass', :value, false)"),
        {"value": "on" if enabled else "off"},
    )


def reset_tenant_context(session: Session) -> None:
    if not _is_postgresql(session):
        return
    try:
        session.rollback()
        session.execute(text("SELECT set_config('app.current_tenant_id', '', false)"))
        session.execute(text("SELECT set_config('app.rls_bypass', '', false)"))
        session.commit()
    except Exception:
        session.rollback()


def get_session() -> Generator[Session, None, None]:
    with SessionLocal() as session:
        try:
            yield session
        finally:
            # Guarantees a pooled connection is always tenant-blind (default
            # deny under row-level security) before it can be reused by an
            # unrelated later request, regardless of how many times this
            # request committed or whether it raised. See set_tenant_context.
            reset_tenant_context(session)
