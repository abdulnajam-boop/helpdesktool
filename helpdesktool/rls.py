"""PostgreSQL Row-Level Security policy definitions.

Single source of truth for which tables are tenant-owned and what their RLS
policy looks like. Shared by the Alembic migration that applies this DDL to a
real database and by tests that need the same DDL applied to a disposable
PostgreSQL test database (SQLAlchemy's ``Base.metadata.create_all`` does not
run Alembic migrations, so tests apply this module's statements directly).

Design
------
Every tenant-owned table gets exactly one policy that permits a row when
either of two things is true for the current database session:

1. ``current_setting('app.current_tenant_id', true)`` equals that row's
   ``tenant_id``. This GUC is set once per authenticated request by
   ``helpdesktool.auth`` (never from unverified client input — see
   ``helpdesktool.database.set_tenant_context``) and is cleared whenever a
   session is torn down, so a pooled connection can never leak one request's
   tenant context into an unrelated later request.
2. ``current_setting('app.rls_bypass', true)`` equals ``'on'``. This is a
   narrow escape hatch used in exactly five situations, all documented
   where they set it:

   - ``helpdesktool.webhook_worker``, a trusted, non-request-driven process
     that legitimately operates across every tenant by design, sets it for
     the duration of a whole delivery batch and clears it again when done.
   - ``helpdesktool.auth.resolving_identity``, used only for the single
     lookup that establishes *which* tenant an otherwise-unauthenticated
     request belongs to (by verified OIDC email, by device/user
     credential, or — as of the Slack channel adapter — by the
     ``ChannelWorkspaceLink`` a webhook's URL path segment names) — there
     is no tenant to scope that lookup by yet, that is exactly what it is
     computing. It is set immediately before that one query and
     unconditionally cleared immediately after, before any other code
     runs; the lookup itself grants no access on its own (a credential
     still has to match, and for the Slack case the request's signature
     still has to verify against the resolved link's own signing secret).
   - ``helpdesktool.auth.aggregating_platform_metrics``, used only by
     ``GET /metrics``'s Prometheus exporter to compute platform-wide
     `COUNT(*) ... GROUP BY` aggregates (action/incident status counts,
     device online/offline counts, ...) — never row-level tenant data, and
     scoped identically: set immediately before those queries, cleared
     immediately after.
   - ``helpdesktool.retention_worker``, a trusted, non-request-driven
     process (like ``webhook_worker``) that purges expired
     heartbeats/inventory/idempotency rows across every tenant on a
     schedule — retention policy is platform-wide, not scoped to any one
     request. Never touches ``audit_events`` (see that module's docstring
     for why deleting hash-chained rows is a different, harder problem this
     worker deliberately does not attempt).
   - ``helpdesktool.connector_request_reaper``, a trusted, non-request-
     driven process (like ``lease_reaper``) that finds ``ConnectorRequest``
     rows stuck ``pending_approval`` past ``Settings.
     connector_request_stale_after_hours`` across every tenant and marks
     them ``expired`` — see that module's docstring for why this is a
     staleness sweep, not a claim/lease recovery like ``lease_reaper``
     (a ``ConnectorRequest`` has no agent claim step to lose).

   No other code path in ``helpdesktool.api`` sets this GUC — that
   additional invariant is enforced by review/grep, not a runtime check, so
   any future change that sets it from request-handling code outside these
   five named call sites should be treated as a security regression.

Both ``ENABLE ROW LEVEL SECURITY`` and ``FORCE ROW LEVEL SECURITY`` are
applied, but neither is sufficient by itself. PostgreSQL superusers and any
role with the ``BYPASSRLS`` attribute ignore row-level security
unconditionally — ``FORCE`` cannot override that, only ``NO FORCE`` vs.
``FORCE`` for the table *owner* specifically. In this project's Docker
Compose setup the single configured database user is the superuser created
by the official Postgres image, and migrations necessarily run as that user
(``CREATE POLICY`` etc. require elevated privileges) — so a second, genuinely
restricted role is required for RLS to enforce anything at all against live
application traffic. ``APP_ROLE`` below is that role: ``NOSUPERUSER
NOBYPASSRLS``, granted exactly the DML privileges it needs on tenant-scoped
tables and nothing else. The API and webhook worker connect as this role at
runtime (see ``helpdesktool.config.Settings.runtime_database_url``);
migrations and the seed script continue to run as the original superuser
role, which owns the schema.
"""

from __future__ import annotations

from collections.abc import Sequence

APP_ROLE = "helpdesk_app"

TENANT_SCOPED_TABLES: tuple[str, ...] = (
    "users",
    "devices",
    "enrollment_tokens",
    "device_inventory",
    "heartbeats",
    "tickets",
    "incidents",
    "diagnoses",
    "actions",
    "approvals",
    "execution_results",
    "audit_events",
    "idempotency_records",
    "domain_events",
    "webhook_subscriptions",
    "webhook_deliveries",
    "application_connectors",
    "conversations",
    "conversation_messages",
    "connector_requests",
    "organizational_baselines",
    "channel_workspace_links",
    "channel_identity_links",
)

# Tables the application role needs ordinary DML on but that are not
# themselves tenant-scoped/RLS-protected: tenants is the root of the tenancy
# model, skills is a platform-wide registry (helpdesktool/skills.py), and
# worker_heartbeats tracks background-process liveness — none of the three
# has a tenant_id to scope by.
UNSCOPED_APPLICATION_TABLES: tuple[str, ...] = (
    "tenants",
    "skills",
    "worker_heartbeats",
    "knowledge_sources",
    "issue_definitions",
    "diagnostic_workflows",
    "diagnostic_steps",
)

# Sequences backing the two integer-autoincrement primary keys in the schema
# (every other table uses a UUID string primary key with no sequence).
APPLICATION_SEQUENCES: tuple[str, ...] = (
    "device_inventory_id_seq",
    "heartbeats_id_seq",
)

POLICY_NAME = "tenant_isolation"

_TENANT_OR_BYPASS = (
    "tenant_id = current_setting('app.current_tenant_id', true) "
    "OR coalesce(current_setting('app.rls_bypass', true), 'off') = 'on'"
)


def enable_statements(table: str) -> list[str]:
    """DDL to enable and force default-deny tenant isolation on ``table``."""
    return [
        f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY",
        f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY",
        f"CREATE POLICY {POLICY_NAME} ON {table} "
        f"USING ({_TENANT_OR_BYPASS}) WITH CHECK ({_TENANT_OR_BYPASS})",
    ]


def disable_statements(table: str) -> list[str]:
    """DDL to fully reverse ``enable_statements`` for ``table``."""
    return [
        f"DROP POLICY IF EXISTS {POLICY_NAME} ON {table}",
        f"ALTER TABLE {table} NO FORCE ROW LEVEL SECURITY",
        f"ALTER TABLE {table} DISABLE ROW LEVEL SECURITY",
    ]


_PASSWORD_HANDOFF_GUC = "helpdesk.tmp_app_role_password"


def stage_app_role_password_statement(password_param: str = "password") -> str:
    """A normal, safely-parameterized statement that stages a password for
    ``provision_app_role_statements`` to consume, so the password value
    itself never has to be interpolated into a raw SQL string anywhere.
    Bind it with ``{"password": "..."}`` when executing (see the migration).
    """
    return f"SELECT set_config('{_PASSWORD_HANDOFF_GUC}', :{password_param}, false)"


def clear_staged_app_role_password_statement() -> str:
    return f"SELECT set_config('{_PASSWORD_HANDOFF_GUC}', '', false)"


def provision_app_role_statements(
    tables: Sequence[str], sequences: Sequence[str] = APPLICATION_SEQUENCES
) -> list[str]:
    """DDL to create (or update the password of) the restricted application
    role and grant it exactly the privileges it needs. Must run after
    ``stage_app_role_password_statement`` has been executed on the same
    connection/transaction. Safe to run more than once (idempotent).

    ``tables`` is a required, explicit argument rather than defaulting to
    ``TENANT_SCOPED_TABLES``/``UNSCOPED_APPLICATION_TABLES`` on purpose:
    those constants describe the *current* schema, but a migration must only
    ever grant on tables that exist as of *that migration* — a later change
    to those constants (e.g. adding a new tenant-scoped table) must not
    silently alter what an already-written, already-run migration does the
    next time it executes against a fresh database. Every migration that
    calls this must pass its own frozen snapshot of table names. Callers
    that genuinely want "every tenant-scoped table as of right now" (tests
    building the full current schema in one shot, not incrementally through
    migrations) should pass ``(*TENANT_SCOPED_TABLES,
    *UNSCOPED_APPLICATION_TABLES)`` explicitly.
    """
    create_or_update_role = f"""
    DO $$
    DECLARE
        pwd text := current_setting('{_PASSWORD_HANDOFF_GUC}', true);
    BEGIN
        IF pwd IS NULL OR pwd = '' THEN
            RAISE EXCEPTION
                '{_PASSWORD_HANDOFF_GUC} was not set before provisioning {APP_ROLE}';
        END IF;
        IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = '{APP_ROLE}') THEN
            EXECUTE format(
                'CREATE ROLE %I LOGIN PASSWORD %L '
                'NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE NOREPLICATION',
                '{APP_ROLE}', pwd
            );
        ELSE
            EXECUTE format('ALTER ROLE %I WITH LOGIN PASSWORD %L', '{APP_ROLE}', pwd);
        END IF;
    END $$;
    """
    grants = [
        f"GRANT USAGE ON SCHEMA public TO {APP_ROLE}",
        *(
            f"GRANT SELECT, INSERT, UPDATE, DELETE ON {table} TO {APP_ROLE}"
            for table in tables
        ),
        *(
            f"GRANT USAGE, SELECT ON SEQUENCE {sequence} TO {APP_ROLE}"
            for sequence in sequences
        ),
    ]
    return [create_or_update_role, *grants]


def revoke_app_role_statements(
    tables: Sequence[str], sequences: Sequence[str] = APPLICATION_SEQUENCES
) -> list[str]:
    """DDL to fully reverse ``provision_app_role_statements``. See its
    docstring for why ``tables`` must be an explicit, migration-owned
    snapshot rather than defaulting to the live constants.
    """
    return [
        *(
            f"REVOKE ALL ON SEQUENCE {sequence} FROM {APP_ROLE}"
            for sequence in sequences
        ),
        *(f"REVOKE ALL ON {table} FROM {APP_ROLE}" for table in tables),
        f"REVOKE USAGE ON SCHEMA public FROM {APP_ROLE}",
        f"DROP ROLE IF EXISTS {APP_ROLE}",
    ]
