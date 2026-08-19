"""Enable PostgreSQL row-level security and provision the restricted app role.

PostgreSQL superusers and BYPASSRLS roles ignore row-level security
unconditionally, regardless of FORCE ROW LEVEL SECURITY. Since this
migration necessarily runs as the schema-owning (superuser, in the default
Docker Compose setup) role, RLS policies alone enforce nothing against that
same connection. This migration therefore also provisions a second,
genuinely restricted role that the API and webhook worker connect as at
runtime (see helpdesktool.config.Settings.runtime_database_url) — without
it, the policies created here would be enforced against nobody.
"""

from alembic import op
from sqlalchemy import text

from helpdesktool.config import get_settings
from helpdesktool.rls import (
    clear_staged_app_role_password_statement,
    disable_statements,
    enable_statements,
    provision_app_role_statements,
    revoke_app_role_statements,
    stage_app_role_password_statement,
)

revision = "0005_row_level_security"
down_revision = "0004_incidents"
branch_labels = None
depends_on = None

# Frozen as of this migration — every tenant-scoped table that exists in the
# schema at this point in the migration history. Do NOT change this to
# import helpdesktool.rls.TENANT_SCOPED_TABLES: that constant tracks the
# *current* schema and will grow in later migrations (see 0006's own
# snapshot, which adds enrollment_tokens); this migration must keep granting
# on exactly the tables that existed when it was written, or a fresh
# `alembic upgrade head` run would fail trying to grant/enable RLS on a
# table (e.g. enrollment_tokens) that migration 0006 hasn't created yet.
TABLES_AS_OF_THIS_MIGRATION = (
    "users",
    "devices",
    "device_inventory",
    "heartbeats",
    "tickets",
    "incidents",
    "actions",
    "approvals",
    "execution_results",
    "audit_events",
    "idempotency_records",
    "domain_events",
    "webhook_subscriptions",
    "webhook_deliveries",
)
UNSCOPED_TABLES_AS_OF_THIS_MIGRATION = ("tenants",)


def upgrade() -> None:
    for table in TABLES_AS_OF_THIS_MIGRATION:
        for statement in enable_statements(table):
            op.execute(statement)

    bind = op.get_bind()
    bind.execute(
        text(stage_app_role_password_statement()),
        {"password": get_settings().app_role_password},
    )
    for statement in provision_app_role_statements(
        (*TABLES_AS_OF_THIS_MIGRATION, *UNSCOPED_TABLES_AS_OF_THIS_MIGRATION)
    ):
        op.execute(statement)
    op.execute(clear_staged_app_role_password_statement())


def downgrade() -> None:
    for statement in revoke_app_role_statements(
        (*TABLES_AS_OF_THIS_MIGRATION, *UNSCOPED_TABLES_AS_OF_THIS_MIGRATION)
    ):
        op.execute(statement)
    for table in TABLES_AS_OF_THIS_MIGRATION:
        for statement in disable_statements(table):
            op.execute(statement)
