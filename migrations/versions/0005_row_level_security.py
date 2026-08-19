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
    TENANT_SCOPED_TABLES,
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


def upgrade() -> None:
    for table in TENANT_SCOPED_TABLES:
        for statement in enable_statements(table):
            op.execute(statement)

    bind = op.get_bind()
    bind.execute(
        text(stage_app_role_password_statement()),
        {"password": get_settings().app_role_password},
    )
    for statement in provision_app_role_statements():
        op.execute(statement)
    op.execute(clear_staged_app_role_password_statement())


def downgrade() -> None:
    for statement in revoke_app_role_statements():
        op.execute(statement)
    for table in TENANT_SCOPED_TABLES:
        for statement in disable_statements(table):
            op.execute(statement)
