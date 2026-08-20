"""Phase 18 omnichannel: workspace and identity links for chat channel
adapters (Slack first, Teams/Google Chat to follow behind the same
tables). Both tenant-scoped/RLS-protected -- see
``helpdesktool/db_models.py``'s ``ChannelWorkspaceLink``/
``ChannelIdentityLink`` docstrings.
"""

import sqlalchemy as sa
from alembic import op

from helpdesktool.rls import APP_ROLE, disable_statements, enable_statements

revision = "0015_channel_links"
down_revision = "0014_organizational_baselines"
branch_labels = None
depends_on = None

_TABLES = ("channel_workspace_links", "channel_identity_links")


def upgrade() -> None:
    op.create_table(
        "channel_workspace_links",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column(
            "tenant_id",
            sa.String(36),
            sa.ForeignKey("tenants.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("channel", sa.String(30), nullable=False),
        sa.Column("workspace_id", sa.String(200), nullable=False),
        sa.Column("signing_secret_ref", sa.String(255), nullable=False),
        sa.Column("active", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("created_by", sa.String(36), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.UniqueConstraint("channel", "workspace_id"),
    )
    op.create_index(
        "ix_channel_workspace_links_tenant_id", "channel_workspace_links", ["tenant_id"]
    )

    op.create_table(
        "channel_identity_links",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column(
            "tenant_id",
            sa.String(36),
            sa.ForeignKey("tenants.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("channel", sa.String(30), nullable=False),
        sa.Column("provider_user_id", sa.String(200), nullable=False),
        sa.Column(
            "user_id",
            sa.String(36),
            sa.ForeignKey("users.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("created_by", sa.String(36), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.UniqueConstraint("tenant_id", "channel", "provider_user_id"),
    )
    op.create_index(
        "ix_channel_identity_links_tenant_id", "channel_identity_links", ["tenant_id"]
    )

    for table in _TABLES:
        for statement in enable_statements(table):
            op.execute(statement)
        op.execute(f"GRANT SELECT, INSERT, UPDATE, DELETE ON {table} TO {APP_ROLE}")


def downgrade() -> None:
    for table in reversed(_TABLES):
        op.execute(f"REVOKE ALL ON {table} FROM {APP_ROLE}")
        for statement in disable_statements(table):
            op.execute(statement)

    op.drop_index(
        "ix_channel_identity_links_tenant_id", table_name="channel_identity_links"
    )
    op.drop_table("channel_identity_links")

    op.drop_index(
        "ix_channel_workspace_links_tenant_id", table_name="channel_workspace_links"
    )
    op.drop_table("channel_workspace_links")
