"""Endpoint trust: device credential rotation/revocation, enrollment tokens."""

import sqlalchemy as sa
from alembic import op

from helpdesktool.rls import APP_ROLE, disable_statements, enable_statements

revision = "0006_endpoint_trust"
down_revision = "0005_row_level_security"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "devices",
        sa.Column("active", sa.Boolean(), nullable=False, server_default=sa.true()),
    )
    op.add_column("devices", sa.Column("revoked_at", sa.DateTime(timezone=True)))
    op.add_column("devices", sa.Column("revoked_reason", sa.String(200)))
    op.add_column(
        "devices", sa.Column("credential_rotated_at", sa.DateTime(timezone=True))
    )

    op.create_table(
        "enrollment_tokens",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column(
            "tenant_id",
            sa.String(36),
            sa.ForeignKey("tenants.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("token_hash", sa.String(64), nullable=False, unique=True),
        sa.Column(
            "created_by", sa.String(36), sa.ForeignKey("users.id"), nullable=False
        ),
        sa.Column("label", sa.String(200), nullable=False, server_default=""),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("used_at", sa.DateTime(timezone=True)),
        sa.Column(
            "used_by_device_id",
            sa.String(36),
            sa.ForeignKey("devices.id", ondelete="SET NULL"),
        ),
        sa.Column("revoked_at", sa.DateTime(timezone=True)),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
    )
    op.create_index(
        "ix_enrollment_tokens_tenant_id", "enrollment_tokens", ["tenant_id"]
    )

    # enrollment_tokens did not exist when migration 0005 applied RLS to every
    # then-existing tenant-scoped table; apply it here for just this one new
    # table (re-running CREATE POLICY for the other 14 would error since the
    # policy already exists on them).
    for statement in enable_statements("enrollment_tokens"):
        op.execute(statement)
    # The restricted role and its password were already established by
    # migration 0005; this migration only needs to extend its grants to
    # cover the one new table, not recreate the role itself.
    op.execute(
        f"GRANT SELECT, INSERT, UPDATE, DELETE ON enrollment_tokens TO {APP_ROLE}"
    )


def downgrade() -> None:
    op.execute(f"REVOKE ALL ON enrollment_tokens FROM {APP_ROLE}")
    for statement in disable_statements("enrollment_tokens"):
        op.execute(statement)
    op.drop_index("ix_enrollment_tokens_tenant_id", table_name="enrollment_tokens")
    op.drop_table("enrollment_tokens")
    op.drop_column("devices", "credential_rotated_at")
    op.drop_column("devices", "revoked_reason")
    op.drop_column("devices", "revoked_at")
    op.drop_column("devices", "active")
