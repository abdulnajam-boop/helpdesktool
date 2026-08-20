"""Phase 6: known-good organizational state.

Adds ``organizational_baselines``, a tenant-scoped/RLS-protected table
recording a tenant's own declared "known good" value for a configuration
key, at one of five distinct scopes (``BaselineScope`` in
``helpdesktool/models.py``): generic best practice, organizational policy,
device baseline, user baseline, or current (observed) state. See
``helpdesktool/baseline.py``'s module docstring for why this distinction
exists -- concretely, so a future DNS-resolution remediation can never
"fix" a device by pointing it at a public resolver just because resolution
is failing, when the organization's own configured DNS is the only
authoritative answer to "what should this key be."

Unlike migrations 0012/0013 (the platform-wide knowledge schema), this
table genuinely needs RLS: a baseline is inherently specific to one
tenant's own environment, never shared across tenants.
"""

import sqlalchemy as sa
from alembic import op

from helpdesktool.rls import APP_ROLE, disable_statements, enable_statements

revision = "0014_organizational_baselines"
down_revision = "0013_reference_knowledge"
branch_labels = None
depends_on = None

_TABLE = "organizational_baselines"


def upgrade() -> None:
    op.create_table(
        _TABLE,
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column(
            "tenant_id",
            sa.String(36),
            sa.ForeignKey("tenants.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("scope", sa.String(30), nullable=False),
        sa.Column("key", sa.String(200), nullable=False),
        sa.Column("value", sa.JSON(), nullable=False),
        sa.Column(
            "device_id", sa.String(36), sa.ForeignKey("devices.id", ondelete="CASCADE")
        ),
        sa.Column(
            "user_id", sa.String(36), sa.ForeignKey("users.id", ondelete="CASCADE")
        ),
        sa.Column("description", sa.Text(), nullable=False, server_default=""),
        sa.Column("active", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("created_by", sa.String(36), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
    )
    op.create_index(f"ix_{_TABLE}_tenant_id", _TABLE, ["tenant_id"])
    op.create_index(f"ix_{_TABLE}_key", _TABLE, ["key"])

    for statement in enable_statements(_TABLE):
        op.execute(statement)
    op.execute(f"GRANT SELECT, INSERT, UPDATE, DELETE ON {_TABLE} TO {APP_ROLE}")


def downgrade() -> None:
    op.execute(f"REVOKE ALL ON {_TABLE} FROM {APP_ROLE}")
    for statement in disable_statements(_TABLE):
        op.execute(statement)
    op.drop_index(f"ix_{_TABLE}_key", table_name=_TABLE)
    op.drop_index(f"ix_{_TABLE}_tenant_id", table_name=_TABLE)
    op.drop_table(_TABLE)
