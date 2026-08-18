"""Add device job claiming and structured execution outcomes."""

import sqlalchemy as sa
from alembic import op

revision = "0002_agent_jobs"
down_revision = "0001_control_plane"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("actions", sa.Column("claim_token_hash", sa.String(64)))
    op.add_column("actions", sa.Column("claimed_at", sa.DateTime(timezone=True)))
    op.add_column("actions", sa.Column("lease_expires_at", sa.DateTime(timezone=True)))
    op.add_column(
        "actions",
        sa.Column("attempt", sa.Integer(), nullable=False, server_default="0"),
    )
    op.add_column(
        "execution_results",
        sa.Column("verified", sa.Boolean(), nullable=False, server_default=sa.false()),
    )
    op.add_column(
        "execution_results",
        sa.Column(
            "rollback_attempted",
            sa.Boolean(),
            nullable=False,
            server_default=sa.false(),
        ),
    )
    op.add_column("execution_results", sa.Column("rollback_succeeded", sa.Boolean()))


def downgrade() -> None:
    op.drop_column("execution_results", "rollback_succeeded")
    op.drop_column("execution_results", "rollback_attempted")
    op.drop_column("execution_results", "verified")
    op.drop_column("actions", "attempt")
    op.drop_column("actions", "lease_expires_at")
    op.drop_column("actions", "claimed_at")
    op.drop_column("actions", "claim_token_hash")
