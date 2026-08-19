"""Worker heartbeats: background-process liveness for observability."""

import sqlalchemy as sa
from alembic import op

from helpdesktool.rls import APP_ROLE

revision = "0009_worker_heartbeats"
down_revision = "0008_skill_registry"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "worker_heartbeats",
        sa.Column("worker_name", sa.String(100), primary_key=True),
        sa.Column("last_heartbeat_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_batch_size", sa.Integer(), nullable=False, server_default="0"),
    )
    op.execute(
        f"GRANT SELECT, INSERT, UPDATE, DELETE ON worker_heartbeats TO {APP_ROLE}"
    )


def downgrade() -> None:
    op.execute(f"REVOKE ALL ON worker_heartbeats FROM {APP_ROLE}")
    op.drop_table("worker_heartbeats")
