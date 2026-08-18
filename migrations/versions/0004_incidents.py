"""Add tenant-scoped deterministic incidents."""

import sqlalchemy as sa
from alembic import op

revision = "0004_incidents"
down_revision = "0003_domain_events_webhooks"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "incidents",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column(
            "tenant_id",
            sa.String(36),
            sa.ForeignKey("tenants.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "device_id",
            sa.String(36),
            sa.ForeignKey("devices.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "ticket_id", sa.String(36), sa.ForeignKey("tickets.id", ondelete="SET NULL")
        ),
        sa.Column("incident_type", sa.String(100), nullable=False),
        sa.Column("severity", sa.String(30), nullable=False),
        sa.Column("status", sa.String(30), nullable=False, server_default="open"),
        sa.Column("summary", sa.String(300), nullable=False),
        sa.Column("evidence", sa.JSON(), nullable=False),
        sa.Column("correlation_key", sa.String(255), nullable=False),
        sa.Column("occurrence_count", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("first_observed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_observed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("resolved_at", sa.DateTime(timezone=True)),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
    )
    for column in ("tenant_id", "device_id", "ticket_id", "incident_type", "status"):
        op.create_index(f"ix_incidents_{column}", "incidents", [column])
    op.create_index(
        "ix_incidents_tenant_device_correlation",
        "incidents",
        ["tenant_id", "device_id", "correlation_key"],
    )


def downgrade() -> None:
    op.drop_table("incidents")
