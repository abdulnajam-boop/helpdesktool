"""Add canonical domain events and webhook delivery outbox."""

import sqlalchemy as sa
from alembic import op

revision = "0003_domain_events_webhooks"
down_revision = "0002_agent_jobs"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "domain_events",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column(
            "tenant_id",
            sa.String(36),
            sa.ForeignKey("tenants.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("event_type", sa.String(100), nullable=False),
        sa.Column("subject_id", sa.String(100), nullable=False),
        sa.Column("schema_version", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("data", sa.JSON(), nullable=False),
        sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_domain_events_tenant_id", "domain_events", ["tenant_id"])
    op.create_index("ix_domain_events_event_type", "domain_events", ["event_type"])
    op.create_index("ix_domain_events_subject_id", "domain_events", ["subject_id"])
    op.create_table(
        "webhook_subscriptions",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column(
            "tenant_id",
            sa.String(36),
            sa.ForeignKey("tenants.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("name", sa.String(100), nullable=False),
        sa.Column("url", sa.String(2048), nullable=False),
        sa.Column("secret_ref", sa.String(255), nullable=False),
        sa.Column("event_types", sa.JSON(), nullable=False),
        sa.Column("active", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column(
            "created_by", sa.String(36), sa.ForeignKey("users.id"), nullable=False
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.UniqueConstraint("tenant_id", "name"),
    )
    op.create_index(
        "ix_webhook_subscriptions_tenant_id", "webhook_subscriptions", ["tenant_id"]
    )
    op.create_table(
        "webhook_deliveries",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column(
            "tenant_id",
            sa.String(36),
            sa.ForeignKey("tenants.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "event_id",
            sa.String(36),
            sa.ForeignKey("domain_events.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "subscription_id",
            sa.String(36),
            sa.ForeignKey("webhook_subscriptions.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("status", sa.String(30), nullable=False, server_default="pending"),
        sa.Column("attempt_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column(
            "next_attempt_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.Column("last_attempt_at", sa.DateTime(timezone=True)),
        sa.Column("delivered_at", sa.DateTime(timezone=True)),
        sa.Column("response_status", sa.Integer()),
        sa.Column("last_error", sa.Text()),
        sa.UniqueConstraint("event_id", "subscription_id"),
    )
    op.create_index(
        "ix_webhook_deliveries_tenant_id", "webhook_deliveries", ["tenant_id"]
    )
    op.create_index(
        "ix_webhook_deliveries_event_id", "webhook_deliveries", ["event_id"]
    )
    op.create_index(
        "ix_webhook_deliveries_subscription_id",
        "webhook_deliveries",
        ["subscription_id"],
    )
    op.create_index("ix_webhook_deliveries_status", "webhook_deliveries", ["status"])
    op.create_index(
        "ix_webhook_deliveries_next_attempt_at",
        "webhook_deliveries",
        ["next_attempt_at"],
    )


def downgrade() -> None:
    op.drop_table("webhook_deliveries")
    op.drop_table("webhook_subscriptions")
    op.drop_table("domain_events")
