"""Initial multi-tenant control-plane schema, frozen at revision 0001."""

import sqlalchemy as sa
from alembic import op

revision = "0001_control_plane"
down_revision = None
branch_labels = None
depends_on = None


def tenant_column() -> sa.Column:
    return sa.Column(
        "tenant_id",
        sa.String(36),
        sa.ForeignKey("tenants.id", ondelete="CASCADE"),
        nullable=False,
    )


def upgrade() -> None:
    op.create_table(
        "tenants",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("name", sa.String(200), nullable=False, unique=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
    )
    op.create_table(
        "users",
        sa.Column("id", sa.String(36), primary_key=True),
        tenant_column(),
        sa.Column("email", sa.String(320), nullable=False),
        sa.Column("role", sa.String(30), nullable=False),
        sa.Column("active", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.UniqueConstraint("tenant_id", "email"),
    )
    op.create_index("ix_users_tenant_id", "users", ["tenant_id"])
    op.create_table(
        "devices",
        sa.Column("id", sa.String(36), primary_key=True),
        tenant_column(),
        sa.Column("external_id", sa.String(200), nullable=False),
        sa.Column("hostname", sa.String(255), nullable=False),
        sa.Column("os", sa.String(30), nullable=False),
        sa.Column("agent_key_hash", sa.String(64), nullable=False),
        sa.Column(
            "enrolled_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.Column("last_seen_at", sa.DateTime(timezone=True)),
        sa.UniqueConstraint("tenant_id", "external_id"),
    )
    op.create_index("ix_devices_tenant_id", "devices", ["tenant_id"])
    op.create_table(
        "device_inventory",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        tenant_column(),
        sa.Column(
            "device_id",
            sa.String(36),
            sa.ForeignKey("devices.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("collected_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("payload", sa.JSON(), nullable=False),
    )
    op.create_index("ix_device_inventory_tenant_id", "device_inventory", ["tenant_id"])
    op.create_index("ix_device_inventory_device_id", "device_inventory", ["device_id"])
    op.create_table(
        "heartbeats",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        tenant_column(),
        sa.Column(
            "device_id",
            sa.String(36),
            sa.ForeignKey("devices.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "received_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.Column("status", sa.JSON(), nullable=False),
    )
    op.create_index("ix_heartbeats_tenant_id", "heartbeats", ["tenant_id"])
    op.create_index("ix_heartbeats_device_id", "heartbeats", ["device_id"])
    op.create_table(
        "tickets",
        sa.Column("id", sa.String(36), primary_key=True),
        tenant_column(),
        sa.Column(
            "device_id", sa.String(36), sa.ForeignKey("devices.id", ondelete="SET NULL")
        ),
        sa.Column("title", sa.String(300), nullable=False),
        sa.Column("description", sa.Text(), nullable=False, server_default=""),
        sa.Column("status", sa.String(30), nullable=False, server_default="open"),
        sa.Column("priority", sa.String(30), nullable=False, server_default="normal"),
        sa.Column(
            "created_by", sa.String(36), sa.ForeignKey("users.id"), nullable=False
        ),
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
    op.create_index("ix_tickets_tenant_id", "tickets", ["tenant_id"])
    op.create_table(
        "actions",
        sa.Column("id", sa.String(36), primary_key=True),
        tenant_column(),
        sa.Column(
            "device_id", sa.String(36), sa.ForeignKey("devices.id"), nullable=False
        ),
        sa.Column(
            "ticket_id", sa.String(36), sa.ForeignKey("tickets.id", ondelete="SET NULL")
        ),
        sa.Column("skill_id", sa.String(200), nullable=False),
        sa.Column(
            "requested_by", sa.String(36), sa.ForeignKey("users.id"), nullable=False
        ),
        sa.Column("parameters", sa.JSON(), nullable=False),
        sa.Column("device_os", sa.String(30), nullable=False),
        sa.Column("risk", sa.String(30), nullable=False),
        sa.Column("status", sa.String(30), nullable=False),
        sa.Column("approved_by", sa.String(36), sa.ForeignKey("users.id")),
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
    op.create_index("ix_actions_tenant_id", "actions", ["tenant_id"])
    op.create_index("ix_actions_device_id", "actions", ["device_id"])
    op.create_table(
        "approvals",
        sa.Column("id", sa.String(36), primary_key=True),
        tenant_column(),
        sa.Column(
            "action_id",
            sa.String(36),
            sa.ForeignKey("actions.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "decided_by", sa.String(36), sa.ForeignKey("users.id"), nullable=False
        ),
        sa.Column("decision", sa.String(20), nullable=False),
        sa.Column("reason", sa.Text()),
        sa.Column(
            "decided_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
    )
    op.create_index("ix_approvals_tenant_id", "approvals", ["tenant_id"])
    op.create_index("ix_approvals_action_id", "approvals", ["action_id"])
    op.create_table(
        "execution_results",
        sa.Column("id", sa.String(36), primary_key=True),
        tenant_column(),
        sa.Column(
            "action_id",
            sa.String(36),
            sa.ForeignKey("actions.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("success", sa.Boolean(), nullable=False),
        sa.Column("output", sa.JSON(), nullable=False),
        sa.Column("error", sa.Text()),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
    )
    op.create_index(
        "ix_execution_results_tenant_id", "execution_results", ["tenant_id"]
    )
    op.create_index(
        "ix_execution_results_action_id", "execution_results", ["action_id"]
    )
    op.create_table(
        "audit_events",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("sequence", sa.Integer(), nullable=False),
        sa.Column(
            "occurred_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        tenant_column(),
        sa.Column("correlation_id", sa.String(100), nullable=False),
        sa.Column("event_type", sa.String(100), nullable=False),
        sa.Column("actor_id", sa.String(100), nullable=False),
        sa.Column("details", sa.JSON(), nullable=False),
        sa.Column("previous_hash", sa.String(64), nullable=False),
        sa.Column("event_hash", sa.String(64), nullable=False, unique=True),
    )
    op.create_index("ix_audit_events_tenant_id", "audit_events", ["tenant_id"])
    op.create_index(
        "ix_audit_events_correlation_id", "audit_events", ["correlation_id"]
    )
    op.create_index(
        "ix_audit_tenant_sequence",
        "audit_events",
        ["tenant_id", "sequence"],
        unique=True,
    )
    op.create_table(
        "idempotency_records",
        sa.Column("id", sa.String(36), primary_key=True),
        tenant_column(),
        sa.Column("scope", sa.String(100), nullable=False),
        sa.Column("key", sa.String(200), nullable=False),
        sa.Column("request_hash", sa.String(64), nullable=False),
        sa.Column("response", sa.JSON(), nullable=False),
        sa.Column("status_code", sa.Integer(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.UniqueConstraint("tenant_id", "scope", "key"),
    )
    op.create_index(
        "ix_idempotency_records_tenant_id", "idempotency_records", ["tenant_id"]
    )


def downgrade() -> None:
    for table in (
        "idempotency_records",
        "audit_events",
        "execution_results",
        "approvals",
        "actions",
        "tickets",
        "heartbeats",
        "device_inventory",
        "devices",
        "users",
        "tenants",
    ):
        op.drop_table(table)
