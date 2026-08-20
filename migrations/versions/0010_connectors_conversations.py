"""Application Integration Framework: connectors, conversations, and
policy-gated connector requests (omnichannel help desk foundation).
"""

import sqlalchemy as sa
from alembic import op

from helpdesktool.rls import APP_ROLE, disable_statements, enable_statements

revision = "0010_connectors_conversations"
down_revision = "0009_worker_heartbeats"
branch_labels = None
depends_on = None

_NEW_TABLES = (
    "application_connectors",
    "conversations",
    "conversation_messages",
    "connector_requests",
)


def upgrade() -> None:
    op.create_table(
        "application_connectors",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column(
            "tenant_id",
            sa.String(36),
            sa.ForeignKey("tenants.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("application_id", sa.String(100), nullable=False),
        sa.Column("display_name", sa.String(200), nullable=False),
        sa.Column("connector_type", sa.String(50), nullable=False),
        sa.Column("config", sa.JSON(), nullable=False, server_default="{}"),
        sa.Column("credential_ref", sa.String(255), nullable=False, server_default=""),
        sa.Column("active", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column(
            "created_by", sa.String(36), sa.ForeignKey("users.id"), nullable=False
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.UniqueConstraint("tenant_id", "application_id"),
    )
    op.create_index(
        "ix_application_connectors_tenant_id", "application_connectors", ["tenant_id"]
    )

    op.create_table(
        "conversations",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column(
            "tenant_id",
            sa.String(36),
            sa.ForeignKey("tenants.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("channel", sa.String(30), nullable=False),
        sa.Column(
            "channel_thread_id", sa.String(255), nullable=False, server_default=""
        ),
        sa.Column("user_id", sa.String(36), sa.ForeignKey("users.id"), nullable=False),
        sa.Column("status", sa.String(30), nullable=False, server_default="open"),
        sa.Column(
            "ticket_id", sa.String(36), sa.ForeignKey("tickets.id", ondelete="SET NULL")
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
    for column in ("tenant_id", "channel", "user_id", "status"):
        op.create_index(f"ix_conversations_{column}", "conversations", [column])

    op.create_table(
        "conversation_messages",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column(
            "tenant_id",
            sa.String(36),
            sa.ForeignKey("tenants.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "conversation_id",
            sa.String(36),
            sa.ForeignKey("conversations.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("role", sa.String(20), nullable=False),
        sa.Column("content", sa.Text(), nullable=False),
        sa.Column("intent", sa.String(50)),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
    )
    for column in ("tenant_id", "conversation_id"):
        op.create_index(
            f"ix_conversation_messages_{column}", "conversation_messages", [column]
        )

    op.create_table(
        "connector_requests",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column(
            "tenant_id",
            sa.String(36),
            sa.ForeignKey("tenants.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "conversation_id",
            sa.String(36),
            sa.ForeignKey("conversations.id", ondelete="SET NULL"),
        ),
        sa.Column(
            "connector_id",
            sa.String(36),
            sa.ForeignKey("application_connectors.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("operation", sa.String(50), nullable=False),
        sa.Column("target_email", sa.String(320), nullable=False),
        sa.Column(
            "requested_by", sa.String(36), sa.ForeignKey("users.id"), nullable=False
        ),
        sa.Column("risk", sa.String(30), nullable=False),
        sa.Column(
            "status", sa.String(30), nullable=False, server_default="pending_approval"
        ),
        sa.Column("decided_by", sa.String(36), sa.ForeignKey("users.id")),
        sa.Column("decision_reason", sa.Text()),
        sa.Column("decided_at", sa.DateTime(timezone=True)),
        sa.Column("result_success", sa.Boolean()),
        sa.Column("result_detail", sa.Text()),
        sa.Column("verified", sa.Boolean(), nullable=False, server_default=sa.false()),
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
    for column in ("tenant_id", "conversation_id", "connector_id", "status"):
        op.create_index(
            f"ix_connector_requests_{column}", "connector_requests", [column]
        )

    # None of these four tables existed when migration 0005 applied RLS to
    # every then-existing tenant-scoped table; apply it here, same pattern
    # as diagnoses in 0007 and enrollment_tokens in 0006.
    for table in _NEW_TABLES:
        for statement in enable_statements(table):
            op.execute(statement)
        op.execute(f"GRANT SELECT, INSERT, UPDATE, DELETE ON {table} TO {APP_ROLE}")


def downgrade() -> None:
    for table in reversed(_NEW_TABLES):
        op.execute(f"REVOKE ALL ON {table} FROM {APP_ROLE}")
        for statement in disable_statements(table):
            op.execute(statement)

    for column in ("tenant_id", "conversation_id", "connector_id", "status"):
        op.drop_index(
            f"ix_connector_requests_{column}", table_name="connector_requests"
        )
    op.drop_table("connector_requests")

    for column in ("tenant_id", "conversation_id"):
        op.drop_index(
            f"ix_conversation_messages_{column}", table_name="conversation_messages"
        )
    op.drop_table("conversation_messages")

    for column in ("tenant_id", "channel", "user_id", "status"):
        op.drop_index(f"ix_conversations_{column}", table_name="conversations")
    op.drop_table("conversations")

    op.drop_index(
        "ix_application_connectors_tenant_id", table_name="application_connectors"
    )
    op.drop_table("application_connectors")
