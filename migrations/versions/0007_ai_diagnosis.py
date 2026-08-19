"""AI diagnosis: stored, schema-validated, advisory-only diagnosis proposals."""

import sqlalchemy as sa
from alembic import op

from helpdesktool.rls import APP_ROLE, disable_statements, enable_statements

revision = "0007_ai_diagnosis"
down_revision = "0006_endpoint_trust"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "diagnoses",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column(
            "tenant_id",
            sa.String(36),
            sa.ForeignKey("tenants.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "incident_id",
            sa.String(36),
            sa.ForeignKey("incidents.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "requested_by", sa.String(36), sa.ForeignKey("users.id"), nullable=False
        ),
        sa.Column("provider_name", sa.String(100), nullable=False),
        sa.Column("model", sa.String(200), nullable=False),
        sa.Column(
            "fallback_used", sa.Boolean(), nullable=False, server_default=sa.false()
        ),
        sa.Column("summary", sa.Text(), nullable=False),
        sa.Column("likely_root_cause", sa.Text(), nullable=False, server_default=""),
        sa.Column("confidence", sa.Float(), nullable=False, server_default="0"),
        sa.Column("suggested_skill_id", sa.String(200)),
        sa.Column(
            "suggested_parameters",
            sa.JSON(),
            nullable=False,
            server_default="{}",
        ),
        sa.Column("escalate", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("escalation_reason", sa.Text(), nullable=False, server_default=""),
        sa.Column("latency_ms", sa.Integer(), nullable=False, server_default="0"),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
    )
    op.create_index("ix_diagnoses_tenant_id", "diagnoses", ["tenant_id"])
    op.create_index("ix_diagnoses_incident_id", "diagnoses", ["incident_id"])

    # diagnoses did not exist when migration 0005 applied RLS to every
    # then-existing tenant-scoped table; apply it here for just this one new
    # table, same pattern as enrollment_tokens in 0006.
    for statement in enable_statements("diagnoses"):
        op.execute(statement)
    op.execute(f"GRANT SELECT, INSERT, UPDATE, DELETE ON diagnoses TO {APP_ROLE}")


def downgrade() -> None:
    op.execute(f"REVOKE ALL ON diagnoses FROM {APP_ROLE}")
    for statement in disable_statements("diagnoses"):
        op.execute(statement)
    op.drop_index("ix_diagnoses_incident_id", table_name="diagnoses")
    op.drop_index("ix_diagnoses_tenant_id", table_name="diagnoses")
    op.drop_table("diagnoses")
