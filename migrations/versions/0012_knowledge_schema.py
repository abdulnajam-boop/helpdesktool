"""Phase 1 knowledge schema: knowledge sources, issue definitions,
diagnostic workflows/steps. Platform-wide/unscoped like `skills` --
knowledge isn't owned by any one tenant, so no RLS policy is needed here
(same pattern as migration 0008/0009), only the restricted app role's DML
grant.
"""

import sqlalchemy as sa
from alembic import op

from helpdesktool.rls import APP_ROLE

revision = "0012_knowledge_schema"
down_revision = "0011_skill_safety_metadata"
branch_labels = None
depends_on = None

_TABLES = (
    "knowledge_sources",
    "issue_definitions",
    "diagnostic_workflows",
    "diagnostic_steps",
)


def upgrade() -> None:
    op.create_table(
        "knowledge_sources",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("source_organization", sa.String(200), nullable=False),
        sa.Column("source_url", sa.String(2048), nullable=False, server_default=""),
        sa.Column("retrieval_date", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_verified_date", sa.DateTime(timezone=True)),
        sa.Column(
            "source_reliability", sa.Float(), nullable=False, server_default="0.5"
        ),
        sa.Column(
            "deprecated", sa.Boolean(), nullable=False, server_default=sa.false()
        ),
        sa.Column(
            "superseded_by",
            sa.String(36),
            sa.ForeignKey("knowledge_sources.id", ondelete="SET NULL"),
        ),
        sa.Column("created_by", sa.String(36), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
    )

    op.create_table(
        "issue_definitions",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("issue_key", sa.String(200), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("title", sa.String(300), nullable=False),
        sa.Column("description", sa.Text(), nullable=False, server_default=""),
        sa.Column("category", sa.String(50), nullable=False),
        sa.Column("applicable_os", sa.JSON(), nullable=False),
        sa.Column(
            "applicable_software_versions",
            sa.JSON(),
            nullable=False,
            server_default="{}",
        ),
        sa.Column(
            "evidence_requirements", sa.JSON(), nullable=False, server_default="[]"
        ),
        sa.Column("mitre_mappings", sa.JSON(), nullable=False, server_default="[]"),
        sa.Column("cve_references", sa.JSON(), nullable=False, server_default="[]"),
        sa.Column("escalation_policy", sa.JSON()),
        sa.Column(
            "source_id",
            sa.String(36),
            sa.ForeignKey("knowledge_sources.id", ondelete="SET NULL"),
        ),
        sa.Column("validated", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("content_hash", sa.String(64), nullable=False),
        sa.Column("active", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("created_by", sa.String(36), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.UniqueConstraint("issue_key", "version"),
    )
    op.create_index(
        "ix_issue_definitions_issue_key", "issue_definitions", ["issue_key"]
    )

    op.create_table(
        "diagnostic_workflows",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column(
            "issue_definition_id",
            sa.String(36),
            sa.ForeignKey("issue_definitions.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("version", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("active", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("created_by", sa.String(36), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
    )
    op.create_index(
        "ix_diagnostic_workflows_issue_definition_id",
        "diagnostic_workflows",
        ["issue_definition_id"],
    )

    op.create_table(
        "diagnostic_steps",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column(
            "workflow_id",
            sa.String(36),
            sa.ForeignKey("diagnostic_workflows.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("step_order", sa.Integer(), nullable=False),
        sa.Column("step_type", sa.String(30), nullable=False),
        sa.Column("description", sa.Text(), nullable=False, server_default=""),
        sa.Column("remediation_skill_id", sa.String(200)),
        sa.Column(
            "verification_description", sa.Text(), nullable=False, server_default=""
        ),
        sa.Column("rollback_skill_id", sa.String(200)),
        sa.Column(
            "reference_description", sa.Text(), nullable=False, server_default=""
        ),
    )
    op.create_index(
        "ix_diagnostic_steps_workflow_id", "diagnostic_steps", ["workflow_id"]
    )

    for table in _TABLES:
        op.execute(f"GRANT SELECT, INSERT, UPDATE, DELETE ON {table} TO {APP_ROLE}")


def downgrade() -> None:
    for table in reversed(_TABLES):
        op.execute(f"REVOKE ALL ON {table} FROM {APP_ROLE}")

    op.drop_index("ix_diagnostic_steps_workflow_id", table_name="diagnostic_steps")
    op.drop_table("diagnostic_steps")

    op.drop_index(
        "ix_diagnostic_workflows_issue_definition_id",
        table_name="diagnostic_workflows",
    )
    op.drop_table("diagnostic_workflows")

    op.drop_index("ix_issue_definitions_issue_key", table_name="issue_definitions")
    op.drop_table("issue_definitions")

    op.drop_table("knowledge_sources")
