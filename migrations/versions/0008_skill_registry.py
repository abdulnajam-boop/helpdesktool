"""Versioned, integrity-checked remediation skill registry.

Seeds the two skills that previously lived only as a hardcoded Python list
literal (``SKILLS`` in ``api.py``) as version-1, active manifests with the
exact same policy values they already had, so this migration is a pure
data-modeling change with zero behavior difference for existing skills.
"""

import uuid

import sqlalchemy as sa
from alembic import op

from helpdesktool.models import RiskLevel
from helpdesktool.rls import APP_ROLE
from helpdesktool.skills import compute_manifest_hash

revision = "0008_skill_registry"
down_revision = "0007_ai_diagnosis"
branch_labels = None
depends_on = None

_SUPPORTED_OS = ["linux", "windows"]


def upgrade() -> None:
    op.create_table(
        "skills",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("skill_id", sa.String(200), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("risk", sa.String(30), nullable=False),
        sa.Column("supported_os", sa.JSON(), nullable=False),
        sa.Column("timeout_seconds", sa.Integer(), nullable=False, server_default="30"),
        sa.Column("rollback_skill_id", sa.String(200)),
        sa.Column("parameters", sa.JSON(), nullable=False, server_default="{}"),
        sa.Column("content_hash", sa.String(64), nullable=False),
        sa.Column("active", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("created_by", sa.String(36), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.UniqueConstraint("skill_id", "version"),
    )
    op.create_index("ix_skills_skill_id", "skills", ["skill_id"])
    op.execute(f"GRANT SELECT, INSERT, UPDATE, DELETE ON skills TO {APP_ROLE}")

    skills_table = sa.table(
        "skills",
        sa.column("id", sa.String),
        sa.column("skill_id", sa.String),
        sa.column("version", sa.Integer),
        sa.column("risk", sa.String),
        sa.column("supported_os", sa.JSON),
        sa.column("timeout_seconds", sa.Integer),
        sa.column("rollback_skill_id", sa.String),
        sa.column("parameters", sa.JSON),
        sa.column("content_hash", sa.String),
        sa.column("active", sa.Boolean),
        sa.column("created_by", sa.String),
    )

    seed_manifests = [
        {
            "skill_id": "diagnostics.collect",
            "risk": RiskLevel.READ_ONLY,
            "rollback_skill_id": None,
            "parameters": {},
        },
        {
            "skill_id": "service.restart",
            "risk": RiskLevel.MEDIUM,
            "rollback_skill_id": "service.restore",
            "parameters": {"service": {"type": "string", "required": True}},
        },
    ]
    rows = []
    for manifest in seed_manifests:
        content_hash = compute_manifest_hash(
            skill_id=manifest["skill_id"],
            version=1,
            risk=manifest["risk"],
            supported_os=frozenset(_SUPPORTED_OS),
            timeout_seconds=30,
            rollback_skill_id=manifest["rollback_skill_id"],
            parameters=manifest["parameters"],
        )
        rows.append(
            {
                "id": str(uuid.uuid4()),
                "skill_id": manifest["skill_id"],
                "version": 1,
                "risk": str(manifest["risk"]),
                "supported_os": _SUPPORTED_OS,
                "timeout_seconds": 30,
                "rollback_skill_id": manifest["rollback_skill_id"],
                "parameters": manifest["parameters"],
                "content_hash": content_hash,
                "active": True,
                "created_by": "00000000-0000-0000-0000-000000000000",
            }
        )
    op.bulk_insert(skills_table, rows)


def downgrade() -> None:
    op.execute(f"REVOKE ALL ON skills FROM {APP_ROLE}")
    op.drop_index("ix_skills_skill_id", table_name="skills")
    op.drop_table("skills")
