"""Registers the ``dns.flush_cache`` skill: the second genuinely executable
mutating skill (after ``service.restart``, migration ``0008``) -- both
``linux_agent/executor.py`` and ``windows_agent/executor.py`` ship a real,
deterministic ``DnsFlushCacheExecutor`` for it (no shell, no parameter
templating, same invariant as every other executor in this codebase).

Closes the "reference skills content DONE, executor code NOT" gap
(`docs/HELPDESK_MATURITY_GAP_ANALYSIS.md`'s P3 row) for one concrete
skill rather than adding more inert manifests -- per the mandate's explicit
"make the existing reference skills excellent and genuinely executable
first" instruction. ``reversible=False``/``rollback_skill_id=None``: a
cache flush has no prior state worth restoring, so this is honestly
declared as having no rollback story rather than a fabricated one. This
manifest classifies as L1 (``automation_level_for``): low risk, no
approval flags, no rollback -- exactly matching what the two real
executors actually do.
"""

import uuid

import sqlalchemy as sa
from alembic import op

from helpdesktool.models import RiskLevel
from helpdesktool.skills import compute_manifest_hash

revision = "0016_dns_flush_cache_skill"
down_revision = "0015_channel_links"
branch_labels = None
depends_on = None

_SUPPORTED_OS = ["linux", "windows"]


def upgrade() -> None:
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
        sa.column("command_type", sa.String),
        sa.column("requires_user_approval", sa.Boolean),
        sa.column("requires_admin_approval", sa.Boolean),
        sa.column("security_sensitive", sa.Boolean),
        sa.column("reversible", sa.Boolean),
    )

    content_hash = compute_manifest_hash(
        skill_id="dns.flush_cache",
        version=1,
        risk=RiskLevel.LOW,
        supported_os=frozenset(_SUPPORTED_OS),
        timeout_seconds=15,
        rollback_skill_id=None,
        parameters={},
        reversible=False,
    )
    op.bulk_insert(
        skills_table,
        [
            {
                "id": str(uuid.uuid4()),
                "skill_id": "dns.flush_cache",
                "version": 1,
                "risk": str(RiskLevel.LOW),
                "supported_os": _SUPPORTED_OS,
                "timeout_seconds": 15,
                "rollback_skill_id": None,
                "parameters": {},
                "content_hash": content_hash,
                "active": True,
                "created_by": "00000000-0000-0000-0000-000000000000",
                "command_type": "low_risk_change",
                "requires_user_approval": False,
                "requires_admin_approval": False,
                "security_sensitive": False,
                "reversible": False,
            }
        ],
    )


def downgrade() -> None:
    op.execute("DELETE FROM skills WHERE skill_id = 'dns.flush_cache'")
