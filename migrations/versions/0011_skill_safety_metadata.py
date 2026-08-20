"""Phase 2 skill safety metadata: command_type, approval/security-sensitivity
flags, and descriptive planning fields on the skill registry.

Column defaults here are chosen to exactly match
``helpdesktool.skills.compute_manifest_hash``'s new keyword-argument
defaults (``command_type="low_risk_change"``, and every new boolean flag
False except ``reversible`` which defaults True). This matters for
integrity verification on a *fresh* database: migration ``0008`` seeds its
two built-in skills by calling ``compute_manifest_hash`` directly with the
*live*, current version of that function (Python imports are live, not a
frozen historical snapshot) -- which, after this migration exists in the
codebase, already includes these five fields' default values in the hash
it computes and stores, even though this migration (which actually adds
the columns) runs later in the sequence. By the time ``alembic upgrade
head`` completes, those two rows' actual column values (populated by this
migration's ``server_default``s) match exactly what 0008's hash assumed --
verified by a real `alembic upgrade head` run plus `load_active_skill_manifests`
in this pass, not merely reasoned about.
"""

import sqlalchemy as sa
from alembic import op

revision = "0011_skill_safety_metadata"
down_revision = "0010_connectors_conversations"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "skills",
        sa.Column(
            "command_type",
            sa.String(30),
            nullable=False,
            server_default="low_risk_change",
        ),
    )
    op.add_column(
        "skills",
        sa.Column(
            "requires_user_approval",
            sa.Boolean(),
            nullable=False,
            server_default=sa.false(),
        ),
    )
    op.add_column(
        "skills",
        sa.Column(
            "requires_admin_approval",
            sa.Boolean(),
            nullable=False,
            server_default=sa.false(),
        ),
    )
    op.add_column(
        "skills",
        sa.Column(
            "security_sensitive",
            sa.Boolean(),
            nullable=False,
            server_default=sa.false(),
        ),
    )
    op.add_column(
        "skills",
        sa.Column("reversible", sa.Boolean(), nullable=False, server_default=sa.true()),
    )
    op.add_column(
        "skills",
        sa.Column(
            "required_privilege", sa.String(100), nullable=False, server_default=""
        ),
    )
    op.add_column(
        "skills",
        sa.Column("preconditions", sa.JSON(), nullable=False, server_default="{}"),
    )
    op.add_column(
        "skills",
        sa.Column("expected_output", sa.Text(), nullable=False, server_default=""),
    )
    op.add_column(
        "skills",
        sa.Column("success_condition", sa.Text(), nullable=False, server_default=""),
    )
    op.add_column(
        "skills",
        sa.Column("failure_condition", sa.Text(), nullable=False, server_default=""),
    )
    op.add_column(
        "skills",
        sa.Column("side_effects", sa.Text(), nullable=False, server_default=""),
    )
    op.add_column(
        "skills",
        sa.Column(
            "requires_reboot", sa.Boolean(), nullable=False, server_default=sa.false()
        ),
    )
    op.add_column(
        "skills",
        sa.Column(
            "allowed_execution_context",
            sa.String(100),
            nullable=False,
            server_default="",
        ),
    )


def downgrade() -> None:
    for column in (
        "allowed_execution_context",
        "requires_reboot",
        "side_effects",
        "failure_condition",
        "success_condition",
        "expected_output",
        "preconditions",
        "required_privilege",
        "reversible",
        "security_sensitive",
        "requires_admin_approval",
        "requires_user_approval",
        "command_type",
    ):
        op.drop_column("skills", column)
