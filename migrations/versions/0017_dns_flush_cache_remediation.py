"""Wires the newly-registered ``dns.flush_cache`` skill (migration ``0016``)
into the existing ``dns_resolution_failure`` reference knowledge workflow
(migration ``0013``), turning its final step from an honest
"no registered remediation skill exists" ``escalate`` into a real
``remediate`` step -- without touching the workflow's own safety judgment
about DNS *misconfiguration*.

This is a genuinely narrow addition, not a reinterpretation of the original
workflow: the ``check_precondition`` step (compare configured DNS servers
against the organization's baseline) is completely unchanged, and the
final ``escalate`` step still fires whenever config deviates from baseline
or resolution still fails after the flush -- reconfiguring DNS servers
themselves is still not something any registered skill can do. The one new
capability is trying a safe, reversible-by-construction cache flush before
giving up on a device whose configuration is already correct.

Only ``diagnostic_steps`` rows change. ``issue_definitions.content_hash``
(``helpdesktool.knowledge.compute_issue_definition_hash``) deliberately
does not cover step content -- see that function's own docstring -- so no
hash recomputation is needed or safe to skip here.
"""

from __future__ import annotations

import uuid

import sqlalchemy as sa
from alembic import op

revision = "0017_dns_flush_cache_remediation"
down_revision = "0016_dns_flush_cache_skill"
branch_labels = None
depends_on = None

_REMEDIATE_DESCRIPTION = (
    "Configured DNS servers already match the organization's known-good "
    "baseline, but resolution is still failing -- attempt dns.flush_cache "
    "to rule out a stale local resolver cache before escalating. This "
    "never reconfigures DNS servers themselves."
)
_VERIFY_DESCRIPTION = (
    "Confirm resolution succeeds against the organization's actual "
    "configured resolvers after the cache flush, never a substituted "
    "public resolver."
)
_ESCALATE_DESCRIPTION = (
    "Escalate to an operator/network team if configured DNS servers "
    "deviate from the organization's baseline, or if resolution still "
    "fails after a cache flush -- no registered skill can reconfigure DNS "
    "servers themselves."
)


def _workflow_id(bind: sa.engine.Connection) -> str:
    return bind.execute(
        sa.text(
            "SELECT dw.id FROM diagnostic_workflows dw "
            "JOIN issue_definitions idf ON idf.id = dw.issue_definition_id "
            "WHERE idf.issue_key = 'dns_resolution_failure' AND dw.active = true"
        )
    ).scalar_one()


def upgrade() -> None:
    bind = op.get_bind()
    workflow_id = _workflow_id(bind)

    # Free up step_order=3 for the new "verify" step before inserting into
    # it, by moving the existing "escalate" step to step_order=4 first.
    bind.execute(
        sa.text(
            "UPDATE diagnostic_steps SET step_order = 4, description = :description "
            "WHERE workflow_id = :workflow_id AND step_order = 3"
        ),
        {"workflow_id": workflow_id, "description": _ESCALATE_DESCRIPTION},
    )
    bind.execute(
        sa.text(
            "UPDATE diagnostic_steps SET step_type = 'remediate', "
            "description = :description, remediation_skill_id = 'dns.flush_cache' "
            "WHERE workflow_id = :workflow_id AND step_order = 2"
        ),
        {"workflow_id": workflow_id, "description": _REMEDIATE_DESCRIPTION},
    )
    bind.execute(
        sa.text(
            "INSERT INTO diagnostic_steps "
            "(id, workflow_id, step_order, step_type, description, "
            "remediation_skill_id, verification_description, rollback_skill_id, "
            "reference_description) "
            "VALUES (:id, :workflow_id, 3, 'verify', :description, NULL, '', NULL, '')"
        ),
        {
            "id": str(uuid.uuid4()),
            "workflow_id": workflow_id,
            "description": _VERIFY_DESCRIPTION,
        },
    )


def downgrade() -> None:
    bind = op.get_bind()
    workflow_id = _workflow_id(bind)
    bind.execute(
        sa.text(
            "DELETE FROM diagnostic_steps "
            "WHERE workflow_id = :workflow_id AND step_order = 3"
        ),
        {"workflow_id": workflow_id},
    )
    bind.execute(
        sa.text(
            "UPDATE diagnostic_steps SET step_type = 'verify', "
            "description = :description, remediation_skill_id = NULL "
            "WHERE workflow_id = :workflow_id AND step_order = 2"
        ),
        {
            "workflow_id": workflow_id,
            "description": (
                "Confirm resolution succeeds against the organization's actual "
                "configured resolvers, never a substituted public resolver."
            ),
        },
    )
    bind.execute(
        sa.text(
            "UPDATE diagnostic_steps SET step_order = 3, description = :description "
            "WHERE workflow_id = :workflow_id AND step_order = 4"
        ),
        {
            "workflow_id": workflow_id,
            "description": (
                "No registered remediation skill exists for DNS "
                "reconfiguration; escalate to an operator/network team."
            ),
        },
    )
