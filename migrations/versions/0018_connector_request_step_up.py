"""Step-up verification for high-risk connector requests (Phase 3/Phase 9):
before this migration, an admin approving a password reset / account
unlock / MFA reset had no way to independently confirm the requester still
controls their own identity beyond the channel-native id that created the
request -- e.g. a Slack/Google Chat identity link that might be stale or,
in a compromise scenario, itself under attacker control.

Adds a short-lived, single-use, hashed step-up code the *requester* must
retrieve through their own authenticated web-console session (``GET
/v1/connector-requests/{id}/step-up-code`` in ``api.py`` — restricted to
the exact ``requested_by`` user id) and hand to their approver out of
band. ``POST /v1/connector-requests/{id}/decision`` now refuses to
approve a high-risk request until the correct, unexpired code is supplied
-- never for ``deny``, which executes nothing. Only the SHA-256 hash is
ever stored, mirroring ``EnrollmentToken.token_hash``'s exact pattern; the
raw code exists only in the one HTTP response that generates it.
"""

import sqlalchemy as sa
from alembic import op

revision = "0018_connector_request_step_up"
down_revision = "0017_dns_flush_cache_remediation"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "connector_requests",
        sa.Column("step_up_code_hash", sa.String(64)),
    )
    op.add_column(
        "connector_requests",
        sa.Column("step_up_code_expires_at", sa.DateTime(timezone=True)),
    )


def downgrade() -> None:
    op.drop_column("connector_requests", "step_up_code_expires_at")
    op.drop_column("connector_requests", "step_up_code_hash")
