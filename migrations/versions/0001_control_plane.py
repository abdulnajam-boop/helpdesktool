"""Initial multi-tenant control-plane schema."""

from alembic import op

from helpdesktool.database import Base
from helpdesktool import db_models  # noqa: F401

revision = "0001_control_plane"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    Base.metadata.create_all(bind=op.get_bind())


def downgrade() -> None:
    Base.metadata.drop_all(bind=op.get_bind())
