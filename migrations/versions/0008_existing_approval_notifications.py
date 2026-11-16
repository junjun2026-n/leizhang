"""Expose existing decisions when introducing approval result messages."""
from alembic import op

revision = '0008'
down_revision = '0007'


def upgrade():
    op.execute("UPDATE approvals SET result_read=false WHERE state IN ('approved','rejected')")


def downgrade():
    pass
