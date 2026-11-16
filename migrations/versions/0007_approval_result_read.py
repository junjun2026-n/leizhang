"""Track unread approval decisions for the applicant."""
from alembic import op
from sqlalchemy import inspect

revision = '0007'
down_revision = '0006'


def upgrade():
    columns = {c['name'] for c in inspect(op.get_bind()).get_columns('approvals')}
    if 'result_read' not in columns:
        op.execute('ALTER TABLE approvals ADD COLUMN result_read BOOLEAN NOT NULL DEFAULT true')


def downgrade():
    op.drop_column('approvals', 'result_read')
