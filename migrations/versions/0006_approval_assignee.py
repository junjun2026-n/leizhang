"""Choose an independent enabled administrator for each new access request."""
from alembic import op
from sqlalchemy import inspect

revision = '0006'
down_revision = '0005'


def upgrade():
    bind = op.get_bind()
    if 'approver_id' not in {c['name'] for c in inspect(bind).get_columns('approvals')}:
        op.execute('ALTER TABLE approvals ADD COLUMN approver_id VARCHAR(36) REFERENCES users(id)')
    op.execute('CREATE INDEX IF NOT EXISTS ix_approvals_approver_id ON approvals (approver_id)')


def downgrade():
    raise RuntimeError('Approval assignment history must be retained')
