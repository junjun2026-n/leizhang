"""Allow password-only connections without requiring a pinned host key."""
from alembic import op
from sqlalchemy import inspect

revision = '0003'
down_revision = '0002'


def upgrade():
    columns = {column['name'] for column in inspect(op.get_bind()).get_columns('assets')}
    if 'verify_host_key' not in columns:
        # Preserve strict checking for assets already configured before this change.
        op.execute('ALTER TABLE assets ADD COLUMN verify_host_key BOOLEAN NOT NULL DEFAULT true')
        op.execute('ALTER TABLE assets ALTER COLUMN verify_host_key SET DEFAULT false')


def downgrade():
    raise RuntimeError('Host verification policy downgrade requires explicit review')
