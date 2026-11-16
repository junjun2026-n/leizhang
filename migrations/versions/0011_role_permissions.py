"""Explicit platform capabilities; NULL preserves existing role defaults."""
from alembic import op
import sqlalchemy as sa

revision = '0011'
down_revision = '0010'


def upgrade():
    if 'permissions' not in {c['name'] for c in sa.inspect(op.get_bind()).get_columns('roles')}:
        op.add_column('roles', sa.Column('permissions', sa.Text(), nullable=True))


def downgrade():
    raise RuntimeError('Restore a reviewed backup to retain permission change history')
