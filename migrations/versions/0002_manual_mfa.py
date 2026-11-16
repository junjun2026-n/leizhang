"""MFA is enabled explicitly by an administrator after verification."""
from alembic import op
from sqlalchemy import inspect

revision = '0002'
down_revision = '0001'


def upgrade():
    # 0001 originally bootstrapped from ORM metadata; support both fresh and existing databases.
    columns = {column['name'] for column in inspect(op.get_bind()).get_columns('users')}
    if 'mfa_enabled' not in columns:
        op.execute('ALTER TABLE users ADD COLUMN mfa_enabled BOOLEAN NOT NULL DEFAULT false')
    if 'mfa_setup_expires_at' not in columns:
        op.execute('ALTER TABLE users ADD COLUMN mfa_setup_expires_at TIMESTAMPTZ')


def downgrade():
    raise RuntimeError('MFA configuration downgrade requires explicit review')
