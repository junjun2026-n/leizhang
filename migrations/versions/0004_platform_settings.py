"""Platform appearance settings."""
from alembic import op
from jump_ssh.models import PlatformSetting

revision = '0004'
down_revision = '0003'


def upgrade():
    PlatformSetting.__table__.create(op.get_bind(), checkfirst=True)
    op.execute('''DO $$ BEGIN IF EXISTS (SELECT FROM pg_roles WHERE rolname='jump_runtime') THEN
        GRANT SELECT, INSERT, UPDATE, DELETE ON platform_settings TO jump_runtime;
    END IF; END; $$''')


def downgrade():
    op.drop_table('platform_settings')
