"""Editable roles and terminal command policies; existing users remain unrestricted."""
from alembic import op
import sqlalchemy as sa

revision = '0010'
down_revision = '0009'


def upgrade():
    # Explicit columns keep historical migrations independent of future models.
    bind = op.get_bind()
    if 'roles' not in sa.inspect(bind).get_table_names():
        op.create_table('roles',
            sa.Column('id', sa.String(36), primary_key=True),
            sa.Column('name', sa.String(80), nullable=False, unique=True),
            sa.Column('base_role', sa.String(20), nullable=False),
            sa.Column('description', sa.String(300), nullable=False, server_default=''),
            sa.Column('builtin', sa.Boolean(), nullable=False, server_default=sa.false()),
            sa.Column('command_mode', sa.String(20), nullable=False, server_default='off'),
            sa.Column('command_rules', sa.Text(), nullable=False, server_default='[]'))
    for key, name in [('admin', '管理员'), ('operator', '运维人员'), ('auditor', '审计员')]:
        bind.execute(sa.text("INSERT INTO roles (id,name,base_role,description,builtin,command_mode,command_rules) VALUES (:key,:name,:key,'',true,'off','[]') ON CONFLICT (id) DO NOTHING"), dict(key=key, name=name))
    columns = {c['name'] for c in sa.inspect(bind).get_columns('users')}
    if 'role_id' not in columns:
        op.add_column('users', sa.Column('role_id', sa.String(36), sa.ForeignKey('roles.id'), nullable=True))
        op.create_index('ix_users_role_id', 'users', ['role_id'])
    if 'command_mode' not in columns:
        op.add_column('users', sa.Column('command_mode', sa.String(20), nullable=False, server_default='off'))
    if 'command_rules' not in columns:
        op.add_column('users', sa.Column('command_rules', sa.Text(), nullable=False, server_default='[]'))
    op.execute('UPDATE users SET role_id = role')
    op.execute("""DO $$ BEGIN IF EXISTS (SELECT FROM pg_roles WHERE rolname='jump_runtime') THEN
        GRANT SELECT,INSERT,UPDATE,DELETE ON roles TO jump_runtime;
    END IF; END; $$""")


def downgrade():
    raise RuntimeError('Retain role and command policy history; restore a reviewed backup instead')
