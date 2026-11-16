"""Initial independent PostgreSQL schema.

Revision ID: 0001
"""
from alembic import op
from jump_ssh.models import Base

revision = '0001'
down_revision = None


def upgrade():
    Base.metadata.create_all(op.get_bind())
    op.execute('''CREATE FUNCTION prevent_audit_mutation() RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN RAISE EXCEPTION 'Audit records are append only'; END; $$''')
    for table in ('audit_logs', 'recordings'):
        op.execute(f'CREATE TRIGGER immutable_{table} BEFORE UPDATE OR DELETE ON {table} FOR EACH ROW EXECUTE FUNCTION prevent_audit_mutation()')
        op.execute(f'CREATE TRIGGER immutable_truncate_{table} BEFORE TRUNCATE ON {table} FOR EACH STATEMENT EXECUTE FUNCTION prevent_audit_mutation()')
    # Docker provisioning creates an unprivileged runtime role before migration.
    op.execute('''DO $$ BEGIN IF EXISTS (SELECT FROM pg_roles WHERE rolname='jump_runtime') THEN
        GRANT USAGE ON SCHEMA public TO jump_runtime;
        GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO jump_runtime;
        GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO jump_runtime;
        REVOKE UPDATE, DELETE, TRUNCATE ON audit_logs, recordings FROM jump_runtime;
        REVOKE ALL ON alembic_version FROM jump_runtime;
    END IF; END; $$''')


def downgrade():
    raise RuntimeError('禁止自动删除审计数据库；请从经过验证的备份恢复')
