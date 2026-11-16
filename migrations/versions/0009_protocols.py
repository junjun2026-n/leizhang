"""Audited SQL, desktop, Telnet and web sessions; existing assets remain SSH."""
from alembic import op
from sqlalchemy import inspect
from jump_ssh.models import ProtocolAudit

revision = '0009'
down_revision = '0008'


def upgrade():
    bind = op.get_bind()
    columns = {c['name'] for c in inspect(bind).get_columns('assets')}
    for name, definition in (
        ('protocol', "VARCHAR(20) NOT NULL DEFAULT 'ssh'"),
        ('database_name', "VARCHAR(128) NOT NULL DEFAULT ''"),
        ('domain', "VARCHAR(128) NOT NULL DEFAULT ''"),
        ('http_scheme', "VARCHAR(8) NOT NULL DEFAULT 'http'"),
        ('http_path', "VARCHAR(1024) NOT NULL DEFAULT '/'"),
        ('tls_verify', 'BOOLEAN NOT NULL DEFAULT true'),
    ):
        if name not in columns:
            op.execute(f'ALTER TABLE assets ADD COLUMN {name} {definition}')
    if 'protocol' not in {c['name'] for c in inspect(bind).get_columns('ssh_sessions')}:
        op.execute("ALTER TABLE ssh_sessions ADD COLUMN protocol VARCHAR(20) NOT NULL DEFAULT 'ssh'")
    ProtocolAudit.__table__.create(bind, checkfirst=True)
    op.execute('CREATE OR REPLACE TRIGGER immutable_protocol_audit BEFORE UPDATE OR DELETE ON protocol_audit FOR EACH ROW EXECUTE FUNCTION prevent_audit_mutation()')
    op.execute('CREATE OR REPLACE TRIGGER immutable_truncate_protocol_audit BEFORE TRUNCATE ON protocol_audit FOR EACH STATEMENT EXECUTE FUNCTION prevent_audit_mutation()')
    op.execute('''DO $$ BEGIN IF EXISTS (SELECT FROM pg_roles WHERE rolname='jump_runtime') THEN
        GRANT SELECT,INSERT ON protocol_audit TO jump_runtime;
        GRANT USAGE,SELECT ON SEQUENCE protocol_audit_id_seq TO jump_runtime;
        REVOKE UPDATE,DELETE,TRUNCATE ON protocol_audit FROM jump_runtime;
    END IF; END; $$''')


def downgrade():
    raise RuntimeError('Protocol audit records must be retained; restore a reviewed backup instead')
