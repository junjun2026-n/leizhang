# ============================================================
# 文件名称：0009_protocols.py
# 生成日期：2026-10-22
# 修改日期：2026-11-20
# 版本信息：v0.261115
# 作    者：JUN
# 备    注：本程序由AI辅助完成。
#           文件功能：实现 0009_protocols 模块相关功能。
#           文件用途：供堡垒机的 leizhang/migrations/versions/0009_protocols.py 模块使用。
#           注意事项：运行前检查依赖与配置；涉及数据或服务变更时先备份并验证。
# ============================================================
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
