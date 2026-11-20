# ============================================================
# 文件名称：0005_system_accounts.py
# 生成日期：2026-10-20
# 修改日期：2026-11-20
# 版本信息：v0.261115
# 作    者：JUN
# 备    注：本程序由AI辅助完成。
#           文件功能：实现 0005_system_accounts 模块相关功能。
#           文件用途：供堡垒机的 leizhang/migrations/versions/0005_system_accounts.py 模块使用。
#           注意事项：运行前检查依赖与配置；涉及数据或服务变更时先备份并验证。
# ============================================================
"""Independent system accounts, account-specific grants, session identity snapshots."""
from alembic import op
from sqlalchemy import inspect
from jump_ssh.models import SystemAccount, AccountGrant

revision = '0005'
down_revision = '0004'


def upgrade():
    bind = op.get_bind()
    SystemAccount.__table__.create(bind, checkfirst=True)
    AccountGrant.__table__.create(bind, checkfirst=True)
    columns = {column['name'] for column in inspect(bind).get_columns('ssh_sessions')}
    if 'account_id' not in columns:
        op.execute('ALTER TABLE ssh_sessions ADD COLUMN account_id VARCHAR(36) REFERENCES system_accounts(id)')
    if 'system_username' not in columns:
        op.execute("ALTER TABLE ssh_sessions ADD COLUMN system_username VARCHAR(80) NOT NULL DEFAULT ''")
    # Existing grants apply ONLY to the migrated original account, never to new accounts.
    op.execute('''INSERT INTO system_accounts(id,asset_id,username,auth_type,credential,enabled,deleted)
        SELECT id,id,username,auth_type,credential,true,false FROM assets
        ON CONFLICT DO NOTHING''')
    op.execute('''UPDATE ssh_sessions s SET account_id=a.id,system_username=a.username
        FROM assets a WHERE s.asset_id=a.id AND s.account_id IS NULL''')
    columns = {column['name'] for column in inspect(bind).get_columns('approvals')}
    if 'account_id' not in columns:
        op.execute('ALTER TABLE approvals ADD COLUMN account_id VARCHAR(36) REFERENCES system_accounts(id)')
    if 'system_username' not in columns:
        op.execute("ALTER TABLE approvals ADD COLUMN system_username VARCHAR(80) NOT NULL DEFAULT ''")
    op.execute('''UPDATE approvals p SET account_id=a.id,system_username=a.username
        FROM assets a WHERE p.asset_id=a.id AND p.account_id IS NULL''')
    op.execute('''DO $$ BEGIN IF EXISTS (SELECT FROM pg_roles WHERE rolname='jump_runtime') THEN
        GRANT SELECT,INSERT,UPDATE,DELETE ON system_accounts,account_grants TO jump_runtime;
    END IF; END; $$''')


def downgrade():
    raise RuntimeError('Account authorization downgrade requires an explicit data migration')
