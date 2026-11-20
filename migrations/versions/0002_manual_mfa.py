# ============================================================
# 文件名称：0002_manual_mfa.py
# 生成日期：2026-10-20
# 修改日期：2026-11-20
# 版本信息：v0.261115
# 作    者：JUN
# 备    注：本程序由AI辅助完成。
#           文件功能：实现 0002_manual_mfa 模块相关功能。
#           文件用途：供堡垒机的 leizhang/migrations/versions/0002_manual_mfa.py 模块使用。
#           注意事项：运行前检查依赖与配置；涉及数据或服务变更时先备份并验证。
# ============================================================
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
