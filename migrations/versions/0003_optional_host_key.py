# ============================================================
# 文件名称：0003_optional_host_key.py
# 生成日期：2026-10-20
# 修改日期：2026-11-20
# 版本信息：v0.261115
# 作    者：JUN
# 备    注：本程序由AI辅助完成。
#           文件功能：实现 0003_optional_host_key 模块相关功能。
#           文件用途：供堡垒机的 leizhang/migrations/versions/0003_optional_host_key.py 模块使用。
#           注意事项：运行前检查依赖与配置；涉及数据或服务变更时先备份并验证。
# ============================================================
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
