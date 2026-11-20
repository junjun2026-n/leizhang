# ============================================================
# 文件名称：0012_mysql_platform_lock.py
# 生成日期：2026-11-19
# 修改日期：2026-11-20
# 版本信息：v0.261115
# 作    者：JUN
# 备    注：本程序由AI辅助完成。
#           文件功能：实现 0012_mysql_platform_lock 模块相关功能。
#           文件用途：供堡垒机的 leizhang/migrations/versions/0012_mysql_platform_lock.py 模块使用。
#           注意事项：运行前检查依赖与配置；涉及数据或服务变更时先备份并验证。
# ============================================================
"""Portable mutex table used by MySQL deployments."""
from alembic import op
import sqlalchemy as sa

revision = '0012'
down_revision = '0011'

def upgrade():
    if 'platform_locks' not in sa.inspect(op.get_bind()).get_table_names():
        op.create_table('platform_locks', sa.Column('key', sa.String(64), primary_key=True))

def downgrade():
    op.drop_table('platform_locks')
