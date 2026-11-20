# ============================================================
# 文件名称：0011_role_permissions.py
# 生成日期：2026-10-23
# 修改日期：2026-11-20
# 版本信息：v0.261115
# 作    者：JUN
# 备    注：本程序由AI辅助完成。
#           文件功能：实现 0011_role_permissions 模块相关功能。
#           文件用途：供堡垒机的 leizhang/migrations/versions/0011_role_permissions.py 模块使用。
#           注意事项：运行前检查依赖与配置；涉及数据或服务变更时先备份并验证。
# ============================================================
"""Explicit platform capabilities; NULL preserves existing role defaults."""
from alembic import op
import sqlalchemy as sa

revision = '0011'
down_revision = '0010'


def upgrade():
    if 'permissions' not in {c['name'] for c in sa.inspect(op.get_bind()).get_columns('roles')}:
        op.add_column('roles', sa.Column('permissions', sa.Text(), nullable=True))


def downgrade():
    raise RuntimeError('Restore a reviewed backup to retain permission change history')
