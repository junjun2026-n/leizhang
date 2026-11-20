# ============================================================
# 文件名称：0008_existing_approval_notifications.py
# 生成日期：2026-10-21
# 修改日期：2026-11-20
# 版本信息：v0.261115
# 作    者：JUN
# 备    注：本程序由AI辅助完成。
#           文件功能：实现 0008_existing_approval_notifications 模块相关功能。
#           文件用途：供堡垒机的 leizhang/migrations/versions/0008_existing_approval_notifications.py 模块使用。
#           注意事项：运行前检查依赖与配置；涉及数据或服务变更时先备份并验证。
# ============================================================
"""Expose existing decisions when introducing approval result messages."""
from alembic import op

revision = '0008'
down_revision = '0007'


def upgrade():
    op.execute("UPDATE approvals SET result_read=false WHERE state IN ('approved','rejected')")


def downgrade():
    pass
