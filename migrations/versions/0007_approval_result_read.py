# ============================================================
# 文件名称：0007_approval_result_read.py
# 生成日期：2026-10-21
# 修改日期：2026-11-20
# 版本信息：v0.261115
# 作    者：JUN
# 备    注：本程序由AI辅助完成。
#           文件功能：实现 0007_approval_result_read 模块相关功能。
#           文件用途：供堡垒机的 leizhang/migrations/versions/0007_approval_result_read.py 模块使用。
#           注意事项：运行前检查依赖与配置；涉及数据或服务变更时先备份并验证。
# ============================================================
"""Track unread approval decisions for the applicant."""
from alembic import op
from sqlalchemy import inspect

revision = '0007'
down_revision = '0006'


def upgrade():
    columns = {c['name'] for c in inspect(op.get_bind()).get_columns('approvals')}
    if 'result_read' not in columns:
        op.execute('ALTER TABLE approvals ADD COLUMN result_read BOOLEAN NOT NULL DEFAULT true')


def downgrade():
    op.drop_column('approvals', 'result_read')
