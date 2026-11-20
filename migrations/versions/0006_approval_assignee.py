# ============================================================
# 文件名称：0006_approval_assignee.py
# 生成日期：2026-10-20
# 修改日期：2026-11-20
# 版本信息：v0.261115
# 作    者：JUN
# 备    注：本程序由AI辅助完成。
#           文件功能：实现 0006_approval_assignee 模块相关功能。
#           文件用途：供堡垒机的 leizhang/migrations/versions/0006_approval_assignee.py 模块使用。
#           注意事项：运行前检查依赖与配置；涉及数据或服务变更时先备份并验证。
# ============================================================
"""Choose an independent enabled administrator for each new access request."""
from alembic import op
from sqlalchemy import inspect

revision = '0006'
down_revision = '0005'


def upgrade():
    bind = op.get_bind()
    if 'approver_id' not in {c['name'] for c in inspect(bind).get_columns('approvals')}:
        op.execute('ALTER TABLE approvals ADD COLUMN approver_id VARCHAR(36) REFERENCES users(id)')
    op.execute('CREATE INDEX IF NOT EXISTS ix_approvals_approver_id ON approvals (approver_id)')


def downgrade():
    raise RuntimeError('Approval assignment history must be retained')
