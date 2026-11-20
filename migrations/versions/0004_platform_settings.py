# ============================================================
# 文件名称：0004_platform_settings.py
# 生成日期：2026-10-20
# 修改日期：2026-11-20
# 版本信息：v0.261115
# 作    者：JUN
# 备    注：本程序由AI辅助完成。
#           文件功能：实现 0004_platform_settings 模块相关功能。
#           文件用途：供堡垒机的 leizhang/migrations/versions/0004_platform_settings.py 模块使用。
#           注意事项：运行前检查依赖与配置；涉及数据或服务变更时先备份并验证。
# ============================================================
"""Platform appearance settings."""
from alembic import op
from jump_ssh.models import PlatformSetting

revision = '0004'
down_revision = '0003'


def upgrade():
    PlatformSetting.__table__.create(op.get_bind(), checkfirst=True)
    op.execute('''DO $$ BEGIN IF EXISTS (SELECT FROM pg_roles WHERE rolname='jump_runtime') THEN
        GRANT SELECT, INSERT, UPDATE, DELETE ON platform_settings TO jump_runtime;
    END IF; END; $$''')


def downgrade():
    op.drop_table('platform_settings')
