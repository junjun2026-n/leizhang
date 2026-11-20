# ============================================================
# 文件名称：env.py
# 生成日期：2026-10-20
# 修改日期：2026-11-20
# 版本信息：v0.261115
# 作    者：JUN
# 备    注：本程序由AI辅助完成。
#           文件功能：实现 env 模块相关功能。
#           文件用途：供堡垒机的 leizhang/migrations/env.py 模块使用。
#           注意事项：运行前检查依赖与配置；涉及数据或服务变更时先备份并验证。
# ============================================================
import os
from alembic import context
from sqlalchemy import create_engine, pool
from jump_ssh.config import Settings
from jump_ssh.models import Base

settings = Settings()
migration_url = os.environ.get('MIGRATION_DATABASE_URL') or settings.database_url
if context.is_offline_mode():
    context.configure(url=migration_url, target_metadata=Base.metadata, literal_binds=True)
    with context.begin_transaction(): context.run_migrations()
else:
    engine = create_engine(migration_url, poolclass=pool.NullPool)
    with engine.connect() as connection:
        context.configure(connection=connection, target_metadata=Base.metadata)
        with context.begin_transaction(): context.run_migrations()
