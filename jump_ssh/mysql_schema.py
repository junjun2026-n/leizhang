# ============================================================
# 文件名称：mysql_schema.py
# 生成日期：2026-11-19
# 修改日期：2026-11-20
# 版本信息：v0.261115
# 作    者：JUN
# 备    注：本程序由AI辅助完成。
#           文件功能：实现 mysql_schema 模块相关功能。
#           文件用途：供堡垒机的 leizhang/jump_ssh/mysql_schema.py 模块使用。
#           注意事项：运行前检查依赖与配置；涉及数据或服务变更时先备份并验证。
# ============================================================
"""Bootstrap a new MySQL storage database without PostgreSQL-specific migrations."""
from sqlalchemy import create_engine, inspect, select, text
from .models import Base, Role
from sqlalchemy.orm import Session
from .db import storage_engine


def initialize(url):
    engine = storage_engine(url)
    try:
        with engine.connect() as conn:
            tables = set(inspect(conn).get_table_names())
            if tables:
                if 'alembic_version' not in tables or conn.scalar(text('SELECT version_num FROM alembic_version')) != '0012':
                    raise ValueError('Target database contains an incompatible schema')
                return
        Base.metadata.create_all(engine)
        with engine.begin() as conn:
            for table in ('audit_logs', 'recordings', 'protocol_audit'):
                for event in ('UPDATE', 'DELETE'):
                    conn.execute(text(f"CREATE TRIGGER immutable_{table}_{event.lower()} BEFORE {event} ON {table} FOR EACH ROW SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='Audit records are append only'"))
        with Session(engine) as db, db.begin():
            for key, name in [('admin', '管理员'), ('operator', '运维人员'), ('auditor', '审计员')]:
                db.add(Role(id=key, name=name, base_role=key, builtin=True))
        with engine.begin() as conn:
            conn.execute(text('CREATE TABLE alembic_version (version_num VARCHAR(32) NOT NULL PRIMARY KEY)'))
            conn.execute(text("INSERT INTO alembic_version(version_num) VALUES ('0012')"))
    finally:
        engine.dispose()
