# ============================================================
# 文件名称：db.py
# 生成日期：2026-10-20
# 修改日期：2026-11-20
# 版本信息：v0.261115
# 作    者：JUN
# 备    注：本程序由AI辅助完成。
#           文件功能：管理数据库连接及数据访问。
#           文件用途：供堡垒机的 leizhang/jump_ssh/db.py 模块使用。
#           注意事项：运行前检查依赖与配置；涉及数据或服务变更时先备份并验证。
# ============================================================
from contextlib import contextmanager
import hashlib
from sqlalchemy import create_engine, text
from sqlalchemy.engine import make_url
from sqlalchemy.orm import sessionmaker


def database(url):
    kwargs = dict(pool_pre_ping=True, pool_size=10, max_overflow=10)
    engine = storage_engine(url, **kwargs)
    factory = sessionmaker(engine, expire_on_commit=False)
    return engine, factory


def storage_engine(url, **kwargs):
    if make_url(url).get_backend_name() in ('mysql', 'mariadb'):
        kwargs['connect_args'] = {'charset': 'utf8mb4', 'connect_timeout': 5}
        if make_url(url).query.get('ssl_verify_cert') == 'true':
            kwargs['connect_args'].update(ssl_verify_cert=True, ssl_verify_identity=True)
    else:
        kwargs.setdefault('connect_args', {'connect_timeout': 5})
    return create_engine(url, **kwargs)


def advisory_lock(db, name):
    """A transaction-scoped mutex on both supported storage engines."""
    if db.bind.dialect.name == 'postgresql':
        db.execute(text('SELECT pg_advisory_xact_lock(hashtext(:name))'), {'name': str(name)})
    else:
        key = hashlib.sha256(str(name).encode()).hexdigest()
        db.execute(text('INSERT INTO platform_locks (`key`) VALUES (:key) ON DUPLICATE KEY UPDATE `key`=VALUES(`key`)'), {'key': key})
        db.execute(text('SELECT `key` FROM platform_locks WHERE `key`=:key FOR UPDATE'), {'key': key})


@contextmanager
def transaction(factory):
    with factory() as db:
        with db.begin():
            yield db
