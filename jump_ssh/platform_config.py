# ============================================================
# 文件名称：platform_config.py
# 生成日期：2026-10-20
# 修改日期：2026-11-20
# 版本信息：v0.261115
# 作    者：JUN
# 备    注：本程序由AI辅助完成。
#           文件功能：实现 platform_config 模块相关功能。
#           文件用途：供堡垒机的 leizhang/jump_ssh/platform_config.py 模块使用。
#           注意事项：运行前检查依赖与配置；涉及数据或服务变更时先备份并验证。
# ============================================================
"""Administrator settings and public branding. Never expose connection secrets."""
import base64
import os
import subprocess
import sys
import threading
from typing import Literal

from dotenv import dotenv_values, set_key
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import create_engine, text
from sqlalchemy.engine import URL, make_url

from .api import admin, audit
from .config import ROOT
from .permissions import require
from .db import transaction, advisory_lock, storage_engine
from .models import PlatformSetting
from .local import secure

router = APIRouter(prefix='/api')
initialization_lock = threading.Lock()


class Appearance(BaseModel):
    platform_name: str = Field(default='JUMP SSH 堡垒机', min_length=1, max_length=60)
    subtitle: str = Field(default='资产访问与会话审计', max_length=120)
    theme: Literal['light', 'dark'] = 'light'
    primary_color: str = Field(default='#147e71', pattern=r'^#[0-9a-fA-F]{6}$')
    font: Literal['system', 'yahei', 'simsun', 'mono'] = 'system'
    font_size: int = Field(default=14, ge=12, le=20)
    logo: str = Field(default='', max_length=45000)

    @field_validator('logo')
    @classmethod
    def valid_logo(cls, value):
        if not value:
            return value
        try:
            header, encoded = value.split(',', 1)
            raw = base64.b64decode(encoded, validate=True)
            signatures = {
                'data:image/png;base64': raw.startswith(b'\x89PNG\r\n\x1a\n'),
                'data:image/jpeg;base64': raw.startswith(b'\xff\xd8\xff'),
                'data:image/webp;base64': raw[:4] == b'RIFF' and raw[8:12] == b'WEBP',
            }
            if len(raw) > 32768 or not signatures.get(header):
                raise ValueError()
        except (ValueError, TypeError):
            raise ValueError('LOGO 仅支持不超过 32KB 的 PNG、JPEG、WebP 图片') from None
        return value


def appearance(factory):
    with transaction(factory) as db:
        row = db.get(PlatformSetting, 'appearance')
        return Appearance.model_validate_json(row.value) if row else Appearance()


@router.get('/platform')
def public_platform(request: Request):
    return appearance(request.app.state.factory)


@router.put('/settings/appearance')
def save_appearance(body: Appearance, request: Request, user=Depends(require('settings.appearance'))):
    with transaction(request.app.state.factory) as db:
        # Serialize concurrent administrator edits, including the first insert.
        advisory_lock(db, 'platform-appearance')
        row = db.get(PlatformSetting, 'appearance')
        if not row:
            row = PlatformSetting(key='appearance')
            db.add(row)
        row.value = body.model_dump_json()
        audit(db, user, 'platform_appearance_updated', 'appearance', request)
    return body


def config_path(request):
    return getattr(request.app.state, 'config_path', ROOT / '.env')


def pending_url(request):
    return (dotenv_values(config_path(request)).get('DATABASE_URL') or
            request.app.state.settings.database_url)


def database_info(value):
    url = make_url(value)
    kind = 'mysql' if url.get_backend_name() in ('mysql', 'mariadb') else 'postgresql'
    return dict(database_type=kind, host=url.host or '', port=url.port or (3306 if kind == 'mysql' else 5432), database=url.database or '',
                username=url.username or '', sslmode=url.query.get('sslmode', 'prefer'),
                mysql_ssl='require' if url.query.get('ssl_verify_cert') == 'true' else 'disable',
                password='', password_configured=bool(url.password))


@router.get('/settings/database')
def read_database(request: Request, user=Depends(require('settings.database'))):
    active = request.app.state.settings.database_url
    pending = pending_url(request)
    return dict(active=database_info(active), configured=database_info(pending),
                restart_required=make_url(active) != make_url(pending))


class DatabaseInput(BaseModel):
    database_type: Literal['postgresql', 'mysql'] = 'postgresql'
    host: str = Field(min_length=1, max_length=253, pattern=r'^[a-zA-Z0-9_.:\-]+$')
    port: int = Field(default=5432, ge=1, le=65535)
    database: str = Field(min_length=1, max_length=63)
    username: str = Field(min_length=1, max_length=63)
    password: str = Field(default='', max_length=1024)
    sslmode: Literal['disable', 'prefer', 'require', 'verify-ca', 'verify-full'] = 'prefer'
    mysql_ssl: Literal['disable', 'require'] = 'disable'


def build_url(body, request):
    previous = make_url(pending_url(request))
    previous_type = 'mysql' if previous.get_backend_name() in ('mysql', 'mariadb') else 'postgresql'
    password = body.password or previous.password
    if not body.password and (body.database_type, body.host, body.port, body.username) != (previous_type, previous.host, previous.port or (3306 if previous_type == 'mysql' else 5432), previous.username):
        raise HTTPException(400, '更换数据库主机、端口或用户时请重新填写密码')
    same_database = (body.database_type, body.host, body.port, body.username, body.database) == (previous_type, previous.host, previous.port or (3306 if previous_type == 'mysql' else 5432), previous.username, previous.database)
    query = dict(previous.query) if same_database else {}
    if body.database_type == 'mysql':
        query.pop('sslmode', None)
        query['charset'] = 'utf8mb4'
        query.pop('ssl', None)
        query.pop('ssl_verify_cert', None)
        query.pop('ssl_verify_identity', None)
        if body.mysql_ssl == 'require':
            query['ssl_verify_cert'] = 'true'
            query['ssl_verify_identity'] = 'true'
    else:
        query['sslmode'] = body.sslmode
    return URL.create('mysql+pymysql' if body.database_type == 'mysql' else 'postgresql+psycopg', username=body.username, password=password,
                      host=body.host, port=body.port, database=body.database,
                      query=query)


def check_database(url):
    engine = storage_engine(url, pool_pre_ping=True)
    try:
        with engine.connect() as conn:
            from sqlalchemy import inspect
            version = conn.scalar(text('SELECT VERSION()'))
            ready = {'users','roles','platform_settings','ssh_sessions','system_accounts','account_grants'}.issubset(inspect(conn).get_table_names())
            if ready:
                conn.execute(text('SELECT id FROM users LIMIT 1'))
                from sqlalchemy import select
                conn.execute(select(PlatformSetting.key).limit(1))
        return dict(connected=True, version=version, schema_ready=ready, database_type=engine.dialect.name)
    except Exception:
        raise HTTPException(400, '数据库连接或权限检查失败，请检查地址、端口、账号、密码和 SSL 配置') from None
    finally:
        engine.dispose()


@router.post('/settings/database/test')
def test_database(body: DatabaseInput, request: Request, user=Depends(require('settings.database'))):
    return check_database(build_url(body, request))


@router.post('/settings/database/initialize')
def initialize_database(body: DatabaseInput, request: Request, user=Depends(require('settings.database'))):
    from alembic.config import Config
    from alembic.script import ScriptDirectory
    from .models import User
    from .db import database
    from sqlalchemy import inspect, select
    url = build_url(body, request)
    engine = storage_engine(url)
    with initialization_lock:
        try:
            with engine.connect() as connection:
                tables=set(inspect(connection).get_table_names())
                if tables:
                    head=ScriptDirectory.from_config(Config(str(ROOT/'alembic.ini'))).get_current_head()
                    if 'alembic_version' not in tables or connection.scalar(text('SELECT version_num FROM alembic_version')) != head:
                        raise HTTPException(409,'目标库已有数据或旧版表结构，请使用迁移工具升级；初始化不会覆盖或重建已有表。')
            if not tables:
                env=dict(os.environ, MIGRATION_DATABASE_URL=url.render_as_string(hide_password=False))
                result=subprocess.run([sys.executable,'-m','jump_ssh.cli','migrate'],cwd=ROOT,env=env,capture_output=True,timeout=120)
                if result.returncode:
                    raise ValueError('migration failed')
            target_engine,factory=database(url)
            try:
                with transaction(factory) as db:
                    advisory_lock(db, 'database-initialize')
                    if not db.scalar(select(User.id).limit(1)):
                        db.add(User(username=user.username,password_hash=user.password_hash,role='admin',role_id='admin'))
            finally:
                target_engine.dispose()
        except HTTPException:
            raise
        except Exception:
            raise HTTPException(422,'数据库初始化失败，请检查目标数据库是否存在、建表及创建函数权限。') from None
        finally:
            engine.dispose()
    return dict(ok=True,message='初始化完成，已有数据及密码保留。空库已创建当前操作用户的管理员账号；未切换连接，未迁移资源与审计数据。')

@router.put('/settings/database')
def save_database(body: DatabaseInput, request: Request, user=Depends(require('settings.database'))):
    url = build_url(body, request)
    result = check_database(url)
    if not result['schema_ready']:
        raise HTTPException(400, '目标数据库尚未准备好：请先迁移原库数据并执行数据库升级，再保存连接配置')
    with transaction(request.app.state.factory) as db:
        audit(db, user, 'database_configuration_updated', 'database', request)
    # python-dotenv replaces the configuration atomically; never log the URL/password.
    set_key(str(config_path(request)), 'DATABASE_URL', url.render_as_string(hide_password=False))
    secure(config_path(request))
    return dict(saved=True, restart_required=True, message='数据库配置已保存，重启服务后生效；此操作不会迁移原库数据')
