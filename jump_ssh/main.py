from contextlib import asynccontextmanager
from pathlib import Path
from urllib.parse import urlsplit

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from sqlalchemy import select, text

from .api import router
from .config import ROOT, Settings
from .db import database, transaction
from .models import SSHSession, now
from .security import Vault, password_hash
from .ssh import ssh_socket
from .platform_config import router as platform_router
from .account_api import router as account_router
from .protocol_api import router as protocol_router
from .role_api import router as role_router
from .sql_gateway import sql_socket
from .desktop_gateway import desktop_socket
from .http_gateway import http_socket
from .sftp_gateway import sftp_socket
from .log_forwarding import Forwarder
from .log_adapter import LogAdapter
from .log_api import router as log_router
from .native_ssh import router as native_router, start_listener


def create_app(settings=None):
    settings = settings or Settings()
    engine, factory = database(settings.database_url)
    forwarder=Forwarder(LogAdapter(factory,Vault(settings.master_key)))

    @asynccontextmanager
    async def lifespan(app):
        # This release supports ONE app instance; finish sessions orphaned by a restart.
        with transaction(factory) as db:
            for session in db.scalars(select(SSHSession).where(SSHSession.state.in_(['active','pending']))):
                session.state, session.ended_at, session.error = 'interrupted', now(), '服务重启'
        listener = await start_listener(app)
        forwarder.start()
        try:yield
        finally:
            forwarder.stop()
            if listener:
                listener.close()
                await listener.wait_closed()
        engine.dispose()

    app = FastAPI(title='JUMP SSH', version='v0.261115', lifespan=lifespan,
                  docs_url=None, redoc_url=None, openapi_url=None)
    app.state.settings, app.state.engine, app.state.factory = settings, engine, factory
    app.state.log_forwarder=forwarder
    app.state.vault = Vault(settings.master_key)
    app.state.dummy_hash = password_hash('dummy-non-login-password')

    @app.exception_handler(RequestValidationError)
    async def validation_error(request, error):
        labels = {'host_key':'SSH 主机公钥','host':'资产地址','port':'端口','username':'用户名',
                  'password':'密码','new_password':'新密码','old_password':'原密码','name':'名称',
                  'credential':'认证凭据','code':'动态验证码','reason':'申请原因'}
        errors = []
        for item in error.errors():
            field = str(item['loc'][-1])
            label = labels.get(field, field)
            kind, ctx = item['type'], item.get('ctx') or {}
            if kind == 'value_error': message = item['msg'].removeprefix('Value error, ')
            elif kind == 'missing': message = f'请填写{label}'
            elif kind == 'string_too_short': message = f'{label}至少需要 {ctx.get("min_length")} 个字符'
            elif kind == 'string_too_long': message = f'{label}不能超过 {ctx.get("max_length")} 个字符'
            elif kind == 'greater_than_equal': message = f'{label}不能小于 {ctx.get("ge")}'
            elif kind == 'less_than_equal': message = f'{label}不能大于 {ctx.get("le")}'
            else: message = f'{label}格式不正确，请检查后重试'
            errors.append({'field':field, 'message':message})
        return JSONResponse({'detail':'；'.join(item['message'] for item in errors), 'errors':errors}, status_code=422)

    @app.middleware('http')
    async def protect(request: Request, call_next):
        if request.method in ('POST','PUT','PATCH','DELETE'):
            origin = request.headers.get('origin', '')
            if origin not in settings.allowed_origins or urlsplit(origin).netloc != request.headers.get('host'):
                return JSONResponse({'detail':'请求来源不匹配'}, status_code=403)
            try: length = int(request.headers.get('content-length', '0'))
            except ValueError: return JSONResponse({'detail':'请求长度无效'}, status_code=400)
            if length > 65536:
                return JSONResponse({'detail':'请求过大'}, status_code=413)
        if request.headers.get('host') not in {urlsplit(origin).netloc for origin in settings.allowed_origins}:
            return JSONResponse({'detail':'访问域名不匹配'}, status_code=400)
        response = await call_next(request)
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-Frame-Options'] = 'DENY'
        response.headers['Referrer-Policy'] = 'no-referrer'
        response.headers['Cache-Control'] = 'no-store'
        response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; connect-src 'self'; img-src 'self' data:; object-src 'none'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'"
        if settings.secure: response.headers['Strict-Transport-Security'] = 'max-age=31536000'
        return response

    app.include_router(router)
    app.include_router(native_router)
    app.include_router(platform_router)
    app.include_router(log_router)
    app.include_router(account_router)
    app.include_router(protocol_router)
    app.include_router(role_router)
    app.websocket('/ws/ssh/{session_id}')(ssh_socket)
    app.websocket('/ws/sftp/{session_id}')(sftp_socket)
    app.websocket('/ws/sql/{session_id}')(sql_socket)
    app.websocket('/ws/desktop/{session_id}')(desktop_socket)
    app.websocket('/ws/http/{session_id}')(http_socket)
    app.mount('/static', StaticFiles(directory=ROOT/'static'), name='static')

    @app.get('/', response_class=HTMLResponse)
    def index():
        return (ROOT/'templates'/'index.html').read_text(encoding='utf-8')

    @app.get('/health/live')
    def live(): return {'status':'ok'}

    @app.get('/health/ready')
    def ready():
        with engine.connect() as conn: conn.execute(text('SELECT 1 FROM users LIMIT 1'))
        return {'status':'ok','database':'postgresql'}

    return app
