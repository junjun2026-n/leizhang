import asyncio
import contextlib
import json
import secrets
import time
from types import SimpleNamespace
from urllib.parse import urlsplit

import asyncssh
from fastapi import WebSocket, WebSocketDisconnect, HTTPException
from sqlalchemy import select

from .api import authorize, audit
from .db import transaction
from .models import Asset, Approval, LoginSession, Recording, SSHSession, User, now
from .security import digest
from .resource_accounts import resolve_account, approval_account_filter
from .permissions import load_permissions


def validate_access(app, session_id, cookie, ticket=None, protocols=None, claim=True):
    with transaction(app.state.factory) as db:
        login = db.get(LoginSession, digest(cookie))
        if not login or login.expires_at <= now(): raise HTTPException(401, '登录已过期')
        user = db.get(User, login.user_id)
        if not user or not user.enabled: raise HTTPException(401, '用户已禁用')
        load_permissions(db, user)
        session = db.get(SSHSession, session_id, with_for_update=True)
        if not session or session.user_id != user.id: raise HTTPException(403, '会话无权访问')
        asset = db.get(Asset, session.asset_id)
        if not asset:
            raise HTTPException(404, '资源不存在')
        if session.protocol != asset.protocol or (protocols and session.protocol not in protocols):
            raise HTTPException(403, '会话协议不匹配')
        account=resolve_account(db,asset,session.account_id)
        authorize(db, user, asset,account.id)
        if asset.approval_required and not db.scalar(select(Approval.id).where(
                Approval.user_id == user.id, Approval.asset_id == asset.id,
                approval_account_filter(account.id,asset.id),
                Approval.state == 'approved', Approval.expires_at > now())):
            raise HTTPException(403, '审批授权已失效')
        if ticket is not None:
            if session.state != 'pending' or session.ticket_expires_at <= now() or not secrets.compare_digest(session.ticket_hash, digest(ticket)):
                raise HTTPException(403, '连接票据失效或已使用')
            if claim:
                session.state, session.ticket_hash = 'active', ''
                audit(db, user, 'session_started', session_id)
        elif session.state != 'active':
            raise HTTPException(403, '会话已被终止')
        return SimpleNamespace(host=asset.host,port=asset.port,host_key=asset.host_key,protocol=asset.protocol,
                               database_name=asset.database_name,domain=asset.domain,http_scheme=asset.http_scheme,
                               http_path=asset.http_path,tls_verify=asset.tls_verify,
                               verify_host_key=asset.verify_host_key,username=account.username,
                               auth_type=account.auth_type,credential=account.credential)


def save_recording(app, session_id, elapsed, text):
    with transaction(app.state.factory) as db:
        db.add(Recording(session_id=session_id, elapsed_ms=elapsed, data=app.state.vault.encrypt(text)))


def finish(app, session_id, state, error):
    with transaction(app.state.factory) as db:
        session = db.get(SSHSession, session_id, with_for_update=True)
        if session and session.state in ('active','pending','terminated'):
            if session.state != 'terminated': session.state = state
            session.ended_at, session.error = now(), error
            audit(db, None, 'session_finished', session_id + ':' + session.state)


async def ssh_socket(ws: WebSocket, session_id: str):
    app = ws.app
    origin = ws.headers.get('origin', '')
    if origin not in app.state.settings.allowed_origins or urlsplit(origin).netloc != ws.headers.get('host'):
        await ws.close(code=1008)
        return
    await ws.accept()
    connection = None
    tasks = []
    state, error = 'closed', ''
    authenticated = False
    try:
        hello = await asyncio.wait_for(ws.receive_json(), timeout=10)
        ticket = hello.get('ticket', '')
        if not isinstance(ticket, str) or len(ticket) > 128: raise ValueError('Invalid ticket')
        cookie = ws.cookies.get('jump_session', '')
        asset = await asyncio.to_thread(validate_access, app, session_id, cookie, ticket, ('ssh', 'telnet'))
        authenticated = True
        credential = app.state.vault.decrypt(asset.credential)
        from .command_policy import effective_policy
        restricted = bool(await asyncio.to_thread(effective_policy, app, session_id, cookie))
        if asset.protocol == 'telnet':
            from .telnet import open_telnet
            connection = process = await open_telnet(asset, credential)
        else:
            known_hosts = ([asyncssh.import_public_key(asset.host_key)], [], []) if asset.verify_host_key else None
            options = {'password': credential} if asset.auth_type == 'password' else {
                'client_keys': [asyncssh.import_private_key(credential)]}
            connection = await asyncssh.connect(asset.host, port=asset.port, username=asset.username,
                known_hosts=known_hosts, client_keys=options.pop('client_keys', []), config=None,
                agent_path=None, connect_timeout=15, login_timeout=15, keepalive_interval=20,
                keepalive_count_max=3, **options)
            if not restricted:
                process = await connection.create_process(term_type='xterm-256color', term_size=(100, 30), encoding='utf-8', errors='replace')
        if restricted:
            from .restricted_terminal import run_restricted
            await run_restricted(ws, session_id, cookie, asset, connection)
            return
        start, last_input = time.monotonic(), time.monotonic()
        total_bytes = 0

        async def output():
            nonlocal total_bytes
            while True:
                text = await process.stdout.read(8192)
                if not text: return
                total_bytes += len(text.encode('utf-8'))
                if total_bytes > app.state.settings.max_recording: raise ValueError('录制容量已达上限')
                # Persist BEFORE sending: database failure stops the session, never silently bypasses audit.
                await asyncio.to_thread(save_recording, app, session_id, int((time.monotonic()-start)*1000), text)
                await ws.send_json({'type':'output', 'data':text})

        async def input_loop():
            nonlocal last_input
            while True:
                raw = await ws.receive_text()
                if len(raw) > 32768: raise ValueError('输入过大')
                message = json.loads(raw)
                if message.get('type') == 'input':
                    data = message.get('data')
                    if not isinstance(data,str) or len(data) > 8192: raise ValueError('输入无效')
                    last_input = time.monotonic()
                    process.stdin.write(data)
                    await process.stdin.drain()
                elif message.get('type') == 'resize':
                    cols, rows = int(message.get('cols',100)), int(message.get('rows',30))
                    if not (20 <= cols <= 400 and 5 <= rows <= 150): raise ValueError('终端尺寸无效')
                    process.change_terminal_size(cols, rows)

        async def guard():
            while True:
                await asyncio.sleep(1)
                if time.monotonic() - start > app.state.settings.ssh_seconds: raise ValueError('会话时长已达上限')
                if time.monotonic() - last_input > app.state.settings.idle_seconds: raise ValueError('会话空闲超时')
                await asyncio.to_thread(validate_access, app, session_id, cookie, protocols=('ssh', 'telnet'))

        tasks = [asyncio.create_task(coro) for coro in (output(), input_loop(), guard())]
        done, _ = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
        for task in done: task.result()
    except WebSocketDisconnect:
        pass
    except HTTPException:
        state, error = 'failed', '访问授权失效或连接票据无效'
    except asyncssh.HostKeyNotVerifiable:
        state, error = 'failed', 'SSH 主机公钥不匹配，连接已拒绝'
    except asyncssh.PermissionDenied:
        state, error = 'failed', 'SSH 上游认证失败'
    except (ValueError, asyncio.TimeoutError, asyncssh.Error, OSError):
        state, error = 'failed', '终端连接失败、超时或触发会话限制'
    except Exception:
        state, error = 'failed', '会话异常，已安全关闭'
        import logging
        logging.getLogger('jump_ssh').error('SSH session failed: %s', session_id)
    finally:
        for task in tasks: task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        if connection:
            connection.close()
            with contextlib.suppress(Exception): await connection.wait_closed()
        if authenticated:
            with contextlib.suppress(Exception):
                await asyncio.to_thread(finish, app, session_id, state, error)
        with contextlib.suppress(Exception):
            await ws.send_json({'type':'closed','message':error or '会话已关闭'})
            await ws.close()
