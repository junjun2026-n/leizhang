# ============================================================
# 文件名称：protocol_sessions.py
# 生成日期：2026-10-22
# 修改日期：2026-11-20
# 版本信息：v0.261115
# 作    者：JUN
# 备    注：本程序由AI辅助完成。
#           文件功能：实现 protocol_sessions 模块相关功能。
#           文件用途：供堡垒机的 leizhang/jump_ssh/protocol_sessions.py 模块使用。
#           注意事项：运行前检查依赖与配置；涉及数据或服务变更时先备份并验证。
# ============================================================
"""Shared access, timeout and append-only audit lifecycle for protocol gateways."""
import asyncio
import contextlib
import json
import time
from urllib.parse import urlsplit

from fastapi import HTTPException, WebSocketDisconnect

from .db import transaction
from .models import ProtocolAudit, identity
from .ssh import finish, save_recording, validate_access


class LiveSession:
    def __init__(self, ws, session_id, cookie, asset, hello):
        self.ws, self.app, self.id, self.cookie = ws, ws.app, session_id, cookie
        self.asset, self.hello = asset, hello
        self.start = self.last_input = time.monotonic()
        self.recorded = 0

    def touch(self):
        self.last_input = time.monotonic()

    async def check(self):
        await asyncio.to_thread(validate_access, self.app, self.id, self.cookie, protocols=(self.asset.protocol,))

    async def record(self, text):
        self.recorded += len(text.encode('utf-8'))
        if self.recorded > self.app.state.settings.max_recording:
            raise HTTPException(400, '录制容量已达上限')
        await asyncio.to_thread(save_recording, self.app, self.id, int((time.monotonic()-self.start)*1000), text)

    async def audit(self, action, detail, operation_id=None, success=None, elapsed_ms=0, row_count=0):
        operation_id = operation_id or identity()
        encrypted = self.app.state.vault.encrypt(json.dumps(detail, ensure_ascii=False, default=str))
        self.recorded += len(encrypted)
        if self.recorded > self.app.state.settings.max_recording:
            raise HTTPException(400, '审计容量已达上限')
        def persist():
            with transaction(self.app.state.factory) as db:
                db.add(ProtocolAudit(session_id=self.id, operation_id=operation_id,
                    protocol=self.asset.protocol, action=action, detail=encrypted,
                    success=success, elapsed_ms=elapsed_ms, row_count=row_count))
        await asyncio.to_thread(persist)
        return operation_id

    async def guard(self):
        while True:
            await asyncio.sleep(1)
            if time.monotonic()-self.start > self.app.state.settings.ssh_seconds:
                raise HTTPException(403, '会话时长已达上限')
            if time.monotonic()-self.last_input > self.app.state.settings.idle_seconds:
                raise HTTPException(403, '会话空闲超时')
            await self.check()


async def serve_protocol(ws, session_id, protocols, handler):
    origin = ws.headers.get('origin', '')
    if origin not in ws.app.state.settings.allowed_origins or urlsplit(origin).netloc != ws.headers.get('host'):
        await ws.close(code=1008)
        return
    await ws.accept()
    authenticated, tasks = False, []
    state, error = 'closed', ''
    try:
        hello = await asyncio.wait_for(ws.receive_json(), 10)
        if not isinstance(hello, dict) or not isinstance(hello.get('ticket'), str) or len(hello['ticket']) > 128:
            raise HTTPException(400, '连接票据无效')
        cookie = ws.cookies.get('jump_session', '')
        asset = await asyncio.to_thread(validate_access, ws.app, session_id, cookie, hello['ticket'], protocols)
        authenticated = True
        live = LiveSession(ws, session_id, cookie, asset, hello)
        tasks = [asyncio.create_task(handler(live)), asyncio.create_task(live.guard())]
        done, _ = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
        for task in done:
            task.result()
    except WebSocketDisconnect:
        pass
    except HTTPException as exc:
        state, error = 'failed', str(exc.detail)
    except (OSError, asyncio.TimeoutError):
        state, error = 'failed', '上游连接失败或超时，请检查资源地址、端口及网关状态'
    except Exception:
        state, error = 'failed', '协议会话异常，已关闭；请检查服务日志'
        import logging
        logging.getLogger('jump_ssh').exception('Protocol session failed: %s', session_id)
    finally:
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        if authenticated:
            with contextlib.suppress(Exception):
                await asyncio.to_thread(finish, ws.app, session_id, state, error)
        with contextlib.suppress(Exception):
            await ws.send_json({'type': 'closed', 'message': error or '会话已关闭'})
            await ws.close()
