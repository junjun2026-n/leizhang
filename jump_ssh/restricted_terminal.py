# ============================================================
# 文件名称：restricted_terminal.py
# 生成日期：2026-10-23
# 修改日期：2026-11-20
# 版本信息：v0.261115
# 作    者：JUN
# 备    注：本程序由AI辅助完成。
#           文件功能：实现 restricted_terminal 模块相关功能。
#           文件用途：供堡垒机的 leizhang/jump_ssh/restricted_terminal.py 模块使用。
#           注意事项：运行前检查依赖与配置；涉及数据或服务变更时先备份并验证。
# ============================================================
"""Line-buffered policy terminal; disallowed input never reaches the upstream."""
import asyncio
import contextlib
import json
import re
import time

from fastapi import HTTPException

from .command_policy import checked_command, effective_policy
from .protocol_sessions import LiveSession


async def run_restricted(ws, session_id, cookie, asset, connection):
    from .ssh import save_recording, validate_access
    app = ws.app
    live = LiveSession(ws, session_id, cookie, asset, {})
    start = last_input = time.monotonic()
    recorded = 0
    send_lock = asyncio.Lock()
    current = None
    tasks = []
    telnet_ready = asyncio.Event()

    async def emit(text):
        nonlocal recorded
        async with send_lock:
            recorded += len(text.encode('utf-8'))
            if recorded > app.state.settings.max_recording:
                raise HTTPException(400, '录制容量已达上限')
            await asyncio.to_thread(save_recording, app, session_id, int((time.monotonic()-start)*1000), text)
            await ws.send_json({'type': 'output', 'data': text})

    async def telnet_output():
        tail = ''
        while True:
            already_authenticated = connection.sent_password or connection.sent_username
            text = await connection.stdout.read(8192)
            if not text:
                return
            await emit(text)
            tail = (tail + text)[-1024:]
            if already_authenticated and re.search(r'(?:^|[\r\n])[^\r\n]*[#$>]\s*$', tail):
                telnet_ready.set()

    async def execute(command):
        nonlocal current
        policies = await asyncio.to_thread(effective_policy, app, session_id, cookie)
        operation = await live.audit('command_requested', {'command': command})
        try:
            safe_command = checked_command(command, policies)
        except HTTPException as exc:
            await live.audit('command_denied', {'command': command, 'reason': exc.detail}, operation, False)
            await emit('\r\n[' + exc.detail + ']\r\npolicy> ')
            return
        if not safe_command:
            await emit('policy> ')
            return
        if asset.protocol == 'telnet':
            await asyncio.wait_for(telnet_ready.wait(), 15)
            # Never forward control sequences, history requests or multiple lines.
            connection.stdin.write(safe_command + '\r\n')
            await connection.stdin.drain()
            await live.audit('command_forwarded', {'command': safe_command}, operation, True)
            await emit('policy> ')
            return
        started = time.monotonic()
        # Independent non-interactive exec channels prevent shell history/editing
        # and stdin escape sequences from bypassing the policy.
        current = await connection.create_process(safe_command, encoding='utf-8', errors='replace', stderr=asyncio.subprocess.STDOUT)
        current.stdin.write_eof()
        try:
            async def stream():
                while True:
                    text = await current.stdout.read(8192)
                    if not text:
                        break
                    await emit(text)
                await current.wait_closed()
            await asyncio.wait_for(stream(), min(60, app.state.settings.idle_seconds))
            await live.audit('command_completed', {'exit_status': current.exit_status}, operation,
                             current.exit_status == 0, int((time.monotonic()-started)*1000))
        except asyncio.TimeoutError:
            await live.audit('command_completed', {'error': '执行超时'}, operation, False)
            await emit('\r\n[命令执行超时]\r\n')
        finally:
            current.close()
            with contextlib.suppress(Exception):
                await asyncio.wait_for(current.wait_closed(), 3)
            current = None
        await emit('\r\npolicy> ')

    async def input_loop():
        nonlocal last_input
        buffer = ''
        previous_cr = False
        while True:
            raw = await ws.receive_text()
            if len(raw) > 32768:
                raise HTTPException(400, '输入过大')
            message = json.loads(raw)
            if message.get('type') != 'input':
                continue
            data = message.get('data')
            if not isinstance(data, str) or len(data) > 8192:
                raise HTTPException(400, '输入无效')
            last_input = time.monotonic()
            # Reject the entire frame before processing any part of it. Arrow
            # keys, bracketed paste, completion and control-key editing stay local.
            if any(ord(c) < 32 and c not in '\r\n\b\x03' for c in data) or '\x1b' in data:
                buffer = ''
                await emit('\r\n[受控会话不支持历史、补全或控制序列，请输入完整命令]\r\npolicy> ')
                continue
            echo = ''
            for c in data:
                if c == '\n' and previous_cr:
                    previous_cr = False
                    continue
                previous_cr = c == '\r'
                if c in '\r\n':
                    command, buffer = buffer, ''
                    await emit(echo + '\r\n')
                    echo = ''
                    await execute(command)
                elif c in '\b\x7f':
                    if buffer:
                        buffer = buffer[:-1]
                        echo += '\b \b'
                elif c == '\x03':
                    buffer = ''
                    echo += '^C\r\npolicy> '
                else:
                    buffer += c
                    if len(buffer.encode('utf-8')) > 8192:
                        raise HTTPException(400, '命令过长')
                    # Echo locally; the upstream sees nothing until approval.
                    echo += c
            if echo:
                await emit(echo)

    async def guard():
        while True:
            await asyncio.sleep(1)
            if time.monotonic()-start > app.state.settings.ssh_seconds or time.monotonic()-last_input > app.state.settings.idle_seconds:
                raise HTTPException(403, '受控会话超时')
            await asyncio.to_thread(validate_access, app, session_id, cookie, protocols=('ssh', 'telnet'))

    await emit('\r\n[命令策略已启用：逐条执行，不支持交互程序、管道或重定向；SSH 每条命令使用独立执行环境。]\r\npolicy> ')
    try:
        tasks = [asyncio.create_task(input_loop()), asyncio.create_task(guard())]
        if asset.protocol == 'telnet':
            tasks.append(asyncio.create_task(telnet_output()))
        done, _ = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
        for task in done:
            task.result()
    finally:
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        if current:
            current.close()
