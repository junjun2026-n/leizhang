# ============================================================
# 文件名称：desktop_gateway.py
# 生成日期：2026-10-22
# 修改日期：2026-11-20
# 版本信息：v0.261115
# 作    者：JUN
# 备    注：本程序由AI辅助完成。
#           文件功能：实现 desktop_gateway 模块相关功能。
#           文件用途：供堡垒机的 leizhang/jump_ssh/desktop_gateway.py 模块使用。
#           注意事项：运行前检查依赖与配置；涉及数据或服务变更时先备份并验证。
# ============================================================
"""Authenticated Guacamole protocol bridge. guacd must be on a trusted network."""
import asyncio
import contextlib

from fastapi import HTTPException, WebSocket

from .protocol_sessions import serve_protocol


def instruction(*parts):
    return ','.join(f'{len(str(p))}.{p}' for p in parts) + ';'


async def read_instruction(reader):
    parts, total = [], 0
    while True:
        length = await reader.readuntil(b'.')
        if len(length) > 8 or not length[:-1].isdigit():
            raise ValueError('Invalid Guacamole length')
        n = int(length[:-1])
        total += n
        if n > 65536 or total > 131072 or len(parts) > 256:
            raise ValueError('Guacamole instruction too large')
        # StreamReader is bytes, but Guacamole lengths count Unicode characters.
        value = ''
        for _ in range(n):
            first = await reader.readexactly(1)
            lead = first[0]
            extra = 0 if lead < 128 else (1 if lead < 224 else (2 if lead < 240 else 3))
            value += (first + await reader.readexactly(extra)).decode('utf-8')
        parts.append(value)
        delimiter = await reader.readexactly(1)
        if delimiter == b';':
            return parts
        if delimiter != b',':
            raise ValueError('Invalid Guacamole delimiter')


def parse_input(raw):
    allowed = {'key': 2, 'mouse': 3, 'size': 2, 'ack': 3, 'sync': 1, 'nop': 0, 'disconnect': 0}
    pos, instructions = 0, []
    while pos < len(raw):
        parts = []
        while True:
            dot = raw.find('.', pos)
            if dot < 0 or dot-pos > 7 or not raw[pos:dot].isdigit():
                raise ValueError('Invalid instruction')
            end = dot+1+int(raw[pos:dot])
            if end >= len(raw):
                raise ValueError('Incomplete instruction')
            parts.append(raw[dot+1:end])
            sep, pos = raw[end], end+1
            if sep == ';':
                break
            if sep != ',' or len(parts) > 8:
                raise ValueError('Invalid instruction')
        if parts[0] not in allowed or len(parts)-1 != allowed[parts[0]]:
            raise ValueError('Unsupported client instruction')
        if parts[0] in ('key', 'mouse', 'size', 'sync'):
            values = [int(v) for v in parts[1:]]
            if any(v < 0 or v > 0xffffffff for v in values):
                raise ValueError('Invalid input range')
            if parts[0] == 'size' and not (320 <= values[0] <= 2560 and 200 <= values[1] <= 1600):
                raise ValueError('Invalid display size')
        instructions.append(parts[0])
    return instructions


async def desktop_handler(live):
    settings, a = live.app.state.settings, live.asset
    reader, writer = await asyncio.wait_for(asyncio.open_connection(settings.guacd_host, settings.guacd_port), 5)
    tasks = []
    async def send(*parts):
        writer.write(instruction(*parts).encode('utf-8'))
        await writer.drain()
    try:
        await send('select', a.protocol)
        args = await asyncio.wait_for(read_instruction(reader), 10)
        if args[0] != 'args':
            raise HTTPException(502, 'Guacamole 网关不支持所选协议')
        password = live.app.state.vault.decrypt(a.credential)
        options = {'hostname': a.host, 'port': str(a.port), 'username': a.username,
            'password': password, 'domain': a.domain, 'security': 'any',
            'ignore-cert': 'false' if a.tls_verify else 'true',
            'disable-copy': 'true', 'disable-paste': 'true', 'enable-drive': 'false',
            'enable-printing': 'false', 'enable-audio-input': 'false', 'disable-audio': 'true',
            'read-only': 'false'}
        await send('size', 1280, 720, 96)
        await send('audio')
        await send('video')
        await send('image', 'image/png', 'image/jpeg')
        await send('timezone', 'Asia/Shanghai')
        await send('connect', *[key if key.startswith('VERSION_') else options.get(key, '') for key in args[1:]])
        ready = await asyncio.wait_for(read_instruction(reader), 20)
        if ready[0] != 'ready':
            raise HTTPException(502, '远程桌面连接失败，请检查凭据、证书及目标服务')
        await live.audit('desktop_connected', {'protocol': a.protocol}, success=True)

        async def output():
            import codecs
            decoder = codecs.getincrementaldecoder('utf-8')()
            while True:
                chunk = await reader.read(16384)
                if not chunk:
                    return
                raw = decoder.decode(chunk)
                if raw:
                    await live.record(raw)
                    await live.ws.send_text(raw)

        async def inputs():
            while True:
                raw = await live.ws.receive_text()
                if len(raw.encode('utf-8')) > 32768:
                    raise ValueError('Input too large')
                opcodes = parse_input(raw)
                if any(op in ('key', 'mouse', 'size') for op in opcodes):
                    await live.check()
                    live.touch()
                writer.write(raw.encode('utf-8'))
                await writer.drain()
        tasks = [asyncio.create_task(output()), asyncio.create_task(inputs())]
        done, _ = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
        for task in done:
            task.result()
    finally:
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        writer.close()
        with contextlib.suppress(Exception):
            await writer.wait_closed()


async def desktop_socket(ws: WebSocket, session_id: str):
    async def handler(live):
        if live.asset.protocol=='vnc' and live.app.state.settings.vnc_backend=='native':
            from .vnc_gateway import vnc_handler
            return await vnc_handler(live)
        return await desktop_handler(live)
    await serve_protocol(ws, session_id, ('rdp', 'vnc'), handler)
