# ============================================================
# 文件名称：sftp_gateway.py
# 生成日期：2026-10-26
# 修改日期：2026-11-20
# 版本信息：v0.261115
# 作    者：JUN
# 备    注：本程序由AI辅助完成。
#           文件功能：实现 sftp_gateway 模块相关功能。
#           文件用途：供堡垒机的 leizhang/jump_ssh/sftp_gateway.py 模块使用。
#           注意事项：运行前检查依赖与配置；涉及数据或服务变更时先备份并验证。
# ============================================================
"""SFTP over a separately ticketed SSH session, with per-operation audit."""
import asyncio
import base64
import hashlib
import posixpath
import stat

import asyncssh
from fastapi import HTTPException, WebSocket

from .protocol_sessions import serve_protocol

LIMIT = 20 * 1024 * 1024
CHUNK = 12000


def path_value(value):
    if not isinstance(value, str) or not value or len(value) > 4096 or '\x00' in value:
        raise ValueError('无效的远程路径')
    return value


async def handler(live):
    from .command_policy import effective_policy
    if await asyncio.to_thread(effective_policy, live.app, live.id, live.cookie):
        await live.audit('sftp_denied', {'reason':'命令限制角色禁止文件传输，防止绕过命令策略'}, success=False)
        raise HTTPException(403, '启用命令黑／白名单时禁止 SFTP，防止绕过命令策略')
    asset = live.asset
    credential = live.app.state.vault.decrypt(asset.credential)
    options = {'password':credential} if asset.auth_type == 'password' else {'client_keys':[asyncssh.import_private_key(credential)]}
    options.setdefault('client_keys', [])
    known = ([asyncssh.import_public_key(asset.host_key)], [], []) if asset.verify_host_key else None
    async with asyncssh.connect(asset.host, port=asset.port, username=asset.username,
            known_hosts=known, config=None, agent_path=None, connect_timeout=15,
            login_timeout=15, keepalive_interval=20, **options) as connection:
        async with connection.start_sftp_client() as client:
            await live.ws.send_json({'type':'ready','path':await client.realpath('.')})
            upload = None
            try:
                while True:
                    raw = await live.ws.receive_text()
                    if len(raw) > 32768:
                        raise ValueError('输入过大')
                    import json
                    message = json.loads(raw)
                    await live.check()
                    live.touch()
                    kind = message.get('type')
                    if kind not in ('list','mkdir','download','upload_start','upload_chunk','upload_end'):
                        raise ValueError('无效的 SFTP 操作')
                    path = path_value(message.get('path', '.'))
                    try:
                        if kind in ('upload_chunk','upload_end'):
                            if not upload or path != upload['path']:
                                raise ValueError('没有匹配的上传任务')
                            if kind == 'upload_chunk':
                                data = base64.b64decode(message.get('data',''), validate=True)
                                if len(data) > CHUNK or upload['size'] + len(data) > LIMIT:
                                    raise ValueError('单文件上传上限 20 MiB')
                                await upload['file'].write(data)
                                upload['size'] += len(data); upload['hash'].update(data)
                                await live.ws.send_json({'type':'upload_ack'})
                            else:
                                await upload['file'].close()
                                await live.audit('sftp_upload_completed',dict(path=path,bytes=upload['size'],sha256=upload['hash'].hexdigest()),success=True)
                                upload = None
                                await live.ws.send_json({'type':'done','message':'上传完成'})
                            continue
                        await live.audit('sftp_'+kind+'_requested',{'path':path})
                        if kind == 'list':
                            entries=[]
                            async for entry in client.scandir(path):
                                if entry.filename in ('.','..'):continue
                                if len(entries)>=2000:raise ValueError('目录超过 2000 项，请缩小目录范围')
                                entries.append(dict(name=entry.filename,directory=stat.S_ISDIR(entry.attrs.permissions or 0),
                                    size=entry.attrs.size or 0))
                            await live.audit('sftp_list_completed',{'path':path,'entries':len(entries)},success=True)
                            await live.ws.send_json({'type':'list','path':await client.realpath(path),'entries':entries})
                        elif kind == 'mkdir':
                            await client.mkdir(path)
                            await live.audit('sftp_mkdir_completed',{'path':path},success=True)
                            await live.ws.send_json({'type':'done','message':'目录已创建'})
                        elif kind == 'upload_start':
                            if upload:raise ValueError('已有上传任务')
                            # Exclusive create avoids silently replacing an existing server file.
                            file = await client.open(path,'xb',encoding=None)
                            upload=dict(path=path,file=file,size=0,hash=hashlib.sha256())
                            await live.ws.send_json({'type':'upload_ack'})
                        elif kind == 'download':
                            size=0;digest=hashlib.sha256()
                            async with client.open(path,'rb',encoding=None) as file:
                                if (await file.stat()).size > LIMIT:raise ValueError('单文件下载上限 20 MiB')
                                await live.ws.send_json({'type':'download_start','name':posixpath.basename(path)})
                                while True:
                                    await live.check()
                                    data=await file.read(CHUNK)
                                    if not data:break
                                    size+=len(data)
                                    if size>LIMIT:raise ValueError('单文件下载上限 20 MiB')
                                    digest.update(data)
                                    await live.ws.send_json({'type':'download_chunk','data':base64.b64encode(data).decode()})
                            await live.audit('sftp_download_completed',dict(path=path,bytes=size,sha256=digest.hexdigest()),success=True)
                            await live.ws.send_json({'type':'download_end'})
                    except (asyncssh.SFTPError, ValueError) as error:
                        if upload:
                            await upload['file'].close()
                            await live.audit('sftp_upload_incomplete',{'path':upload['path'],'bytes':upload['size']},success=False)
                            upload=None
                        await live.audit('sftp_operation_failed',{'operation':kind,'path':path,'error':str(error)},success=False)
                        await live.ws.send_json({'type':'error','message':str(error)})
            finally:
                if upload:
                    await upload['file'].close()
                    await live.audit('sftp_upload_incomplete',{'path':upload['path'],'bytes':upload['size']},success=False)


async def sftp_socket(ws: WebSocket, session_id: str):
    await serve_protocol(ws, session_id, ('ssh',), handler)
