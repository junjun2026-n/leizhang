"""Native VNC bridge: the application connects directly, without guacd."""
import asyncio
import base64
import contextlib
import io
import json
import struct

import asyncvnc
from fastapi import HTTPException
from PIL import Image


async def vnc_handler(live):
    asset=live.asset
    transport=[]
    async def opener(host,port):
        reader,writer=await asyncio.wait_for(asyncio.open_connection(host,port),10)
        transport.append(writer)
        return reader,writer
    manager=asyncvnc.connect(asset.host,asset.port,username=asset.username,
        password=live.app.state.vault.decrypt(asset.credential),opener=opener)
    try:
        client=await asyncio.wait_for(manager.__aenter__(),20)
    except BaseException as error:
        for writer in transport:
            writer.close()
            with contextlib.suppress(Exception):await writer.wait_closed()
        if isinstance(error,(PermissionError,ValueError)):
            raise HTTPException(502,'VNC 认证失败或服务器安全类型不支持，请检查 VNC 密码与目标安全类型（传统 VNC 密码仅使用前 8 字节）') from error
        if isinstance(error,(OSError,asyncio.TimeoutError)):
            raise HTTPException(502,'无法连接目标 VNC 桌面，请检查 Linux VNC 服务是否启动、监听地址、端口及防火墙放行设置') from error
        raise
    tasks=[]
    try:
        width,height=client.video.width,client.video.height
        if not (1<=width<=4096 and 1<=height<=2160):
            raise HTTPException(400,'VNC 桌面尺寸上限为 4096 × 2160')
        await live.audit('vnc_connected',{'backend':'native','width':width,'height':height},success=True)
        await live.ws.send_json({'type':'ready','message':'VNC 已连接（本机直接连接）','width':width,'height':height})

        async def frames():
            previous=None
            client.video.refresh()
            await client.drain()
            while True:
                # An unchanged desktop may send no update for a long time.
                # Keep the read pending; the shared guard enforces session limits.
                update=await client.read()
                if update is not asyncvnc.UpdateType.VIDEO:
                    continue
                if not client.video.is_complete():
                    client.video.refresh();await client.drain();continue
                rgba=client.video.as_rgba().copy()
                def encode():
                    output=io.BytesIO()
                    Image.fromarray(rgba).convert('RGB').save(output,format='JPEG',quality=65)
                    return base64.b64encode(output.getvalue()).decode()
                image=await asyncio.to_thread(encode)
                if image!=previous:
                    frame={'type':'frame','data':image,'width':width,'height':height}
                    await live.record(json.dumps(frame))
                    await live.ws.send_json(frame)
                    previous=image
                await asyncio.sleep(.2)
                client.video.refresh()
                await client.drain()

        async def inputs():
            while True:
                raw=await live.ws.receive_text()
                if len(raw)>4096:raise ValueError('VNC 输入过大')
                message=json.loads(raw);await live.check();live.touch()
                if message.get('type')=='pointer':
                    x,y,buttons=message.get('x'),message.get('y'),message.get('buttons')
                    if not all(type(v) is int for v in (x,y,buttons)) or not (0<=x<width and 0<=y<height and 0<=buttons<=31):
                        raise ValueError('VNC 鼠标输入无效')
                    client.writer.write(struct.pack('>BBHH',5,buttons,x,y))
                elif message.get('type')=='key':
                    key=message.get('key');down=message.get('down')
                    if type(key) is not int or not 0<=key<=0x1fffffff or type(down) is not bool:
                        raise ValueError('VNC 按键无效')
                    client.writer.write(struct.pack('>BBHI',4,int(down),0,key))
                else:raise ValueError('VNC 操作无效')
                await client.drain()
        tasks=[asyncio.create_task(frames()),asyncio.create_task(inputs())]
        done,_=await asyncio.wait(tasks,return_when=asyncio.FIRST_COMPLETED)
        for task in done:task.result()
    finally:
        for task in tasks:task.cancel()
        await asyncio.gather(*tasks,return_exceptions=True)
        with contextlib.suppress(Exception):await manager.__aexit__(None,None,None)
