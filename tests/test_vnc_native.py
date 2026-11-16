import asyncio
import base64
import contextlib
import io
import struct

import pytest
from PIL import Image
from sqlalchemy import select

from test_protocol_bridges import listener,prepare
from jump_ssh.db import transaction
from jump_ssh.models import Recording,ProtocolAudit


@pytest.mark.parametrize('reject',[False,True])
def test_native_vnc_rfb_auth_frame_input_recording(app,client,reject):
    observed=[]
    async def upstream(reader,writer):
        try:
            writer.write(b'RFB 003.008\n');await writer.drain()
            assert await reader.readexactly(12)==b'RFB 003.008\n'
            writer.write(b'\x01\x02');await writer.drain()  # VNC password authentication.
            assert await reader.readexactly(1)==b'\x02'
            challenge=b'0123456789abcdef';writer.write(challenge);await writer.drain()
            response=await reader.readexactly(16)
            from cryptography.hazmat.primitives.ciphers import Cipher,modes
            from cryptography.hazmat.decrepit.ciphers.algorithms import TripleDES
            key=bytes(int(f'{n:08b}'[::-1],2) for n in b'bridge-s')
            encryptor=Cipher(TripleDES(key),modes.ECB()).encryptor()
            assert response==encryptor.update(challenge)+encryptor.finalize()
            writer.write(struct.pack('>I',1 if reject else 0));await writer.drain()
            if reject:return
            await reader.readexactly(1)
            pixel_format=struct.pack('>BBBBHHHBBBxxx',32,24,0,1,255,255,255,0,8,16)
            writer.write(struct.pack('>HH',8,6)+pixel_format+struct.pack('>I',4)+b'Test');await writer.drain()
            while True:
                kind=(await reader.readexactly(1))[0]
                if kind==0:await reader.readexactly(19)
                elif kind==2:
                    header=await reader.readexactly(3);await reader.readexactly(struct.unpack('>H',header[1:])[0]*4)
                elif kind==3:
                    await reader.readexactly(9)
                    writer.write(b'\x00\x00\x00\x01'+struct.pack('>HHHHi',0,0,8,6,0)+b'\x00\x80\xff\x00'*48);await writer.drain()
                elif kind==4:observed.append(('key',await reader.readexactly(7)))
                elif kind==5:observed.append(('pointer',await reader.readexactly(5)))
                else:raise AssertionError(kind)
        except (asyncio.IncompleteReadError,ConnectionError):pass
        finally:
            writer.close()
            with contextlib.suppress(Exception):await writer.wait_closed()
    async def start():return await asyncio.start_server(upstream,'127.0.0.1',0)
    with listener(start) as port:
        assert app.state.settings.vnc_backend=='native'
        session=prepare(app,client,'vnc',port)
        with client.websocket_connect(session['websocket']) as ws:
            ws.send_json({'ticket':session['ticket']})
            ready=ws.receive_json()
            if reject:
                assert ready['type']=='closed' and 'VNC' in ready['message'];return
            assert ready['type']=='ready'
            frame=ws.receive_json();assert frame['type']=='frame'
            image=Image.open(io.BytesIO(base64.b64decode(frame['data'])))
            assert image.size==(8,6)
            ws.send_json({'type':'key','key':65,'down':True})
            ws.send_json({'type':'pointer','x':2,'y':3,'buttons':1})
            # Trigger an explicit rejection after input and confirm clean shutdown.
            ws.send_json({'type':'pointer','x':99999,'y':3,'buttons':1})
            while ws.receive_json()['type']!='closed':pass
        assert {entry[0] for entry in observed}=={'key','pointer'}
        with transaction(app.state.factory) as db:
            rows=list(db.scalars(select(Recording).where(Recording.session_id==session['id'])))
            assert rows and '"type": "frame"' in app.state.vault.decrypt(rows[0].data)
            assert db.scalar(select(ProtocolAudit.id).where(ProtocolAudit.session_id==session['id'],ProtocolAudit.action=='vnc_connected'))
