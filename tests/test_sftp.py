import asyncio
import base64
import json
from types import SimpleNamespace
from unittest.mock import AsyncMock

import asyncssh
import pytest
from fastapi import HTTPException, WebSocketDisconnect

from jump_ssh.sftp_gateway import handler, path_value


def test_paths():
    for value in ['', None, 'a\x00b', 'a'*4097]:
        with pytest.raises(ValueError):path_value(value)
    assert path_value('/home/user/file') == '/home/user/file'


def test_sftp_websocket_rejects_invalid_ticket(app,client,monkeypatch):
    from conftest import add_user,login
    _,secret=add_user(app,'sftp_admin','admin')
    assert login(client,'sftp_admin',secret).status_code==200
    asset=client.post('/api/assets',json=dict(name='sftp-test',host='127.0.0.1',port=22,
        username='tester',credential='test',approval_required=False)).json()
    session=client.post('/api/sessions',json={'asset_id':asset['id']}).json()
    connect=AsyncMock();monkeypatch.setattr('jump_ssh.sftp_gateway.asyncssh.connect',connect)
    with client.websocket_connect('/ws/sftp/'+session['id'],headers={'Origin':'http://testserver'}) as ws:
        ws.send_json({'ticket':'invalid'})
        assert ws.receive_json()['type']=='closed'
    connect.assert_not_called()


def test_restricted_role_cannot_use_sftp(monkeypatch):
    monkeypatch.setattr('jump_ssh.command_policy.effective_policy',lambda *args:[('allow',['whoami'])])
    live=SimpleNamespace(app=None,id='test',cookie='cookie',audit=AsyncMock())
    with pytest.raises(HTTPException) as error:asyncio.run(handler(live))
    assert error.value.status_code == 403
    assert live.audit.await_args.args[0] == 'sftp_denied'


def test_real_sftp_transfer_audit_and_no_overwrite(tmp_path,monkeypatch):
    monkeypatch.setattr('jump_ssh.command_policy.effective_policy',lambda *args:[])

    async def run():
        class Server(asyncssh.SSHServer):
            def begin_auth(self,username):return False
        key=asyncssh.generate_private_key('ssh-ed25519')
        server=await asyncssh.create_server(Server,'127.0.0.1',0,server_host_keys=[key],
            sftp_factory=lambda channel:asyncssh.SFTPServer(channel,chroot=str(tmp_path)))
        payload=b'hello\x00\xff'+b'x'*17000
        messages=[dict(type='mkdir',path='/folder'),dict(type='upload_start',path='/folder/sample.bin'),
                  dict(type='upload_chunk',path='/folder/sample.bin',data=base64.b64encode(payload[:12000]).decode()),
                  dict(type='upload_chunk',path='/folder/sample.bin',data=base64.b64encode(payload[12000:]).decode()),
                  dict(type='upload_end',path='/folder/sample.bin'),dict(type='list',path='/folder'),
                  dict(type='upload_start',path='/folder/sample.bin'),dict(type='download',path='/folder/sample.bin')]
        output=[]
        class WS:
            async def receive_text(self):
                if messages:return json.dumps(messages.pop(0))
                raise WebSocketDisconnect()
            async def send_json(self,value):output.append(value)
        live=SimpleNamespace(ws=WS(),id='test',cookie='cookie',
            app=SimpleNamespace(state=SimpleNamespace(vault=SimpleNamespace(decrypt=lambda value:value))),
            asset=SimpleNamespace(host='127.0.0.1',port=server.get_port(),username='tester',
                auth_type='password',credential='test',verify_host_key=True,host_key=key.export_public_key().decode()),
            check=AsyncMock(),touch=lambda:None,audit=AsyncMock())
        try:
            with pytest.raises(WebSocketDisconnect):await handler(live)
        finally:
            server.close();await server.wait_closed()
        assert (tmp_path/'folder/sample.bin').read_bytes()==payload
        downloaded=b''.join(base64.b64decode(m['data']) for m in output if m['type']=='download_chunk')
        assert downloaded==payload
        assert any(m['type']=='error' for m in output)  # Duplicate upload refused.
        assert any(m['type']=='list' and m['entries'][0]['name']=='sample.bin' for m in output)
        actions=[call.args[0] for call in live.audit.await_args_list]
        assert 'sftp_upload_completed' in actions and 'sftp_download_completed' in actions
        assert 'sftp_operation_failed' in actions
        assert live.check.await_count>=len(messages)
    asyncio.run(run())
