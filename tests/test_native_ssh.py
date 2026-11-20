# ============================================================
# 文件名称：test_native_ssh.py
# 生成日期：2026-11-16
# 修改日期：2026-11-20
# 版本信息：v0.261115
# 作    者：JUN
# 备    注：本程序由AI辅助完成。
#           文件功能：验证 native_ssh 相关功能。
#           文件用途：用于开发验证及功能回归。
#           注意事项：使用隔离测试环境，避免操作正式业务数据。
# ============================================================
import asyncio
import socket
import json
import time

import asyncssh
import pytest
from sqlalchemy import select

from jump_ssh.db import transaction
from jump_ssh.models import Recording, SSHSession, User, ProtocolAudit
from jump_ssh.native_ssh import NativeServer, start_listener
from test_ssh import prepare, upstream


@pytest.mark.parametrize('restricted', [False, True])
def test_native_terminal_recording_replay_and_termination(client, app, tmp_path, restricted):
    commands = []
    async def handle(proc):
        commands.append(proc.command)
        proc.stdout.write('result:'+proc.command+'\r\n')
        proc.exit(0)
    with upstream(command_handler=handle if restricted else None) as (port, key):
        session = prepare(client, app, port, key)
        with transaction(app.state.factory) as db:
            asset_id = db.get(SSHSession, session['id']).asset_id
            if restricted:
                user = db.get(User, db.get(SSHSession, session['id']).user_id)
                user.command_mode, user.command_rules = 'allow', '["whoami"]'
        with socket.socket() as probe:
            probe.bind(('127.0.0.1', 0))
            app.state.settings.ssh_proxy_port = probe.getsockname()[1]
        app.state.settings.ssh_proxy_host = '127.0.0.1'
        app.state.settings.ssh_proxy_key = tmp_path/'host-key'
        response = client.post('/api/native-ssh/sessions', json={'asset_id': asset_id})
        assert response.status_code == 201, response.text
        ticket = response.json()

        async def run():
            listener = await start_listener(app)
            try:
                options = dict(host='127.0.0.1', port=ticket['port'], username=ticket['username'],
                               password=ticket['password'], known_hosts=None, client_keys=[], agent_path=None)
                async with asyncssh.connect(**options) as conn:
                    with pytest.raises(asyncssh.ChannelOpenError):
                        await conn.open_connection('127.0.0.1', port)
                    rejected = await conn.run('id', check=False)
                    assert rejected.exit_status == 1
                    assert not commands
                    proc = await conn.create_process(term_type='xterm')
                    if restricted:
                        await asyncio.wait_for(proc.stdout.readuntil('policy> '), 5)
                        proc.stdin.write('rm secret\r')
                        assert '白名单' in await asyncio.wait_for(proc.stdout.readuntil('policy> '), 5)
                        assert not commands
                        proc.stdin.write('whoami\r')
                        assert 'result:whoami' in await asyncio.wait_for(proc.stdout.readuntil('policy> '), 5)
                        assert commands == ['whoami']
                    else:
                        assert 'test ready' in await asyncio.wait_for(proc.stdout.readline(), 5)
                        proc.stdin.write('native-test\n')
                        output = ''
                        while 'echo: native-test' not in output:
                            output += await asyncio.wait_for(proc.stdout.readline(), 5)
                    with pytest.raises(asyncssh.PermissionDenied):
                        await asyncssh.connect(**options)
                    await asyncio.to_thread(client.post, '/api/sessions/'+ticket['username']+'/terminate', json={})
                    await asyncio.wait_for(proc.wait_closed(), 5)
            finally:
                listener.close()
                await listener.wait_closed()
        asyncio.run(run())
        with transaction(app.state.factory) as db:
            assert db.get(SSHSession, ticket['username']).state == 'terminated'
            records = db.scalars(select(Recording).where(Recording.session_id == ticket['username'])).all()
            assert ('result:whoami' if restricted else 'native-test') in ''.join(app.state.vault.decrypt(r.data) for r in records)
            assert all('native-test' not in r.data for r in records)
            if restricted:
                audits = db.scalars(select(ProtocolAudit).where(ProtocolAudit.session_id == ticket['username'])).all()
                assert any(a.action == 'command_denied' for a in audits)


def test_native_disabled(client):
    assert client.post('/api/native-ssh/sessions', json={'asset_id':'missing'}).status_code == 401


def test_native_rejects_expired_modified_and_mismatched_credentials(app):
    data = json.dumps({'id':'session-id', 'ticket':'test', 'cookie':'secret-cookie'}).encode()
    server = NativeServer(app)
    async def run():
        expired = app.state.vault.cipher.encrypt_at_time(data, int(time.time())-60).decode()
        assert not await server.validate_password('session-id', expired)
        assert not await server.validate_password('session-id', 'invalid-token')
        assert not await server.validate_password('other-session', app.state.vault.cipher.encrypt(data).decode())
    asyncio.run(run())


def test_native_disabled_after_login(client, app):
    with upstream() as (port, key):
        prepare(client, app, port, key)
        assert client.post('/api/native-ssh/sessions', json={'asset_id':'missing'}).status_code == 409
