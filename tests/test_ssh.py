import asyncio
import threading
from contextlib import contextmanager

import asyncssh
from sqlalchemy import select

from conftest import add_user, login
from jump_ssh.db import transaction
from jump_ssh.models import Recording, SSHSession


class Server(asyncssh.SSHServer):
    def __init__(self, users=None):
        self.users = users or {'tester':'test-ssh-password'}
    def begin_auth(self, username): return True
    def password_auth_supported(self): return True
    def validate_password(self, username, password):
        return self.users.get(username) == password


@contextmanager
def upstream(users=None, command_handler=None):
    key = asyncssh.generate_private_key('ssh-ed25519')
    ready = threading.Event()
    state = {}
    loop = asyncio.new_event_loop()

    async def process(proc):
        proc.stdout.write('JUMP SSH test ready user=' + proc.get_extra_info('username') + '\r\n')
        async for line in proc.stdin:
            proc.stdout.write('echo: ' + line)
            if line.strip() == 'exit':
                proc.exit(0)
                return

    async def start():
        state['server'] = await asyncssh.create_server(lambda: Server(users), '127.0.0.1', 0,
            server_host_keys=[key], process_factory=command_handler or process)
        state['port'] = state['server'].get_port()
        ready.set()

    def run():
        asyncio.set_event_loop(loop)
        loop.run_until_complete(start())
        loop.run_forever()
        loop.close()

    thread = threading.Thread(target=run, daemon=True)
    thread.start()
    assert ready.wait(10)
    try:
        yield state['port'], key.export_public_key().decode()
    finally:
        async def stop():
            state['server'].close()
            await state['server'].wait_closed()
        asyncio.run_coroutine_threadsafe(stop(), loop).result(10)
        loop.call_soon_threadsafe(loop.stop)
        thread.join(10)


def prepare(client, app, port, key, verify_host_key=True):
    _, secret = add_user(app, 'administrator', 'admin')
    assert login(client, 'administrator', secret).status_code == 200
    response = client.post('/api/assets',json=dict(name='SSH fixture',host='127.0.0.1',port=port,
        username='tester',credential='test-ssh-password',host_key=key,verify_host_key=verify_host_key,approval_required=False))
    assert response.status_code == 201, response.text
    session = client.post('/api/sessions', json={'asset_id':response.json()['id']})
    assert session.status_code == 201, session.text
    return session.json()


def test_real_ssh_terminal_recording_and_replay(client, app):
    with upstream() as (port,key):
        session=prepare(client,app,port,key)
        with client.websocket_connect(session['websocket'],headers={'Origin':'http://testserver'}) as ws:
            ws.send_json({'ticket':session['ticket']})
            assert 'test ready' in ws.receive_json()['data']
            ws.send_json({'type':'input','data':'hello\n'})
            output=''
            while 'echo: hello' not in output: output+=ws.receive_json().get('data','')
            ws.send_json({'type':'input','data':'exit\n'})
            while ws.receive_json().get('type')!='closed': pass
        response=client.get('/api/sessions/'+session['id']+'/recording')
        assert response.status_code==200
        assert 'echo: hello' in ''.join(event['data'] for event in response.json())
        with transaction(app.state.factory) as db:
            assert db.get(SSHSession,session['id']).state=='closed'
            for record in db.scalars(select(Recording)):
                assert 'hello' not in record.data


def test_wrong_host_key_is_rejected(client,app):
    with upstream() as (port,key):
        wrong=asyncssh.generate_private_key('ssh-ed25519').export_public_key().decode()
        session=prepare(client,app,port,wrong)
        with client.websocket_connect(session['websocket'],headers={'Origin':'http://testserver'}) as ws:
            ws.send_json({'ticket':session['ticket']})
            result=ws.receive_json()
            assert result['type']=='closed'
        with transaction(app.state.factory) as db:
            assert db.get(SSHSession,session['id']).state=='failed'
            assert db.get(SSHSession,session['id']).error


def test_password_only_without_host_key_connects_and_records(client, app):
    with upstream() as (port, key):
        session = prepare(client, app, port, '', verify_host_key=False)
        with client.websocket_connect(session['websocket'], headers={'Origin': 'http://testserver'}) as ws:
            ws.send_json({'ticket': session['ticket']})
            assert 'test ready' in ws.receive_json()['data']
            ws.send_json({'type': 'input', 'data': 'password-only\n'})
            output = ''
            while 'echo: password-only' not in output:
                output += ws.receive_json().get('data', '')
            ws.send_json({'type': 'input', 'data': 'exit\n'})
            while ws.receive_json().get('type') != 'closed':
                pass
        response = client.get('/api/sessions/' + session['id'] + '/recording')
        assert response.status_code == 200
        assert 'echo: password-only' in ''.join(event['data'] for event in response.json())


def test_admin_termination_closes_live_connection(client,app):
    with upstream() as (port,key):
        session=prepare(client,app,port,key)
        with client.websocket_connect(session['websocket'],headers={'Origin':'http://testserver'}) as ws:
            ws.send_json({'ticket':session['ticket']})
            assert ws.receive_json()['type']=='output'
            assert client.post('/api/sessions/'+session['id']+'/terminate',json={}).status_code==200
            assert ws.receive_json()['type']=='closed'
        with transaction(app.state.factory) as db:
            assert db.get(SSHSession,session['id']).state=='terminated'
