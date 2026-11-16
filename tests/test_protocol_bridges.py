import asyncio
import contextlib
import threading

import pytest
import telnetlib3
from sqlalchemy import select

from conftest import add_user, login
from jump_ssh.db import transaction
from jump_ssh.desktop_gateway import instruction, read_instruction
from jump_ssh.models import Recording


@contextlib.contextmanager
def listener(start_server):
    loop=asyncio.new_event_loop()
    ready=threading.Event()
    state={}
    async def start():
        state['server']=await start_server()
        state['port']=state['server'].sockets[0].getsockname()[1]
        ready.set()
    def run():
        asyncio.set_event_loop(loop)
        loop.run_until_complete(start())
        loop.run_forever()
        remaining=asyncio.all_tasks(loop)
        for task in remaining:task.cancel()
        loop.run_until_complete(asyncio.gather(*remaining,return_exceptions=True))
        loop.close()
    thread=threading.Thread(target=run,daemon=True);thread.start()
    assert ready.wait(10)
    try:yield state['port']
    finally:
        async def stop():
            state['server'].close();await state['server'].wait_closed()
        asyncio.run_coroutine_threadsafe(stop(),loop).result(10)
        loop.call_soon_threadsafe(loop.stop);thread.join(10)


def prepare(app,client,protocol,port):
    _,secret=add_user(app,'bridge_admin','admin')
    assert login(client,'bridge_admin',secret).status_code==200
    r=client.post('/api/assets',json=dict(name='bridge-'+protocol,protocol=protocol,host='127.0.0.1',
        port=port,username='tester',credential='bridge-secret',approval_required=False,tls_verify=False))
    assert r.status_code==201,r.text
    session=client.post('/api/sessions',json={'asset_id':r.json()['id']})
    assert session.status_code==201,session.text
    return session.json()


def test_telnet_real_negotiation_login_and_recording(app,client):
    observed=[]
    async def shell(reader,writer):
        try:
            writer.write('login: ');await writer.drain()
            observed.append((await reader.readline()).strip())
            writer.write('Password: ');await writer.drain()
            observed.append((await reader.readline()).strip())
            writer.write('terminal ready\r\n');await writer.drain()
            while True:
                line=await reader.readline()
                if not line:break
                writer.write('echo: '+line);await writer.drain()
        finally:writer.close()
    async def start():
        return await telnetlib3.create_server(host='127.0.0.1',port=0,shell=shell,connect_maxwait=.5)
    with listener(start) as port:
        session=prepare(app,client,'telnet',port)
        with client.websocket_connect(session['websocket']) as ws:
            ws.send_json({'ticket':session['ticket']})
            output=''
            while 'terminal ready' not in output:
                m=ws.receive_json();assert m['type']=='output',m;output+=m['data']
            assert observed==['tester','bridge-secret']
            ws.send_json({'type':'resize','cols':120,'rows':35})
            ws.send_json({'type':'input','data':'hello\r\n'})
            while 'echo: hello' not in output:
                m=ws.receive_json();assert m['type']=='output',m;output+=m['data']
        recordings=client.get('/api/sessions/'+session['id']+'/recording').json()
        assert 'echo: hello' in ''.join(r['data'] for r in recordings)


@pytest.mark.parametrize('protocol',['rdp','vnc'])
def test_guacd_handshake_recording_and_input(app,client,protocol):
    app.state.settings.vnc_backend='guacd'
    observed=[]
    async def upstream(reader,writer):
        try:
            observed.append(await read_instruction(reader))
            writer.write(instruction('args','VERSION_1_5_0','hostname','port','username','password','disable-copy').encode());await writer.drain()
            for _ in range(6):observed.append(await read_instruction(reader))
            writer.write(instruction('ready','fake-id').encode()+instruction('size',0,800,600).encode()+instruction('sync',1).encode());await writer.drain()
            observed.append(await read_instruction(reader))
            writer.write(instruction('sync',2).encode());await writer.drain()
            await reader.read()
        finally:writer.close()
    async def start():return await asyncio.start_server(upstream,'127.0.0.1',0)
    with listener(start) as port:
        app.state.settings.guacd_port=port
        session=prepare(app,client,protocol,3389 if protocol=='rdp' else 5900)
        with client.websocket_connect(session['websocket']) as ws:
            ws.send_json({'ticket':session['ticket']})
            assert '4.size' in ws.receive_text()
            ws.send_text(instruction('key',65,1))
            assert '4.sync' in ws.receive_text()
            assert observed[0]==['select',protocol]
            assert observed[6][:2]==['connect','VERSION_1_5_0']
            assert observed[6][-2:]==['bridge-secret','true']
        with transaction(app.state.factory) as db:
            rows=list(db.scalars(select(Recording).where(Recording.session_id==session['id'])))
            assert rows
            assert all('bridge-secret' not in app.state.vault.decrypt(r.data) for r in rows)


def test_mysql_driver_audit_contract(app,client,monkeypatch):
    from jump_ssh import sql_gateway
    calls=[]
    class Cursor:
        description=[('answer',)]
        rowcount=1
        def __enter__(self):return self
        def __exit__(self,*args):pass
        def execute(self,sql):calls.append(sql)
        def fetchmany(self,limit):return [(42,)]
    class Connection:
        _secure=True
        def cursor(self):return Cursor()
        def close(self):pass
    def connect(**kwargs):
        assert kwargs['autocommit'] is True
        assert kwargs.get('client_flag',0)==0
        assert kwargs['user']=='tester'
        return Connection()
    monkeypatch.setattr(sql_gateway.pymysql,'connect',connect)
    _,secret=add_user(app,'mysql_admin','admin');login(client,'mysql_admin',secret)
    r=client.post('/api/assets',json=dict(name='mysql-test',protocol='mysql',host='127.0.0.1',port=3306,
        username='tester',credential='bridge-secret',database_name='demo',approval_required=False))
    assert r.status_code==201,r.text
    session=client.post('/api/sessions',json={'asset_id':r.json()['id']}).json()
    with client.websocket_connect(session['websocket']) as ws:
        ws.send_json({'ticket':session['ticket']});assert ws.receive_json()['type']=='ready'
        ws.send_json({'sql':'SELECT 42'});assert ws.receive_json()['rows']==[[42]]
    rows=client.get('/api/protocol-audit').json()
    assert len(rows)==2 and {r['action'] for r in rows}=={'sql_requested','sql_completed'}
    assert calls==['SELECT 42']
