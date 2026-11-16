import asyncio
import json
import os
import threading
from contextlib import contextmanager
from datetime import timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from types import SimpleNamespace

import pytest
from fastapi import HTTPException
from sqlalchemy import select, text
from sqlalchemy.engine import make_url
from sqlalchemy.exc import DBAPIError

from conftest import add_user, login
from jump_ssh.api import AssetInput
from jump_ssh.db import transaction
from jump_ssh.desktop_gateway import instruction, parse_input, read_instruction
from jump_ssh.http_gateway import same_origin
from jump_ssh.models import Asset, Grant, ProtocolAudit, Recording, SSHSession, now
from jump_ssh.ssh import validate_access


def admin_login(app, client):
    uid, secret = add_user(app, 'protocol_admin', 'admin')
    assert login(client, 'protocol_admin', secret).status_code == 200
    return uid


def asset(client, protocol, **extra):
    body = dict(name='resource-'+protocol, protocol=protocol, host='127.0.0.1',
                port=22, username='demo', credential='demo-pass', approval_required=False,
                database_name='test', tls_verify=False)
    body.update(extra)
    r = client.post('/api/assets', json=body)
    assert r.status_code == 201, r.text
    return r.json()


def connect(client, resource):
    r = client.post('/api/sessions', json={'asset_id': resource['id']})
    assert r.status_code == 201, r.text
    return r.json()


@pytest.mark.parametrize('protocol,route', [('ssh','ssh'),('telnet','ssh'),('rdp','desktop'),('vnc','desktop'),('http','http'),('postgresql','sql'),('mysql','sql')])
def test_protocol_routes_and_wrong_ticket_endpoint(app, client, protocol, route):
    admin_login(app, client)
    r = asset(client, protocol)
    session = connect(client, r)
    assert session['protocol'] == protocol
    assert session['websocket'] == '/ws/'+route+'/'+session['id']
    wrong = ('mysql',) if protocol != 'mysql' else ('ssh',)
    cookie = client.cookies.get('jump_session')
    with pytest.raises(HTTPException):
        validate_access(app, session['id'], cookie, session['ticket'], wrong)
    with transaction(app.state.factory) as db:
        assert db.get(SSHSession, session['id']).state == 'pending'
    assert client.put('/api/assets/'+r['id'], json=dict(name=r['name'],host=r['host'],port=r['port'],username='demo',protocol='mysql' if protocol!='mysql' else 'ssh',database_name='test')).status_code == 409


def test_nonssh_validation():
    assert AssetInput(name='x', host='localhost', username='x').protocol == 'ssh'
    for kwargs in ({'protocol':'postgresql'}, {'protocol':'vnc','auth_type':'private_key'}, {'protocol':'http','http_path':'//other/'}):
        with pytest.raises(ValueError):
            AssetInput(name='x', host='localhost', username='x', **kwargs)


@pytest.mark.parametrize('protocol', ['telnet','rdp','vnc','http','postgresql','mysql'])
def test_protocols_require_grant_and_approval(app, client, protocol):
    admin_login(app, client)
    r = asset(client, protocol, approval_required=True)
    uid, secret = add_user(app,'protocol_operator')
    client.cookies.clear()
    login(client,'protocol_operator',secret)
    assert client.post('/api/sessions', json={'asset_id':r['id']}).status_code == 403
    with transaction(app.state.factory) as db:
        db.add(Grant(user_id=uid, asset_id=r['id'], expires_at=now()+timedelta(hours=1)))
    assert client.post('/api/sessions', json={'asset_id':r['id']}).status_code == 403
    assert client.get('/api/protocol-audit').status_code == 403


def test_real_postgresql_console_audit(app, client):
    admin_login(app, client)
    target = make_url(os.environ['TEST_DATABASE_URL'])
    r = asset(client,'postgresql',host=target.host,port=target.port or 5432,
              username=target.username,credential=target.password,database_name=target.database)
    session = connect(client,r)
    with client.websocket_connect(session['websocket']) as ws:
        ws.send_json({'ticket':session['ticket']})
        assert ws.receive_json()['type'] == 'ready'
        for sql in ('SELECT 42 AS answer', 'SELECT generate_series(1,600)', 'SELECT missing_column', 'SELECT 1; SELECT 2'):
            ws.send_json({'type':'query','sql':sql})
            result = ws.receive_json()
            assert result['type'] == 'result',result
            if sql.startswith('SELECT 42'):
                assert result['rows'] == [[42]]
            elif 'generate_series' in sql:
                assert len(result['rows']) == 500 and result['truncated']
            else:
                assert result.get('error')
        ws.send_json({'type':'query','sql':'SELECT 99'})
        assert ws.receive_json()['rows'] == [[99]]
    rows=client.get('/api/protocol-audit',params={'session_id':session['id']}).json()
    assert len(rows) == 10
    assert sum(row['success'] is False for row in rows) == 2
    assert len({row['operation_id'] for row in rows}) == 5
    with transaction(app.state.factory) as db:
        encrypted=db.scalar(select(ProtocolAudit.detail).where(ProtocolAudit.action=='sql_requested'))
        assert 'SELECT' not in encrypted
    with pytest.raises(DBAPIError):
        with transaction(app.state.factory) as db:
            db.execute(text('DELETE FROM protocol_audit'))


@pytest.mark.parametrize('driver_error,expected', [
    ('server does not support SSL, but SSL was required', '未启用 SSL'),
    ('SSL error: certificate verify failed', 'TLS 证书校验失败'),
    ('password authentication failed for user demo', '用户名或密码验证失败'),
    ('database "missing" does not exist', '数据库不存在'),
    ('connection refused; secret=demo-pass', '连接失败'),
])
def test_postgresql_connection_failure_is_actionable(app, client, monkeypatch, driver_error, expected):
    from jump_ssh import sql_gateway
    admin_login(app, client)
    r = asset(client, 'postgresql', tls_verify=True)
    attempts = []

    def fail_connect(**kwargs):
        attempts.append(kwargs['sslmode'])
        raise sql_gateway.psycopg.OperationalError(driver_error)

    monkeypatch.setattr(sql_gateway.psycopg, 'connect', fail_connect)
    session = connect(client, r)
    with client.websocket_connect(session['websocket']) as ws:
        ws.send_json({'ticket': session['ticket']})
        result = ws.receive_json()
    assert result['type'] == 'closed'
    assert expected in result['message']
    assert 'demo-pass' not in result['message']
    assert attempts == ['verify-full']
    with transaction(app.state.factory) as db:
        saved = db.get(SSHSession, session['id'])
        assert saved.state == 'failed' and expected in saved.error


def test_guacamole_parser_security():
    assert parse_input(instruction('key',65,1)+instruction('mouse',10,10,0)) == ['key','mouse']
    for raw in (instruction('connect','password'),instruction('clipboard',1,'text/plain'),instruction('size',99999,1,96),'4.key,1.1;'):
        with pytest.raises(ValueError):
            parse_input(raw)
    async def check():
        reader=asyncio.StreamReader()
        reader.feed_data(instruction('args','中文','username').encode())
        assert await read_instruction(reader) == ['args','中文','username']
    asyncio.run(check())


def test_http_origin_restriction():
    assert same_origin('http://example.com/a','http://example.com:80')
    for url in ('https://example.com/a','http://other.com','http://example.com:81','http://user@example.com','file:///etc/passwd'):
        assert not same_origin(url,'http://example.com:80')


@contextmanager
def upstream(handler):
    server=ThreadingHTTPServer(('127.0.0.1',0),handler)
    thread=threading.Thread(target=server.serve_forever,daemon=True)
    thread.start()
    try:
        yield server.server_port
    finally:
        server.shutdown();server.server_close();thread.join(3)


def test_http_browser_isolated_recorded_and_revoked(app,client):
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200);self.send_header('Content-Type','text/html');self.end_headers()
            self.wfile.write(b'<html><body>Audited browser<input id="entry"></body></html>')
        def log_message(self,*args): pass
    admin_login(app,client)
    with upstream(Handler) as port:
        r=asset(client,'http',port=port)
        session=connect(client,r)
        with client.websocket_connect(session['websocket']) as ws:
            ws.send_json({'ticket':session['ticket']})
            assert ws.receive_json()['type']=='ready'
            frame=ws.receive_json()
            assert frame['type']=='frame' and len(frame['data'])>100
            with transaction(app.state.factory) as db:
                assert db.scalar(select(Recording).where(Recording.session_id==session['id']))
                db.get(Asset,r['id']).enabled=False
            while True:
                message=ws.receive_json()
                if message['type']=='closed':break
            assert '失效' in message['message'] or '停用' in message['message'] or '禁用' in message['message']
    rows=client.get('/api/protocol-audit',params={'session_id':session['id']}).json()
    assert any(row['action']=='http_request' for row in rows)
