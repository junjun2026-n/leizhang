# ============================================================
# 文件名称：test_roles_commands.py
# 生成日期：2026-10-23
# 修改日期：2026-11-20
# 版本信息：v0.261115
# 作    者：JUN
# 备    注：本程序由AI辅助完成。
#           文件功能：验证 roles_commands 相关功能。
#           文件用途：用于开发验证及功能回归。
#           注意事项：使用隔离测试环境，避免操作正式业务数据。
# ============================================================
import asyncio
import json

import pytest
import telnetlib3
from fastapi import HTTPException
from sqlalchemy import select

from conftest import add_user, login
from jump_ssh.command_policy import checked_command
from jump_ssh.db import transaction
from jump_ssh.models import Role, SSHSession, User
from test_protocol_bridges import listener, prepare as prepare_bridge
from test_ssh import upstream, prepare


def admin(app, client):
    uid, secret = add_user(app, 'role_admin', 'admin')
    assert login(client, 'role_admin', secret).status_code == 200
    return uid


def test_role_crud_assignment_and_permission_changes(app, client):
    admin_id = admin(app, client)
    r = client.post('/api/roles', json=dict(name='只读运维', description='巡检',
        command_mode='allow', command_rules=['whoami', 'ls *']))
    assert r.status_code == 201, r.text
    role = r.json()
    response = client.post('/api/users', json=dict(username='role_member', password='test-password-only-123', role_id=role['id']))
    assert response.status_code == 201, response.text
    uid = response.json()['id']
    with transaction(app.state.factory) as db:
        assert db.get(User, uid).role == 'operator'
    assert client.delete('/api/roles/'+role['id']).status_code == 409
    payload = {**role, 'name':'只读审计', 'base_role':'auditor'}
    assert client.put('/api/roles/'+role['id'], json=payload).status_code == 200
    with transaction(app.state.factory) as db:
        assert db.get(User, uid).role == 'auditor'
    rows = client.get('/api/users').json()
    assert next(u for u in rows if u['id'] == uid)['role_name'] == '只读审计'
    assert client.patch('/api/users/'+uid, json=dict(role='operator', enabled=True, role_id='operator')).status_code == 200
    assert client.delete('/api/roles/'+role['id']).status_code == 200
    assert client.delete('/api/roles/operator').status_code == 400
    builtin = next(r for r in client.get('/api/roles').json() if r['id'] == 'admin')
    assert client.put('/api/roles/admin', json={**builtin,'base_role':'operator'}).status_code == 400
    assert client.patch('/api/users/'+admin_id, json=dict(role='operator', enabled=True)).status_code == 400


def test_nonadmin_cannot_edit_roles_or_policies(app, client):
    uid, secret = add_user(app, 'operator_only')
    login(client, 'operator_only', secret)
    assert client.get('/api/roles').status_code == 403
    assert client.post('/api/roles', json=dict(name='forbidden')).status_code == 403
    assert client.put('/api/users/'+uid+'/command-policy', json=dict(command_mode='allow', command_rules=['*'])).status_code == 403


def test_role_policy_inheritance_revokes_only_terminal_sessions(app, client):
    from jump_ssh.command_policy import policies_for
    uid = admin(app, client)
    role = client.post('/api/roles',json=dict(name='受控管理员',base_role='admin')).json()
    with transaction(app.state.factory) as db:
        db.get(User,uid).role_id = role['id']
    sessions = {}
    for protocol in ['ssh','telnet','postgresql']:
        asset = client.post('/api/assets',json=dict(name='inherit-'+protocol,protocol=protocol,
            host='127.0.0.1',port=22,username='tester',credential='test-secret',
            approval_required=False,database_name='demo')).json()
        sessions[protocol] = client.post('/api/sessions',json={'asset_id':asset['id']}).json()['id']
    payload = {**role,'command_mode':'allow','command_rules':['whoami','ls *']}
    assert client.put('/api/roles/'+role['id'],json=payload).status_code == 200
    assert client.get('/api/auth/me').json()['role_name'] == '受控管理员'
    with transaction(app.state.factory) as db:
        assert db.get(SSHSession,sessions['ssh']).state == 'terminated'
        assert db.get(SSHSession,sessions['telnet']).state == 'terminated'
        assert db.get(SSHSession,sessions['postgresql']).state == 'pending'
        assert policies_for(db,db.get(User,uid)) == [('allow',['whoami','ls *'])]
    assert client.put('/api/roles/'+role['id'],json={**payload,'base_role':'operator'}).status_code == 400
    assert client.put('/api/users/'+uid+'/command-policy',json=dict(command_mode='deny',command_rules=['ls'])).status_code == 200
    with transaction(app.state.factory) as db:
        policies = policies_for(db,db.get(User,uid))
        assert checked_command('whoami',policies) == 'whoami'
        with pytest.raises(HTTPException):checked_command('ls -l',policies)
        assert db.get(SSHSession,sessions['postgresql']).state == 'pending'
    assert client.post('/api/roles',json=dict(name='受控管理员')).status_code == 409
    assert client.post('/api/roles',json=dict(name='   ')).status_code == 422


@pytest.mark.parametrize('command', ['rm -rf /', '/bin/rm -rf /', 'ls; rm x', 'ls && whoami',
    'echo $(id)', 'echo `id`', 'echo $SHELL', 'ls\nwhoami', 'bash', 'python3.10 -c pass',
    'env rm x', 'sudo ls', 'ls > /tmp/x', 'find . -exec rm x', 'echo \\x', 'vim',
    '. /tmp/script', 'alias innocent=rm', 'export PROMPT_COMMAND="rm x"', 'trap "rm x" EXIT'])
def test_policy_rejects_denials_and_shell_bypasses(command):
    with pytest.raises(HTTPException):
        checked_command(command, [('deny', ['rm'])])


def test_policy_intersection_and_empty_allowlist():
    assert checked_command('ls -l', [('allow',['ls *']),('deny',['rm'])]) == 'ls -l'
    assert checked_command('/bin/ls -l', [('allow',['ls *'])]) == '/bin/ls -l'
    for policies in [[('allow', [])], [('allow',['ls *']),('allow',['whoami'])], [('allow',['ls *']),('deny',['ls'])]]:
        with pytest.raises(HTTPException):
            checked_command('ls -l', policies)


def receive_until(ws, needle):
    output = ''
    while needle not in output:
        message = ws.receive_json()
        assert message['type'] == 'output', message
        output += message['data']
    return output


def test_restricted_ssh_denied_commands_never_reach_upstream(app, client):
    commands = []
    async def handle(proc):
        commands.append(proc.command)
        proc.stdout.write('result:'+proc.command+'\r\n')
        proc.exit(0)
    with upstream(command_handler=handle) as (port,key):
        session = prepare(client, app, port, key)
        uid = client.get('/api/auth/me').json()['id']
        assert client.put('/api/users/'+uid+'/command-policy', json=dict(command_mode='allow', command_rules=['whoami','echo *'])).status_code == 200
        # Saving policy invalidates pending tickets too.
        with transaction(app.state.factory) as db:
            assert db.get(SSHSession, session['id']).state == 'terminated'
            asset_id = db.get(SSHSession, session['id']).asset_id
        session = client.post('/api/sessions', json={'asset_id':asset_id}).json()
        with client.websocket_connect(session['websocket']) as ws:
            ws.send_json({'ticket':session['ticket']})
            receive_until(ws, 'policy> ')
            ws.send_json({'type':'input','data':'rm secret\r'})
            receive_until(ws, '白名单')
            assert commands == []
            ws.send_json({'type':'input','data':'echo safe; rm x\r'})
            receive_until(ws, '单条命令')
            assert commands == []
            ws.send_json({'type':'input','data':'\x1b[A\r'})
            receive_until(ws, '控制序列')
            assert commands == []
            ws.send_json({'type':'input','data':'whoami\r'})
            receive_until(ws, 'result:whoami')
            assert commands == ['whoami']
        audits = client.get('/api/protocol-audit',params={'session_id':session['id']}).json()
        assert sum(r['action']=='command_denied' for r in audits) == 2
        assert any(r['action']=='command_completed' and r['success'] for r in audits)
        assert client.put('/api/users/'+uid+'/command-policy',json=dict(command_mode='deny', command_rules=[])).status_code == 422


def test_restricted_telnet_line_filtering_and_audit(app, client):
    commands = []
    async def shell(reader, writer):
        try:
            writer.write('login: '); await writer.drain()
            assert (await reader.readline()).strip() == 'tester'
            writer.write('Password: '); await writer.drain()
            assert (await reader.readline()).strip() == 'bridge-secret'
            writer.write('\r\nready> '); await writer.drain()
            while True:
                line = await reader.readline()
                if not line: break
                commands.append(line.strip())
                writer.write('result:'+line+'\r\nready> '); await writer.drain()
        finally:
            writer.close()
    async def start():
        return await telnetlib3.create_server(host='127.0.0.1',port=0,shell=shell,connect_maxwait=.5)
    with listener(start) as port:
        initial = prepare_bridge(app, client, 'telnet', port)
        uid = client.get('/api/auth/me').json()['id']
        with transaction(app.state.factory) as db:
            asset_id = db.get(SSHSession,initial['id']).asset_id
        client.put('/api/users/'+uid+'/command-policy',json=dict(command_mode='deny', command_rules=['rm']))
        session = client.post('/api/sessions',json={'asset_id':asset_id}).json()
        with client.websocket_connect(session['websocket']) as ws:
            ws.send_json({'ticket':session['ticket']})
            receive_until(ws, 'ready> ')
            ws.send_json({'type':'input','data':'rm x\r'})
            receive_until(ws, '黑名单')
            assert commands == []
            ws.send_json({'type':'input','data':'whoami\r'})
            receive_until(ws, 'result:whoami')
            assert commands == ['whoami']
        audits = client.get('/api/protocol-audit',params={'session_id':session['id']}).json()
        assert any(r['action']=='command_denied' for r in audits)
        assert any(r['action']=='command_forwarded' for r in audits)
