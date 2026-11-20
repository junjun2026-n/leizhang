# ============================================================
# 文件名称：test_permissions.py
# 生成日期：2026-10-23
# 修改日期：2026-11-20
# 版本信息：v0.261115
# 作    者：JUN
# 备    注：本程序由AI辅助完成。
#           文件功能：验证 permissions 相关功能。
#           文件用途：用于开发验证及功能回归。
#           注意事项：使用隔离测试环境，避免操作正式业务数据。
# ============================================================
import json
from unittest.mock import AsyncMock

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from conftest import add_user, login
from jump_ssh.db import transaction
from jump_ssh.models import Role, SSHSession, User, ProtocolAudit, identity
from jump_ssh.permissions import ALL, defaults, normalize


def root_login(app, client):
    uid, secret = add_user(app, 'permission_root', 'admin')
    assert login(client, 'permission_root', secret).status_code == 200
    return uid


def role(client, codes, base='operator', name='limited'):
    response = client.post('/api/roles',json=dict(name=name,base_role=base))
    assert response.status_code == 201,response.text
    result = client.put('/api/roles/'+response.json()['id']+'/permissions',json={'permissions':codes})
    assert result.status_code == 200,result.text
    return result.json()


def member(app, client, assigned, name='limited_user'):
    response = client.post('/api/users',json=dict(username=name,password='fixture-password-only-123',role_id=assigned['id']))
    assert response.status_code == 201,response.text
    other = TestClient(app,headers={'Origin':'http://testserver'})
    response_login = other.post('/api/auth/login',json=dict(username=name,password='fixture-password-only-123'))
    assert response_login.status_code == 200,response_login.text
    return response.json()['id'],other


def resource(client, protocol='ssh', approval=False):
    response = client.post('/api/assets',json=dict(name='fixture-'+protocol,protocol=protocol,
        host='127.0.0.1',port=22,username='tester',credential='fixture-secret',
        database_name='test',approval_required=approval))
    assert response.status_code == 201,response.text
    return response.json()['id']


def test_defaults_and_permission_dependencies():
    assert defaults('admin') == ALL
    assert 'sessions.connect' not in defaults('auditor')
    assert {'roles.view','users.view','grants.view','assets.view_all','assets.view'} <= normalize(['grants.manage'])
    assert {'sessions.view','sessions.view_all','sessions.terminate'} <= normalize(['sessions.terminate_all'])


def test_admin_template_can_be_restricted_and_read_operations_stay_separate(app, client):
    root_login(app, client)
    asset_id = resource(client)
    assigned = role(client,['overview.view','assets.view_all','users.view','grants.view','sessions.view_all'],base='admin')
    uid,other = member(app,client,assigned)
    try:
        assert other.get('/api/auth/me').json()['permissions'] == assigned['permissions']
        for path in ['/api/statistics','/api/assets','/api/users','/api/roles','/api/grants','/api/sessions']:
            assert other.get(path).status_code == 200,path
        assert any(a['id'] == asset_id for a in other.get('/api/assets').json())
        for path in ['/api/audit','/api/permissions','/api/protocol-audit','/api/settings/database']:
            assert other.get(path).status_code == 403,path
        assert other.post('/api/sessions',json={'asset_id':asset_id}).status_code == 403
        assert other.post('/api/users',json=dict(username='forbidden',password='test-password-only-123')).status_code == 403
        assert other.post('/api/roles',json={'name':'forbidden'}).status_code == 403
        assert other.post('/api/grants',json=dict(user_id=uid,asset_id=asset_id,hours=1)).status_code == 403
        assert other.put('/api/settings/appearance',json={}).status_code == 403
    finally:
        other.close()


def test_operator_template_can_receive_platform_read_permissions(app, client):
    root_login(app,client)
    assigned = role(client,['users.view','audit.view'])
    _,other = member(app,client,assigned)
    try:
        assert other.get('/api/users').status_code == 200
        assert other.get('/api/audit').status_code == 200
        assert other.get('/api/assets').status_code == 403
        assert other.get('/api/statistics').status_code == 403
        assert other.post('/api/users',json=dict(username='blocked',password='test-password-only-123')).status_code == 403
    finally:
        other.close()


def test_empty_role_can_login_but_cannot_access_platform_modules(app,client):
    root_login(app,client)
    assigned = role(client,[])
    _,other = member(app,client,assigned)
    try:
        assert other.get('/api/auth/me').json()['permissions'] == []
        assert other.get('/api/notifications').status_code == 200
        for path in ['/api/assets','/api/users','/api/sessions','/api/roles','/api/audit','/api/statistics']:
            assert other.get(path).status_code == 403,path
    finally:
        other.close()


def test_delegation_self_lockout_and_protected_admin(app,client):
    root_id = root_login(app,client)
    delegated = role(client,['permissions.manage','users.manage','roles.manage','users.mfa','users.policy'])
    uid,other = member(app,client,delegated)
    try:
        assert other.get('/api/permissions').status_code == 200
        assert other.put('/api/roles/'+delegated['id']+'/permissions',json={'permissions':[]}).status_code == 400
        assert other.put('/api/roles/operator/permissions',json={'permissions':['overview.view']}).status_code == 403
        assert other.patch('/api/users/'+root_id,json=dict(role='operator',enabled=False)).status_code == 403
        assert other.post('/api/users/'+root_id+'/mfa/disable',json={}).status_code == 403
        assert other.put('/api/users/'+root_id+'/command-policy',json=dict(command_mode='allow',command_rules=[])).status_code == 403
        assert other.post('/api/roles',json=dict(name='elevated',base_role='admin')).status_code == 403
        assert other.post('/api/users',json=dict(username='escalated',password='test-password-only-123',role_id='admin')).status_code == 403
        assert client.put('/api/roles/admin/permissions',json={'permissions':[]}).status_code == 400
        assert client.put('/api/roles/operator/permissions',json={'permissions':['unknown.code']}).status_code == 422
    finally:
        other.close()


def test_revoke_permissions_invalidates_login_tickets_and_all_protocol_sessions(app,client):
    root_login(app,client)
    assigned = role(client,sorted(defaults('operator')))
    uid,other = member(app,client,assigned)
    try:
        sessions = []
        for protocol in ['ssh','postgresql']:
            asset_id = resource(client,protocol)
            client.post('/api/grants',json=dict(user_id=uid,asset_id=asset_id,hours=1))
            response = other.post('/api/sessions',json={'asset_id':asset_id})
            assert response.status_code == 201,response.text
            sessions.append(response.json())
        response = client.put('/api/roles/'+assigned['id']+'/permissions',json={'permissions':['assets.view']})
        assert response.status_code == 200,response.text
        assert other.get('/api/auth/me').status_code == 401
        with transaction(app.state.factory) as db:
            assert all(db.get(SSHSession,s['id']).state == 'terminated' for s in sessions)
        with other.websocket_connect(sessions[0]['websocket']) as ws:
            ws.send_json({'ticket':sessions[0]['ticket']})
            assert ws.receive_json()['type'] == 'closed'
        events = client.get('/api/audit').json()
        assert any(e['action']=='permission_revoked' and e['target']==assigned['id']+':sessions.connect' for e in events)
    finally:
        other.close()


def test_websocket_checks_fresh_role_permissions_independent_of_http(app,client,monkeypatch):
    root_login(app,client)
    assigned = role(client,sorted(defaults('operator')))
    uid,other = member(app,client,assigned)
    asset_id = resource(client)
    client.post('/api/grants',json=dict(user_id=uid,asset_id=asset_id,hours=1))
    session = other.post('/api/sessions',json={'asset_id':asset_id}).json()
    connect = AsyncMock()
    monkeypatch.setattr('jump_ssh.ssh.asyncssh.connect',connect)
    try:
        # Leave login and ticket untouched to prove the WebSocket checks permissions itself.
        with transaction(app.state.factory) as db:
            db.get(Role,assigned['id']).permissions = json.dumps(['assets.view'])
        with other.websocket_connect(session['websocket']) as ws:
            ws.send_json({'ticket':session['ticket']})
            assert ws.receive_json()['type'] == 'closed'
        connect.assert_not_awaited()
    finally:
        other.close()


def test_global_asset_visibility_does_not_grant_connection_rights(app,client):
    root_login(app,client)
    asset_id = resource(client)
    assigned = role(client,['assets.view_all','sessions.connect'])
    uid,other = member(app,client,assigned)
    try:
        assert len(other.get('/api/assets').json()) == 1
        assert other.post('/api/sessions',json={'asset_id':asset_id}).status_code == 403
        assert client.post('/api/grants',json=dict(user_id=uid,asset_id=asset_id,hours=1)).status_code == 200
        assert other.post('/api/sessions',json={'asset_id':asset_id}).status_code == 201
    finally:
        other.close()


def test_approval_review_is_permission_based_and_keeps_designated_reviewer(app,client):
    root_login(app,client)
    reviewer_role = role(client,['approvals.review'],name='reviewer')
    reviewer_id,reviewer = member(app,client,reviewer_role,name='reviewer_user')
    requester_role = role(client,sorted(defaults('operator')),name='requester')
    requester_id,requester = member(app,client,requester_role,name='requester_user')
    try:
        asset_id = resource(client,approval=True)
        client.post('/api/grants',json=dict(user_id=requester_id,asset_id=asset_id,hours=1))
        candidates = requester.get('/api/approvals/reviewers').json()
        assert reviewer_id in [u['id'] for u in candidates]
        response = requester.post('/api/approvals',json=dict(asset_id=asset_id,approver_id=reviewer_id,reason='permission review test',hours=1))
        assert response.status_code == 201,response.text
        approval_id = response.json()['id']
        assert reviewer.get('/api/notifications').json()['pending_count'] == 1
        assert client.post('/api/approvals/'+approval_id+'/decide',json={'approve':True}).status_code == 403
        assert reviewer.post('/api/approvals/'+approval_id+'/decide',json={'approve':True}).status_code == 200
        assert requester.post('/api/sessions',json={'asset_id':asset_id}).status_code == 201
    finally:
        reviewer.close()
        requester.close()


def test_global_connection_permission_includes_visibility_but_not_approval_bypass(app,client):
    root_login(app,client)
    open_asset = resource(client)
    approved_asset = resource(client,'postgresql',approval=True)
    assigned = role(client,['assets.access_all'])
    _,other = member(app,client,assigned)
    try:
        assert 'assets.view_all' in other.get('/api/auth/me').json()['permissions']
        assert len(other.get('/api/assets').json()) == 2
        assert other.get('/api/assets/'+open_asset+'/accounts').status_code == 200
        assert other.post('/api/sessions',json={'asset_id':open_asset}).status_code == 201
        assert other.post('/api/sessions',json={'asset_id':approved_asset}).status_code == 403
    finally:
        other.close()


def test_command_and_sql_audit_permissions_do_not_leak_each_others_records(app,client):
    root_login(app,client)
    terminal = resource(client)
    database = resource(client,'postgresql')
    ssh_session = client.post('/api/sessions',json={'asset_id':terminal}).json()['id']
    sql_session = client.post('/api/sessions',json={'asset_id':database}).json()['id']
    with transaction(app.state.factory) as db:
        for session,protocol,action in [(ssh_session,'ssh','command_requested'),(sql_session,'postgresql','sql_requested')]:
            db.add(ProtocolAudit(session_id=session,operation_id=identity(),protocol=protocol,
                action=action,detail=app.state.vault.encrypt(json.dumps({'test':'record'}))))
    sql_role = role(client,['protocols.audit'],name='sql_reader')
    command_role = role(client,['commands.audit'],name='command_reader')
    _,sql_user = member(app,client,sql_role,name='sql_reader_user')
    _,command_user = member(app,client,command_role,name='command_reader_user')
    try:
        rows = sql_user.get('/api/protocol-audit').json()
        assert [r['action'] for r in rows] == ['sql_requested']
        assert sql_user.get('/api/protocol-audit?action_group=command').status_code == 403
        assert sql_user.get('/api/protocol-audit?session_id='+ssh_session).json() == []
        assert command_user.get('/api/protocol-audit').status_code == 403
        rows = command_user.get('/api/protocol-audit?action_group=command').json()
        assert [r['action'] for r in rows] == ['command_requested']
    finally:
        sql_user.close()
        command_user.close()
