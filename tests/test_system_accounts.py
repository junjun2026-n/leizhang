# ============================================================
# 文件名称：test_system_accounts.py
# 生成日期：2026-10-20
# 修改日期：2026-11-20
# 版本信息：v0.261115
# 作    者：JUN
# 备    注：本程序由AI辅助完成。
#           文件功能：验证 system_accounts 相关功能。
#           文件用途：用于开发验证及功能回归。
#           注意事项：使用隔离测试环境，避免操作正式业务数据。
# ============================================================
from fastapi.testclient import TestClient
from sqlalchemy import select

from conftest import add_user, login
from jump_ssh.db import transaction
from jump_ssh.models import AccountGrant, SystemAccount, SSHSession
from test_api import asset_payload
from test_ssh import upstream


def setup(client,app):
    _, secret=add_user(app,'administrator','admin')
    alice,alice_secret=add_user(app,'alice')
    login(client,'administrator',secret)
    operator=TestClient(app,headers={'Origin':'http://testserver'})
    login(operator,'alice',alice_secret)
    return alice,operator


def test_independent_credentials_and_account_specific_permissions_over_real_ssh(client,app):
    alice,operator=setup(client,app)
    try:
        with upstream({'root':'root-ssh-password','developer':'dev-ssh-password'}) as (port,key):
            payload=asset_payload();payload.update(username='root',credential='root-ssh-password',port=port)
            asset=client.post('/api/assets',json=payload).json()
            asset_id=asset['id']
            dev=client.post(f'/api/assets/{asset_id}/accounts',json={
                'username':'developer','credential':'dev-ssh-password'}).json()
            dev_id=dev['id']
            assert 'credential' not in dev
            assert len(client.get(f'/api/assets/{asset_id}/accounts').json())==2
            # A legacy resource grant permits only root, never automatically developer.
            assert client.post('/api/grants',json={'user_id':alice,'asset_id':asset_id,'hours':2}).status_code==200
            assert [a['username'] for a in operator.get(f'/api/assets/{asset_id}/accounts').json()]==['root']
            assert operator.post('/api/sessions',json={'asset_id':asset_id,'account_id':dev_id}).status_code==403
            assert client.post('/api/grants',json={'user_id':alice,'asset_id':asset_id,'account_id':dev_id,'hours':2}).status_code==200
            assert client.get('/api/assets').json()[0]['granted_user_count']==1
            assert operator.get('/api/statistics').json()['assets']==1
            sessions=[]
            for account_id,username in [(asset_id,'root'),(dev_id,'developer')]:
                response=operator.post('/api/sessions',json={'asset_id':asset_id,'account_id':account_id})
                assert response.status_code==201,response.text
                sessions.append(response.json())
            with operator.websocket_connect(sessions[0]['websocket'],headers={'Origin':'http://testserver'}) as root_ws:
                root_ws.send_json({'ticket':sessions[0]['ticket']})
                assert 'user=root' in root_ws.receive_json()['data']
                with operator.websocket_connect(sessions[1]['websocket'],headers={'Origin':'http://testserver'}) as dev_ws:
                    dev_ws.send_json({'ticket':sessions[1]['ticket']})
                    assert 'user=developer' in dev_ws.receive_json()['data']
                    response=client.post('/api/grants/actions',json={
                        'targets':[{'user_id':alice,'asset_id':asset_id,'account_id':asset_id}], 'action':'revoke'})
                    assert response.status_code==200
                    assert root_ws.receive_json()['type']=='closed'
                    dev_ws.send_json({'type':'input','data':'still-dev\n'})
                    output=''
                    while 'echo: still-dev' not in output:
                        output+=dev_ws.receive_json().get('data','')
                    assert operator.post('/api/sessions',json={'asset_id':asset_id}).status_code==403
                    visible=operator.get('/api/assets').json()[0]
                    assert [a['username'] for a in visible['accounts']]==['developer']
                    assert 'dev-ssh-password' not in str(visible)
                    dev_ws.send_json({'type':'input','data':'exit\n'})
                    while dev_ws.receive_json().get('type')!='closed': pass
            # Rename after the session: historical session identity remains developer.
            assert client.put(f'/api/assets/{asset_id}/accounts/{dev_id}',json={'username':'engineer','credential':''}).status_code==200
            historical=next(s for s in client.get('/api/sessions').json() if s['id']==sessions[1]['id'])
            assert historical['system_username']=='developer'
            with transaction(app.state.factory) as db:
                accounts=list(db.scalars(select(SystemAccount).where(SystemAccount.asset_id==asset_id)))
                assert {app.state.vault.decrypt(a.credential) for a in accounts}=={'root-ssh-password','dev-ssh-password'}
    finally:
        operator.close()


def test_account_lifecycle_is_scoped_and_cannot_bypass_permissions(client,app):
    alice,operator=setup(client,app)
    try:
        asset=client.post('/api/assets',json=asset_payload()).json()['id']
        second=asset_payload();second['name']='second'
        other=client.post('/api/assets',json=second).json()['id']
        path=f'/api/assets/{asset}/accounts'
        dev=client.post(path,json={'username':'developer','credential':'dev-secret'}).json()['id']
        assert client.post(path,json={'username':'developer','credential':'duplicate'}).status_code==409
        assert client.post(path,json={'username':'blank'}).status_code==400
        assert client.post(path,json={'username':'key','auth_type':'private_key','credential':'bad-key'}).status_code==400
        assert operator.post(path,json={'username':'root','credential':'bad'}).status_code==403
        assert operator.get(path).status_code==403
        assert client.post('/api/grants',json={'user_id':alice,'asset_id':other,'account_id':dev}).status_code==404
        assert client.put(f'/api/assets/{other}/accounts/{dev}',json={'username':'developer'}).status_code==404
        assert client.post('/api/grants',json={'user_id':alice,'asset_id':asset,'account_id':dev}).status_code==200
        response=operator.post('/api/sessions',json={'asset_id':asset,'account_id':dev})
        assert response.status_code==201
        session_id=response.json()['id']
        assert client.put(path+'/'+dev,json={'username':'developer','enabled':False}).status_code==200
        assert operator.post('/api/sessions',json={'asset_id':asset,'account_id':dev}).status_code==403
        assert operator.get('/api/assets').json()==[]
        with transaction(app.state.factory) as db:
            assert db.get(SSHSession,session_id).state=='terminated'
        assert client.put(path+'/'+dev,json={'username':'developer','enabled':True}).status_code==200
        assert client.request('DELETE',path+'/'+dev,json={}).status_code==200
        assert operator.post('/api/sessions',json={'asset_id':asset,'account_id':dev}).status_code==404
        with transaction(app.state.factory) as db:
            assert db.get(AccountGrant,(alice,dev)) is None
            assert db.get(SystemAccount,dev).credential==''
        # Recreate a deleted username without reviving its prior grants.
        recreated=client.post(path,json={'username':'developer','credential':'new-secret'})
        assert recreated.status_code==201
        assert operator.post('/api/sessions',json={'asset_id':asset,'account_id':recreated.json()['id']}).status_code==403
    finally:
        operator.close()


def test_approvals_cannot_be_reused_for_another_system_account(client,app):
    alice,operator=setup(client,app)
    reviewer=client.get('/api/auth/me').json()['id']
    try:
        payload=asset_payload();payload['approval_required']=True
        asset=client.post('/api/assets',json=payload).json()['id']
        dev=client.post(f'/api/assets/{asset}/accounts',json={'username':'developer','credential':'dev-secret'}).json()['id']
        for account_id in [asset,dev]:
            assert client.post('/api/grants',json={'user_id':alice,'asset_id':asset,'account_id':account_id}).status_code==200
        approval=operator.post('/api/approvals',json={'asset_id':asset,'account_id':asset,'reason':'maintenance','approver_id':reviewer}).json()['id']
        assert client.post(f'/api/approvals/{approval}/decide',json={'approve':True}).status_code==200
        assert operator.post('/api/sessions',json={'asset_id':asset,'account_id':asset}).status_code==201
        assert operator.post('/api/sessions',json={'asset_id':asset,'account_id':dev}).status_code==403
        approval=operator.post('/api/approvals',json={'asset_id':asset,'account_id':dev,'reason':'maintenance','approver_id':reviewer}).json()['id']
        assert client.post(f'/api/approvals/{approval}/decide',json={'approve':True}).status_code==200
        assert operator.post('/api/sessions',json={'asset_id':asset,'account_id':dev}).status_code==201
    finally:
        operator.close()


def test_upgrade_preserves_legacy_credentials_and_default_grants(client,app):
    from alembic import command
    from alembic.config import Config
    from pathlib import Path
    from sqlalchemy import text
    from jump_ssh.models import Asset, Grant
    alice,operator=setup(client,app)
    try:
        asset=client.post('/api/assets',json=asset_payload()).json()['id']
        assert client.post('/api/grants',json={'user_id':alice,'asset_id':asset}).status_code==200
        session=operator.post('/api/sessions',json={'asset_id':asset}).json()['id']
        with app.state.engine.begin() as conn:
            for table in ['ssh_sessions','approvals']:
                conn.execute(text(f'ALTER TABLE {table} DROP COLUMN account_id'))
                conn.execute(text(f'ALTER TABLE {table} DROP COLUMN system_username'))
            conn.execute(text('DROP TABLE account_grants'))
            conn.execute(text('DROP TABLE system_accounts'))
            conn.execute(text("UPDATE alembic_version SET version_num='0004'"))
        command.upgrade(Config(str(Path(__file__).resolve().parents[1]/'alembic.ini')),'head')
        with transaction(app.state.factory) as db:
            assert db.get(SystemAccount,asset).credential==db.get(Asset,asset).credential
            assert db.get(Grant,(alice,asset)) is not None
            assert db.get(SSHSession,session).account_id==asset
            assert db.get(SSHSession,session).system_username=='tester'
        assert operator.get(f'/api/assets/{asset}/accounts').json()[0]['username']=='tester'
    finally:
        operator.close()
