import secrets
from datetime import timedelta

import asyncssh
from sqlalchemy import select

from jump_ssh.db import transaction
from jump_ssh.models import Asset, Audit, Grant, LoginSession, SSHSession, now
from jump_ssh.security import digest
from conftest import add_user, login


def asset_payload(**changes):
    key = asyncssh.generate_private_key('ssh-ed25519').export_public_key().decode()
    return dict(name='test server',host='127.0.0.1',username='tester',credential='secret-credential',
                host_key=key,approval_required=False, **changes)


def test_login_totp_replay_logout(client, app):
    _, secret = add_user(app, 'operator')
    assert login(client, 'operator', secret).status_code == 200
    assert client.get('/api/auth/me').json()['username'] == 'operator'
    assert login(client, 'operator', secret).status_code == 401
    assert client.post('/api/auth/logout', json={}).status_code == 200
    assert client.get('/api/auth/me').status_code == 401


def test_login_failure_rate_limit(client, app):
    add_user(app, 'operator')
    for _ in range(10):
        assert client.post('/api/auth/login', json={'username':'operator','password':'wrong'}).status_code == 401
    assert client.post('/api/auth/login', json={'username':'operator','password':'wrong'}).status_code == 429


def test_origin_and_host_enforced(client):
    assert client.post('/api/auth/login',headers={'Origin':'https://evil.example'},json={}).status_code == 403
    assert client.get('/',headers={'Host':'evil.example'}).status_code == 400
    response = client.get('/')
    assert response.status_code == 200
    assert "frame-ancestors 'none'" in response.headers['Content-Security-Policy']


def test_lan_origin_supported_but_cross_origin_request_rejected(client, app):
    lan='http://192.168.2.201:8200'
    app.state.settings.allowed_origins.add(lan)
    assert client.get('/',headers={'Host':'192.168.2.201:8200'}).status_code==200
    assert client.post('/api/auth/login',headers={'Host':'testserver','Origin':lan},json={}).status_code==403
    _,secret=add_user(app,'lan_operator')
    import pyotp
    response=client.post('/api/auth/login',headers={'Host':'192.168.2.201:8200','Origin':lan},json={
        'username':'lan_operator','password':'test-password-only-123','code':pyotp.TOTP(secret).now()})
    assert response.status_code==200


def test_operator_cannot_manage_assets_or_users(client, app):
    _,secret=add_user(app,'operator')
    login(client,'operator',secret)
    assert client.get('/api/users').status_code == 403
    assert client.get('/api/audit').status_code == 403
    assert client.post('/api/assets',json=asset_payload()).status_code == 403


def test_credential_encrypted_and_not_returned(client, app):
    _,secret=add_user(app,'administrator','admin')
    login(client,'administrator',secret)
    response=client.post('/api/assets',json=asset_payload())
    assert response.status_code == 201
    assert 'credential' not in response.json()
    with transaction(app.state.factory) as db:
        asset=db.get(Asset,response.json()['id'])
        assert asset.credential != 'secret-credential'
        assert app.state.vault.decrypt(asset.credential) == 'secret-credential'
    assert 'secret-credential' not in client.get('/api/assets').text


def test_grant_required_and_revocation_terminates(client, app):
    admin_id,secret=add_user(app,'administrator','admin')
    user_id,_=add_user(app,'operator')
    login(client,'administrator',secret)
    asset=client.post('/api/assets',json=asset_payload()).json()
    assert client.post('/api/grants',json={'user_id':user_id,'asset_id':asset['id'],'hours':1}).status_code==200
    with transaction(app.state.factory) as db:
        session=SSHSession(user_id=user_id,asset_id=asset['id'],ticket_hash='x',ticket_expires_at=now()+timedelta(minutes=1),state='active')
        db.add(session);db.flush();session_id=session.id
    assert client.request('DELETE', f"/api/grants/{user_id}/{asset['id']}",json={}).status_code==200
    with transaction(app.state.factory) as db:
        assert db.get(SSHSession,session_id).state=='terminated'


def test_approval_no_self_review(client, app):
    _,secret=add_user(app,'administrator','admin')
    reviewer,_=add_user(app,'reviewer','admin')
    login(client,'administrator',secret)
    data=asset_payload();data['approval_required']=True
    asset=client.post('/api/assets',json=data).json()
    response=client.post('/api/sessions',json={'asset_id':asset['id']})
    assert response.status_code==403
    approval=client.post('/api/approvals',json={'asset_id':asset['id'],'reason':'test maintenance','approver_id':reviewer}).json()
    assert client.post('/api/approvals/'+approval['id']+'/decide',json={'approve':True}).status_code==403


def test_disabled_user_loses_existing_session(client, app):
    user_id,secret=add_user(app,'operator')
    login(client,'operator',secret)
    with transaction(app.state.factory) as db:
        from jump_ssh.models import User
        db.get(User,user_id).enabled=False
    assert client.get('/api/auth/me').status_code==401


def test_ticket_bound_to_cookie_owner_and_single_use(client, app):
    from fastapi import HTTPException
    import pytest
    from jump_ssh.ssh import validate_access
    _,secret=add_user(app,'administrator','admin')
    login(client,'administrator',secret)
    asset=client.post('/api/assets',json=asset_payload()).json()
    response=client.post('/api/sessions',json={'asset_id':asset['id']})
    assert response.status_code==201
    session=response.json()
    cookie=client.cookies.get('jump_session')
    with pytest.raises(HTTPException): validate_access(app,session['id'],'wrong',session['ticket'])
    validate_access(app,session['id'],cookie,session['ticket'])
    with pytest.raises(HTTPException): validate_access(app,session['id'],cookie,session['ticket'])


def test_password_change_revokes_sessions(client,app):
    _,secret=add_user(app,'operator')
    login(client,'operator',secret)
    response=client.post('/api/auth/password',json={'old_password':'test-password-only-123','new_password':'replacement-password-123'})
    assert response.status_code==200
    assert client.get('/api/auth/me').status_code==401


def test_audit_rows_cannot_be_changed_or_deleted(app):
    import pytest
    from sqlalchemy import text
    from sqlalchemy.exc import DBAPIError
    with app.state.engine.begin() as conn:
        conn.execute(text("INSERT INTO audit_logs(action,target,ip,created_at) VALUES('test','target','local',now())"))
    for statement in ("UPDATE audit_logs SET target='changed'", 'DELETE FROM audit_logs', 'TRUNCATE audit_logs'):
        with pytest.raises(DBAPIError):
            with app.state.engine.begin() as conn: conn.execute(text(statement))


def test_ungranted_asset_is_hidden_and_connection_denied(client,app):
    _,secret=add_user(app,'operator')
    with transaction(app.state.factory) as db:
        payload=asset_payload()
        payload['credential']=app.state.vault.encrypt(payload['credential'])
        asset=Asset(**payload);db.add(asset);db.flush();asset_id=asset.id
    login(client,'operator',secret)
    assert client.get('/api/assets').json()==[]
    assert client.post('/api/sessions',json={'asset_id':asset_id}).status_code==403
