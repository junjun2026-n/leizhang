# ============================================================
# 文件名称：test_manual_mfa.py
# 生成日期：2026-10-20
# 修改日期：2026-11-20
# 版本信息：v0.261115
# 作    者：JUN
# 备    注：本程序由AI辅助完成。
#           文件功能：验证 manual_mfa 相关功能。
#           文件用途：用于开发验证及功能回归。
#           注意事项：使用隔离测试环境，避免操作正式业务数据。
# ============================================================
import time
from datetime import timedelta

import pyotp
from fastapi.testclient import TestClient

from conftest import add_user, login
from jump_ssh.db import transaction
from jump_ssh.models import User, now
from jump_ssh.security import password_hash


def test_first_login_does_not_require_mfa(client, app):
    with transaction(app.state.factory) as db:
        db.add(User(username='first_user',password_hash=password_hash('first-login-password')))
    result=client.post('/api/auth/login',json={'username':'first_user','password':'first-login-password'})
    assert result.status_code==200
    assert client.get('/api/auth/me').json()['mfa'] is False


def test_admin_creates_user_with_mfa_off(client, app):
    _,secret=add_user(app,'administrator','admin')
    login(client,'administrator',secret)
    response=client.post('/api/users',json={'username':'new_user','password':'initial-password-123'})
    assert response.status_code==201
    assert 'mfa_uri' not in response.json()
    with transaction(app.state.factory) as db:
        target=db.get(User,response.json()['id'])
        assert target.mfa_enabled is False and target.mfa_secret is None


def test_enable_requires_binding_verification_then_disable_restores_password_login(client, app):
    _,secret=add_user(app,'administrator','admin')
    login(client,'administrator',secret)
    target=client.post('/api/users',json={'username':'target_user','password':'initial-password-123'}).json()['id']
    with TestClient(app,headers={'Origin':'http://testserver'}) as other:
        assert other.post('/api/auth/login',json={'username':'target_user','password':'initial-password-123'}).status_code==200
        setup=client.post(f'/api/users/{target}/mfa/setup',json={}).json()
        assert other.get('/api/auth/me').json()['mfa'] is False
        assert client.post(f'/api/users/{target}/mfa/enable',json={'code':'------'}).status_code==422
        code=pyotp.TOTP(setup['secret']).now()
        assert client.post(f'/api/users/{target}/mfa/enable',json={'code':code}).status_code==200
        assert other.get('/api/auth/me').status_code==401
        assert other.post('/api/auth/login',json={'username':'target_user','password':'initial-password-123'}).status_code==401
        code=pyotp.TOTP(setup['secret']).at((int(time.time())//30+1)*30)
        assert other.post('/api/auth/login',json={'username':'target_user','password':'initial-password-123','code':code}).status_code==200
        assert client.post(f'/api/users/{target}/mfa/disable',json={}).status_code==200
        assert other.get('/api/auth/me').status_code==401
        assert other.post('/api/auth/login',json={'username':'target_user','password':'initial-password-123'}).status_code==200


def test_setup_expires_and_operator_cannot_manage_mfa(client, app):
    admin_id,secret=add_user(app,'administrator','admin')
    login(client,'administrator',secret)
    target=client.post('/api/users',json={'username':'target_user','password':'initial-password-123'}).json()['id']
    setup=client.post(f'/api/users/{target}/mfa/setup',json={}).json()
    with transaction(app.state.factory) as db:
        db.get(User,target).mfa_setup_expires_at=now()-timedelta(seconds=1)
    assert client.post(f'/api/users/{target}/mfa/enable',json={'code':pyotp.TOTP(setup['secret']).now()}).status_code==400
    client.post('/api/auth/logout',json={})
    client.post('/api/auth/login',json={'username':'target_user','password':'initial-password-123'})
    assert client.post(f'/api/users/{admin_id}/mfa/setup',json={}).status_code==403
    assert client.post(f'/api/users/{admin_id}/mfa/disable',json={}).status_code==403
