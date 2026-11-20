# ============================================================
# 文件名称：test_user_password_reset.py
# 生成日期：2026-11-11
# 修改日期：2026-11-20
# 版本信息：v0.261115
# 作    者：JUN
# 备    注：本程序由AI辅助完成。
#           文件功能：验证 user_password_reset 相关功能。
#           文件用途：用于开发验证及功能回归。
#           注意事项：使用隔离测试环境，避免操作正式业务数据。
# ============================================================
from conftest import add_user,login
from jump_ssh.db import transaction
from jump_ssh.models import User,LoginSession,Audit
from jump_ssh.security import verify_password
from sqlalchemy import select


def test_admin_reset_permissions_invalidation_and_audit(client,app):
    target_id,target_secret=add_user(app,'reset_target')
    admin_id,admin_secret=add_user(app,'reset_admin','admin')
    login(client,'reset_target',target_secret)
    old_cookie=client.cookies.get('jump_session')
    url=f'/api/users/{target_id}/password'
    password='changed-password-12345'
    assert client.post(url,json={'new_password':password}).status_code==403
    client.cookies.clear()
    login(client,'reset_admin',admin_secret)
    assert client.post(url,json={'new_password':'short'}).status_code==422
    assert client.post(f'/api/users/{admin_id}/password',json={'new_password':password}).status_code==403
    assert client.post('/api/users/missing/password',json={'new_password':password}).status_code==404
    from datetime import timedelta
    from jump_ssh.models import Asset,SSHSession,now
    with transaction(app.state.factory) as db:
        asset=Asset(name='reset-test',host='192.0.2.1',port=22,username='test',credential='unused',host_key='')
        db.add(asset);db.flush()
        connection=SSHSession(user_id=target_id,asset_id=asset.id,ticket_hash='unused',ticket_expires_at=now()+timedelta(minutes=1),state='active')
        db.add(connection);db.flush();connection_id=connection.id
        assert db.scalar(select(LoginSession).where(LoginSession.user_id==target_id))
    assert client.post(url,json={'new_password':password}).status_code==200
    with transaction(app.state.factory) as db:
        target=db.get(User,target_id)
        assert verify_password(target.password_hash,password)
        assert not verify_password(target.password_hash,'test-password-only-123')
        assert target.mfa_enabled
        assert not db.scalar(select(LoginSession).where(LoginSession.user_id==target_id))
        assert db.get(SSHSession,connection_id).state=='terminated'
        audit=db.scalar(select(Audit).where(Audit.action=='user_password_reset'))
        assert audit.actor_id==admin_id and audit.target==target_id
        assert password not in audit.target
    client.cookies.clear();client.cookies.set('jump_session',old_cookie)
    assert client.get('/api/auth/me').status_code==401
