# ============================================================
# 文件名称：test_host_key_probe.py
# 生成日期：2026-10-20
# 修改日期：2026-11-20
# 版本信息：v0.261115
# 作    者：JUN
# 备    注：本程序由AI辅助完成。
#           文件功能：验证 host_key_probe 相关功能。
#           文件用途：用于开发验证及功能回归。
#           注意事项：使用隔离测试环境，避免操作正式业务数据。
# ============================================================
from unittest.mock import AsyncMock, patch

from conftest import add_user, login
from test_api import asset_payload
from test_ssh import upstream


def test_blank_host_key_returns_chinese_message_without_secret(client,app):
    _,secret=add_user(app,'administrator','admin')
    login(client,'administrator',secret)
    payload=asset_payload();payload['host_key']='';payload['verify_host_key']=True
    response=client.post('/api/assets',json=payload)
    assert response.status_code==422
    data=response.json()
    assert isinstance(data['detail'],str)
    assert 'SSH' in data['detail']
    assert data['errors']
    assert 'secret-credential' not in response.text
    assert 'input' not in data['errors'][0]


def test_probe_retrieves_real_server_public_key_and_fingerprint(client,app):
    _,secret=add_user(app,'administrator','admin')
    login(client,'administrator',secret)
    with upstream() as (port,key):
        response=client.post('/api/assets/host-key/probe',json={'host':'127.0.0.1','port':port})
    assert response.status_code==200,response.text
    assert response.json()['host_key']==key.strip()
    assert response.json()['fingerprint'].startswith('SHA256:')
    # A probe must never create or modify an asset automatically.
    assert client.get('/api/assets').json()==[]


def test_asset_defaults_to_password_without_public_key(client, app):
    _, secret = add_user(app, 'administrator', 'admin')
    login(client, 'administrator', secret)
    payload = asset_payload()
    payload.pop('host_key', None)
    payload.pop('verify_host_key', None)
    response = client.post('/api/assets', json=payload)
    assert response.status_code == 201, response.text
    assert response.json()['host_key'] == ''
    assert response.json()['verify_host_key'] is False


def test_probe_requires_admin_and_handles_unreachable_server(client,app):
    _,secret=add_user(app,'operator')
    login(client,'operator',secret)
    assert client.post('/api/assets/host-key/probe',json={'host':'127.0.0.1'}).status_code==403
    client.post('/api/auth/logout',json={})
    _,secret=add_user(app,'administrator','admin')
    login(client,'administrator',secret)
    with patch('jump_ssh.api.asyncssh.get_server_host_key',new_callable=AsyncMock,side_effect=OSError('unreachable')):
        response=client.post('/api/assets/host-key/probe',json={'host':'127.0.0.1'})
    assert response.status_code==502
    assert isinstance(response.json()['detail'],str)
