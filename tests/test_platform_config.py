# ============================================================
# 文件名称：test_platform_config.py
# 生成日期：2026-10-20
# 修改日期：2026-11-20
# 版本信息：v0.261115
# 作    者：JUN
# 备    注：本程序由AI辅助完成。
#           文件功能：验证 platform_config 相关功能。
#           文件用途：用于开发验证及功能回归。
#           注意事项：使用隔离测试环境，避免操作正式业务数据。
# ============================================================
from unittest.mock import patch

from dotenv import dotenv_values
from sqlalchemy.engine import make_url

from conftest import add_user, login


def admin_login(client, app):
    _, secret = add_user(app, 'administrator', 'admin')
    assert login(client, 'administrator', secret).status_code == 200


def test_branding_public_but_updates_admin_only(client, app):
    original = client.get('/api/platform').json()
    assert original['platform_name'] == 'JUMP SSH 堡垒机'
    assert client.put('/api/settings/appearance', json=original).status_code == 401
    _, secret = add_user(app, 'operator')
    login(client, 'operator', secret)
    assert client.put('/api/settings/appearance', json=original).status_code == 403
    assert client.get('/api/settings/database').status_code == 403
    assert client.post('/api/settings/database/test', json={}).status_code == 403
    assert client.put('/api/settings/database', json={}).status_code == 403
    client.post('/api/auth/logout', json={})
    admin_login(client, app)
    changed = {**original, 'platform_name':'运维测试平台', 'theme':'dark', 'font':'yahei', 'font_size':16}
    assert client.put('/api/settings/appearance', json=changed).status_code == 200
    client.post('/api/auth/logout', json={})
    assert client.get('/api/platform').json() == changed


def test_appearance_rejects_unsafe_values(client, app):
    admin_login(client, app)
    for value in [{'logo':'data:image/svg+xml;base64,PHN2Zz4='},
                  {'primary_color':'red; background:url(x)'}, {'font_size':100},
                  {'platform_name':''}, {'font':'arbitrary'}]:
        assert client.put('/api/settings/appearance', json=value).status_code == 422


def test_database_password_hidden_and_saved_only_after_check(client, app, tmp_path):
    admin_login(client, app)
    config = tmp_path / '.env'
    config.write_text("DATABASE_URL='postgresql+psycopg://olduser:SET_LOCALLY_BEFORE_USE@127.0.0.1:5432/testdb'\nMASTER_KEY='unchanged'\n")
    app.state.config_path = config
    response = client.get('/api/settings/database')
    assert response.status_code == 200
    assert 'private-db-secret' not in response.text
    configured = response.json()['configured']
    payload = {k:configured[k] for k in ['host','port','database','username','password','sslmode']}
    with patch('jump_ssh.platform_config.check_database', return_value={'connected':True,'schema_ready':False}):
        assert client.put('/api/settings/database', json=payload).status_code == 400
    assert 'sslmode' not in config.read_text()
    with patch('jump_ssh.platform_config.check_database', return_value={'connected':True,'schema_ready':True}) as check:
        result = client.put('/api/settings/database', json=payload)
        assert result.status_code == 200
        assert check.call_args.args[0].password == 'private-db-secret'
    assert make_url(dotenv_values(config)['DATABASE_URL']).password == 'private-db-secret'
    assert dotenv_values(config)['MASTER_KEY'] == 'unchanged'
    assert app.state.settings.database_url != dotenv_values(config)['DATABASE_URL']
    payload['host'] = 'other-host'
    assert client.post('/api/settings/database/test', json=payload).status_code == 400


def test_real_database_connection_and_schema_check(client, app, tmp_path):
    admin_login(client, app)
    config = tmp_path / '.env'
    config.write_text('DATABASE_URL=' + repr(app.state.settings.database_url) + '\n')
    app.state.config_path = config
    payload = client.get('/api/settings/database').json()['configured']
    payload.pop('password_configured')
    result = client.post('/api/settings/database/test', json=payload)
    assert result.status_code == 200, result.text
    assert result.json()['connected'] is True
    assert result.json()['schema_ready'] is True


def test_initialization_keeps_current_users_and_settings(client,app,tmp_path):
    admin_login(client,app)
    config=tmp_path/'.env'
    config.write_text('DATABASE_URL='+repr(app.state.settings.database_url)+'\n')
    app.state.config_path=config
    payload=client.get('/api/settings/database').json()['configured']
    payload.pop('password_configured')
    before=config.read_text()
    for _ in range(2):
        result=client.post('/api/settings/database/initialize',json=payload)
        assert result.status_code==200,result.text
    assert config.read_text()==before


def test_mysql_configuration_preserves_backend_and_password(client, app, tmp_path):
    admin_login(client, app)
    config = tmp_path / '.env'
    config.write_text("DATABASE_URL='mysql+pymysql://storage:SET_LOCALLY_BEFORE_USE@127.0.0.1:3306/platform?charset=utf8mb4'\n", encoding='utf-8')
    app.state.config_path = config
    response = client.get('/api/settings/database')
    assert 'private-mysql-secret' not in response.text
    payload = response.json()['configured']
    assert payload['database_type'] == 'mysql'
    assert payload['port'] == 3306
    payload.pop('password_configured')
    with patch('jump_ssh.platform_config.check_database', return_value={'connected': True, 'schema_ready': True}) as check:
        assert client.put('/api/settings/database', json=payload).status_code == 200
        url = check.call_args.args[0]
        assert url.drivername == 'mysql+pymysql'
        assert url.password == 'private-mysql-secret'
        assert 'sslmode' not in url.query
    payload['database_type'] = 'postgresql'
    assert client.post('/api/settings/database/test', json=payload).status_code == 400
