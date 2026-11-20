# ============================================================
# 文件名称：test_logging.py
# 生成日期：2026-11-09
# 修改日期：2026-11-20
# 版本信息：v0.261115
# 作    者：JUN
# 备    注：本程序由AI辅助完成。
#           文件功能：验证 logging 相关功能。
#           文件用途：用于开发验证及功能回归。
#           注意事项：使用隔离测试环境，避免操作正式业务数据。
# ============================================================
import json
import socket

from conftest import add_user,login
from jump_ssh.db import transaction
from jump_ssh.models import Audit
from jump_ssh.log_forwarding import LogConfig,Forwarder
from jump_ssh.log_adapter import LogAdapter


def test_operation_details_forwarded_without_credentials(app):
    from datetime import timedelta
    from jump_ssh.models import SSHSession,ProtocolAudit,Asset,now
    user_id,_=add_user(app,'trace_operator')
    with transaction(app.state.factory) as db:
        asset=Asset(name='trace-target',host='192.0.2.20',port=22,username='root',credential='unused',host_key='')
        db.add(asset);db.flush()
        session=SSHSession(user_id=user_id,asset_id=asset.id,system_username='root',ticket_hash='x',ticket_expires_at=now()+timedelta(minutes=1))
        db.add(session);db.flush()
        db.add(ProtocolAudit(session_id=session.id,operation_id='op-trace',protocol='ssh',action='command_forwarded',
            detail=app.state.vault.encrypt(json.dumps({'command':'uname -a','password':'must-not-forward','output':'not-forwarded'})),success=True))
    event=LogAdapter(app.state.factory,app.state.vault).fetch('protocol',0,10)[0][1]
    assert event['operation_detail']=={'command':'uname -a'}
    assert event['actor']=='trace_operator' and event['system_username']=='root'
    assert event['dst_ip']=='192.0.2.20' and event['operation_id']=='op-trace'


def test_logging_permissions_and_udp_test(client,app):
    assert client.get('/api/settings/logging').status_code==401
    _,secret=add_user(app,'log_operator');login(client,'log_operator',secret)
    assert client.get('/api/settings/logging').status_code==403
    assert client.put('/api/settings/logging',json={}).status_code==403
    assert client.post('/api/settings/logging/test',json={}).status_code==403
    client.post('/api/auth/logout',json={})
    _,secret=add_user(app,'log_admin','admin');login(client,'log_admin',secret)
    assert client.get('/api/settings/logging').status_code==200
    assert client.put('/api/settings/logging',json={}).status_code==200
    assert client.put('/api/settings/logging',json={'enabled':True}).status_code==422
    with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as receiver:
        receiver.bind(('127.0.0.1',0));receiver.settimeout(3)
        response=client.post('/api/settings/logging/test',json={'enabled':True,'host':'127.0.0.1','port':receiver.getsockname()[1]})
        assert response.status_code==200
        assert json.loads(receiver.recv(60000))['source']=='test'


def test_pg_log_checkpoint_and_failure(app,monkeypatch):
    sender=Forwarder(LogAdapter(app.state.factory))
    sender.configure(LogConfig(enabled=True,host='127.0.0.1'))
    with transaction(app.state.factory) as db:db.add(Audit(action='test',target='asset',ip='127.0.0.1'))
    def fail(*_):raise OSError('unavailable')
    monkeypatch.setattr('jump_ssh.log_forwarding.send',fail)
    assert not sender.batch() and sender.status()['state']['last_error']
    sent=[];monkeypatch.setattr('jump_ssh.log_forwarding.send',lambda c,p:sent.append(json.loads(p)))
    assert sender.batch() and sent[0]['action']=='test'
    assert not sender.batch()
    assert Forwarder(LogAdapter(app.state.factory)).status()['state']['sent']==1
