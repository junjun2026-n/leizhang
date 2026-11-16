from fastapi.testclient import TestClient
from datetime import timedelta

from conftest import add_user, login
from jump_ssh.db import transaction
from jump_ssh.models import Grant, User, SSHSession, now
from test_api import asset_payload
from test_ssh import upstream


def test_batch_grant_validates_all_users_before_saving(client, app):
    _, secret = add_user(app, 'administrator', 'admin')
    alice, _ = add_user(app, 'alice')
    auditor, _ = add_user(app, 'auditor', 'auditor')
    login(client, 'administrator', secret)
    asset = client.post('/api/assets', json=asset_payload()).json()
    payload = {'asset_id':asset['id'], 'user_ids':[alice, 'missing-user'], 'hours':1}
    assert client.post('/api/grants/batch', json=payload).status_code == 404
    assert client.get('/api/grants').json() == []
    payload['user_ids'] = [alice, auditor]
    assert client.post('/api/grants/batch', json=payload).status_code == 400
    assert client.get('/api/grants').json() == []
    with transaction(app.state.factory) as db:
        db.get(User, alice).enabled = False
    payload['user_ids'] = [alice]
    assert client.post('/api/grants/batch', json=payload).status_code == 400


def test_two_platform_users_share_resource_system_account_and_revoke_independently(client, app):
    _, secret = add_user(app, 'administrator', 'admin')
    alice_id, alice_secret = add_user(app, 'alice')
    bob_id, bob_secret = add_user(app, 'bob')
    login(client, 'administrator', secret)
    alice = TestClient(app, headers={'Origin':'http://testserver'})
    bob = TestClient(app, headers={'Origin':'http://testserver'})
    try:
        assert login(alice, 'alice', alice_secret).status_code == 200
        assert login(bob, 'bob', bob_secret).status_code == 200
        with upstream() as (port, key):
            payload = asset_payload()
            payload.update(port=port, username='tester', credential='test-ssh-password', host_key='')
            asset = client.post('/api/assets', json=payload).json()
            asset_id = asset['id']
            response = client.post('/api/grants/batch', json={
                'asset_id':asset_id, 'user_ids':[alice_id, bob_id, alice_id], 'hours':2})
            assert response.status_code == 200, response.text
            assert response.json()['count'] == 2
            assert len(client.get('/api/grants').json()) == 2
            assert client.get('/api/assets').json()[0]['granted_user_count'] == 2
            for operator in [alice, bob]:
                assets = operator.get('/api/assets')
                assert assets.json()[0]['username'] == 'tester'
                assert 'credential' not in assets.json()[0]
                assert assets.json()[0]['authorization_expires_at']
                assert 'granted_user_count' not in assets.json()[0]
                assert 'test-ssh-password' not in assets.text
                assert operator.post('/api/grants/batch', json={
                    'asset_id':asset_id, 'user_ids':[alice_id], 'hours':1}).status_code == 403
                assert operator.post('/api/grants/actions', json={
                    'targets':[{'asset_id':asset_id,'user_id':alice_id}], 'action':'revoke'}).status_code == 403
            first = alice.post('/api/sessions', json={'asset_id':asset_id}).json()
            second = bob.post('/api/sessions', json={'asset_id':asset_id}).json()
            # The upstream accepts only tester/test-ssh-password, never alice or bob.
            with alice.websocket_connect(first['websocket'], headers={'Origin':'http://testserver'}) as ws1:
                ws1.send_json({'ticket':first['ticket']})
                assert 'test ready' in ws1.receive_json()['data']
                with bob.websocket_connect(second['websocket'], headers={'Origin':'http://testserver'}) as ws2:
                    ws2.send_json({'ticket':second['ticket']})
                    assert 'test ready' in ws2.receive_json()['data']
                    own = alice.get('/api/sessions').json()
                    assert len(own) == 1 and own[0]['id'] == first['id']
                    assert own[0]['username'] == 'alice' and own[0]['system_username'] == 'tester'
                    assert alice.post('/api/sessions/'+second['id']+'/terminate', json={}).status_code == 403
                    # Renew Alice without affecting Bob's expiration.
                    with transaction(app.state.factory) as db:
                        original_bob_expiry = db.get(Grant, (bob_id, asset_id)).expires_at
                    assert client.post('/api/grants', json={'asset_id':asset_id,'user_id':alice_id,'hours':3}).status_code == 200
                    with transaction(app.state.factory) as db:
                        assert db.get(Grant, (bob_id, asset_id)).expires_at == original_bob_expiry
                    assert client.request('DELETE', f'/api/grants/{alice_id}/{asset_id}', json={}).status_code == 200
                    assert ws1.receive_json()['type'] == 'closed'
                    assert alice.get('/api/assets').json() == []
                    assert alice.post('/api/sessions', json={'asset_id':asset_id}).status_code == 403
                    assert len(bob.get('/api/assets').json()) == 1
                    assert client.get('/api/assets').json()[0]['granted_user_count'] == 1
                    ws2.send_json({'type':'input','data':'bob-still-connected\n'})
                    output = ''
                    while 'echo: bob-still-connected' not in output:
                        output += ws2.receive_json().get('data', '')
                    ws2.send_json({'type':'input','data':'exit\n'})
                    while ws2.receive_json().get('type') != 'closed':
                        pass
            sessions = client.get('/api/sessions').json()
            assert {row['username'] for row in sessions} == {'alice','bob'}
            recording = client.get('/api/sessions/'+second['id']+'/recording').json()
            assert 'echo: bob-still-connected' in ''.join(row['data'] for row in recording)
    finally:
        alice.close()
        bob.close()


def test_batch_renew_and_revoke_selected_pairs_atomically(client, app):
    _, secret = add_user(app, 'administrator', 'admin')
    alice, _ = add_user(app, 'alice')
    bob, _ = add_user(app, 'bob')
    login(client, 'administrator', secret)
    first = client.post('/api/assets', json=asset_payload()).json()['id']
    payload = asset_payload();payload['name'] = 'second server'
    second = client.post('/api/assets', json=payload).json()['id']
    for asset_id in [first, second]:
        assert client.post('/api/grants/batch', json={'asset_id':asset_id,'user_ids':[alice,bob],'hours':2}).status_code == 200
    sessions = []
    with transaction(app.state.factory) as db:
        db.get(Grant, (alice, first)).expires_at = now() - timedelta(hours=1)
        original_bob = db.get(Grant, (bob, second)).expires_at
        untouched = db.get(Grant, (bob, first)).expires_at
        for user_id, asset_id in [(alice,first),(bob,second),(bob,first)]:
            session = SSHSession(user_id=user_id,asset_id=asset_id,ticket_hash='fixture',
                                 ticket_expires_at=now()+timedelta(minutes=1),state='pending')
            db.add(session);db.flush();sessions.append(session.id)
    targets = [{'user_id':alice,'asset_id':first}, {'user_id':bob,'asset_id':second}]
    invalid = client.post('/api/grants/actions', json={'targets':targets+[{'user_id':'missing','asset_id':first}], 'action':'renew','hours':3})
    assert invalid.status_code == 409
    with transaction(app.state.factory) as db:
        assert db.get(Grant, (bob, second)).expires_at == original_bob
        assert db.get(Grant, (alice, first)).expires_at < now()
    before = now()
    response = client.post('/api/grants/actions', json={'targets':targets+[targets[0]],'action':'renew','hours':3})
    assert response.status_code == 200, response.text
    assert response.json()['count'] == 2
    with transaction(app.state.factory) as db:
        assert db.get(Grant, (bob, second)).expires_at == original_bob + timedelta(hours=3)
        assert before+timedelta(hours=3) <= db.get(Grant, (alice, first)).expires_at <= now()+timedelta(hours=3)
        assert db.get(Grant, (bob, first)).expires_at == untouched
    response = client.post('/api/grants/actions', json={'targets':targets,'action':'revoke'})
    assert response.status_code == 200
    with transaction(app.state.factory) as db:
        assert db.get(Grant, (alice, first)) is None
        assert db.get(Grant, (bob, second)) is None
        assert db.get(Grant, (bob, first)).expires_at == untouched
        assert db.get(Grant, (alice, second)) is not None
        assert db.get(SSHSession, sessions[0]).state == 'terminated'
        assert db.get(SSHSession, sessions[1]).state == 'terminated'
        assert db.get(SSHSession, sessions[2]).state == 'pending'
    assert client.post('/api/grants/actions', json={'targets':[],'action':'renew'}).status_code == 422
