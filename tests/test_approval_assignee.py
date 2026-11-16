from types import SimpleNamespace
from datetime import timedelta

from conftest import add_user
from jump_ssh.api import actor
from jump_ssh.db import transaction
from jump_ssh.models import Approval, User, now
from test_api import asset_payload


def test_selected_approver_is_enforced_and_names_are_visible(client, app):
    owner, _ = add_user(app, 'requester', 'admin')
    reviewer, _ = add_user(app, 'reviewer', 'admin')
    other, _ = add_user(app, 'other', 'admin')
    operator, _ = add_user(app, 'operator')
    disabled, _ = add_user(app, 'disabled', 'admin')
    with transaction(app.state.factory) as db:
        db.get(User, disabled).enabled = False
    current = SimpleNamespace(id=owner, role='admin')
    app.dependency_overrides[actor] = lambda: current
    asset = client.post('/api/assets', json=asset_payload()).json()['id']
    reviewers = client.get('/api/approvals/reviewers').json()
    assert {u['id'] for u in reviewers} == {reviewer, other}
    assert all(set(u) == {'id', 'username'} for u in reviewers)
    payload = dict(asset_id=asset, reason='maintenance')
    for invalid in (None, owner, operator, disabled, 'missing'):
        response = client.post('/api/approvals', json={**payload, 'approver_id': invalid})
        assert response.status_code == 400, response.text
    response = client.post('/api/approvals', json={**payload, 'approver_id': reviewer})
    assert response.status_code == 201, response.text
    request_id = response.json()['id']
    assert client.get('/api/notifications/approvals').json() == {'count': 0, 'items': []}
    row = client.get('/api/approvals').json()[0]
    assert row['approver_id'] == reviewer and row['approver_name'] == 'reviewer'
    assert row['username'] == 'requester' and row['reviewer_id'] is None
    current = SimpleNamespace(id=other, role='admin')
    assert client.get('/api/notifications/approvals').json()['count'] == 0
    assert client.post(f'/api/approvals/{request_id}/decide', json={'approve': True}).status_code == 403
    current = SimpleNamespace(id=operator, role='operator')
    assert client.get('/api/notifications/approvals').status_code == 403
    assert client.get('/api/approvals').json() == []
    assert client.post(f'/api/approvals/{request_id}/decide', json={'approve': True}).status_code == 403
    current = SimpleNamespace(id=reviewer, role='admin')
    reminder = client.get('/api/notifications/approvals').json()
    assert reminder['count'] == 1
    assert reminder['items'][0]['id'] == request_id
    assert reminder['items'][0]['username'] == 'requester'
    assert reminder['items'][0]['asset_name'] == asset_payload()['name']
    assert client.post(f'/api/approvals/{request_id}/decide', json={'approve': True}).status_code == 200
    assert client.get('/api/approvals').json()[0]['reviewer_name'] == 'reviewer'
    assert client.get('/api/notifications/approvals').json()['count'] == 0
    assert client.post(f'/api/approvals/{request_id}/decide', json={'approve': False}).status_code == 409
    assert client.get('/api/notifications').json()['results'] == []
    assert client.post(f'/api/notifications/approvals/{request_id}/read', json={}).status_code == 404
    current = SimpleNamespace(id=owner, role='admin')
    messages = client.get('/api/notifications').json()
    assert messages['count'] == 1
    assert messages['results'][0]['state'] == 'approved'
    assert messages['results'][0]['reviewer_name'] == 'reviewer'
    assert client.post(f'/api/notifications/approvals/{request_id}/read', json={}).status_code == 200
    assert client.get('/api/notifications').json()['count'] == 0
    current = SimpleNamespace(id=reviewer, role='admin')
    # Pre-migration requests remain reviewable by an independent administrator.
    with transaction(app.state.factory) as db:
        prior = db.get(Approval, request_id)
        legacy = Approval(user_id=owner, asset_id=asset, account_id=prior.account_id,
                          reason='legacy request', expires_at=prior.expires_at)
        db.add(legacy)
        db.flush()
        legacy_id = legacy.id
    assert client.get('/api/notifications/approvals').json()['count'] == 1
    assert client.post(f'/api/approvals/{legacy_id}/decide', json={'approve': False}).status_code == 200
    current = SimpleNamespace(id=owner, role='operator')
    assert client.get('/api/notifications').json()['results'][0]['state'] == 'rejected'
    assert client.post(f'/api/notifications/approvals/{legacy_id}/read', json={}).status_code == 200
    assert client.get('/api/notifications').json()['count'] == 0
    current = SimpleNamespace(id=reviewer, role='admin')
    with transaction(app.state.factory) as db:
        expired = db.get(Approval, request_id)
        expired.state = 'pending'
        expired.expires_at = now() - timedelta(seconds=1)
    assert client.get('/api/notifications/approvals').json() == {'count': 0, 'items': []}


def test_requester_cannot_choose_self_and_empty_reviewers_are_explicit(client, app):
    owner, _ = add_user(app, 'only-admin', 'admin')
    app.dependency_overrides[actor] = lambda: SimpleNamespace(id=owner, role='admin')
    assert client.get('/api/approvals/reviewers').json() == []
    asset = client.post('/api/assets', json=asset_payload()).json()['id']
    assert client.post('/api/approvals', json=dict(asset_id=asset, reason='maintenance',
                                                 approver_id=owner)).status_code == 400
