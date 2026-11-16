from datetime import timedelta
from types import SimpleNamespace

from sqlalchemy import event, select

from jump_ssh.api import statistics
from jump_ssh.db import transaction
from jump_ssh.models import Asset, AccountGrant, Grant, SSHSession, SystemAccount, User, now
from jump_ssh.resource_accounts import accessible_accounts
from conftest import add_user


def test_statistics_preserves_account_access_and_uses_constant_queries(app):
    operator_id, _ = add_user(app, 'stats_operator')
    other_id, _ = add_user(app, 'stats_other')
    admin_id, _ = add_user(app, 'stats_admin', 'admin')
    auditor_id, _ = add_user(app, 'stats_auditor', 'auditor')
    with transaction(app.state.factory) as db:
        for name in ('legacy', 'disabled_asset', 'disabled_account', 'deleted_account',
                     'default', 'extra', 'expired', 'other_user', 'ungranted'):
            asset = Asset(id=name, name=name, host='localhost', username='tester',
                          credential='encrypted', host_key='', enabled=name != 'disabled_asset')
            db.add(asset)
            db.flush()
            if name in ('disabled_account', 'deleted_account', 'default', 'extra'):
                account = SystemAccount(id=name if name != 'extra' else 'extra-account',
                    asset_id=name, username='tester', credential='encrypted',
                    enabled=name != 'disabled_account', deleted=name == 'deleted_account')
                db.add(account)
                db.flush()
            if name == 'extra':
                db.add(AccountGrant(user_id=operator_id, account_id='extra-account', expires_at=now()+timedelta(hours=1)))
            elif name != 'ungranted':
                db.add(Grant(user_id=other_id if name == 'other_user' else operator_id,
                    asset_id=name, expires_at=now()+timedelta(hours=-1 if name == 'expired' else 1)))
        for owner, state in ((operator_id, 'active'), (operator_id, 'failed'),
                             (operator_id, 'closed'), (other_id, 'active')):
            db.add(SSHSession(user_id=owner, asset_id='legacy', state=state,
                ticket_hash='test', ticket_expires_at=now()+timedelta(minutes=1)))
    with transaction(app.state.factory) as db:
        operator = db.get(User, operator_id)
        expected = sum(bool(accessible_accounts(db, operator, asset)) for asset in db.scalars(select(Asset)))
        admin, auditor = db.get(User, admin_id), db.get(User, auditor_id)
    assert expected == 3
    statements = []
    def record(conn, cursor, statement, parameters, context, executemany):
        statements.append(statement)
    event.listen(app.state.engine, 'before_cursor_execute', record)
    try:
        result = statistics(SimpleNamespace(app=app), operator)
    finally:
        event.remove(app.state.engine, 'before_cursor_execute', record)
    assert result == dict(assets=expected, sessions=3, active=1, failures=1)
    assert len(statements) == 2
    assert statistics(SimpleNamespace(app=app), admin) == dict(assets=9, sessions=4, active=2, failures=1)
    assert statistics(SimpleNamespace(app=app), auditor) == dict(assets=0, sessions=4, active=2, failures=1)
