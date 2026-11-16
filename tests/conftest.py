import os
import uuid

import pyotp
import pytest
from cryptography.fernet import Fernet
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, text
from sqlalchemy.engine import make_url

from jump_ssh.config import Settings
from jump_ssh.db import transaction
from jump_ssh.main import create_app
from jump_ssh.models import Base, User
from jump_ssh.security import password_hash


@pytest.fixture
def app(monkeypatch):
    url = os.environ.get('TEST_DATABASE_URL')
    if not url: pytest.skip('Set TEST_DATABASE_URL to an isolated PostgreSQL test database')
    schema = 'jump_test_' + uuid.uuid4().hex
    control = create_engine(url)
    with control.begin() as conn: conn.execute(text(f'CREATE SCHEMA {schema}'))
    test_url = make_url(url).update_query_dict({'options':'-csearch_path=' + schema})
    monkeypatch.setenv('DATABASE_URL', test_url.render_as_string(hide_password=False))
    monkeypatch.setenv('MASTER_KEY', Fernet.generate_key().decode())
    monkeypatch.setenv('PUBLIC_ORIGIN', 'http://testserver')
    monkeypatch.setenv('COOKIE_SECURE', 'false')
    monkeypatch.setenv('REQUIRE_MFA', 'true')
    monkeypatch.setenv('SSH_PROXY_PORT', '0')
    app = create_app(Settings())
    from alembic import command
    from alembic.config import Config
    from pathlib import Path
    monkeypatch.delenv('MIGRATION_DATABASE_URL', raising=False)
    command.upgrade(Config(str(Path(__file__).resolve().parents[1]/'alembic.ini')), 'head')
    try:
        yield app
    finally:
        app.state.engine.dispose()
        # schema is generated here, never supplied by the operator.
        with control.begin() as conn: conn.execute(text(f'DROP SCHEMA {schema} CASCADE'))
        control.dispose()


@pytest.fixture
def client(app):
    with TestClient(app, headers={'Origin':'http://testserver'}) as client:
        yield client


def add_user(app, username, role='operator'):
    secret = pyotp.random_base32()
    with transaction(app.state.factory) as db:
        user = User(username=username, password_hash=password_hash('test-password-only-123'), role=role,
                    mfa_secret=app.state.vault.encrypt(secret), mfa_enabled=True)
        db.add(user)
        db.flush()
        user_id = user.id
    return user_id, secret


def login(client, username, secret):
    return client.post('/api/auth/login', json={'username':username, 'password':'test-password-only-123',
                                                'code':pyotp.TOTP(secret).now()})
