import time

import asyncssh
import pyotp
import pytest
from cryptography.fernet import Fernet, InvalidToken
from pydantic import ValidationError

from jump_ssh.api import AssetInput
from jump_ssh.security import Vault, digest, password_hash, totp_step, verify_password


def test_password_hash_and_minimum():
    encoded = password_hash('a-long-unique-password')
    assert encoded.startswith('$argon2id$')
    assert verify_password(encoded, 'a-long-unique-password')
    assert not verify_password(encoded, 'wrong')
    with pytest.raises(ValueError): password_hash('short')


def test_vault_wrong_key_cannot_decrypt():
    vault = Vault(Fernet.generate_key().decode())
    encrypted = vault.encrypt('secret')
    assert 'secret' not in encrypted
    assert vault.decrypt(encrypted) == 'secret'
    with pytest.raises(InvalidToken): Vault(Fernet.generate_key().decode()).decrypt(encrypted)


def test_totp_replay_rejected():
    secret = pyotp.random_base32()
    step = totp_step(secret, pyotp.TOTP(secret).now(), -1)
    assert step is not None
    assert totp_step(secret, pyotp.TOTP(secret).now(), step) is None
    assert totp_step(secret, '------', -1) is None


def test_asset_rejects_unverified_host_key_and_invalid_host():
    key = asyncssh.generate_private_key('ssh-ed25519').export_public_key().decode()
    data = dict(name='test', host='127.0.0.1', username='tester', host_key=key)
    assert AssetInput(**data).port == 22
    with pytest.raises(ValidationError): AssetInput(**{**data, 'host_key':'untrusted'})
    with pytest.raises(ValidationError): AssetInput(**{**data, 'host':'host;rm -rf'})


def test_ticket_digest_does_not_store_plaintext():
    assert digest('opaque-ticket') != 'opaque-ticket'
    assert len(digest('opaque-ticket')) == 64


def test_allowed_origins_reject_wildcard(monkeypatch):
    from jump_ssh.config import Settings
    monkeypatch.setenv('DATABASE_URL','postgresql+psycopg://test:SET_LOCALLY_BEFORE_USE@localhost/test')
    monkeypatch.setenv('MASTER_KEY',Fernet.generate_key().decode())
    monkeypatch.setenv('PUBLIC_ORIGIN','http://localhost:8200')
    monkeypatch.setenv('COOKIE_SECURE','false')
    monkeypatch.setenv('ALLOWED_ORIGINS','http://*:8200')
    with pytest.raises(ValueError): Settings()
