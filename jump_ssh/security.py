import hashlib
import secrets
import time

import pyotp
from argon2 import PasswordHasher
from argon2.exceptions import VerificationError, InvalidHashError
from cryptography.fernet import Fernet

hasher = PasswordHasher()


def digest(value):
    return hashlib.sha256(value.encode()).hexdigest()


def password_hash(value):
    if len(value) < 12 or len(value) > 256:
        raise ValueError('密码长度必须为 12–256 个字符')
    return hasher.hash(value)


def verify_password(encoded, value):
    try:
        return hasher.verify(encoded, value)
    except (VerificationError, InvalidHashError):
        return False


def totp_step(secret, code, last_step):
    step = int(time.time() // 30)
    for candidate in (step, step - 1, step + 1):
        if candidate > last_step and secrets.compare_digest(pyotp.TOTP(secret).at(candidate * 30), code):
            return candidate
    return None


class Vault:
    def __init__(self, key):
        self.cipher = Fernet(key.encode())

    def encrypt(self, value):
        return self.cipher.encrypt(value.encode()).decode()

    def decrypt(self, value):
        return self.cipher.decrypt(value.encode()).decode()
