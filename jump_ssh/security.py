# ============================================================
# 文件名称：security.py
# 生成日期：2026-10-20
# 修改日期：2026-11-20
# 版本信息：v0.261115
# 作    者：JUN
# 备    注：本程序由AI辅助完成。
#           文件功能：提供身份验证及安全处理。
#           文件用途：供堡垒机的 leizhang/jump_ssh/security.py 模块使用。
#           注意事项：运行前检查依赖与配置；涉及数据或服务变更时先备份并验证。
# ============================================================
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
