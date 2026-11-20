# ============================================================
# 文件名称：models.py
# 生成日期：2026-10-20
# 修改日期：2026-11-20
# 版本信息：v0.261115
# 作    者：JUN
# 备    注：本程序由AI辅助完成。
#           文件功能：实现 models 模块相关功能。
#           文件用途：供堡垒机的 leizhang/jump_ssh/models.py 模块使用。
#           注意事项：运行前检查依赖与配置；涉及数据或服务变更时先备份并验证。
# ============================================================
import uuid
from datetime import datetime, timezone

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String, Text, Index, UniqueConstraint
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column
from sqlalchemy.types import TypeDecorator
from sqlalchemy.dialects.mysql import LONGTEXT


class UTCDateTime(TypeDecorator):
    impl = DateTime(timezone=True)
    cache_ok = True

    def process_bind_param(self, value, dialect):
        if value is not None and dialect.name in ('mysql', 'mariadb'):
            return value.astimezone(timezone.utc).replace(tzinfo=None)
        return value

    def process_result_value(self, value, dialect):
        if value is not None and value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value


def now():
    return datetime.now(timezone.utc)


def identity():
    return str(uuid.uuid4())


class Base(DeclarativeBase):
    pass


class PlatformLock(Base):
    __tablename__ = 'platform_locks'
    key: Mapped[str] = mapped_column(String(64), primary_key=True)


class PlatformSetting(Base):
    __tablename__ = 'platform_settings'
    key: Mapped[str] = mapped_column(String(80), primary_key=True)
    value: Mapped[str] = mapped_column(Text().with_variant(LONGTEXT(), 'mysql', 'mariadb'))


class Role(Base):
    __tablename__ = 'roles'
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=identity)
    name: Mapped[str] = mapped_column(String(80), unique=True)
    base_role: Mapped[str] = mapped_column(String(20))
    description: Mapped[str] = mapped_column(String(300), default='')
    builtin: Mapped[bool] = mapped_column(Boolean, default=False)
    command_mode: Mapped[str] = mapped_column(String(20), default='off')
    command_rules: Mapped[str] = mapped_column(Text().with_variant(LONGTEXT(), 'mysql', 'mariadb'), default='[]')
    permissions: Mapped[str | None] = mapped_column(Text().with_variant(LONGTEXT(), 'mysql', 'mariadb'))


class User(Base):
    __tablename__ = 'users'
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=identity)
    username: Mapped[str] = mapped_column(String(80), unique=True)
    password_hash: Mapped[str] = mapped_column(Text().with_variant(LONGTEXT(), 'mysql', 'mariadb'))
    role: Mapped[str] = mapped_column(String(20), default='operator')
    role_id: Mapped[str | None] = mapped_column(ForeignKey('roles.id'), index=True)
    command_mode: Mapped[str] = mapped_column(String(20), default='off')
    command_rules: Mapped[str] = mapped_column(Text().with_variant(LONGTEXT(), 'mysql', 'mariadb'), default='[]')
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    mfa_secret: Mapped[str | None] = mapped_column(Text().with_variant(LONGTEXT(), 'mysql', 'mariadb'))
    mfa_enabled: Mapped[bool] = mapped_column(Boolean, default=False, server_default="0")
    mfa_setup_expires_at: Mapped[datetime | None] = mapped_column(UTCDateTime())
    last_totp_step: Mapped[int] = mapped_column(Integer, default=-1)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=now)


class LoginSession(Base):
    __tablename__ = 'login_sessions'
    digest: Mapped[str] = mapped_column(String(64), primary_key=True)
    user_id: Mapped[str] = mapped_column(ForeignKey('users.id'), index=True)
    expires_at: Mapped[datetime] = mapped_column(UTCDateTime())


class Asset(Base):
    __tablename__ = 'assets'
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=identity)
    name: Mapped[str] = mapped_column(String(120), unique=True)
    host: Mapped[str] = mapped_column(String(253))
    port: Mapped[int] = mapped_column(Integer, default=22)
    username: Mapped[str] = mapped_column(String(80))
    credential: Mapped[str] = mapped_column(Text().with_variant(LONGTEXT(), 'mysql', 'mariadb'))
    auth_type: Mapped[str] = mapped_column(String(20), default='password')
    host_key: Mapped[str] = mapped_column(Text().with_variant(LONGTEXT(), 'mysql', 'mariadb'))
    verify_host_key: Mapped[bool] = mapped_column(Boolean, default=False, server_default="0")
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    approval_required: Mapped[bool] = mapped_column(Boolean, default=True)
    tags: Mapped[str] = mapped_column(String(300), default='')
    protocol: Mapped[str] = mapped_column(String(20), default='ssh', server_default='ssh')
    database_name: Mapped[str] = mapped_column(String(128), default='', server_default='')
    domain: Mapped[str] = mapped_column(String(128), default='', server_default='')
    http_scheme: Mapped[str] = mapped_column(String(8), default='http', server_default='http')
    http_path: Mapped[str] = mapped_column(String(1024), default='/', server_default='/')
    tls_verify: Mapped[bool] = mapped_column(Boolean, default=True, server_default="1")


class Grant(Base):
    __tablename__ = 'grants'
    user_id: Mapped[str] = mapped_column(ForeignKey('users.id'), primary_key=True)
    asset_id: Mapped[str] = mapped_column(ForeignKey('assets.id'), primary_key=True)
    expires_at: Mapped[datetime] = mapped_column(UTCDateTime())


class SystemAccount(Base):
    __tablename__ = 'system_accounts'
    __table_args__ = (UniqueConstraint('asset_id', 'username', name='uq_system_account_username'),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=identity)
    asset_id: Mapped[str] = mapped_column(ForeignKey('assets.id'), index=True)
    username: Mapped[str] = mapped_column(String(80))
    auth_type: Mapped[str] = mapped_column(String(20), default='password')
    credential: Mapped[str] = mapped_column(Text().with_variant(LONGTEXT(), 'mysql', 'mariadb'))
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    deleted: Mapped[bool] = mapped_column(Boolean, default=False, server_default="0")


class AccountGrant(Base):
    __tablename__ = 'account_grants'
    user_id: Mapped[str] = mapped_column(ForeignKey('users.id'), primary_key=True)
    account_id: Mapped[str] = mapped_column(ForeignKey('system_accounts.id'), primary_key=True)
    expires_at: Mapped[datetime] = mapped_column(UTCDateTime())


class Approval(Base):
    __tablename__ = 'approvals'
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=identity)
    user_id: Mapped[str] = mapped_column(ForeignKey('users.id'), index=True)
    asset_id: Mapped[str] = mapped_column(ForeignKey('assets.id'))
    account_id: Mapped[str | None] = mapped_column(ForeignKey('system_accounts.id'))
    system_username: Mapped[str] = mapped_column(String(80), default='', server_default='')
    reason: Mapped[str] = mapped_column(Text().with_variant(LONGTEXT(), 'mysql', 'mariadb'))
    state: Mapped[str] = mapped_column(String(20), default='pending')
    reviewer_id: Mapped[str | None] = mapped_column(ForeignKey('users.id'))
    result_read: Mapped[bool] = mapped_column(Boolean, default=True, server_default="1")
    approver_id: Mapped[str | None] = mapped_column(ForeignKey('users.id'), index=True)
    expires_at: Mapped[datetime] = mapped_column(UTCDateTime())
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=now)


class SSHSession(Base):
    __tablename__ = 'ssh_sessions'
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=identity)
    user_id: Mapped[str] = mapped_column(ForeignKey('users.id'), index=True)
    asset_id: Mapped[str] = mapped_column(ForeignKey('assets.id'))
    account_id: Mapped[str | None] = mapped_column(ForeignKey('system_accounts.id'))
    system_username: Mapped[str] = mapped_column(String(80), default='', server_default='')
    ticket_hash: Mapped[str] = mapped_column(String(64))
    ticket_expires_at: Mapped[datetime] = mapped_column(UTCDateTime())
    state: Mapped[str] = mapped_column(String(20), default='pending')
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=now)
    ended_at: Mapped[datetime | None] = mapped_column(UTCDateTime())
    error: Mapped[str] = mapped_column(String(120), default='')
    protocol: Mapped[str] = mapped_column(String(20), default='ssh', server_default='ssh')


class Recording(Base):
    __tablename__ = 'recordings'
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    session_id: Mapped[str] = mapped_column(ForeignKey('ssh_sessions.id'), index=True)
    elapsed_ms: Mapped[int] = mapped_column(Integer)
    data: Mapped[str] = mapped_column(Text().with_variant(LONGTEXT(), 'mysql', 'mariadb'))


class Audit(Base):
    __tablename__ = 'audit_logs'
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    actor_id: Mapped[str | None] = mapped_column(String(36))
    action: Mapped[str] = mapped_column(String(80))
    target: Mapped[str] = mapped_column(String(300), default='')
    ip: Mapped[str] = mapped_column(String(64), default='')
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=now)


class ProtocolAudit(Base):
    __tablename__ = 'protocol_audit'
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    session_id: Mapped[str] = mapped_column(ForeignKey('ssh_sessions.id'), index=True)
    operation_id: Mapped[str] = mapped_column(String(36), index=True)
    protocol: Mapped[str] = mapped_column(String(20))
    action: Mapped[str] = mapped_column(String(40))
    detail: Mapped[str] = mapped_column(Text().with_variant(LONGTEXT(), 'mysql', 'mariadb'))
    success: Mapped[bool | None] = mapped_column(Boolean)
    elapsed_ms: Mapped[int] = mapped_column(Integer, default=0)
    row_count: Mapped[int] = mapped_column(Integer, default=0)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=now)


Index('ix_audit_rate', Audit.action, Audit.target, Audit.created_at)
