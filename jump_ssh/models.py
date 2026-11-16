import uuid
from datetime import datetime, timezone

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String, Text, Index, UniqueConstraint
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


def now():
    return datetime.now(timezone.utc)


def identity():
    return str(uuid.uuid4())


class Base(DeclarativeBase):
    pass


class PlatformSetting(Base):
    __tablename__ = 'platform_settings'
    key: Mapped[str] = mapped_column(String(80), primary_key=True)
    value: Mapped[str] = mapped_column(Text)


class Role(Base):
    __tablename__ = 'roles'
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=identity)
    name: Mapped[str] = mapped_column(String(80), unique=True)
    base_role: Mapped[str] = mapped_column(String(20))
    description: Mapped[str] = mapped_column(String(300), default='')
    builtin: Mapped[bool] = mapped_column(Boolean, default=False)
    command_mode: Mapped[str] = mapped_column(String(20), default='off')
    command_rules: Mapped[str] = mapped_column(Text, default='[]')
    permissions: Mapped[str | None] = mapped_column(Text)


class User(Base):
    __tablename__ = 'users'
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=identity)
    username: Mapped[str] = mapped_column(String(80), unique=True)
    password_hash: Mapped[str] = mapped_column(Text)
    role: Mapped[str] = mapped_column(String(20), default='operator')
    role_id: Mapped[str | None] = mapped_column(ForeignKey('roles.id'), index=True)
    command_mode: Mapped[str] = mapped_column(String(20), default='off')
    command_rules: Mapped[str] = mapped_column(Text, default='[]')
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    mfa_secret: Mapped[str | None] = mapped_column(Text)
    mfa_enabled: Mapped[bool] = mapped_column(Boolean, default=False, server_default='false')
    mfa_setup_expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_totp_step: Mapped[int] = mapped_column(Integer, default=-1)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)


class LoginSession(Base):
    __tablename__ = 'login_sessions'
    digest: Mapped[str] = mapped_column(String(64), primary_key=True)
    user_id: Mapped[str] = mapped_column(ForeignKey('users.id'), index=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class Asset(Base):
    __tablename__ = 'assets'
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=identity)
    name: Mapped[str] = mapped_column(String(120), unique=True)
    host: Mapped[str] = mapped_column(String(253))
    port: Mapped[int] = mapped_column(Integer, default=22)
    username: Mapped[str] = mapped_column(String(80))
    credential: Mapped[str] = mapped_column(Text)
    auth_type: Mapped[str] = mapped_column(String(20), default='password')
    host_key: Mapped[str] = mapped_column(Text)
    verify_host_key: Mapped[bool] = mapped_column(Boolean, default=False, server_default='false')
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    approval_required: Mapped[bool] = mapped_column(Boolean, default=True)
    tags: Mapped[str] = mapped_column(String(300), default='')
    protocol: Mapped[str] = mapped_column(String(20), default='ssh', server_default='ssh')
    database_name: Mapped[str] = mapped_column(String(128), default='', server_default='')
    domain: Mapped[str] = mapped_column(String(128), default='', server_default='')
    http_scheme: Mapped[str] = mapped_column(String(8), default='http', server_default='http')
    http_path: Mapped[str] = mapped_column(String(1024), default='/', server_default='/')
    tls_verify: Mapped[bool] = mapped_column(Boolean, default=True, server_default='true')


class Grant(Base):
    __tablename__ = 'grants'
    user_id: Mapped[str] = mapped_column(ForeignKey('users.id'), primary_key=True)
    asset_id: Mapped[str] = mapped_column(ForeignKey('assets.id'), primary_key=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class SystemAccount(Base):
    __tablename__ = 'system_accounts'
    __table_args__ = (UniqueConstraint('asset_id', 'username', name='uq_system_account_username'),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=identity)
    asset_id: Mapped[str] = mapped_column(ForeignKey('assets.id'), index=True)
    username: Mapped[str] = mapped_column(String(80))
    auth_type: Mapped[str] = mapped_column(String(20), default='password')
    credential: Mapped[str] = mapped_column(Text)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    deleted: Mapped[bool] = mapped_column(Boolean, default=False, server_default='false')


class AccountGrant(Base):
    __tablename__ = 'account_grants'
    user_id: Mapped[str] = mapped_column(ForeignKey('users.id'), primary_key=True)
    account_id: Mapped[str] = mapped_column(ForeignKey('system_accounts.id'), primary_key=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class Approval(Base):
    __tablename__ = 'approvals'
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=identity)
    user_id: Mapped[str] = mapped_column(ForeignKey('users.id'), index=True)
    asset_id: Mapped[str] = mapped_column(ForeignKey('assets.id'))
    account_id: Mapped[str | None] = mapped_column(ForeignKey('system_accounts.id'))
    system_username: Mapped[str] = mapped_column(String(80), default='', server_default='')
    reason: Mapped[str] = mapped_column(Text)
    state: Mapped[str] = mapped_column(String(20), default='pending')
    reviewer_id: Mapped[str | None] = mapped_column(ForeignKey('users.id'))
    result_read: Mapped[bool] = mapped_column(Boolean, default=True, server_default='true')
    approver_id: Mapped[str | None] = mapped_column(ForeignKey('users.id'), index=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)


class SSHSession(Base):
    __tablename__ = 'ssh_sessions'
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=identity)
    user_id: Mapped[str] = mapped_column(ForeignKey('users.id'), index=True)
    asset_id: Mapped[str] = mapped_column(ForeignKey('assets.id'))
    account_id: Mapped[str | None] = mapped_column(ForeignKey('system_accounts.id'))
    system_username: Mapped[str] = mapped_column(String(80), default='', server_default='')
    ticket_hash: Mapped[str] = mapped_column(String(64))
    ticket_expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    state: Mapped[str] = mapped_column(String(20), default='pending')
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
    ended_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    error: Mapped[str] = mapped_column(String(120), default='')
    protocol: Mapped[str] = mapped_column(String(20), default='ssh', server_default='ssh')


class Recording(Base):
    __tablename__ = 'recordings'
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    session_id: Mapped[str] = mapped_column(ForeignKey('ssh_sessions.id'), index=True)
    elapsed_ms: Mapped[int] = mapped_column(Integer)
    data: Mapped[str] = mapped_column(Text)


class Audit(Base):
    __tablename__ = 'audit_logs'
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    actor_id: Mapped[str | None] = mapped_column(String(36))
    action: Mapped[str] = mapped_column(String(80))
    target: Mapped[str] = mapped_column(String(300), default='')
    ip: Mapped[str] = mapped_column(String(64), default='')
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)


class ProtocolAudit(Base):
    __tablename__ = 'protocol_audit'
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    session_id: Mapped[str] = mapped_column(ForeignKey('ssh_sessions.id'), index=True)
    operation_id: Mapped[str] = mapped_column(String(36), index=True)
    protocol: Mapped[str] = mapped_column(String(20))
    action: Mapped[str] = mapped_column(String(40))
    detail: Mapped[str] = mapped_column(Text)
    success: Mapped[bool | None] = mapped_column(Boolean)
    elapsed_ms: Mapped[int] = mapped_column(Integer, default=0)
    row_count: Mapped[int] = mapped_column(Integer, default=0)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)


Index('ix_audit_rate', Audit.action, Audit.target, Audit.created_at)
