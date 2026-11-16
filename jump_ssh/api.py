import asyncio
import json
import secrets
from datetime import timedelta
from typing import Literal

import asyncssh
import pyotp
from fastapi import APIRouter, Depends, HTTPException, Request, Response
from pydantic import BaseModel, Field, field_validator, model_validator
from sqlalchemy import func, select

from .permissions import require, allows, check, load_permissions, role_permissions, ensure_delegable, protect_target
from .db import transaction
from .models import Asset, Approval, Audit, Grant, AccountGrant, SystemAccount, LoginSession, Recording, SSHSession, User, Role, now
from .resource_accounts import resolve_account, account_grant, accessible_accounts, accessible_asset_filter, all_grants, approval_account_filter
from .security import digest, password_hash, totp_step, verify_password

router = APIRouter(prefix='/api')


def audit(db, user, action, target='', request=None):
    db.add(Audit(actor_id=user.id if user else None, action=action, target=target,
                 ip=request.client.host if request and request.client else ''))


def actor(request: Request):
    with transaction(request.app.state.factory) as db:
        session = db.get(LoginSession, digest(request.cookies.get('jump_session', '')))
        if not session or session.expires_at <= now(): raise HTTPException(401, '请先登录')
        user = db.get(User, session.user_id)
        if not user or not user.enabled: raise HTTPException(401, '账号已停用')
        load_permissions(db, user)
        return user


def admin(user=Depends(actor)):
    if user.role != 'admin': raise HTTPException(403, '需要管理员权限')
    return user


def auditor(user=Depends(actor)):
    if user.role not in ('admin', 'auditor'): raise HTTPException(403, '需要审计权限')
    return user


def authorize(db, user, asset, account_id=None):
    if not asset or not asset.enabled: raise HTTPException(404, '资产不存在或已停用')
    check(user, 'sessions.connect')
    if account_id is not None:
        resolve_account(db, asset, account_id)
        grant = account_grant(db, user.id, asset.id, account_id)
        if not allows(user, 'assets.access_all') and (not grant or grant.expires_at <= now()):
            raise HTTPException(403, '无此系统账号授权或授权已过期')
    elif not allows(user, 'assets.access_all') and not accessible_accounts(db, user, asset):
        raise HTTPException(403, '无资产系统账号授权或授权已过期')


class LoginInput(BaseModel):
    username: str = Field(min_length=1, max_length=80)
    password: str = Field(min_length=1, max_length=256)
    code: str = Field(default='', max_length=6)


@router.post('/auth/login')
def login(body: LoginInput, request: Request, response: Response):
    settings = request.app.state.settings
    failed = False
    with transaction(request.app.state.factory) as db:
        # Lock per username to serialize password checks and prevent parallel TOTP reuse.
        db.execute(select(func.pg_advisory_xact_lock(func.hashtext('login:' + body.username))))
        ip = request.client.host if request.client else ''
        window = now() - timedelta(minutes=15)
        db.execute(select(func.pg_advisory_xact_lock(func.hashtext('login-ip:' + ip))))
        failures = db.scalar(select(func.count()).select_from(Audit).where(
            Audit.action == 'login_failed', Audit.created_at > window,
            Audit.target == body.username))
        ip_failures = db.scalar(select(func.count()).select_from(Audit).where(
            Audit.action == 'login_failed', Audit.created_at > window, Audit.ip == ip))
        if failures >= 10 or ip_failures >= 100: raise HTTPException(429, '登录失败次数过多，请 15 分钟后重试')
        user = db.scalar(select(User).where(User.username == body.username).with_for_update())
        # Dummy hash keeps unknown-user password work comparable.
        encoded = user.password_hash if user else request.app.state.dummy_hash
        valid = verify_password(encoded, body.password) and user is not None and user.enabled
        if valid and user.mfa_enabled and user.mfa_secret:
            step = totp_step(request.app.state.vault.decrypt(user.mfa_secret), body.code, user.last_totp_step)
            valid = step is not None
            if valid: user.last_totp_step = step
        elif valid and user.mfa_enabled:
            valid = False
        if not valid:
            audit(db, None, 'login_failed', body.username, request)
            failed = True
        else:
            token = secrets.token_urlsafe(48)
            db.add(LoginSession(digest=digest(token), user_id=user.id,
                                expires_at=now() + timedelta(minutes=settings.session_minutes)))
            audit(db, user, 'login', user.id, request)
    if failed: raise HTTPException(401, '账号、密码或动态验证码错误；仅已启用 MFA 的账号需要验证码')
    response.set_cookie('jump_session', token, httponly=True, secure=settings.secure,
                        samesite='strict', max_age=settings.session_minutes * 60, path='/')
    return {'username': user.username, 'role': user.role}


@router.post('/auth/logout')
def logout(request: Request, response: Response, user=Depends(actor)):
    with transaction(request.app.state.factory) as db:
        session = db.get(LoginSession, digest(request.cookies.get('jump_session', '')))
        if session: db.delete(session)
        audit(db, user, 'logout', user.id, request)
    response.delete_cookie('jump_session', path='/')
    return {'ok': True}


@router.get('/auth/me')
def me(request: Request, user=Depends(actor)):
    with transaction(request.app.state.factory) as db:
        role = db.get(Role, user.role_id or user.role)
        return {'id': user.id, 'username': user.username, 'role': user.role, 'role_id': user.role_id,
                'role_name': role.name if role else '', 'mfa': user.mfa_enabled,
                'permissions': sorted(user._permissions)}


class PasswordInput(BaseModel):
    old_password: str = Field(max_length=256)
    new_password: str = Field(min_length=12, max_length=256)


@router.post('/auth/password')
def change_password(body: PasswordInput, request: Request, user=Depends(actor)):
    with transaction(request.app.state.factory) as db:
        target = db.get(User, user.id, with_for_update=True)
        if not verify_password(target.password_hash, body.old_password): raise HTTPException(400, '原密码错误')
        target.password_hash = password_hash(body.new_password)
        db.query(LoginSession).filter_by(user_id=user.id).delete()
        audit(db, user, 'password_changed', user.id, request)
    return {'message': '密码已修改，请重新登录'}


class UserInput(BaseModel):
    username: str = Field(pattern=r'^[A-Za-z0-9_.@-]{3,80}$')
    password: str = Field(min_length=12, max_length=256)
    role: Literal['admin', 'operator', 'auditor'] = 'operator'
    role_id: str | None = Field(default=None, max_length=36)


class AdminPasswordInput(BaseModel):
    new_password: str = Field(min_length=12, max_length=256)


@router.post('/users/{user_id}/password')
def reset_user_password(user_id: str, body: AdminPasswordInput, request: Request, user=Depends(admin)):
    check(user, 'users.manage')
    with transaction(request.app.state.factory) as db:
        db.execute(select(func.pg_advisory_xact_lock(func.hashtext('role-edit'))))
        target=db.get(User,user_id,with_for_update=True)
        if not target:raise HTTPException(404,'用户不存在')
        if target.id==user.id or target.role=='admin':
            raise HTTPException(403,'此功能仅用于重置普通用户密码；自己的密码请在修改密码中设置')
        protect_target(db,user,target)
        target.password_hash=password_hash(body.new_password)
        db.query(LoginSession).filter_by(user_id=user_id).delete()
        for session in db.scalars(select(SSHSession).where(SSHSession.user_id==user_id,SSHSession.state.in_(['active','pending']))):
            session.state='terminated'
        audit(db,user,'user_password_reset',user_id,request)
    return {'message':'密码已重置，该用户需使用新密码重新登录，原有连接会话已终止。'}


@router.get('/users')
def users(request: Request, user=Depends(require('users.view'))):
    with transaction(request.app.state.factory) as db:
        role_names = {r.id: r.name for r in db.scalars(select(Role))}
        return [dict(id=u.id, username=u.username, role=u.role, role_id=u.role_id or u.role,
                     role_name=role_names.get(u.role_id or u.role, ''), enabled=u.enabled, mfa=u.mfa_enabled,
                     command_mode=u.command_mode, command_rules=json.loads(u.command_rules),
                     can_connect='sessions.connect' in load_permissions(db,u),
                     can_review=allows(u,'approvals.review'))
                for u in db.scalars(select(User).order_by(User.username))]


@router.post('/users', status_code=201)
def create_user(body: UserInput, request: Request, user=Depends(require('users.manage'))):
    with transaction(request.app.state.factory) as db:
        db.execute(select(func.pg_advisory_xact_lock(func.hashtext('role-edit'))))
        if db.scalar(select(User.id).where(User.username == body.username)): raise HTTPException(409, '用户名已存在')
        role = db.get(Role, body.role_id or body.role)
        if not role: raise HTTPException(400, '角色不存在')
        ensure_delegable(user, role_permissions(role))
        target = User(username=body.username, password_hash=password_hash(body.password), role=role.base_role, role_id=role.id)
        db.add(target)
        db.flush()
        audit(db, user, 'user_created', target.id, request)
        return {'id': target.id, 'message': '用户已创建，首次登录仅需账号密码。MFA 可由管理员在用户管理中手动启用。'}


@router.post('/users/{user_id}/mfa/setup')
def setup_mfa(user_id: str, request: Request, user=Depends(require('users.mfa'))):
    secret = pyotp.random_base32()
    with transaction(request.app.state.factory) as db:
        target = db.get(User, user_id, with_for_update=True)
        if not target: raise HTTPException(404, '用户不存在')
        protect_target(db, user, target)
        if target.mfa_enabled: raise HTTPException(409, '请先关闭 MFA，再重新绑定')
        target.mfa_secret = request.app.state.vault.encrypt(secret)
        target.mfa_setup_expires_at = now() + timedelta(minutes=10)
        target.last_totp_step = -1
        audit(db, user, 'mfa_setup_started', target.id, request)
        return {'secret': secret, 'mfa_uri': pyotp.TOTP(secret).provisioning_uri(target.username, issuer_name='JUMP SSH'),
                'expires_at': target.mfa_setup_expires_at}


class MfaConfirmation(BaseModel):
    code: str = Field(pattern=r'^\d{6}$')


def revoke_mfa_sessions(db, target, request):
    current = digest(request.cookies.get('jump_session', ''))
    db.query(LoginSession).filter(LoginSession.user_id == target.id, LoginSession.digest != current).delete()


@router.post('/users/{user_id}/mfa/enable')
def enable_mfa(user_id: str, body: MfaConfirmation, request: Request, user=Depends(require('users.mfa'))):
    with transaction(request.app.state.factory) as db:
        target = db.get(User, user_id, with_for_update=True)
        if not target: raise HTTPException(404, '用户不存在')
        protect_target(db, user, target)
        if target.mfa_enabled: raise HTTPException(409, 'MFA 已启用')
        if not target.mfa_secret or not target.mfa_setup_expires_at or target.mfa_setup_expires_at <= now():
            raise HTTPException(400, '绑定已过期，请重新点击开启 MFA')
        step = totp_step(request.app.state.vault.decrypt(target.mfa_secret), body.code, target.last_totp_step)
        if step is None: raise HTTPException(400, '验证码无效，请检查身份验证器和手机时间')
        target.mfa_enabled, target.last_totp_step, target.mfa_setup_expires_at = True, step, None
        revoke_mfa_sessions(db, target, request)
        audit(db, user, 'mfa_enabled', target.id, request)
    return {'message': 'MFA 已启用，下次登录需要动态验证码'}


@router.post('/users/{user_id}/mfa/disable')
def disable_mfa(user_id: str, request: Request, user=Depends(require('users.mfa'))):
    with transaction(request.app.state.factory) as db:
        target = db.get(User, user_id, with_for_update=True)
        if not target: raise HTTPException(404, '用户不存在')
        protect_target(db, user, target)
        target.mfa_enabled, target.mfa_secret = False, None
        target.mfa_setup_expires_at, target.last_totp_step = None, -1
        revoke_mfa_sessions(db, target, request)
        audit(db, user, 'mfa_disabled', target.id, request)
    return {'message': 'MFA 已关闭，该用户仅需账号密码登录'}


class UserUpdate(BaseModel):
    role: Literal['admin', 'operator', 'auditor']
    enabled: bool
    role_id: str | None = Field(default=None, max_length=36)


@router.patch('/users/{user_id}')
def update_user(user_id: str, body: UserUpdate, request: Request, user=Depends(require('users.manage'))):
    if user_id == user.id: raise HTTPException(400, '不可修改自己的角色或启停状态')
    with transaction(request.app.state.factory) as db:
        db.execute(select(func.pg_advisory_xact_lock(func.hashtext('role-edit'))))
        target = db.get(User, user_id, with_for_update=True)
        if not target: raise HTTPException(404, '用户不存在')
        protect_target(db, user, target)
        role = db.get(Role, body.role_id or body.role)
        if not role: raise HTTPException(400, '角色不存在')
        ensure_delegable(user, role_permissions(role))
        target.role, target.role_id, target.enabled = role.base_role, role.id, body.enabled
        db.query(LoginSession).filter_by(user_id=user_id).delete()
        for session in db.scalars(select(SSHSession).where(SSHSession.user_id == user_id, SSHSession.state.in_(['active','pending']))):
            session.state = 'terminated'
        audit(db, user, 'user_updated', user_id, request)
    return {'ok': True}


class AssetInput(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    host: str = Field(pattern=r'^[a-zA-Z0-9:.\-]{1,253}$')
    port: int = Field(default=22, ge=1, le=65535)
    username: str = Field(pattern=r'^[a-zA-Z0-9_@.\-]{1,80}$')
    auth_type: Literal['password','private_key'] = 'password'
    credential: str = Field(default='', max_length=32768)
    host_key: str = Field(default='', max_length=4096)
    verify_host_key: bool = False
    enabled: bool = True
    approval_required: bool = True
    tags: str = Field(default='', max_length=300)
    protocol: Literal['ssh', 'telnet', 'rdp', 'vnc', 'http', 'postgresql', 'mysql'] = 'ssh'
    database_name: str = Field(default='', max_length=128)
    domain: str = Field(default='', max_length=128)
    http_scheme: Literal['http', 'https'] = 'http'
    http_path: str = Field(default='/', max_length=1024, pattern=r'^/[^\r\n]*$')
    tls_verify: bool = True

    @field_validator('host_key')
    @classmethod
    def validate_host_key(cls, value):
        if not value.strip(): return ''
        try: asyncssh.import_public_key(value)
        except (ValueError, asyncssh.KeyImportError): raise ValueError('主机公钥格式无效，请填写受信任的 OpenSSH 公钥')
        return value.strip()

    @model_validator(mode='after')
    def require_verified_host_key(self):
        if self.protocol != 'ssh' and self.auth_type != 'password':
            raise ValueError('所选协议仅支持密码认证')
        if self.protocol != 'ssh' and self.verify_host_key:
            raise ValueError('主机公钥校验仅适用于 SSH')
        if self.protocol in ('postgresql', 'mysql') and not self.database_name.strip():
            raise ValueError('请填写目标数据库名称')
        if self.http_path.startswith('//') or '#' in self.http_path:
            raise ValueError('HTTP 路径必须是本站路径，不能包含片段')
        if self.verify_host_key and not self.host_key:
            raise ValueError('已开启 SSH 主机公钥校验，请填写或获取主机公钥；仅使用用户名密码连接时可关闭该选项')
        return self


class HostKeyProbe(BaseModel):
    host: str = Field(pattern=r'^[a-zA-Z0-9:.\-]{1,253}$')
    port: int = Field(default=22, ge=1, le=65535)


@router.post('/assets/host-key/probe')
async def probe_host_key(body: HostKeyProbe, request: Request, user=Depends(require('assets.manage'))):
    try:
        key = await asyncio.wait_for(asyncssh.get_server_host_key(
            body.host, body.port, config=None, proxy_command=None), timeout=10)
        if key is None: raise ValueError('No host key')
    except (asyncio.TimeoutError, OSError, asyncssh.Error, ValueError):
        raise HTTPException(502, '无法获取 SSH 主机公钥，请检查资产地址、SSH 端口和网络连通性') from None
    with transaction(request.app.state.factory) as db:
        audit(db, user, 'host_key_probed', body.host + ':' + str(body.port), request)
    return {'host': body.host, 'port': body.port,
            'host_key': key.export_public_key('openssh').decode().strip(),
            'fingerprint': key.get_fingerprint('sha256'),
            'message': '此公钥仅由网络探测获得，尚未核验。请与服务器控制台显示的 SHA256 指纹比对后再使用。'}


def public_asset(asset):
    return {key: getattr(asset, key) for key in ('id','name','host','port','username','auth_type',
                                                'host_key','verify_host_key','enabled','approval_required','tags',
                                                'protocol','database_name','domain','http_scheme','http_path','tls_verify')}


@router.get('/assets')
def assets(request: Request, user=Depends(require('assets.view'))):
    with transaction(request.app.state.factory) as db:
        result=[]
        global_view = allows(user, 'assets.view_all')
        grants = all_grants(db) if global_view else []
        enabled_users = {u.id for u in db.scalars(select(User).where(User.enabled.is_(True))) if 'sessions.connect' in load_permissions(db,u)} if global_view else set()
        for asset in db.scalars(select(Asset).order_by(Asset.name)):
            accounts = accessible_accounts(db,user,asset)
            if not global_view and not accounts:
                continue
            row=public_asset(asset)
            row['accounts']=[dict(id=a.id,username=a.username,auth_type=a.auth_type,enabled=a.enabled) for a in accounts]
            row['system_account_count']=len(accounts)
            if global_view:
                active_ids={a.id for a in accounts if a.enabled}
                row['granted_user_count']=len({g['user_id'] for g in grants if g['asset_id']==asset.id and g['account_id'] in active_ids and g['user_id'] in enabled_users and g['expires_at']>now()})
            else:
                for account in row['accounts']:
                    account['expires_at']=account_grant(db,user.id,asset.id,account['id']).expires_at
                row['authorization_expires_at']=max(a['expires_at'] for a in row['accounts'])
                # Do not expose an ungranted default identity as the selected account.
                row['username']='、'.join(a.username for a in accounts)
            result.append(row)
        return result


def save_asset(body, request, user, asset_id=None):
    with transaction(request.app.state.factory) as db:
        asset = db.get(Asset, asset_id, with_for_update=True) if asset_id else Asset()
        if not asset: raise HTTPException(404, '资产不存在')
        if asset_id and asset.protocol != body.protocol:
            raise HTTPException(409, '已有资源不可更改协议，请为新协议新增资源以保留账号和历史审计')
        was_verified = asset.verify_host_key if asset_id else True
        duplicate = db.scalar(select(Asset).where(Asset.name == body.name))
        if duplicate and duplicate.id != asset_id: raise HTTPException(409, '资产名称已存在')
        if asset_id and db.scalar(select(SystemAccount.id).where(SystemAccount.asset_id==asset_id,SystemAccount.username==body.username,SystemAccount.id!=asset_id)):
            raise HTTPException(409,'该系统用户名已存在，请通过系统账号管理修改')
        if not body.credential and (not asset_id or body.auth_type != asset.auth_type):
            raise HTTPException(400, '创建资产或修改认证类型时必须填写凭据')
        if body.auth_type == 'private_key' and body.credential:
            try: asyncssh.import_private_key(body.credential)
            except (ValueError, asyncssh.KeyImportError): raise HTTPException(400, '私钥格式无效；当前仅支持未加口令的私钥，入库后由平台加密')
        for key, value in body.model_dump(exclude={'credential'}).items(): setattr(asset, key, value)
        if body.credential: asset.credential = request.app.state.vault.encrypt(body.credential)
        if asset_id:
            for active in db.scalars(select(SSHSession).where(SSHSession.asset_id == asset_id, SSHSession.state.in_(['pending', 'active']))):
                active.state = 'terminated'
        db.add(asset)
        db.flush()
        default = db.get(SystemAccount, asset.id)
        if not default:
            default = SystemAccount(id=asset.id, asset_id=asset.id, enabled=True)
            db.add(default)
        default.username, default.auth_type, default.credential = asset.username, asset.auth_type, asset.credential
        audit(db, user, 'asset_updated' if asset_id else 'asset_created', asset.id, request)
        if was_verified and not asset.verify_host_key:
            audit(db, user, 'asset_host_key_check_disabled', asset.id, request)
        return public_asset(asset)


@router.post('/assets', status_code=201)
def create_asset(body: AssetInput, request: Request, user=Depends(require('assets.manage'))):
    return save_asset(body, request, user)


@router.put('/assets/{asset_id}')
def update_asset(asset_id: str, body: AssetInput, request: Request, user=Depends(require('assets.manage'))):
    return save_asset(body, request, user, asset_id)


class GrantInput(BaseModel):
    user_id: str
    asset_id: str
    account_id: str | None = None
    hours: int = Field(default=24, ge=1, le=8760)


class BatchGrantInput(BaseModel):
    user_ids: list[str] = Field(min_length=1, max_length=100)
    asset_id: str
    account_id: str | None = None
    hours: int = Field(default=24, ge=1, le=8760)


class GrantTarget(BaseModel):
    user_id: str = Field(min_length=1, max_length=36)
    asset_id: str = Field(min_length=1, max_length=36)
    account_id: str | None = Field(default=None, min_length=1, max_length=36)


class GrantActionInput(BaseModel):
    targets: list[GrantTarget] = Field(min_length=1, max_length=100)
    action: Literal['renew', 'revoke']
    hours: int = Field(default=24, ge=1, le=8760)


def revoke_grant(db, user_id, asset_id, user, request, account_id=None):
    account_id = account_id or asset_id
    grant = account_grant(db,user_id,asset_id,account_id)
    if grant:
        db.delete(grant)
    for session in db.scalars(select(SSHSession).where(SSHSession.user_id == user_id,
            SSHSession.asset_id == asset_id, SSHSession.state.in_(['pending','active']))):
        if (session.account_id or asset_id)==account_id:
            session.state = 'terminated'
    for approval in db.scalars(select(Approval).where(Approval.user_id==user_id,Approval.asset_id==asset_id,
            approval_account_filter(account_id,asset_id),Approval.state.in_(['pending','approved']))):
        approval.state='revoked'
    audit(db, user, 'grant_revoked', user_id + ':' + asset_id + ':' + account_id, request)


def save_grants(db, user_ids, asset_id, hours, user, request, account_id=None):
    # Lock the shared resource to serialize grant creation/renewal.
    asset = db.get(Asset, asset_id, with_for_update=True)
    if not asset:
        raise HTTPException(404, '资产不存在')
    account = resolve_account(db,asset,account_id)
    user_ids = list(dict.fromkeys(user_ids))
    targets = list(db.scalars(select(User).where(User.id.in_(user_ids))))
    if len(targets) != len(user_ids):
        raise HTTPException(404, '所选平台用户不存在')
    if any(not target.enabled or 'sessions.connect' not in load_permissions(db,target) for target in targets):
        raise HTTPException(400, '只能向已启用且具有运维权限的平台用户授权')
    expires_at = now() + timedelta(hours=hours)
    for user_id in user_ids:
        grant = account_grant(db,user_id,asset_id,account.id)
        if not grant:
            grant = Grant(user_id=user_id,asset_id=asset_id) if account.id==asset_id else AccountGrant(user_id=user_id,account_id=account.id)
        grant.expires_at = expires_at
        db.add(grant)
        audit(db, user, 'grant_saved', user_id + ':' + asset_id + ':' + account.id, request)
    return len(user_ids)


@router.get('/grants')
def grants(request: Request, user=Depends(require('grants.view'))):
    with transaction(request.app.state.factory) as db:
        return all_grants(db)


@router.post('/grants')
def grant_access(body: GrantInput, request: Request, user=Depends(require('grants.manage'))):
    with transaction(request.app.state.factory) as db:
        save_grants(db, [body.user_id], body.asset_id, body.hours, user, request,body.account_id)
    return {'ok': True}


@router.post('/grants/batch')
def batch_grant_access(body: BatchGrantInput, request: Request, user=Depends(require('grants.manage'))):
    with transaction(request.app.state.factory) as db:
        count = save_grants(db, body.user_ids, body.asset_id, body.hours, user, request,body.account_id)
    return {'ok': True, 'count': count}


@router.delete('/grants/{user_id}/{asset_id}')
@router.delete('/grants/{user_id}/{asset_id}/{account_id}')
def revoke_access(user_id: str, asset_id: str, request: Request, account_id: str | None=None, user=Depends(require('grants.manage'))):
    with transaction(request.app.state.factory) as db:
        asset=db.get(Asset, asset_id, with_for_update=True)
        if asset and account_id:
            resolve_account(db,asset,account_id,allow_disabled=True)
        revoke_grant(db, user_id, asset_id, user, request,account_id)
    return {'ok': True}


@router.post('/grants/actions')
def grant_actions(body: GrantActionInput, request: Request, user=Depends(require('grants.manage'))):
    keys = sorted({(item.user_id, item.asset_id,item.account_id or item.asset_id) for item in body.targets})
    with transaction(request.app.state.factory) as db:
        for asset_id in sorted({asset_id for _, asset_id,_ in keys}):
            if not db.get(Asset, asset_id, with_for_update=True):
                raise HTTPException(404, '所选资源不存在，请刷新列表')
        grants = []
        # Validate the entire selection before changing any authorization.
        for user_id, asset_id,account_id in keys:
            account=resolve_account(db,db.get(Asset,asset_id),account_id,allow_disabled=body.action=='revoke')
            grant = account_grant(db,user_id,asset_id,account_id)
            if not grant:
                raise HTTPException(409, '所选授权已被撤销，请刷新列表后重试')
            target = db.get(User, user_id)
            if body.action == 'renew' and (not target or not target.enabled or 'sessions.connect' not in load_permissions(db,target)):
                raise HTTPException(400, '停用用户或审计员的授权无法续期')
            grants.append((grant,user_id,asset_id,account_id))
        current_time = now()
        for grant,user_id,asset_id,account_id in grants:
            if body.action == 'revoke':
                revoke_grant(db, user_id, asset_id, user, request,account_id)
            else:
                grant.expires_at = max(grant.expires_at, current_time) + timedelta(hours=body.hours)
                audit(db, user, 'grant_extended', user_id + ':' + asset_id + ':' + account_id, request)
    return {'ok':True, 'count':len(keys)}


class ApprovalInput(BaseModel):
    asset_id: str
    account_id: str | None = None
    approver_id: str | None = Field(default=None, min_length=1, max_length=36)
    reason: str = Field(min_length=5, max_length=1000)
    hours: int = Field(default=1, ge=1, le=8)


@router.get('/approvals/reviewers')
def approval_reviewers(request: Request, user=Depends(require('approvals.request'))):
    with transaction(request.app.state.factory) as db:
        return [dict(id=u.id, username=u.username) for u in db.scalars(
            select(User).where(User.enabled.is_(True),
                               User.id != user.id).order_by(User.username))
                if 'approvals.review' in load_permissions(db,u)]


@router.post('/approvals', status_code=201)
def request_approval(body: ApprovalInput, request: Request, user=Depends(require('approvals.request'))):
    with transaction(request.app.state.factory) as db:
        asset=db.get(Asset,body.asset_id)
        if not asset:
            raise HTTPException(404,'资源不存在')
        account=resolve_account(db,asset,body.account_id)
        authorize(db, user, asset,account.id)
        if not body.approver_id:
            raise HTTPException(400, '请选择审批人')
        approver = db.get(User, body.approver_id)
        if not approver or not approver.enabled or 'approvals.review' not in load_permissions(db,approver):
            raise HTTPException(400, '审批人必须是已启用且具有访问审批权限的用户，请重新选择')
        if approver.id == user.id:
            raise HTTPException(400, '不可选择自己作为审批人')
        approval = Approval(user_id=user.id, asset_id=body.asset_id, reason=body.reason,
                            approver_id=approver.id,
                            account_id=account.id if isinstance(account,SystemAccount) else None,
                            system_username=account.username,
                            expires_at=now() + timedelta(hours=body.hours))
        db.add(approval)
        db.flush()
        audit(db, user, 'approval_requested', approval.id, request)
        return {'id': approval.id}


@router.get('/approvals')
def approvals(request: Request, user=Depends(require('approvals.view'))):
    with transaction(request.app.state.factory) as db:
        stmt = select(Approval).order_by(Approval.created_at.desc()).limit(200)
        if not allows(user, 'approvals.review'): stmt = stmt.where(Approval.user_id == user.id)
        rows = list(db.scalars(stmt))
        user_ids = {uid for a in rows for uid in (a.user_id, a.approver_id, a.reviewer_id) if uid}
        names = dict(db.execute(select(User.id, User.username).where(User.id.in_(user_ids))).all())
        return [dict(id=a.id,user_id=a.user_id,username=names.get(a.user_id,a.user_id),asset_id=a.asset_id,account_id=a.account_id,system_username=a.system_username,reason=a.reason,state=a.state,
                     expires_at=a.expires_at,reviewer_id=a.reviewer_id,reviewer_name=names.get(a.reviewer_id),
                     approver_id=a.approver_id,approver_name=names.get(a.approver_id)) for a in rows]


@router.get('/notifications/approvals')
def approval_notifications(request: Request, user=Depends(require('approvals.review'))):
    """Pending work for this reviewer, including unassigned legacy requests."""
    with transaction(request.app.state.factory) as db:
        pending = (Approval.state == 'pending', Approval.expires_at > now(),
                   Approval.user_id != user.id,
                   ((Approval.approver_id == user.id) | Approval.approver_id.is_(None)))
        count = db.scalar(select(func.count()).select_from(Approval).where(*pending))
        rows = db.execute(select(Approval.id, User.username, Asset.name,
                                 Approval.system_username, Approval.created_at)
                          .join(User, User.id == Approval.user_id)
                          .join(Asset, Asset.id == Approval.asset_id)
                          .where(*pending).order_by(Approval.created_at.desc()).limit(5)).all()
        return {'count': count, 'items': [dict(id=r.id, username=r.username,
                asset_name=r.name, system_username=r.system_username,
                created_at=r.created_at) for r in rows]}


@router.get('/notifications')
def notifications(request: Request, user=Depends(actor)):
    pending = approval_notifications(request, user) if allows(user, 'approvals.review') else {'count': 0, 'items': []}
    with transaction(request.app.state.factory) as db:
        unread = (Approval.user_id == user.id, Approval.result_read.is_(False),
                  Approval.state.in_(['approved', 'rejected']))
        count = db.scalar(select(func.count()).select_from(Approval).where(*unread))
        rows = db.execute(select(Approval.id, Approval.state, Asset.name,
                                 Approval.system_username, User.username)
                          .join(Asset, Asset.id == Approval.asset_id)
                          .join(User, User.id == Approval.reviewer_id)
                          .where(*unread).order_by(Approval.created_at.desc()).limit(50)).all()
        return {'count': pending['count'] + count, 'pending_count': pending['count'],
                'results': [dict(id=r.id, state=r.state, asset_name=r.name,
                                 system_username=r.system_username, reviewer_name=r.username) for r in rows]}


@router.post('/notifications/approvals/{approval_id}/read')
def read_approval_result(approval_id: str, request: Request, user=Depends(actor)):
    with transaction(request.app.state.factory) as db:
        approval = db.get(Approval, approval_id, with_for_update=True)
        if not approval or approval.user_id != user.id:
            raise HTTPException(404, '消息不存在')
        if approval.state not in ('approved', 'rejected'):
            raise HTTPException(409, '申请尚无审批结果')
        approval.result_read = True
    return {'ok': True}


class Decision(BaseModel):
    approve: bool


@router.post('/approvals/{approval_id}/decide')
def decide(approval_id: str, body: Decision, request: Request, user=Depends(require('approvals.review'))):
    with transaction(request.app.state.factory) as db:
        approval = db.get(Approval, approval_id, with_for_update=True)
        if not approval: raise HTTPException(404, '申请不存在')
        if approval.user_id == user.id: raise HTTPException(403, '不可审批自己的申请')
        if approval.approver_id and approval.approver_id != user.id:
            raise HTTPException(403, '仅指定审批人可处理此申请')
        if approval.state != 'pending' or approval.expires_at <= now(): raise HTTPException(409, '申请已处理或过期')
        approval.state, approval.reviewer_id = ('approved' if body.approve else 'rejected'), user.id
        approval.result_read = False
        audit(db, user, 'approval_' + approval.state, approval.id, request)
    return {'ok': True}


class ConnectInput(BaseModel):
    asset_id: str
    account_id: str | None = None


@router.post('/sessions', status_code=201)
def create_session(body: ConnectInput, request: Request, user=Depends(require('sessions.connect'))):
    with transaction(request.app.state.factory) as db:
        db.execute(select(func.pg_advisory_xact_lock(func.hashtext('session:' + user.id))))
        asset = db.get(Asset, body.asset_id)
        if not asset:
            raise HTTPException(404, '资源不存在')
        account=resolve_account(db,asset,body.account_id)
        authorize(db, user, asset,account.id)
        if asset.approval_required:
            approval = db.scalar(select(Approval).where(Approval.user_id == user.id, Approval.asset_id == asset.id,
                approval_account_filter(account.id,asset.id),
                Approval.state == 'approved', Approval.expires_at > now()))
            if not approval: raise HTTPException(403, '请先提交访问申请并由其他管理员审批')
        count = db.scalar(select(func.count()).select_from(SSHSession).where(SSHSession.user_id == user.id,
            ((SSHSession.state == 'active') | ((SSHSession.state == 'pending') & (SSHSession.ticket_expires_at > now())))))
        if count >= 5: raise HTTPException(429, '每个用户最多同时开启 5 个会话')
        token = secrets.token_urlsafe(48)
        session = SSHSession(user_id=user.id, asset_id=asset.id, ticket_hash=digest(token),
                             protocol=asset.protocol,
                             account_id=account.id if isinstance(account,SystemAccount) else None,
                             system_username=account.username,
                             ticket_expires_at=now() + timedelta(seconds=30))
        db.add(session)
        db.flush()
        audit(db, user, 'session_requested', session.id, request)
        route = 'ssh' if asset.protocol in ('ssh', 'telnet') else ('desktop' if asset.protocol in ('rdp', 'vnc') else ('sql' if asset.protocol in ('postgresql', 'mysql') else 'http'))
        return {'id': session.id, 'account_id':account.id, 'system_username':account.username,
                'protocol': asset.protocol, 'ticket': token, 'websocket': '/ws/' + route + '/' + session.id}


@router.get('/sessions')
def sessions(request: Request, user=Depends(require('sessions.view'))):
    with transaction(request.app.state.factory) as db:
        stmt = select(SSHSession, User.username, Asset.name, Asset.username).join(User, User.id == SSHSession.user_id).join(Asset, Asset.id == SSHSession.asset_id)
        if not allows(user, 'sessions.view_all'): stmt = stmt.where(SSHSession.user_id == user.id)
        return [dict(id=s.id, protocol=s.protocol, username=username, account_id=s.account_id, system_username=s.system_username or system_username, asset=name, state=s.state, created_at=s.created_at,
                     ended_at=s.ended_at, error=s.error) for s, username, name, system_username in db.execute(stmt.order_by(SSHSession.created_at.desc()).limit(200))]


@router.post('/sessions/{session_id}/terminate')
def terminate(session_id: str, request: Request, user=Depends(require('sessions.terminate'))):
    with transaction(request.app.state.factory) as db:
        session = db.get(SSHSession, session_id, with_for_update=True)
        if not session: raise HTTPException(404, '会话不存在')
        if session.user_id != user.id and not allows(user, 'sessions.terminate_all'): raise HTTPException(403, '无权终止此会话')
        if session.state in ('pending', 'active'): session.state = 'terminated'
        audit(db, user, 'session_terminated', session_id, request)
    return {'ok': True}


@router.get('/sessions/{session_id}/recording')
def recording(session_id: str, request: Request, user=Depends(require('recordings.view'))):
    with transaction(request.app.state.factory) as db:
        if not db.get(SSHSession, session_id): raise HTTPException(404, '会话不存在')
        audit(db, user, 'recording_read', session_id, request)
        return [dict(ms=r.elapsed_ms, data=request.app.state.vault.decrypt(r.data)) for r in
                db.scalars(select(Recording).where(Recording.session_id == session_id).order_by(Recording.id))]


@router.get('/audit')
def audit_logs(request: Request, user=Depends(require('audit.view')), page: int = 1):
    if not 1 <= page <= 100000: raise HTTPException(422, '页码无效')
    with transaction(request.app.state.factory) as db:
        return [dict(id=a.id,actor_id=a.actor_id,action=a.action,target=a.target,ip=a.ip,created_at=a.created_at)
                for a in db.scalars(select(Audit).order_by(Audit.id.desc()).offset((page-1)*100).limit(100))]


@router.get('/statistics')
def statistics(request: Request, user=Depends(require('overview.view'))):
    with transaction(request.app.state.factory) as db:
        session_filter = [] if allows(user, 'sessions.view_all') else [SSHSession.user_id == user.id]
        if allows(user, 'assets.view_all'):
            assets_count = db.scalar(select(func.count()).select_from(Asset))
        else:
            assets_count = db.scalar(select(func.count()).select_from(Asset).where(accessible_asset_filter(user.id)))
        counts = db.execute(select(
            func.count(), func.count().filter(SSHSession.state == 'active'),
            func.count().filter(SSHSession.state == 'failed')
        ).select_from(SSHSession).where(*session_filter)).one()
        return dict(assets=assets_count, sessions=counts[0], active=counts[1], failures=counts[2])
