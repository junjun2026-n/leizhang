"""System account lifecycle. Credentials are never returned to clients."""
from typing import Literal

import asyncssh
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy import select

from .api import actor, admin, audit, authorize
from .permissions import require, allows
from .db import transaction
from .models import Asset, SystemAccount, AccountGrant, Grant, SSHSession, Approval
from .resource_accounts import accessible_accounts, resolve_account, approval_account_filter, account_grant

router=APIRouter(prefix='/api')


class AccountInput(BaseModel):
    username: str = Field(pattern=r'^[a-zA-Z0-9_@.\-]{1,80}$')
    auth_type: Literal['password','private_key'] = 'password'
    credential: str = Field(default='',max_length=32768)
    enabled: bool = True


def public_account(account, asset_id):
    return dict(id=account.id,asset_id=asset_id,username=account.username,auth_type=account.auth_type,
                enabled=account.enabled,is_default=account.id==asset_id)


def terminate_account_sessions(db, asset_id, account_id):
    for session in db.scalars(select(SSHSession).where(SSHSession.asset_id==asset_id,SSHSession.state.in_(['active','pending']))):
        if (session.account_id or asset_id)==account_id:
            session.state='terminated'


@router.get('/assets/{asset_id}/accounts')
def list_accounts(asset_id: str,request: Request,user=Depends(require('assets.view'))):
    with transaction(request.app.state.factory) as db:
        asset=db.get(Asset,asset_id)
        if not asset:
            raise HTTPException(404,'资源不存在')
        global_view = allows(user,'assets.view_all')
        if not global_view and not asset.enabled:
            raise HTTPException(404, '资源不存在或已停用')
        available = accessible_accounts(db,user,asset)
        if not global_view and not available:
            raise HTTPException(403, '无资源系统账号授权')
        result=[]
        for account in available:
            row=public_account(account,asset_id)
            if not global_view:
                row['expires_at']=account_grant(db,user.id,asset_id,account.id).expires_at
            result.append(row)
        return result


def save_account(asset_id,body,request,user,account_id=None):
    with transaction(request.app.state.factory) as db:
        asset=db.get(Asset,asset_id,with_for_update=True)
        if not asset:
            raise HTTPException(404,'资源不存在')
        if asset.protocol != 'ssh' and body.auth_type != 'password':
            raise HTTPException(400, '所选协议仅支持密码认证')
        account=db.get(SystemAccount,account_id) if account_id else None
        if account_id and (not account or account.asset_id!=asset_id or account.deleted):
            raise HTTPException(404,'资源系统账号不存在')
        duplicate=db.scalar(select(SystemAccount).where(SystemAccount.asset_id==asset_id,SystemAccount.username==body.username))
        if duplicate and duplicate.id!=account_id:
            if not account_id and duplicate.deleted:
                account=duplicate
            else:
                raise HTTPException(409,'此资源已存在相同系统账号')
        creating=not account_id
        if (creating or (account and account.auth_type!=body.auth_type)) and not body.credential:
            raise HTTPException(400,'新增账号或更改认证方式时必须填写凭据')
        if body.auth_type=='private_key' and body.credential:
            try:
                asyncssh.import_private_key(body.credential)
            except (ValueError,asyncssh.KeyImportError):
                raise HTTPException(400,'SSH 私钥无效，当前仅支持未加口令的私钥') from None
        if not account:
            account=SystemAccount(asset_id=asset_id)
            db.add(account)
        else:
            if not body.enabled or body.credential or account.username!=body.username:
                terminate_account_sessions(db,asset_id,account.id)
        account.username,account.auth_type,account.enabled=body.username,body.auth_type,body.enabled
        account.deleted=False
        if body.credential:
            account.credential=request.app.state.vault.encrypt(body.credential)
        db.flush()
        if account.id==asset.id:
            asset.username,asset.auth_type,asset.credential=account.username,account.auth_type,account.credential
        audit(db,user,'system_account_created' if creating else 'system_account_updated',asset_id+':'+account.id,request)
        return public_account(account,asset_id)


@router.post('/assets/{asset_id}/accounts',status_code=201)
def create_account(asset_id: str,body: AccountInput,request: Request,user=Depends(require('accounts.manage'))):
    return save_account(asset_id,body,request,user)


@router.put('/assets/{asset_id}/accounts/{account_id}')
def update_account(asset_id: str,account_id: str,body: AccountInput,request: Request,user=Depends(require('accounts.manage'))):
    return save_account(asset_id,body,request,user,account_id)


@router.delete('/assets/{asset_id}/accounts/{account_id}')
def delete_account(asset_id: str,account_id: str,request: Request,user=Depends(require('accounts.manage'))):
    with transaction(request.app.state.factory) as db:
        asset=db.get(Asset,asset_id,with_for_update=True)
        if not asset:
            raise HTTPException(404,'资源不存在')
        account=resolve_account(db,asset,account_id,allow_disabled=True)
        if not isinstance(account,SystemAccount):
            raise HTTPException(409,'请先完成系统账号迁移')
        terminate_account_sessions(db,asset_id,account.id)
        for approval in db.scalars(select(Approval).where(Approval.asset_id==asset_id,
                approval_account_filter(account.id,asset_id),Approval.state.in_(['pending','approved']))):
            approval.state='revoked'
        if account.id==asset_id:
            for grant in db.scalars(select(Grant).where(Grant.asset_id==asset_id)):
                db.delete(grant)
        else:
            for grant in db.scalars(select(AccountGrant).where(AccountGrant.account_id==account.id)):
                db.delete(grant)
        account.deleted,account.enabled=True,False
        # Keep only identity for historical sessions; remove obsolete stored secrets.
        account.credential=''
        if account.id==asset_id:
            asset.credential=''
        audit(db,user,'system_account_deleted',asset_id+':'+account.id,request)
    return {'ok':True}
