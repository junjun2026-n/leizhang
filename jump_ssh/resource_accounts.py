"""Shared resolution rules: a resource grant never implies all system accounts."""
from fastapi import HTTPException
from sqlalchemy import and_, or_, select

from .models import AccountGrant, Approval, Asset, Grant, SystemAccount, now
from .permissions import allows


def accessible_asset_filter(user_id):
    """SQL equivalent of accessible_accounts for operators, including legacy grants."""
    timestamp = now()
    legacy_grant = select(Grant.asset_id).where(
        Grant.user_id == user_id, Grant.asset_id == Asset.id,
        Grant.expires_at > timestamp).correlate(Asset).exists()
    extra_grant = select(AccountGrant.account_id).where(
        AccountGrant.user_id == user_id, AccountGrant.account_id == SystemAccount.id,
        AccountGrant.expires_at > timestamp).correlate(SystemAccount).exists()
    account = select(SystemAccount.id).where(
        SystemAccount.asset_id == Asset.id, SystemAccount.enabled.is_(True),
        SystemAccount.deleted.is_(False), or_(
            and_(SystemAccount.id == Asset.id, legacy_grant),
            and_(SystemAccount.id != Asset.id, extra_grant))).correlate(Asset).exists()
    default_exists = select(SystemAccount.id).where(
        SystemAccount.id == Asset.id).correlate(Asset).exists()
    return and_(Asset.enabled.is_(True), or_(account,
        and_(~default_exists, Asset.username != '', legacy_grant)))


def approval_account_filter(account_id,asset_id):
    condition=Approval.account_id==account_id
    return condition | Approval.account_id.is_(None) if account_id==asset_id else condition


def resolve_account(db, asset, account_id=None, allow_disabled=False):
    account_id = account_id or asset.id
    account = db.get(SystemAccount, account_id)
    # Compatibility for programmatically created legacy assets; production rows are migrated.
    if not account and account_id == asset.id and asset.username:
        return asset
    if not account or account.asset_id != asset.id or account.deleted:
        raise HTTPException(404, '资源系统账号不存在')
    if not allow_disabled and not account.enabled:
        raise HTTPException(403, '资源系统账号已停用')
    return account


def account_grant(db, user_id, asset_id, account_id):
    return db.get(Grant, (user_id, asset_id)) if account_id == asset_id else db.get(AccountGrant, (user_id, account_id))


def all_grants(db):
    rows = [dict(user_id=g.user_id,asset_id=g.asset_id,account_id=g.asset_id,expires_at=g.expires_at)
            for g in db.scalars(select(Grant))]
    rows += [dict(user_id=g.user_id,asset_id=a.asset_id,account_id=a.id,expires_at=g.expires_at)
             for g,a in db.execute(select(AccountGrant,SystemAccount).join(SystemAccount, SystemAccount.id==AccountGrant.account_id))]
    return rows


def accessible_accounts(db, user, asset):
    accounts = list(db.scalars(select(SystemAccount).where(SystemAccount.asset_id==asset.id, SystemAccount.deleted.is_(False)).order_by(SystemAccount.username)))
    if not db.get(SystemAccount, asset.id) and asset.username:
        accounts.insert(0, asset)
    if allows(user, 'assets.view_all') or allows(user, 'assets.access_all'):
        return accounts
    if not asset.enabled:
        return []
    result=[]
    for account in accounts:
        grant = account_grant(db, user.id, asset.id, account.id)
        if account.enabled and grant and grant.expires_at>now():
            result.append(account)
    return result
