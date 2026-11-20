# ============================================================
# 文件名称：role_api.py
# 生成日期：2026-10-23
# 修改日期：2026-11-20
# 版本信息：v0.261115
# 作    者：JUN
# 备    注：本程序由AI辅助完成。
#           文件功能：实现 role_api 模块相关功能。
#           文件用途：供堡垒机的 leizhang/jump_ssh/role_api.py 模块使用。
#           注意事项：运行前检查依赖与配置；涉及数据或服务变更时先备份并验证。
# ============================================================
import json
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import func, select, or_

from .api import admin, audit
from .command_policy import CommandPolicyInput
from .permissions import require, role_permissions, ensure_delegable, protect_target
from .db import transaction, advisory_lock
from .models import LoginSession, Role, SSHSession, User
from .permissions import CATALOG, REQUIRES, defaults, normalize

router = APIRouter(prefix='/api')


def stop_sessions(db, user_ids, terminal_only=True):
    stmt = select(SSHSession).where(SSHSession.user_id.in_(user_ids), SSHSession.state.in_(['active', 'pending']))
    if terminal_only:
        stmt = stmt.where(SSHSession.protocol.in_(['ssh', 'telnet']))
    for session in db.scalars(stmt):
        session.state = 'terminated'


def serialize(role, count=0):
    return dict(id=role.id, name=role.name, base_role=role.base_role,
                description=role.description, builtin=role.builtin, user_count=count,
                command_mode=role.command_mode, command_rules=json.loads(role.command_rules),
                permissions=sorted(role_permissions(role)), permissions_locked=role.id == 'admin')


class RoleInput(CommandPolicyInput):
    name: str = Field(min_length=1, max_length=80)
    base_role: Literal['admin', 'operator', 'auditor'] = 'operator'
    description: str = Field(default='', max_length=300)

    @field_validator('name')
    @classmethod
    def nonblank(cls, value):
        if not value.strip():
            raise ValueError('角色名称不能为空')
        return value.strip()


@router.get('/roles')
def roles(request: Request, user=Depends(require('roles.view'))):
    with transaction(request.app.state.factory) as db:
        role_key = func.coalesce(User.role_id, User.role)
        counts = dict(db.execute(select(role_key, func.count()).group_by(role_key)).all())
        return [serialize(r, counts.get(r.id, 0)) for r in db.scalars(select(Role).order_by(Role.builtin.desc(), Role.name))]


@router.post('/roles', status_code=201)
def create_role(body: RoleInput, request: Request, user=Depends(require('roles.manage'))):
    ensure_delegable(user, defaults(body.base_role))
    with transaction(request.app.state.factory) as db:
        advisory_lock(db, 'role-edit')
        if db.scalar(select(Role.id).where(Role.name == body.name)):
            raise HTTPException(409, '角色名称已存在')
        target = Role(**body.model_dump(exclude={'command_rules'}),
                      command_rules=json.dumps(body.command_rules, ensure_ascii=False))
        db.add(target)
        db.flush()
        audit(db, user, 'role_created', target.id, request)
        return serialize(target)


@router.put('/roles/{role_id}')
def edit_role(role_id: str, body: RoleInput, request: Request, user=Depends(require('roles.manage'))):
    with transaction(request.app.state.factory) as db:
        advisory_lock(db, 'role-edit')
        target = db.get(Role, role_id, with_for_update=True)
        if not target:
            raise HTTPException(404, '角色不存在')
        ensure_delegable(user, role_permissions(target))
        ensure_delegable(user, role_permissions(target) if target.permissions is not None else defaults(body.base_role))
        if db.scalar(select(Role.id).where(Role.name == body.name, Role.id != role_id)):
            raise HTTPException(409, '角色名称已存在')
        if target.builtin and target.base_role != body.base_role:
            raise HTTPException(400, '内置角色的权限类型不可修改')
        assigned = list(db.scalars(select(User).where(or_(User.role_id == role_id,
            (User.role_id.is_(None)) & (User.role == role_id))).with_for_update()))
        if target.base_role != body.base_role and any(u.id == user.id for u in assigned):
            raise HTTPException(400, '不可通过角色修改自己的权限类型')
        changed_policy = target.command_mode != body.command_mode or json.loads(target.command_rules) != body.command_rules
        for u in assigned:
            if u.role != body.base_role:
                u.role = body.base_role
                db.query(LoginSession).filter_by(user_id=u.id).delete()
        if changed_policy or target.base_role != body.base_role:
            stop_sessions(db, [u.id for u in assigned], terminal_only=target.base_role == body.base_role)
        target.name, target.description, target.base_role = body.name, body.description, body.base_role
        target.command_mode, target.command_rules = body.command_mode, json.dumps(body.command_rules, ensure_ascii=False)
        audit(db, user, 'role_updated', target.id, request)
        return serialize(target, len(assigned))


@router.delete('/roles/{role_id}')
def delete_role(role_id: str, request: Request, user=Depends(require('roles.manage'))):
    with transaction(request.app.state.factory) as db:
        advisory_lock(db, 'role-edit')
        target = db.get(Role, role_id, with_for_update=True)
        if not target:
            raise HTTPException(404, '角色不存在')
        ensure_delegable(user, role_permissions(target))
        if target.builtin:
            raise HTTPException(400, '内置角色不可删除')
        if db.scalar(select(User.id).where(User.role_id == role_id).limit(1)):
            raise HTTPException(409, '角色仍有用户使用，请先调整用户角色')
        db.delete(target)
        audit(db, user, 'role_deleted', role_id, request)
        return {'ok': True}


@router.put('/users/{user_id}/command-policy')
def edit_user_policy(user_id: str, body: CommandPolicyInput, request: Request, user=Depends(require('users.policy'))):
    with transaction(request.app.state.factory) as db:
        target = db.get(User, user_id, with_for_update=True)
        if not target:
            raise HTTPException(404, '用户不存在')
        protect_target(db, user, target)
        target.command_mode = body.command_mode
        target.command_rules = json.dumps(body.command_rules, ensure_ascii=False)
        stop_sessions(db, [target.id])
        audit(db, user, 'user_command_policy_updated', target.id, request)
    return {'ok': True}


class PermissionsInput(BaseModel):
    permissions: list[str] = Field(max_length=100)


@router.get('/permissions')
def permission_catalog(request: Request, user=Depends(require('permissions.manage'))):
    return dict(items=[dict(code=code, group=group, label=label, requires=REQUIRES.get(code, []))
                       for code, group, label in CATALOG],
                defaults={base: sorted(defaults(base)) for base in ('admin', 'operator', 'auditor')})


@router.put('/roles/{role_id}/permissions')
def assign_permissions(role_id: str, body: PermissionsInput, request: Request, user=Depends(require('permissions.manage'))):
    codes = normalize(body.permissions)
    ensure_delegable(user, codes)
    with transaction(request.app.state.factory) as db:
        advisory_lock(db, 'role-edit')
        role = db.get(Role, role_id, with_for_update=True)
        if not role:
            raise HTTPException(404, '角色不存在')
        previous = role_permissions(role)
        ensure_delegable(user, previous)
        if role.id == 'admin' and codes != defaults('admin'):
            raise HTTPException(400, '内置管理员保留全部权限，请使用自定义角色分配受限权限')
        if (user.role_id or user.role) == role_id and codes != previous:
            raise HTTPException(400, '不可修改自己所属角色的平台权限，请由其他权限管理员操作')
        if codes != previous:
            assigned = list(db.scalars(select(User).where(or_(User.role_id == role_id,
                (User.role_id.is_(None)) & (User.role == role_id))).with_for_update()))
            ids = [u.id for u in assigned]
            stop_sessions(db, ids, terminal_only=False)
            db.query(LoginSession).filter(LoginSession.user_id.in_(ids)).delete(synchronize_session=False)
            role.permissions = json.dumps(sorted(codes))
            for code in sorted(codes - previous):
                audit(db, user, 'permission_granted', role.id + ':' + code, request)
            for code in sorted(previous - codes):
                audit(db, user, 'permission_revoked', role.id + ':' + code, request)
            audit(db, user, 'role_permissions_updated', role.id, request)
        return serialize(role)
