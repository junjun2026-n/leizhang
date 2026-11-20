# ============================================================
# 文件名称：permissions.py
# 生成日期：2026-10-23
# 修改日期：2026-11-20
# 版本信息：v0.261115
# 作    者：JUN
# 备    注：本程序由AI辅助完成。
#           文件功能：实现 permissions 模块相关功能。
#           文件用途：供堡垒机的 leizhang/jump_ssh/permissions.py 模块使用。
#           注意事项：运行前检查依赖与配置；涉及数据或服务变更时先备份并验证。
# ============================================================
"""Role capabilities shared by HTTP, WebSockets and resource scope checks."""
import json

from fastapi import Depends, HTTPException

CATALOG = [
    ('overview.view', '总览', '查看总览'),
    ('assets.view', '资产', '查看授权资产'),
    ('assets.view_all', '资产', '查看全部资产'),
    ('assets.manage', '资产', '新增及修改资产'),
    ('accounts.manage', '系统账号', '管理全部资源系统账号'),
    ('assets.access_all', '连接范围', '免账号授权连接全部启用资源（仍须审批）'),
    ('sessions.connect', '连接与会话', '连接资源'),
    ('sessions.view', '连接与会话', '查看自己的会话'),
    ('sessions.view_all', '连接与会话', '查看全部会话'),
    ('sessions.terminate', '连接与会话', '终止自己的会话'),
    ('sessions.terminate_all', '连接与会话', '终止全部用户会话'),
    ('recordings.view', '审计', '查看全部会话录像'),
    ('commands.audit', '审计', '查看命令审计'),
    ('protocols.audit', '审计', '查看 SQL / 协议审计'),
    ('audit.view', '审计', '查看操作审计'),
    ('users.view', '用户', '查看平台用户'),
    ('users.manage', '用户', '创建用户、分配角色及启停'),
    ('users.mfa', '用户', '管理用户 MFA'),
    ('users.policy', '用户', '修改用户命令策略'),
    ('roles.view', '角色与权限', '查看角色'),
    ('roles.manage', '角色与权限', '新增、编辑及删除角色'),
    ('permissions.manage', '角色与权限', '分配角色平台权限'),
    ('grants.view', '资源授权', '查看全部账号授权'),
    ('grants.manage', '资源授权', '分配、续期及撤销账号授权'),
    ('approvals.view', '审批', '查看自己的访问申请'),
    ('approvals.request', '审批', '提交访问申请'),
    ('approvals.review', '审批', '查看全部申请及处理指定审批'),
    ('settings.appearance', '系统配置', '查看及修改平台外观'),
    ('settings.database', '系统配置', '查看及修改平台数据库配置'),
    ('settings.logging', '系统配置', '查看及修改日志转发配置'),
]
ALL = {code for code, _, _ in CATALOG}
REQUIRES = {
    'assets.view_all': ['assets.view'], 'assets.manage': ['assets.view_all'],
    'accounts.manage': ['assets.view_all', 'grants.view'], 'assets.access_all': ['sessions.connect', 'assets.view_all'],
    'sessions.connect': ['assets.view'], 'sessions.view_all': ['sessions.view'],
    'sessions.terminate': ['sessions.view'], 'sessions.terminate_all': ['sessions.terminate', 'sessions.view_all'],
    'recordings.view': ['sessions.view_all'],
    'users.view': ['roles.view'], 'users.manage': ['users.view'],
    'users.mfa': ['users.view'], 'users.policy': ['users.view'],
    'roles.manage': ['roles.view'], 'permissions.manage': ['roles.view'],
    'grants.view': ['assets.view_all', 'users.view'], 'grants.manage': ['grants.view'],
    'approvals.request': ['approvals.view', 'assets.view'], 'approvals.review': ['approvals.view'],
}


def normalize(codes):
    result = set(codes)
    if result - ALL:
        raise HTTPException(422, '包含未知的平台权限')
    pending = list(result)
    while pending:
        for dependency in REQUIRES.get(pending.pop(), []):
            if dependency not in result:
                result.add(dependency)
                pending.append(dependency)
    return result


def defaults(base):
    if base == 'admin':
        return set(ALL)
    common = {'overview.view', 'assets.view', 'sessions.view', 'approvals.view'}
    if base == 'auditor':
        return normalize(common | {'sessions.view_all', 'recordings.view', 'audit.view', 'commands.audit', 'protocols.audit'})
    return normalize(common | {'sessions.connect', 'sessions.terminate', 'approvals.request'})


def role_permissions(role, base=None):
    if role and role.permissions is not None:
        return set(json.loads(role.permissions)) & ALL
    return defaults(role.base_role if role else base)


def load_permissions(db, user):
    from .models import Role
    key = user.role_id or user.role
    roles = db.info.setdefault('permission_roles', {})
    if key not in roles:
        roles[key] = db.get(Role, key)
    user._permissions = role_permissions(roles[key], user.role)
    return user._permissions


def allows(user, code):
    codes = getattr(user, '_permissions', None)
    return code in (codes if codes is not None else defaults(user.role))


def check(user, code):
    if not allows(user, code):
        label = next((label for key, _, label in CATALOG if key == code), code)
        raise HTTPException(403, '没有平台权限：' + label)


def require(code):
    from .api import actor
    def dependency(user=Depends(actor)):
        check(user, code)
        return user
    return dependency


def ensure_delegable(user, codes):
    own = getattr(user, '_permissions', None)
    if set(codes) - (own if own is not None else defaults(user.role)):
        raise HTTPException(403, '不能管理或分配超出自身权限的角色或用户')


def protect_target(db, actor, target):
    ensure_delegable(actor, load_permissions(db, target))
