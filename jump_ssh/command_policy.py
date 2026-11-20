# ============================================================
# 文件名称：command_policy.py
# 生成日期：2026-10-23
# 修改日期：2026-11-20
# 版本信息：v0.261115
# 作    者：JUN
# 备    注：本程序由AI辅助完成。
#           文件功能：实现 command_policy 模块相关功能。
#           文件用途：供堡垒机的 leizhang/jump_ssh/command_policy.py 模块使用。
#           注意事项：运行前检查依赖与配置；涉及数据或服务变更时先备份并验证。
# ============================================================
"""Terminal-only policy checks. No shell fragments are forwarded unchecked."""
import fnmatch
import json
import re
import shlex
from pathlib import PurePosixPath

from fastapi import HTTPException
from pydantic import BaseModel, Field, field_validator, model_validator
from typing import Literal

from .models import Role


class CommandPolicyInput(BaseModel):
    command_mode: Literal['off', 'deny', 'allow'] = 'off'
    command_rules: list[str] = Field(default_factory=list, max_length=100)

    @field_validator('command_rules')
    @classmethod
    def rules_valid(cls, rules):
        cleaned = []
        for rule in rules:
            rule = rule.strip()
            if not rule or len(rule) > 256 or any(ord(c) < 32 for c in rule):
                raise ValueError('每条命令规则需为 1～256 个字符，不能含换行或控制符')
            if rule not in cleaned:
                cleaned.append(rule)
        return cleaned

    @model_validator(mode='after')
    def require_rules(self):
        if self.command_mode == 'deny' and not self.command_rules:
            raise ValueError('黑名单至少需要一条规则；无需限制时请选择不限制')
        return self


def policies_for(db, user):
    role = db.get(Role, user.role_id or user.role)
    return [(p.command_mode, json.loads(p.command_rules)) for p in (role, user)
            if p and p.command_mode != 'off']


def effective_policy(app, session_id, cookie):
    from .db import transaction
    from .models import SSHSession, User
    from .ssh import validate_access
    validate_access(app, session_id, cookie, protocols=('ssh', 'telnet'))
    with transaction(app.state.factory) as db:
        session = db.get(SSHSession, session_id)
        return policies_for(db, db.get(User, session.user_id))


# Restricted sessions cannot launch a nested interactive interpreter or an editor
# with shell escapes. This is a gateway control, not a replacement for OS permissions.
UNSAFE_PROGRAMS = set('sh bash zsh dash ksh csh tcsh fish cmd powershell pwsh python python2 python3 perl ruby php node lua tclsh expect busybox env sudo su doas ssh telnet rlogin screen tmux vi vim nvim emacs nano ed ex less more man awk gawk nawk sed find xargs parallel watch ftp sftp nc ncat netcat socat docker podman kubectl chroot unshare nsenter systemd-run exec eval source command builtin time nohup setsid runuser nice ionice script make cmake gdb lldb strace ltrace sqlite3 psql mysql mariadb'.split())
UNSAFE_PROGRAMS.update('. alias unalias export unset set enable trap fc history bind read readonly declare typeset let coproc complete compgen'.split())


def checked_command(command, policies):
    if not command.strip():
        return ''
    if len(command.encode('utf-8')) > 8192 or re.search(r'[\x00-\x1f\x7f;&|<>`$\\]', command):
        raise HTTPException(403, '受控会话仅支持单条命令，不能使用控制符、管道、重定向、变量或命令替换')
    try:
        argv = shlex.split(command)
    except ValueError:
        raise HTTPException(403, '命令引号不完整')
    if not argv or not re.fullmatch(r'[A-Za-z0-9_./+-]+', argv[0]) or '=' in argv[0]:
        raise HTTPException(403, '命令名称无效')
    executable = PurePosixPath(argv[0]).name.lower()
    if not executable or executable in UNSAFE_PROGRAMS or re.fullmatch(r'(python|perl|ruby|php|node|lua)[0-9.]*', executable):
        raise HTTPException(403, '受控会话不允许启动解释器、交互程序或命令代理')
    if any(a in ('-exec', '-execdir', '--exec', '--checkpoint-action', '-e', '--eval') or
           a.startswith(('--exec=', '--checkpoint-action=', '--use-compress-program=', '--rsync-path=')) for a in argv[1:]):
        raise HTTPException(403, '受控会话不允许执行外部命令的参数')
    normalized = shlex.join(argv)
    plain = ' '.join(argv)
    candidates = [command.strip(), normalized, plain, ' '.join([executable, *argv[1:]])]

    def matches(rule):
        # A bare executable rule covers that command with any arguments.
        if not any(c.isspace() for c in rule) and not any(c in rule for c in '*?['):
            return rule in (argv[0], executable)
        return any(fnmatch.fnmatchcase(c, rule) for c in candidates)

    if any(mode == 'deny' and any(matches(r) for r in rules) for mode, rules in policies):
        raise HTTPException(403, '命令命中黑名单，已拒绝执行')
    if any(mode == 'allow' and not any(matches(r) for r in rules) for mode, rules in policies):
        raise HTTPException(403, '命令不在白名单中，已拒绝执行')
    return normalized
