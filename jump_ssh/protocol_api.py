import asyncio
import json

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import select

from .api import actor, audit
from .permissions import require, allows, check
from .db import transaction
from .models import Asset, ProtocolAudit, SSHSession, User

router = APIRouter(prefix='/api')


@router.get('/protocol-audit')
def protocol_audit(request: Request, user=Depends(actor), page: int = 1,
                   session_id: str = '', protocol: str = '', action_group: str = ''):
    check(user, 'commands.audit' if action_group == 'command' else 'protocols.audit')
    if not 1 <= page <= 100000:
        raise HTTPException(422, '页码无效')
    with transaction(request.app.state.factory) as db:
        stmt = (select(ProtocolAudit, SSHSession.system_username, User.username, Asset.name)
                .join(SSHSession, SSHSession.id == ProtocolAudit.session_id)
                .join(User, User.id == SSHSession.user_id).join(Asset, Asset.id == SSHSession.asset_id))
        if session_id:
            stmt = stmt.where(ProtocolAudit.session_id == session_id)
        if protocol:
            stmt = stmt.where(ProtocolAudit.protocol == protocol)
        if action_group == 'command':
            stmt = stmt.where(ProtocolAudit.action.in_(['command_requested', 'command_denied', 'command_completed', 'command_forwarded']))
        elif not allows(user, 'commands.audit'):
            stmt = stmt.where(ProtocolAudit.action.not_in(['command_requested', 'command_denied', 'command_completed', 'command_forwarded']))
        rows = db.execute(stmt.order_by(ProtocolAudit.id.desc()).offset((page-1)*100).limit(100)).all()
        audit(db, user, 'protocol_audit_read', session_id or protocol or 'all', request)
        return [dict(id=a.id, session_id=a.session_id, operation_id=a.operation_id,
            protocol=a.protocol, action=a.action, username=username, system_username=system_username,
            asset=name, success=a.success, elapsed_ms=a.elapsed_ms, row_count=a.row_count,
            created_at=a.created_at, detail=json.loads(request.app.state.vault.decrypt(a.detail)))
            for a, system_username, username, name in rows]


@router.get('/protocol-status')
async def protocol_status(request: Request, user=Depends(require('sessions.connect'))):
    settings = request.app.state.settings
    try:
        _, writer = await asyncio.wait_for(asyncio.open_connection(settings.guacd_host, settings.guacd_port), 1)
        writer.close()
        await writer.wait_closed()
        desktop = True
    except (OSError, asyncio.TimeoutError):
        desktop = False
    return {'vnc_native':settings.vnc_backend=='native','desktop_gateway': desktop, 'desktop_message': '网关可连接' if desktop else 'Guacamole 网关未连接，请配置 GUACD_HOST / GUACD_PORT'}
