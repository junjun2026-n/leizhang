from fastapi import APIRouter,Depends,HTTPException,Request

from .log_forwarding import LogConfig
from .permissions import require
from .api import audit
from .db import transaction

router=APIRouter(prefix='/api/settings/logging')


@router.get('')
def status(request:Request,user=Depends(require('settings.logging'))):
    return request.app.state.log_forwarder.status()


@router.put('')
def configure(value:LogConfig,request:Request,user=Depends(require('settings.logging'))):
    result=request.app.state.log_forwarder.configure(value)
    with transaction(request.app.state.factory) as db:audit(db,user,'log_forwarding.updated','enabled' if value.enabled else 'disabled',request)
    return result


@router.post('/test')
def test(value:LogConfig,request:Request,user=Depends(require('settings.logging'))):
    try:result=request.app.state.log_forwarder.test(value)
    except (OSError,ValueError):raise HTTPException(422,'测试发送失败，请检查接收地址、端口、协议和 TLS 证书') from None
    with transaction(request.app.state.factory) as db:audit(db,user,'log_forwarding.test','logging',request)
    return result
