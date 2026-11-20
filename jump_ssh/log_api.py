# ============================================================
# 文件名称：log_api.py
# 生成日期：2026-11-09
# 修改日期：2026-11-20
# 版本信息：v0.261115
# 作    者：JUN
# 备    注：本程序由AI辅助完成。
#           文件功能：实现 log_api 模块相关功能。
#           文件用途：供堡垒机的 leizhang/jump_ssh/log_api.py 模块使用。
#           注意事项：运行前检查依赖与配置；涉及数据或服务变更时先备份并验证。
# ============================================================
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
