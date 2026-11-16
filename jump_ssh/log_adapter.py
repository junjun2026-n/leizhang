import json
from datetime import timezone

from sqlalchemy import select,func

from .db import transaction
from .models import Audit,ProtocolAudit,PlatformSetting,SSHSession,Asset,User


class LogAdapter:
    sources=('audit','protocol')
    models={'audit':Audit,'protocol':ProtocolAudit}

    def __init__(self,factory,vault=None):self.factory,self.vault=factory,vault

    def read(self,key):
        with transaction(self.factory) as db:
            row=db.get(PlatformSetting,key)
            return json.loads(row.value) if row else None

    def write(self,key,value):
        with transaction(self.factory) as db:
            row=db.get(PlatformSetting,key)
            if row:row.value=json.dumps(value)
            else:db.add(PlatformSetting(key=key,value=json.dumps(value)))

    def platform(self):
        appearance=self.read('appearance') or {}
        return appearance.get('platform_name','JUMP SSH 堡垒机')

    def heads(self):
        with transaction(self.factory) as db:
            return {source:db.scalar(select(func.coalesce(func.max(model.id),0))) for source,model in self.models.items()}

    def fetch(self,source,cursor,limit):
        model=self.models[source]
        with transaction(self.factory) as db:
            result=[]
            for row in db.scalars(select(model).where(model.id>cursor).order_by(model.id).limit(limit)):
                stamp=row.created_at
                if stamp.tzinfo is None:stamp=stamp.replace(tzinfo=timezone.utc)
                event=dict(id=row.id,time=stamp.isoformat(),source=source,source_system='jump',action=row.action)
                if source=='audit':
                    actor=db.get(User,row.actor_id) if row.actor_id else None
                    event.update(actor=actor.username if actor else row.actor_id or '',target=row.target,ip=row.ip)
                else:
                    # Only explicit operation audit fields; never credentials or recordings.
                    event.update(target=row.session_id,protocol=row.protocol,success=row.success,
                                 elapsed_ms=row.elapsed_ms,row_count=row.row_count,operation_id=row.operation_id,
                                 session_id=row.session_id,status='success' if row.success else 'failed' if row.success is False else 'unknown')
                    if self.vault:
                        detail=json.loads(self.vault.decrypt(row.detail))
                        allowed={'command','sql','path','bytes','sha256','operation','database','exit_status','error','reason','truncated'}
                        event['operation_detail']={k:v for k,v in detail.items() if k in allowed}
                        event['content_scope']='结构化操作审计；不含终端输出、文件正文或录像'
                    else:event['content_scope']='未配置审计解密器，仅含元数据'
                session=db.get(SSHSession,row.session_id if source=='protocol' else row.target.split(':',1)[0])
                if session:
                    asset=db.get(Asset,session.asset_id);user=db.get(User,session.user_id)
                    event.update(session_id=session.id,actor=user.username if user else session.user_id,
                                 asset_id=session.asset_id,system_username=session.system_username,session_state=session.state,
                                 asset_context='转发时查询的资产配置，历史记录不保证与事件发生时相同')
                    if asset:event.update(dst_ip=asset.host,dst_port=asset.port,protocol=session.protocol)
                result.append((row.id,event))
            return result
