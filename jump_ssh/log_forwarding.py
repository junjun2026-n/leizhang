# ============================================================
# 文件名称：log_forwarding.py
# 生成日期：2026-11-09
# 修改日期：2026-11-20
# 版本信息：v0.261115
# 作    者：JUN
# 备    注：本程序由AI辅助完成。
#           文件功能：组织并转发平台日志。
#           文件用途：供堡垒机的 leizhang/jump_ssh/log_forwarding.py 模块使用。
#           注意事项：运行前检查依赖与配置；涉及数据或服务变更时先备份并验证。
# ============================================================
"""Bounded background log shipping with durable per-stream checkpoints."""
import ipaddress
import json
import socket
import ssl
import string
import threading
from datetime import datetime, timezone
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

FIELDS={'id','time','source','action','actor','target','ip','detail','hostname','platform_name'}


class LogConfig(BaseModel):
    model_config=ConfigDict(extra='forbid')
    enabled: bool=False
    host: str=Field(default='',max_length=64)
    port: int=Field(default=514,ge=1,le=65535)
    protocol: Literal['udp','tcp','tls']='udp'
    format: Literal['json','syslog','custom']='json'
    facility: int=Field(default=16,ge=0,le=23)
    template: str=Field(default='{time} {source} {action} {actor} {target} {ip} {detail}',max_length=8192)

    @model_validator(mode='after')
    def valid(self):
        if self.host:
            try:self.host=str(ipaddress.ip_address(self.host))
            except ValueError:raise ValueError('接收服务器须为 IPv4 或 IPv6 地址')
        if self.enabled and not self.host:raise ValueError('启用时请填写接收服务器 IP')
        if any(ord(c)<32 for c in self.template):raise ValueError('模板须为单行文本')
        try:
            for _,name,spec,conversion in string.Formatter().parse(self.template):
                if name is not None and (name not in FIELDS or spec or conversion):raise ValueError('模板字段或表达式不受支持')
        except ValueError as e:raise ValueError('模板无效：'+str(e))
        if self.format=='custom' and not self.template.strip():raise ValueError('模板不能为空')
        return self


def utc():return datetime.now(timezone.utc).isoformat()


def render(config,event,platform):
    record={**dict.fromkeys(FIELDS,''),**event,'hostname':socket.gethostname(),'platform_name':platform}
    try:
        with socket.socket(socket.AF_INET6 if ':' in config.host else socket.AF_INET,socket.SOCK_DGRAM) as route:
            route.connect((config.host,config.port));record['sender_ip']=route.getsockname()[0]
    except OSError:record['sender_ip']=''
    payload=json.dumps(record,ensure_ascii=False,separators=(',',':'),default=str)
    if config.format=='syslog':
        host=''.join(c for c in record['hostname'] if 33<=ord(c)<=126)[:255] or '-'
        payload=f'<{config.facility*8+6}>1 {record["time"]} {host} PLATFORM - LOG - {payload}'
    elif config.format=='custom':
        safe={k:json.dumps(str(v),ensure_ascii=False)[1:-1] for k,v in record.items()}
        payload=config.template.format_map(safe)
    data=payload.encode('utf-8')
    if len(data)>60000:raise ValueError('日志超过 60000 字节')
    return data


def send(config,payload):
    if not config.host:raise ValueError('请填写接收服务器 IP')
    if config.protocol=='udp':
        family=socket.AF_INET6 if ipaddress.ip_address(config.host).version==6 else socket.AF_INET
        with socket.socket(family,socket.SOCK_DGRAM) as conn:
            conn.settimeout(2);conn.sendto(payload,(config.host,config.port))
    else:
        with socket.create_connection((config.host,config.port),timeout=2) as conn:
            if config.protocol=='tls':
                with ssl.create_default_context().wrap_socket(conn,server_hostname=config.host) as secure:secure.sendall(payload+b'\n')
            else:conn.sendall(payload+b'\n')


class Forwarder:
    """Adapter supplies persistent JSON settings and bounded ordered log streams."""
    def __init__(self,adapter):
        self.adapter=adapter;self.lock=threading.RLock();self.stop_event=threading.Event();self.thread=None

    def status(self):
        with self.lock:
            config=self.adapter.read('log_config') or LogConfig().model_dump()
            state=self.adapter.read('log_state') or {}
            return dict(config=config,state=state,sources=list(self.adapter.sources),running=bool(self.thread and self.thread.is_alive()))

    def configure(self,config):
        with self.lock:
            state=self.adapter.read('log_state')
            # Start with new logs, avoiding an unexpected historical data flood.
            if state is None:
                state=dict(cursors=self.adapter.heads(),sent=0,last_error='',initialized_at=utc())
                self.adapter.write('log_state',state)
            self.adapter.write('log_config',config.model_dump())
        return self.status()

    def test(self,config):
        if not config.enabled:raise ValueError('请先选择启用日志转发再测试')
        event=dict(id='test',time=utc(),source='test',action='forwarding.test',detail='日志转发测试消息')
        send(config,render(config,event,self.adapter.platform()))
        return {'detail':'测试消息已交给发送端；UDP 无确认，请在接收服务器核实。'}

    def batch(self):
        with self.lock:
            config=LogConfig(**(self.adapter.read('log_config') or {}))
            if not config.enabled:return False
            state=self.adapter.read('log_state')
            if state is None:
                state=dict(cursors=self.adapter.heads(),sent=0,last_error='',initialized_at=utc());self.adapter.write('log_state',state)
            try:
                busy=False
                for source in self.adapter.sources:
                    for cursor,event in self.adapter.fetch(source,state['cursors'].get(source,0),20):
                        if self.stop_event.is_set():return False
                        send(config,render(config,event,self.adapter.platform()))
                        state['cursors'][source]=cursor;state['sent']=state.get('sent',0)+1
                        state.update(last_sent_at=utc(),last_error='')
                        self.adapter.write('log_state',state);busy=True
                return busy
            except (OSError,ValueError):
                state.update(last_error='发送失败：请检查接收地址、端口、协议及 TLS 证书；将自动重试',last_attempt_at=utc())
                self.adapter.write('log_state',state);return False

    def start(self):
        self.stop_event.clear()
        def run():
            while not self.stop_event.is_set():
                try:busy=self.batch()
                except Exception:busy=False
                self.stop_event.wait(.15 if busy else 5)
        self.thread=threading.Thread(target=run,name='log-forwarder',daemon=True);self.thread.start()

    def stop(self):
        self.stop_event.set()
        if self.thread:self.thread.join(5)
