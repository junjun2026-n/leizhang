# ============================================================
# 文件名称：sql_gateway.py
# 生成日期：2026-10-22
# 修改日期：2026-11-20
# 版本信息：v0.261115
# 作    者：JUN
# 备    注：本程序由AI辅助完成。
#           文件功能：实现 sql_gateway 模块相关功能。
#           文件用途：供堡垒机的 leizhang/jump_ssh/sql_gateway.py 模块使用。
#           注意事项：运行前检查依赖与配置；涉及数据或服务变更时先备份并验证。
# ============================================================
"""Audits statements executed through this console, not native client traffic."""
import asyncio
import base64
import contextlib
import json
import socket
import time

import psycopg
import pymysql
from fastapi import HTTPException, WebSocket

from .protocol_sessions import serve_protocol


def pack_result(description, rows, count, limit):
    def value(v):
        if v is None or isinstance(v, (str, int, float, bool)):
            return v
        return 'base64:' + base64.b64encode(v).decode() if isinstance(v, bytes) else str(v)
    result = dict(columns=[str(c[0]) for c in description] if description else [],
                  rows=[], row_count=max(0, count), truncated=len(rows) > limit)
    size = 0
    for row in rows[:limit]:
        converted = [value(v) for v in row]
        size += len(json.dumps(converted, ensure_ascii=False).encode('utf-8'))
        if size > 1024 * 1024:
            result['truncated'] = True
            break
        result['rows'].append(converted)
    return result


async def sql_handler(live):
    a, settings = live.asset, live.app.state.settings
    password = live.app.state.vault.decrypt(a.credential)
    connection = None

    def execute_query(sql):
        with connection.cursor() as cursor:
            if a.protocol == 'postgresql':
                cursor.execute(sql, prepare=True)
            else:
                cursor.execute(sql)
            rows = cursor.fetchmany(settings.sql_rows + 1) if cursor.description else []
            return pack_result(cursor.description, rows, cursor.rowcount, settings.sql_rows)

    try:
        if a.protocol == 'postgresql':
            connect = lambda: psycopg.connect(host=a.host, port=a.port,
                user=a.username, password=password, dbname=a.database_name,
                connect_timeout=10, autocommit=True,
                sslmode='verify-full' if a.tls_verify else 'prefer',
                options=f'-c statement_timeout={settings.sql_timeout * 1000} -c lock_timeout=5000')
        else:
            connect = lambda: pymysql.connect(
                host=a.host, port=a.port, user=a.username, password=password,
                database=a.database_name, connect_timeout=10, read_timeout=settings.sql_timeout,
                write_timeout=10, autocommit=True,
                ssl={'check_hostname': True} if a.tls_verify else None,
                ssl_verify_cert=a.tls_verify, ssl_verify_identity=a.tls_verify)
        # Blocking drivers run off the event loop: works on Windows Proactor as well.
        pending = asyncio.create_task(asyncio.to_thread(connect))
        try:
            connection = await asyncio.shield(pending)
        except psycopg.Error as exc:
            message = str(exc).lower()
            if 'does not support ssl' in message:
                detail = 'PostgreSQL 未启用 SSL，但资源已勾选“校验 TLS”。请为数据库启用 SSL，或在确认允许非 TLS 连接后取消该资源的“校验 TLS”再重连。'
            elif 'certificate verify failed' in message or 'root certificate file' in message or 'does not match host name' in message:
                detail = 'PostgreSQL TLS 证书校验失败，请检查可信 CA、证书有效期及资源地址是否匹配证书。'
            elif 'password authentication failed' in message:
                detail = 'PostgreSQL 用户名或密码验证失败，请检查该资源的系统账号凭据。'
            elif 'does not exist' in message and 'database' in message:
                detail = 'PostgreSQL 数据库不存在，请检查资源中填写的数据库名称。'
            else:
                detail = 'PostgreSQL 连接失败，请检查地址、端口、数据库名、账号及 pg_hba.conf 访问规则。'
            raise HTTPException(502, detail) from exc
        except asyncio.CancelledError:
            late = await pending
            late.close()
            raise
        if a.protocol == 'mysql' and a.tls_verify and not connection._secure:
            raise HTTPException(502, 'MySQL 服务未启用 TLS，证书校验连接已拒绝')
        await live.ws.send_json({'type': 'ready', 'message': '已连接。每次执行一条 SQL，写入操作立即提交。'})
        while True:
            message = await live.ws.receive_json()
            sql = message.get('sql') if isinstance(message, dict) else None
            if not isinstance(sql, str) or not sql.strip() or len(sql.encode('utf-8')) > 32000:
                raise HTTPException(400, 'SQL 不能为空且不能超过 32KB')
            await live.check()
            live.touch()
            operation = await live.audit('sql_requested', {'sql': sql, 'database': a.database_name})
            started = time.monotonic()
            try:
                result = await asyncio.wait_for(asyncio.to_thread(execute_query, sql), settings.sql_timeout + 1)
                success = True
            except asyncio.CancelledError:
                with contextlib.suppress(Exception):
                    await live.audit('sql_completed', {'error': '会话关闭或授权失效，执行被中断；请核实事务结果'}, operation, False,
                                     int((time.monotonic()-started)*1000))
                raise
            except Exception as exc:
                error = str(exc).replace(password, '[凭据]') if password else str(exc)
                result = {'columns': [], 'rows': [], 'row_count': 0, 'error': error[:2000] or 'SQL 执行超时'}
                success = False
            elapsed = int((time.monotonic()-started)*1000)
            await live.audit('sql_completed', {'error': result.get('error'), 'truncated': result.get('truncated', False)},
                             operation, success, elapsed, result['row_count'])
            await live.check()
            await live.ws.send_json(dict(type='result', elapsed_ms=elapsed, **result))
            if not success and a.protocol == 'mysql':
                return
    finally:
        if connection:
            if a.protocol == 'postgresql':
                with contextlib.suppress(Exception):
                    await asyncio.to_thread(connection.cancel_safe, timeout=3)
                await asyncio.to_thread(connection.close)
            else:
                with contextlib.suppress(Exception):
                    connection._sock.shutdown(socket.SHUT_RDWR)
                with contextlib.suppress(Exception):
                    connection.close()


async def sql_socket(ws: WebSocket, session_id: str):
    await serve_protocol(ws, session_id, ('postgresql', 'mysql'), sql_handler)
