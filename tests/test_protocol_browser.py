# ============================================================
# 文件名称：test_protocol_browser.py
# 生成日期：2026-10-22
# 修改日期：2026-11-20
# 版本信息：v0.261115
# 作    者：JUN
# 备    注：本程序由AI辅助完成。
#           文件功能：验证 protocol_browser 相关功能。
#           文件用途：用于开发验证及功能回归。
#           注意事项：使用隔离测试环境，避免操作正式业务数据。
# ============================================================
"""Real Edge smoke test against an isolated, disposable PostgreSQL schema."""
import os
import socket
import threading
import time

import pyotp
import uvicorn
from playwright.sync_api import sync_playwright
from sqlalchemy.engine import make_url

from conftest import add_user


def test_browser_protocol_forms_sql_audit_and_gateway_notice(app,tmp_path):
    sock=socket.socket();sock.bind(('127.0.0.1',0));sock.listen(128)
    origin=f'http://127.0.0.1:{sock.getsockname()[1]}'
    app.state.settings.origin=origin
    app.state.settings.allowed_origins={origin}
    _,secret=add_user(app,'browser_protocol_admin','admin')
    server=uvicorn.Server(uvicorn.Config(app,log_level='error',ws_max_size=32768))
    thread=threading.Thread(target=lambda:server.run(sockets=[sock]),daemon=True);thread.start()
    try:
        for _ in range(100):
            if server.started:break
            time.sleep(.05)
        assert server.started
        with sync_playwright() as pw:
            browser=pw.chromium.launch(channel='msedge',headless=True)
            page=browser.new_page(viewport={'width':1440,'height':1000})
            errors=[]
            page.on('pageerror',lambda error:errors.append(str(error)))
            page.goto(origin)
            page.get_by_label('用户名',exact=True).fill('browser_protocol_admin')
            page.get_by_label('密码',exact=True).fill('test-password-only-123')
            page.get_by_role('button',name='已启用 MFA？填写验证码').click()
            page.get_by_label('MFA 动态验证码（仅已启用账号填写）').fill(pyotp.TOTP(secret).now())
            page.get_by_role('button',name='登录',exact=True).click()
            page.locator('nav button[data-page=assets]').click()
            page.get_by_role('button',name='新增资产',exact=True).click()
            protocol=page.get_by_label('协议',exact=True)
            assert protocol.locator('option').count()==7
            protocol.select_option('rdp')
            assert page.get_by_label('连接端口').input_value()=='3389'
            assert page.get_by_label('Windows 域（可选）').is_visible()
            assert not page.get_by_label('数据库名称',exact=True).is_visible()
            protocol.select_option('postgresql')
            target=make_url(os.environ['TEST_DATABASE_URL'])
            page.get_by_label('名称',exact=True).fill('Browser PostgreSQL')
            page.get_by_label('IP / 主机名').fill(target.host)
            page.get_by_label('连接端口').fill(str(target.port or 5432))
            page.get_by_label('数据库名称',exact=True).fill(target.database)
            page.get_by_label('资源系统账号（与平台用户独立）').fill(target.username)
            page.get_by_label('密码或私钥（加密存储）').fill(target.password)
            page.get_by_label('校验 TLS / 远程证书').uncheck()
            page.get_by_label('需要审批',exact=True).uncheck()
            page.get_by_role('button',name='保存',exact=True).click()
            page.wait_for_selector('#modal:not([open])',state='attached')
            row=page.locator('#content tr').filter(has_text='Browser PostgreSQL')
            row.get_by_role('button',name='连接',exact=True).click()
            # Account selection may present a modal even for one account.
            if page.get_by_role('button',name='使用此账号连接').count():
                page.get_by_role('button',name='使用此账号连接').click()
            page.get_by_label('SQL 语句').wait_for()
            page.get_by_label('SQL 语句').fill('SELECT 42 AS browser_answer')
            page.get_by_role('button',name='执行 SQL',exact=True).click()
            page.get_by_role('cell',name='42',exact=True).wait_for()
            page.screenshot(path=str(tmp_path/'sql-console.png'))
            page.locator('#modal-close-top').click()
            page.locator('nav button[data-page=protocolAudit]').click()
            page.get_by_text('SELECT 42 AS browser_answer',exact=False).wait_for()
            page.screenshot(path=str(tmp_path/'sql-audit.png'))
            assert not errors,errors
            browser.close()
    finally:
        server.should_exit=True;thread.join(15);sock.close()
