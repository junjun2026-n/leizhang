"""An isolated remote browser: target HTML never runs on the bastion origin."""
import asyncio
import base64
import contextlib
import hashlib
import json
from urllib.parse import urlsplit, urlunsplit

from fastapi import HTTPException, WebSocket
from playwright.async_api import async_playwright

from .protocol_sessions import serve_protocol


def target_origin(asset):
    host = f'[{asset.host}]' if ':' in asset.host else asset.host
    return f'{asset.http_scheme}://{host}:{asset.port}'


def same_origin(url, origin):
    a, b = urlsplit(url), urlsplit(origin)
    def port(p):
        return p.port or (443 if p.scheme == 'https' else 80)
    return (a.scheme, a.hostname, port(a)) == (b.scheme, b.hostname, port(b)) and not a.username and not a.password


def audit_url(url):
    p = urlsplit(url)
    return urlunsplit((p.scheme, p.netloc, p.path, '[redacted]' if p.query else '', ''))


async def http_handler(live):
    a, settings = live.asset, live.app.state.settings
    origin = target_origin(a)
    browser = context = None
    tasks = []
    failed = asyncio.Event()
    async with async_playwright() as pw:
        try:
            browser = await pw.chromium.launch(headless=True, channel=settings.browser_channel or None)
            context = await browser.new_context(viewport={'width': 1280, 'height': 720},
                ignore_https_errors=not a.tls_verify, accept_downloads=False,
                service_workers='block', http_credentials={'username': a.username,
                'password': live.app.state.vault.decrypt(a.credential), 'origin': origin})
            async def route_request(route):
                request = route.request
                if not same_origin(request.url, origin) or request.resource_type in ('websocket',):
                    await route.abort()
                    return
                try:
                    await live.check()
                    await live.audit('http_request', {'method': request.method, 'url': audit_url(request.url)})
                    await route.continue_()
                except BaseException:
                    failed.set()
                    with contextlib.suppress(Exception):
                        await route.abort()
                    raise
            await context.route('**/*', route_request)
            # WebSocket traffic cannot be inspected by the HTTP audit adapter.
            await context.route_web_socket('**/*', lambda route: route.close())
            page = await context.new_page()
            async def response_received(response):
                try:
                    await live.audit('http_response', {'url': audit_url(response.url), 'status': response.status},
                                     success=response.status < 400)
                except Exception:
                    failed.set()
            page.on('response', response_received)
            context.on('page', lambda popup: asyncio.create_task(popup.close()) if popup != page else None)
            page.on('download', lambda download: asyncio.create_task(download.cancel()))
            await page.goto(origin + a.http_path, wait_until='domcontentloaded', timeout=20000)
            await live.ws.send_json({'type': 'ready', 'message': 'HTTP 远程浏览器已连接，仅允许访问当前资源。'})

            async def frames():
                previous = None
                while True:
                    if failed.is_set():
                        raise HTTPException(503, 'HTTP 审计不可用，会话已关闭')
                    data = await page.screenshot(type='jpeg', quality=55, timeout=10000)
                    digest = hashlib.sha256(data).digest()
                    if digest != previous:
                        message = dict(type='frame', data=base64.b64encode(data).decode(), width=1280, height=720,
                                       url=audit_url(page.url))
                        await live.record(json.dumps(message))
                        await live.ws.send_json(message)
                        previous = digest
                    await asyncio.sleep(1)

            async def inputs():
                while True:
                    m = await live.ws.receive_json()
                    if not isinstance(m, dict):
                        raise ValueError('Invalid browser input')
                    await live.check()
                    live.touch()
                    kind = m.get('type')
                    if kind == 'click':
                        x, y = float(m.get('x', -1)), float(m.get('y', -1))
                        if not (0 <= x < 1280 and 0 <= y < 720):
                            raise ValueError('Invalid coordinates')
                        await page.mouse.click(x, y)
                    elif kind == 'text':
                        text = m.get('text')
                        if not isinstance(text, str) or len(text) > 4000:
                            raise ValueError('Invalid text')
                        await page.keyboard.insert_text(text)
                    elif kind == 'key' and m.get('key') in ('Enter', 'Tab', 'Backspace', 'Delete', 'Escape', 'ArrowUp', 'ArrowDown', 'ArrowLeft', 'ArrowRight', 'Home', 'End', 'PageUp', 'PageDown'):
                        await page.keyboard.press(m['key'])
                    elif kind == 'wheel':
                        await page.mouse.wheel(0, max(-1000, min(1000, float(m.get('delta', 0)))))
                    elif kind == 'navigate':
                        path = m.get('path', '')
                        if not isinstance(path, str) or len(path) > 2000 or not path.startswith('/') or path.startswith('//') or not same_origin(origin + path, origin):
                            raise ValueError('Invalid path')
                        await page.goto(origin + path, wait_until='domcontentloaded', timeout=20000)
                    else:
                        raise ValueError('Unsupported browser input')
            tasks = [asyncio.create_task(frames()), asyncio.create_task(inputs())]
            done, _ = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
            for task in done:
                task.result()
        finally:
            for task in tasks:
                task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
            if context:
                with contextlib.suppress(Exception):
                    await context.close()
            if browser:
                await browser.close()


async def http_socket(ws: WebSocket, session_id: str):
    await serve_protocol(ws, session_id, ('http',), http_handler)
