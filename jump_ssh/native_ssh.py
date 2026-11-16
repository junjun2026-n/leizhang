"""Interactive native SSH transport for the existing audited terminal gateway."""
import asyncio
import json
import os
from urllib.parse import urlsplit

import asyncssh
from fastapi import APIRouter, Depends, HTTPException, Request, WebSocketDisconnect

from .api import ConnectInput, create_session
from .db import transaction
from .models import Asset
from .permissions import require
from .ssh import ssh_socket, validate_access

router = APIRouter(prefix='/api')


@router.post('/native-ssh/sessions', status_code=201)
def ticket(body: ConnectInput, request: Request, user=Depends(require('sessions.connect'))):
    if not request.app.state.settings.ssh_proxy_port:
        raise HTTPException(409, '原生 SSH 入口未启用')
    with transaction(request.app.state.factory) as db:
        asset = db.get(Asset, body.asset_id)
        if not asset or asset.protocol != 'ssh':
            raise HTTPException(400, '原生 SSH 仅支持 SSH 资源')
    session = create_session(body, request, user)
    password = request.app.state.vault.encrypt(json.dumps({
        'id': session['id'], 'ticket': session['ticket'],
        'cookie': request.cookies.get('jump_session', '')}))
    return {'username': session['id'], 'password': password, 'expires_in': 30,
            'host_key_fingerprint': getattr(request.app.state, 'ssh_proxy_fingerprint', ''),
            'port': request.app.state.settings.ssh_proxy_port}


class NativeServer(asyncssh.SSHServer):
    def __init__(self, app):
        self.app, self.credentials, self.used = app, None, False
        self.attempts = 0

    def connection_made(self, conn):
        self.connection = conn

    def begin_auth(self, username):
        return True

    def password_auth_supported(self):
        return True

    async def validate_password(self, username, password):
        self.credentials = None
        self.attempts += 1
        if self.attempts > 3:
            self.connection.close()
            return False
        try:
            if len(password) > 4096:
                return False
            payload = json.loads(self.app.state.vault.cipher.decrypt(password.encode(), ttl=30))
            if payload['id'] != username:
                return False
            await asyncio.to_thread(validate_access, self.app, username, payload['cookie'],
                                    payload['ticket'], ('ssh',), False)
            self.credentials = payload
            return True
        except Exception:
            return False


class TerminalTransport:
    def __init__(self, app, process, credentials):
        self.app, self.process, self.credentials = app, process, credentials
        origin = app.state.settings.origin
        self.headers = {'origin': origin, 'host': urlsplit(origin).netloc}
        self.cookies = {'jump_session': credentials['cookie']}

    async def accept(self):
        pass

    async def receive_json(self):
        return {'ticket': self.credentials['ticket']}

    async def receive_text(self):
        while True:
            try:
                text = await self.process.stdin.read(8192)
            except asyncssh.TerminalSizeChanged as change:
                return json.dumps({'type': 'resize', 'cols': max(20, min(400, change.width)),
                                   'rows': max(5, min(150, change.height))})
            if not text:
                raise WebSocketDisconnect()
            return json.dumps({'type': 'input', 'data': text})

    async def send_json(self, message):
        if message['type'] == 'output':
            self.process.stdout.write(message['data'])
            await self.process.stdout.drain()
        elif message.get('message'):
            self.process.stdout.write('\r\n[' + message['message'] + ']\r\n')

    async def close(self, code=None):
        self.process.exit(0)


async def start_listener(app):
    settings = app.state.settings
    if not settings.ssh_proxy_port:
        return None
    key_path = settings.ssh_proxy_key
    key_path.parent.mkdir(parents=True, exist_ok=True)
    if not key_path.exists():
        key = asyncssh.generate_private_key('ssh-ed25519')
        with os.fdopen(os.open(key_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), 'wb') as stream:
            stream.write(key.export_private_key())

    async def handle(process):
        owner = process.get_extra_info('connection').get_owner()
        if owner.used or not owner.credentials or process.command or process.subsystem:
            process.stderr.write('仅支持单个交互终端；不支持 exec、SCP、SFTP 或端口转发。\r\n')
            process.exit(1)
            return
        owner.used = True
        await ssh_socket(TerminalTransport(app, process, owner.credentials), owner.credentials['id'])

    app.state.ssh_proxy_fingerprint = asyncssh.read_private_key(str(key_path)).get_fingerprint()
    return await asyncssh.create_server(lambda: NativeServer(app), settings.ssh_proxy_host,
        settings.ssh_proxy_port, server_host_keys=[str(key_path)], process_factory=handle,
        encoding='utf-8', errors='replace', line_editor=False, login_timeout=20,
        agent_forwarding=False, x11_forwarding=False, config=None)
