import os
from pathlib import Path
from urllib.parse import urlsplit

from cryptography.fernet import Fernet
from dotenv import load_dotenv

ROOT = Path(__file__).resolve().parents[1]
load_dotenv(ROOT / '.env', override=False)


class Settings:
    def __init__(self):
        self.database_url = os.environ.get('DATABASE_URL', '')
        self.master_key = os.environ.get('MASTER_KEY', '')
        self.origin = os.environ.get('PUBLIC_ORIGIN', 'https://localhost').rstrip('/')
        self.allowed_origins = {self.origin} | {value.strip().rstrip('/') for value in
            os.environ.get('ALLOWED_ORIGINS', '').split(',') if value.strip()}
        self.secure = os.environ.get('COOKIE_SECURE', 'true').lower() == 'true'
        self.session_minutes = int(os.environ.get('SESSION_MINUTES', '480'))
        self.ssh_seconds = int(os.environ.get('SSH_SESSION_SECONDS', '3600'))
        self.idle_seconds = int(os.environ.get('SSH_IDLE_SECONDS', '900'))
        self.max_recording = int(os.environ.get('MAX_RECORDING_BYTES', '20971520'))
        self.guacd_host = os.environ.get('GUACD_HOST', '127.0.0.1')
        self.guacd_port = int(os.environ.get('GUACD_PORT', '4822'))
        self.vnc_backend = os.environ.get('VNC_BACKEND', 'native')
        if self.vnc_backend not in ('native','guacd'):
            raise ValueError('VNC_BACKEND 必须为 native 或 guacd')
        self.browser_channel = os.environ.get('HTTP_BROWSER_CHANNEL', 'msedge' if os.name == 'nt' else '')
        self.sql_timeout = 30
        self.sql_rows = 500
        self.ssh_proxy_port = int(os.environ.get('SSH_PROXY_PORT', '2222'))
        self.ssh_proxy_host = os.environ.get('SSH_PROXY_HOST', '0.0.0.0')
        self.ssh_proxy_key = Path(os.environ.get('SSH_PROXY_KEY', str(ROOT/'runtime'/'ssh-proxy-key')))
        if not 0 <= self.ssh_proxy_port <= 65535:
            raise ValueError('SSH_PROXY_PORT 必须为 0–65535；0 表示关闭')
        if not self.database_url.startswith('postgresql+psycopg://'):
            raise ValueError('DATABASE_URL 必须使用独立 PostgreSQL 数据库（postgresql+psycopg://）')
        Fernet(self.master_key.encode())
        parsed = urlsplit(self.origin)
        if parsed.scheme not in ('http', 'https') or not parsed.netloc or parsed.path:
            raise ValueError('PUBLIC_ORIGIN 必须为完整且不含路径的访问源')
        if self.secure and parsed.scheme != 'https':
            raise ValueError('生产安全 Cookie 必须使用 HTTPS')
        for origin in self.allowed_origins:
            item = urlsplit(origin)
            if (item.scheme not in ('http', 'https') or not item.netloc or item.path or
                    item.query or item.fragment or item.username or '*' in item.netloc):
                raise ValueError('ALLOWED_ORIGINS 必须为明确的 HTTP/HTTPS 访问源，不支持通配符')
            if self.secure and item.scheme != 'https':
                raise ValueError('生产安全 Cookie 必须为所有访问源使用 HTTPS')
        if min(self.session_minutes, self.ssh_seconds, self.idle_seconds, self.max_recording) <= 0:
            raise ValueError('超时及录制限制必须为正数')
