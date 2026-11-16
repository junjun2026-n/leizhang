import argparse
import getpass
import secrets
from pathlib import Path

from cryptography.fernet import Fernet


def main():
    parser = argparse.ArgumentParser(description='JUMP SSH 管理工具')
    sub = parser.add_subparsers(dest='command', required=True)
    init = sub.add_parser('init-config')
    init.add_argument('--origin', default='http://127.0.0.1:8200')
    init.add_argument('--database-host', default='127.0.0.1')
    admin = sub.add_parser('create-admin')
    admin.add_argument('username')
    reset = sub.add_parser('reset-mfa')
    reset.add_argument('username')
    sub.add_parser('migrate')
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    if args.command == 'init-config':
        target = root/'.env'
        if target.exists(): parser.error('.env 已存在，拒绝覆盖密钥')
        password = secrets.token_urlsafe(32)
        config = (f'DATABASE_URL=postgresql+psycopg://jump_ssh:SET_LOCALLY_BEFORE_USE@{args.database_host}:5432/jump_ssh\n'
                  f'POSTGRES_PASSWORD={password}\nJUMP_RUNTIME_PASSWORD={secrets.token_urlsafe(32)}\nMASTER_KEY={Fernet.generate_key().decode()}\n'
                  f'PUBLIC_ORIGIN={args.origin}\nCOOKIE_SECURE={str(args.origin.startswith("https://")).lower()}\n'
                  'SESSION_MINUTES=480\nSSH_SESSION_SECONDS=3600\nSSH_IDLE_SECONDS=900\nMAX_RECORDING_BYTES=20971520\n')
        with target.open('x', encoding='utf-8') as stream: stream.write(config)
        try: target.chmod(0o600)
        except OSError: pass
        print('已生成 .env。请限制文件读取权限，并独立备份 MASTER_KEY。未创建数据库。')
        return
    if args.command == 'migrate':
        from alembic import command
        from alembic.config import Config
        config = Config(str(root/'alembic.ini'))
        command.upgrade(config, 'head')
        print('数据库迁移完成')
        return
    from sqlalchemy import select
    from .config import Settings
    from .db import database, transaction
    from .models import Audit, LoginSession, User
    from .security import password_hash
    settings = Settings()
    engine, factory = database(settings.database_url)
    with transaction(factory) as db:
        user = db.scalar(select(User).where(User.username == args.username).with_for_update())
        if args.command == 'create-admin':
            import re
            if not re.fullmatch(r'[A-Za-z0-9_.@-]{3,80}', args.username): parser.error('用户名格式无效')
            if user: parser.error('用户已存在')
            password = getpass.getpass('管理员密码（至少 12 位）: ')
            if password != getpass.getpass('再次输入密码: '): parser.error('两次密码不一致')
            user = User(username=args.username, password_hash=password_hash(password), role='admin', role_id='admin')
            db.add(user)
            db.flush()
            action = 'cli_admin_created'
        else:
            if not user: parser.error('用户不存在')
            user.mfa_secret, user.last_totp_step = None, -1
            user.mfa_enabled, user.mfa_setup_expires_at = False, None
            db.query(LoginSession).filter_by(user_id=user.id).delete()
            action = 'cli_mfa_reset'
        db.add(Audit(actor_id=user.id, action=action, target=user.id, ip='local-cli'))
    engine.dispose()
    print('MFA 默认关闭，首次登录仅需账号和密码。管理员可在后台用户管理中绑定并启用 MFA。')


if __name__ == '__main__': main()
