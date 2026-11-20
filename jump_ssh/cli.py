# ============================================================
# 文件名称：cli.py
# 生成日期：2026-10-20
# 修改日期：2026-11-20
# 版本信息：v0.261115
# 作    者：JUN
# 备    注：本程序由AI辅助完成。
#           文件功能：实现 cli 模块相关功能。
#           文件用途：供堡垒机的 leizhang/jump_ssh/cli.py 模块使用。
#           注意事项：运行前检查依赖与配置；涉及数据或服务变更时先备份并验证。
# ============================================================
import argparse
import getpass
import secrets
import os
from pathlib import Path

from cryptography.fernet import Fernet


def main():
    parser = argparse.ArgumentParser(description='JUMP SSH 管理工具')
    sub = parser.add_subparsers(dest='command', required=True)
    init = sub.add_parser('init-config')
    init.add_argument('--origin', default='http://127.0.0.1:8200')
    init.add_argument('--database-host', default='127.0.0.1')
    init.add_argument('--database-type', choices=['postgresql', 'mysql'], default='postgresql')
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
        driver, port = ('mysql+pymysql', 3306) if args.database_type == 'mysql' else ('postgresql+psycopg', 5432)
        config = (f'DATABASE_URL={driver}://jump_ssh:{password}@{args.database_host}:{port}/jump_ssh\n'
                  f'POSTGRES_PASSWORD={password}\nJUMP_RUNTIME_PASSWORD={secrets.token_urlsafe(32)}\nMASTER_KEY={Fernet.generate_key().decode()}\n'
                  f'PUBLIC_ORIGIN={args.origin}\nCOOKIE_SECURE={str(args.origin.startswith("https://")).lower()}\n'
                  'SESSION_MINUTES=480\nSSH_SESSION_SECONDS=3600\nSSH_IDLE_SECONDS=900\nMAX_RECORDING_BYTES=20971520\n')
        with target.open('x', encoding='utf-8') as stream: stream.write(config)
        try: target.chmod(0o600)
        except OSError: pass
        print('已生成 .env。请限制文件读取权限，并独立备份 MASTER_KEY。未创建数据库。')
        return
    if args.command == 'migrate':
        from .config import Settings
        from sqlalchemy import create_engine, text
        from sqlalchemy.engine import make_url
        settings = Settings()
        migration_url = os.environ.get('MIGRATION_DATABASE_URL') or settings.database_url
        if make_url(migration_url).get_backend_name() in ('mysql', 'mariadb'):
            from .mysql_schema import initialize
            initialize(migration_url)
            print('MySQL 数据库结构初始化完成')
            return
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
