"""Manage the optional project-local PostgreSQL instance on Windows."""
import argparse
import json
import os
import secrets
import subprocess
import sys
from pathlib import Path
from urllib.parse import quote

import psycopg
from psycopg import sql
from dotenv import dotenv_values, set_key

ROOT = Path(__file__).resolve().parents[1]
RUNTIME = ROOT / 'runtime'
PG_BIN = RUNTIME / 'pgsql' / 'bin'
PG_DATA = RUNTIME / 'pgdata'
CONFIG = RUNTIME / 'postgres-local.json'


def secure(path):
    if os.name == 'nt':
        who = subprocess.check_output(['whoami'], text=True).strip()
        subprocess.run(['icacls', str(path), '/inheritance:r', '/grant:r', who + ':(F)', 'SYSTEM:(F)'],
                       check=True, capture_output=True)
    else:
        path.chmod(0o600)


def load():
    if not CONFIG.is_file(): raise RuntimeError('尚未初始化项目本地 PostgreSQL')
    return json.loads(CONFIG.read_text(encoding='utf-8'))


def start():
    if not (PG_BIN / 'pg_ctl.exe').is_file(): raise RuntimeError('runtime/pgsql 中未安装 PostgreSQL 二进制文件')
    status = subprocess.run([str(PG_BIN/'pg_ctl.exe'), 'status', '-D', str(PG_DATA)], capture_output=True)
    if status.returncode == 0:
        print('Project-local PostgreSQL is already running')
        return
    subprocess.run([str(PG_BIN/'pg_ctl.exe'), 'start', '-D', str(PG_DATA),
                    '-l', str(RUNTIME/'postgres.log'), '-w', '-t', '30'], check=True)


def initialize():
    RUNTIME.mkdir(exist_ok=True)
    if CONFIG.exists():
        start()
        return
    if PG_DATA.exists(): raise RuntimeError('pgdata 已存在但无本地配置，拒绝覆盖')
    values = dotenv_values(ROOT/'.env')
    if not values.get('DATABASE_URL', '').startswith('postgresql+psycopg://jump_ssh:') or '@127.0.0.1:5432/jump_ssh' not in values['DATABASE_URL']:
        raise RuntimeError('检测到非默认数据库配置，拒绝覆盖；请配置或启动原有数据库')
    config = {'port':55432, 'bootstrap_password':secrets.token_urlsafe(32),
              'migration_password':secrets.token_urlsafe(32),
              'runtime_password':secrets.token_urlsafe(32)}
    pwfile = RUNTIME/'initdb-password.tmp'
    with pwfile.open('x',encoding='utf-8') as stream: stream.write(config['bootstrap_password'])
    secure(pwfile)
    try:
        subprocess.run([str(PG_BIN/'initdb.exe'), '-D', str(PG_DATA), '-U', 'jump_bootstrap',
                        '--auth=scram-sha-256', '--pwfile='+str(pwfile), '--encoding=UTF8', '--locale=C'], check=True)
    finally:
        pwfile.unlink(missing_ok=True)
    with (PG_DATA/'postgresql.conf').open('a',encoding='utf-8') as stream:
        stream.write("\nlisten_addresses = '127.0.0.1'\nport = 55432\npassword_encryption = 'scram-sha-256'\n")
    CONFIG.write_text(json.dumps(config,indent=2)+'\n',encoding='utf-8')
    secure(CONFIG)
    start()
    with psycopg.connect(host='127.0.0.1',port=config['port'],dbname='postgres',user='jump_bootstrap',
                         password=config['bootstrap_password'],autocommit=True) as conn:
        for role, password in [('jump_migrate', config['migration_password']),('jump_runtime', config['runtime_password'])]:
            conn.execute(sql.SQL('CREATE ROLE {} LOGIN PASSWORD {} NOSUPERUSER NOCREATEDB NOCREATEROLE').format(
                sql.Identifier(role),sql.Literal(password)))
        conn.execute('CREATE DATABASE jump_ssh OWNER jump_migrate')
        conn.execute('REVOKE ALL ON DATABASE jump_ssh FROM PUBLIC')
        conn.execute('GRANT CONNECT ON DATABASE jump_ssh TO jump_migrate, jump_runtime')
    with psycopg.connect(host='127.0.0.1',port=config['port'],dbname='jump_ssh',user='jump_migrate',
                         password=config['migration_password'],autocommit=True) as conn:
        conn.execute('REVOKE CREATE ON SCHEMA public FROM PUBLIC')
    set_key(str(ROOT/'.env'), 'DATABASE_URL', connection_url(config, 'jump_runtime'))
    print('Independent local database initialized on 127.0.0.1:55432')


def connection_url(config, role):
    password = config['migration_password'] if role == 'jump_migrate' else config['runtime_password']
    return f"postgresql+psycopg://{role}:{quote(password,safe='')}@127.0.0.1:{config['port']}/jump_ssh"


def migrate():
    config = load()
    env = dict(os.environ, MIGRATION_DATABASE_URL=connection_url(config, 'jump_migrate'))
    subprocess.run([sys.executable,'-m','jump_ssh.cli','migrate'], cwd=ROOT, env=env, check=True)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('command',choices=['init','start','migrate','stop'])
    args = parser.parse_args()
    if args.command=='init': initialize()
    elif args.command=='start': start()
    elif args.command=='migrate': migrate()
    else:
        subprocess.run([str(PG_BIN/'pg_ctl.exe'),'stop','-D',str(PG_DATA),'-m','fast','-w'],check=True)


if __name__=='__main__': main()
