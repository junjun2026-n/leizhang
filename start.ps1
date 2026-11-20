# ============================================================
# 文件名称：start.ps1
# 生成日期：2026-10-20
# 修改日期：2026-11-20
# 版本信息：v0.261115
# 作    者：JUN
# 备    注：本程序由AI辅助完成。
#           文件功能：执行 start 对应的启动、构建或运维任务。
#           文件用途：供堡垒机的 leizhang/start.ps1 模块使用。
#           注意事项：运行前检查依赖与配置；涉及数据或服务变更时先备份并验证。
# ============================================================
param([string]$BindAddress='0.0.0.0',[int]$Port=8200)
$ErrorActionPreference='Stop'
Set-Location -LiteralPath $PSScriptRoot
$python=Join-Path $PSScriptRoot '.venv/Scripts/python.exe'
if(-not (Test-Path -LiteralPath $python)){throw 'Create the project virtual environment and install requirements.lock first. See README.md.'}
if(-not (Test-Path -LiteralPath (Join-Path $PSScriptRoot '.env'))){throw 'Run python -m jump_ssh.cli init-config and configure PostgreSQL or MySQL first.'}
$localDatabase = & $python -c "from jump_ssh.config import Settings; from sqlalchemy.engine import make_url; u=make_url(Settings().database_url); print('yes' if u.host in ('127.0.0.1','localhost') and u.port==55432 and u.database=='jump_ssh' else 'no')"
if($LASTEXITCODE -ne 0){throw 'Invalid database configuration'}
if(($localDatabase -eq 'yes') -and (Test-Path -LiteralPath (Join-Path $PSScriptRoot 'runtime/postgres-local.json'))){
    & $python -m jump_ssh.local start
    if($LASTEXITCODE -ne 0){throw 'Local PostgreSQL failed to start'}
    & $python -m jump_ssh.local migrate
}else{
    # External databases must be migrated with a separate migration account beforehand.
    & $python -c "from jump_ssh.config import Settings; from jump_ssh.db import storage_engine; from jump_ssh.models import PlatformSetting; from sqlalchemy import select; e=storage_engine(Settings().database_url); c=e.connect(); c.execute(select(PlatformSetting.key).limit(1)); c.close(); e.dispose()"
}
if($LASTEXITCODE -ne 0){throw 'Database migration failed.'}
& $python -m uvicorn jump_ssh.main:create_app --factory --host $BindAddress --port $Port --workers 1 --no-proxy-headers --ws-max-size 32768
