param([string]$BindAddress='0.0.0.0',[int]$Port=8200)
$ErrorActionPreference='Stop'
Set-Location -LiteralPath $PSScriptRoot
$python=Join-Path $PSScriptRoot '.venv/Scripts/python.exe'
if(-not (Test-Path -LiteralPath $python)){throw 'Create the project virtual environment and install requirements.lock first. See README.md.'}
if(-not (Test-Path -LiteralPath (Join-Path $PSScriptRoot '.env'))){throw 'Run python -m jump_ssh.cli init-config and configure PostgreSQL first.'}
$localDatabase = & $python -c "from jump_ssh.config import Settings; from sqlalchemy.engine import make_url; u=make_url(Settings().database_url); print('yes' if u.host in ('127.0.0.1','localhost') and u.port==55432 and u.database=='jump_ssh' else 'no')"
if($LASTEXITCODE -ne 0){throw 'Invalid database configuration'}
if(($localDatabase -eq 'yes') -and (Test-Path -LiteralPath (Join-Path $PSScriptRoot 'runtime/postgres-local.json'))){
    & $python -m jump_ssh.local start
    if($LASTEXITCODE -ne 0){throw 'Local PostgreSQL failed to start'}
    & $python -m jump_ssh.local migrate
}else{
    # External databases must be migrated with a separate migration account beforehand.
    & $python -c "from jump_ssh.config import Settings; from sqlalchemy import create_engine,text; e=create_engine(Settings().database_url,connect_args={'connect_timeout':5}); c=e.connect(); c.execute(text('SELECT key FROM platform_settings LIMIT 1')); c.close(); e.dispose()"
}
if($LASTEXITCODE -ne 0){throw 'Database migration failed.'}
& $python -m uvicorn jump_ssh.main:create_app --factory --host $BindAddress --port $Port --workers 1 --no-proxy-headers --ws-max-size 32768
