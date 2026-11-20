#!/usr/bin/env sh
# ============================================================
# 文件名称：init-runtime.sh
# 生成日期：2026-10-20
# 修改日期：2026-11-20
# 版本信息：v0.261115
# 作    者：JUN
# 备    注：本程序由AI辅助完成。
#           文件功能：执行 init-runtime 对应的启动、构建或运维任务。
#           文件用途：供堡垒机的 leizhang/deploy/init-runtime.sh 模块使用。
#           注意事项：运行前检查依赖与配置；涉及数据或服务变更时先备份并验证。
# ============================================================
set -eu
psql --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" -v ON_ERROR_STOP=1 -v runtime_password="$JUMP_RUNTIME_PASSWORD" <<'SQL'
CREATE ROLE jump_runtime LOGIN PASSWORD :'runtime_password' NOSUPERUSER NOCREATEDB NOCREATEROLE;
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
GRANT USAGE ON SCHEMA public TO jump_runtime;
SQL
