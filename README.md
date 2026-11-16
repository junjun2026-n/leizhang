# JUMP SSH 堡垒机

???**v0.261115** ? ???????? ? [GPLv3 ??](LICENSE) ? [????](COPYRIGHT.md)

独立的 Python SSH 堡垒机项目，数据库使用 **PostgreSQL（PG）**。源码、静态资源、部署配置、测试和文档均位于本目录，不依赖 QIONGHAI 或 TaaS 代码。默认端口 `8200`。

详细操作步骤见[堡垒机使用手册](docs/user-guide.zh-CN.md)，包括登录与 MFA、用户和角色、资源账号授权、审批消息、多协议连接、命令黑／白名单、录像审计、系统配置及常见问题。

**当前版本为 v0.261115，可验证的 SSH 堡垒机基础版本，并非完整商业堡垒机或已经通过生产验收的产品。** 已实现功能、未实现能力及生产部署边界见 [功能与验收范围](docs/features.zh-CN.md)。

## 已实现

- 原生 SSH 客户端交互入口（默认 `2222`）：网页生成一次性票据，复用资源授权、审批、命令策略和加密录像，见[使用说明](docs/native-ssh.zh-CN.md)。
- PostgreSQL / MySQL / MariaDB 网页 SQL 控制台与加密 SQL 审计；TELNET 终端、RDP/VNC 网关接入、HTTP 隔离浏览器。配置、依赖和支持边界见[多协议使用说明](docs/protocols.zh-CN.md)。

- 中文网页工作台、运维总览、资产列表、用户及角色管理。
- 可编辑自定义角色，按角色及用户配置 SSH/TELNET 命令黑／白名单、受控逐条执行与命令审计，见[角色与命令规则](docs/roles-commands.zh-CN.md)。
- 按角色逐项分配平台功能及操作权限，菜单、HTTP 接口和连接入口同步校验，见[平台权限管理](docs/permissions.zh-CN.md)。
- Argon2id 密码、TOTP MFA、防验证码重放、数据库登录限流、会话注销与密码修改。
- 管理员 / 运维人员 / 审计员角色；同一资源多个系统账号，按平台用户和具体系统账号独立授权、审批及到期检查。操作步骤见[资源账号与授权](docs/resource-authorization.zh-CN.md)。
- 密码 / 私钥认证，Fernet 加密存储凭据；支持仅使用账号密码连接，也可按资产开启 SSH 主机公钥校验。
- 访问申请、独立管理员审批、审批到期及资产授权到期检查。
- 浏览器 SSH 交互终端、并发限制、空闲及总时长限制、管理员强制终止。
- 加密输出录像、按原始时间回放、审计读取留痕、操作日志。
- PostgreSQL 迁移、审计表禁止更新 / 删除 / 清空的触发器。
- Docker Compose、独立 PostgreSQL、独立迁移与运行数据库角色、Nginx TLS 示例、Windows / Linux 启动脚本。
- 终端资源随项目本地提供，无浏览器 CDN 依赖。

## Docker 独立部署

需要 Docker Engine / Docker Desktop 与 Compose v2；生产建议使用 Linux 主机。所有命令均在本目录执行。

```powershell
python -m venv .venv
.venv/Scripts/python.exe -m pip install -r requirements.lock
.venv/Scripts/python.exe -m jump_ssh.cli init-config --origin https://jump.example.com
docker compose up -d --build
docker compose exec app python -m jump_ssh.cli create-admin admin
```

本工作区已生成 `.env`，再次执行 `init-config` 会拒绝覆盖密钥。请先将其中 `PUBLIC_ORIGIN` 改为实际域名，并在 HTTPS 部署时将 `COOKIE_SECURE` 设置为 `true`。

管理员密码通过隐藏输入设置，**没有默认账号密码**。MFA 默认关闭，首次登录只需账号和密码。管理员可在后台“用户管理”点击“开启 MFA”，绑定身份验证器并验证动态验证码后启用；也可通过“关闭 MFA”恢复仅密码登录。

Compose 创建 `jump_ssh` 数据库及独立卷，数据库不发布宿主机端口。迁移服务持有建表账号，应用仅持有 `jump_runtime` 运行账号；应用禁止修改和删除审计记录。应用只发布 `127.0.0.1:8200`，用 [Nginx 配置](deploy/nginx.conf) 提供 HTTPS / WebSocket。

本地试用可使用 `PUBLIC_ORIGIN=http://127.0.0.1:8200` 与 `COOKIE_SECURE=false`；此组合仅供本机验证，不能作为生产配置。使用实际访问域名必须与 `PUBLIC_ORIGIN` 完全一致。

## 使用已有 PostgreSQL

请让数据库管理员创建**独立数据库、迁移账号与运行账号**，并限制网络访问。项目不会自动使用 QIONGHAI / TaaS 的数据库凭据。

1. 修改 `.env` 的 `DATABASE_URL` 为 PostgreSQL 专用连接串。
2. 如迁移与运行账号分离，设置 `MIGRATION_DATABASE_URL`，迁移成功后从运行环境移除该变量及其密码。
3. 执行 `.venv/Scripts/python.exe -m jump_ssh.cli migrate`。
4. 执行 `.venv/Scripts/python.exe -m jump_ssh.cli create-admin admin`。
5. Windows 执行 `./start.ps1`；Linux 执行 `sh start.sh`。以权限受限的运行账号启动时，先用迁移账号完成迁移，再直接使用下方 Uvicorn 命令启动，避免将迁移账号保留在服务环境。

```sh
.venv/bin/python -m uvicorn jump_ssh.main:create_app --factory --host 127.0.0.1 --port 8200 --workers 1 --no-proxy-headers --ws-max-size 32768
```

当前工作区已于 2026-10-23 将堡垒机数据迁移到 `192.168.17.127:5432/jump`，应用使用 `jumpuser` 连接。原本地 PostgreSQL 17.10 已停止，`runtime/pgdata` 保留用于回退。应用监听 `0.0.0.0:8200`，当前 HTTP 环境不代表已完成生产部署验收。详见[迁移记录](docs/database-migration-2026-10-23.zh-CN.md)。

初始管理员账号和密码保存在受权限保护且忽略提交的 `runtime/initial-admin.txt`。首次登录不需要 MFA；文件内旧的 TOTP 信息不代表已启用 MFA。需要时请在后台重新绑定并开启。修改初始密码后将凭据安全保存并删除该文件。

以后可执行 `./start.ps1`，脚本读取 `.env`；当前远端配置下只检查远端数据库并启动应用，不会启动本地 PostgreSQL。远端数据库升级请使用针对远端的 `MIGRATION_DATABASE_URL` 执行 `python -m jump_ssh.cli migrate`，不要使用仅针对旧本地库的 `jump_ssh.local migrate`。旧本地 PostgreSQL 安装包来源、版本和 SHA-256 记录在 `runtime/postgresql-package.json`。

## 服务监听与局域网访问

Windows `start.ps1` 和 Linux `start.sh` 默认监听 `0.0.0.0:8200`。浏览器应使用服务器实际 IP 或域名访问，不能将 `0.0.0.0` 作为访问地址。

主访问源由 `.env` 的 `PUBLIC_ORIGIN` 配置；其他明确允许的访问源可在 `ALLOWED_ORIGINS` 中以逗号分隔，均需包含协议和端口。HTTP Host、变更请求 Origin 及 WebSocket Origin 都受校验，不支持通配符。修改后重启应用。

当前已配置本机各网卡地址及 localhost，可使用 WLAN 地址 `http://10.26.6.133:8200`。生产使用 HTTPS 时，应同步将所有允许访问源改为实际 HTTPS 域名。Docker Compose 仍默认只发布宿主回环端口，由 Nginx 对外提供服务。

## 首次运维

1. 管理员创建用户，通过安全渠道交付初始密码。新用户默认无需 MFA，应立即修改密码。需要 MFA 时在“用户管理”中手动绑定并开启，绑定配置有效期为 10 分钟，验证后才生效。
2. 管理员新增资产，填写地址、系统账号和密码 / 私钥。
3. 默认选择密码认证，填写系统账号和密码即可，无需填写公钥。若需核验服务器身份，开启“校验 SSH 主机公钥（可选）”，此时必须提供可信公钥。可从服务器控制台获取 `/etc/ssh/ssh_host_ed25519_key.pub`，或点击“获取主机公钥”并通过控制台核验 SHA256 指纹后使用。升级前已有资产保留公钥校验，可在修改资产时关闭；关闭后不核验服务器身份。
4. 在“资产授权”中授权用户并设置有效期。
5. 运维人员申请访问；由其他管理员审批后连接。管理员本人连接启用审批的资产也需由其他管理员审批。
6. 在“会话与录像”查看状态，审计员或管理员可以查看录像，管理员可以终止活动会话。

`approval_required=false` 可用于经制度允许的无需逐次审批资产，仍需资产授权。停用资产会在下一次会话检查时断开连接。撤权、禁用用户和修改角色也会使已有连接失效。

## 测试

```powershell
.venv/Scripts/python.exe -m pytest tests/test_security.py -q
# 设置专用测试数据库，账号需要 CREATE SCHEMA 权限；测试会创建随机 schema 并清理。
$env:TEST_DATABASE_URL='postgresql+psycopg://test_user:SET_LOCALLY_BEFORE_USE@localhost:5432/jump_ssh_test'
.venv/Scripts/python.exe -m pytest tests -q
```

未设置 `TEST_DATABASE_URL` 时数据库集成测试会跳过。测试覆盖登录与 MFA、权限边界、审批、撤权、凭据加密、SSH 公钥拒绝、真实 SSH 终端交互、加密录像、终止会话等。上游 SSH 测试使用本机临时 SSH 服务，不连接业务资产。

## 目录

```text
JUMP_SSH/
  jump_ssh/        配置、安全、ORM、API、SSH 网关、管理 CLI
  templates/      中文工作台页面
  static/         页面脚本、样式和本地 xterm 资源
  migrations/     Alembic 数据库迁移
  deploy/         Nginx、数据库初始化配置
  tests/          单元与 PostgreSQL / SSH 集成测试
  docs/           功能边界、生产部署与运维文档
  compose.yaml    独立容器部署
  start.ps1       Windows 启动
  start.sh        Linux 启动
  requirements.lock  已验证依赖版本
```

项目内 `.env`、虚拟环境、运行日志及测试连接文件均忽略提交。**MASTER_KEY 丢失会导致所有凭据、MFA 秘钥和录像无法解密**；密钥必须与数据库分开备份。详见 [生产部署与运维](docs/operations.zh-CN.md)。


[Log forwarding configuration](docs/LOG_FORWARDING.md)
