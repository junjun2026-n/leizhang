# 数据库配置与初始化

系统配置 → 数据库配置提供 PostgreSQL（PQ）和 MySQL / MariaDB 两种平台存储，包含数据库地址、端口、库名、用户名、密码和 TLS 配置。此处配置的是堡垒机自身存储，与资产中的 SQL 控制台目标数据库独立。

## 使用 MySQL

支持 MySQL 8.0+ / MariaDB 10.6+，默认端口 3306，字符集 utf8mb4，使用 InnoDB。由数据库管理员创建独立数据库和账号并授权；初始化需要 CREATE、INDEX、REFERENCES、TRIGGER 权限及日常 SELECT、INSERT、UPDATE、DELETE 权限。运行账号应取消 DROP、ALTER、TRIGGER 等管理权限，审计表额外取消 UPDATE、DELETE 权限。触发器阻止修改和删除审计，但不能阻止数据库所有者删除触发器或清空表。

1. 在数据库配置选择 MySQL / MariaDB，填写连接信息。切换类型、地址、端口或用户后须重新填写密码，同一连接密码留空则保留。
2. 点击“测试连接”。目标数据库必须事先存在。
3. 对空库点击“初始化数据库”，建立平台表、内置角色和审计保护触发器，并复制当前操作管理员的登录密码散列。重复初始化保留已有数据。已有非平台表或不兼容版本会拒绝初始化。
4. 点击“保存数据库配置”，再重启堡垒机服务。

MySQL TLS 选择“必须使用”时验证服务器证书与主机名，服务器证书应由运行环境信任的 CA 签发。禁用时连接不加密。PostgreSQL 保留原有 SSL 模式选项。

命令行连接串使用 `mysql+pymysql://USER:SET_LOCALLY_BEFORE_USE@HOST:3306/DB?charset=utf8mb4`，写入本地 `.env` 的 `DATABASE_URL` 后执行 `python -m jump_ssh.cli migrate`。也可通过 `MIGRATION_DATABASE_URL` 为初始化指定独立管理账号。不要提交真实密码文件。

初始化与保存连接均不搬迁原有用户、资产、授权、录像和审计数据。迁移历史数据需单独导出、转换、导入并校验；必须同时保留原 MASTER_KEY，才能解密凭据和录像。现有 PostgreSQL 配置不会因加入 MySQL 支持自动改变。

PostgreSQL 升级继续使用 `python -m jump_ssh.cli migrate`。MySQL 初始化仅接受空库或当前版本的平台库，不会覆盖已有旧版或其它项目的表。
