# content-platform

`content-platform` 是一个使用 Go 标准库 `net/http` 构建的内容平台后端。当前分支交付 M2 Identity：在 M1 的配置、日志、PostgreSQL、可降级 Redis、统一 JSON、健康检查、migration 和优雅关闭基线上，实现注册、登录、JWT access token、可轮换 refresh session、资料读取/修改、账户软删除、用户状态控制和审计。

M2 仍不包含文章、评论、互动、转发、私信或举报业务；Identity 已提供这些后续模块需要的认证主体和最新用户状态边界。

## 技术基线

- Go `1.26.4`
- HTTP：标准库 `net/http` 与 `http.ServeMux`
- 数据库抽象：标准库 `database/sql`
- PostgreSQL driver：`github.com/jackc/pgx/v5 v5.10.0`
- Redis：`github.com/redis/go-redis/v9 v9.21.0`
- Migration：`github.com/pressly/goose/v3 v3.27.1`
- 配置：`github.com/caarlos0/env/v11 v11.4.1`
- JWT：`github.com/golang-jwt/jwt/v5 v5.3.1`
- 密码哈希：`golang.org/x/crypto v0.53.0`
- 输入校验：`github.com/go-playground/validator/v10 v10.30.3`
- 并发辅助（间接版本约束）：`golang.org/x/sync v0.21.0`
- 日志：标准库 `log/slog`

Go module：

```text
github.com/Free-sp1rit/content-platform
```

## 目录边界

项目采用业务模块优先的目录边界。Identity 的 handler、service 和 domain 在同一个业务模块下；JWT、bcrypt、PostgreSQL 等具体适配器留在 infra，跨模块可复用的认证 context 留在 platform：

```text
cmd/server                              HTTP 服务入口
cmd/migrate                             独立 migration 入口
internal/app                            唯一依赖组装、路由和生命周期入口
internal/identity/domain                用户、会话、状态和字段规则
internal/identity/service               Identity 用例、事务编排与最小端口
internal/identity/handler               Identity HTTP DTO、解析和错误映射
internal/platform/authn                 JWT principal context 与认证中间件
internal/platform/httpx                 通用严格 JSON、envelope 和 HTTP 中间件
internal/infra/password                 bcrypt 适配器
internal/infra/token                    HS256 access JWT 与 refresh token codec
internal/infra/postgres/identity        Identity PostgreSQL repository
internal/infra/postgres/migration       goose 适配
internal/system/service                 健康检查业务编排
internal/system/handler                 健康检查 HTTP 适配
internal/testkit                        build-tagged 集成测试工具
migrations                              SQL migration 目录
```

依赖方向为 `identity/handler -> identity/service -> identity/domain`，infra 只实现 service 定义的端口，`internal/app` 是唯一组合根。后续业务按 `article`、`comment`、`messaging`、`moderation` 继续建立模块，不创建全局 `handler/service/repository` 大包。

## 本地配置

复制示例文件：

```bash
cp .env.example .env
```

应用只读取进程环境，不会自动读取 `.env`。在当前 shell 导入：

```bash
set -a
source .env
set +a
```

`.env` 已被 Git 忽略；不要提交真实密码、token、JWT secret 或生产连接信息。配置错误会让进程立即退出，但安全错误信息不会输出数据库 URL、Redis 密码或 JWT secret。

`go run ./cmd/server` 使用完整的 `config.Load`，因此 `DATABASE_URL` 和 `AUTH_JWT_SECRET` 都是必需项。`go run ./cmd/migrate ...` 使用只包含 environment、database 和 log 的 `config.LoadMigration`；migration 命令不需要也不会校验 JWT secret。

### Auth 配置

| 环境变量 | 默认值 | 规则 |
| --- | --- | --- |
| `AUTH_JWT_SECRET` | 无 | Server 必填；至少 32 bytes；原样保留且不 trim。生产必须为当前环境独立生成的 CSPRNG secret，并由 secret manager 注入。 |
| `AUTH_JWT_ISSUER` | `content-platform` | trim 后必须非空。 |
| `AUTH_JWT_AUDIENCE` | `content-platform-api` | trim 后必须非空。 |
| `AUTH_ACCESS_TOKEN_TTL` | `15m` | 至少 1 秒，并且必须是整秒。 |
| `AUTH_REFRESH_TOKEN_TTL` | `720h` | 至少 1 秒、必须是整秒，并且严格大于 access TTL。 |
| `AUTH_BCRYPT_COST` | `12` | 只允许 `10..15`；还有下述跨部署持久化约束。 |

`.env.example` 中的 JWT secret 是满足长度校验的明显 development-only 占位值，只能用于本地开发。生产环境必须为每个环境独立生成足够长度的随机字节，存入受控 secret manager；不要复制示例值、跨环境复用 secret，或依赖人工可记忆短语。由于 secret 不 trim，前导/尾随空白也会成为签名 key 的真实字节。

配置加载会 trim `APP_ENV`、HTTP 地址、数据库 URL、Redis 地址、JWT issuer 和 JWT audience；日志级别与格式还会转为小写。`REDIS_PASSWORD` 与 `AUTH_JWT_SECRET` 始终原样保留。

数据库连接池规则：

- `DATABASE_MAX_OPEN_CONNS` 必须大于零；Go 的 `database/sql` 会把零解释为不限制连接数，因此应用拒绝零；
- `DATABASE_MAX_IDLE_CONNS` 可以为零，表示不保留空闲连接，但不能为负数或超过最大打开连接数。

不要记录完整 `Config`，也不要单独记录数据库 URL、Redis 密码或 JWT secret。配置类型为 `slog` 提供了脱敏表示作为误用防护，但这不替代字段级日志设计和代码审查。

### bcrypt cost 生命周期

`AUTH_BCRYPT_COST` 只能在 `users` 表为空、创建首个用户之前从 `10..15` 中选择。首个用户创建后，该值就是持久化兼容性契约：

- 同一环境所有实例必须使用完全相同的 cost；
- 普通 rolling deploy、扩缩容和回滚均不得改变 cost；
- bcrypt 不能在没有明文密码时离线提高已有 hash 的 cost；
- 未来提高 cost 必须单独设计受控密码重置或 credential-upgrade 流程；M2 不支持 rehash。

首次选择 cost，或在尚无用户时重新选择 cost，必须先停止/隔离所有可写实例和注册 writer，在 authoritative writer 上确认 `users` 仍为空，并保持停写直到全部实例以同一新 cost 启动后再开放注册。否则检查为 0 后仍可能有旧实例写入旧 cost，形成 TOCTOU。保持原 cost 的普通部署只需执行兼容性检查，不需要因此停写；任何实际 cost 变更都不能采用 rolling deploy。

运行时若 `bcrypt.Cost` 成功解析出 `10..15`：cost 与实例配置不同时，adapter 执行当前配置 cost 的 dummy workload 后按普通凭据不匹配失败；cost 相同时则遵循 `CompareHashAndPassword` 的比较结果，包括 x/crypto parser 接受的非标准 minor。范围外 cost，或被 `bcrypt.Cost`/`CompareHashAndPassword` 实际作为 malformed 拒绝的结构、salt/checksum，会在 dummy workload 后返回内部错误。这些都不是迁移机制。部署前 SQL 是更严格的持久化门禁，只允许 `2a/2b/2y` 和精确的长度/alphabet；其他 prefix 或格式必须阻断部署并调查，不能依赖运行时解析器替代该检查。

### bcrypt 部署前阻断检查

每次部署、扩缩容或回滚前，都必须通过受控 libpq service 连接目标环境的 authoritative writer，并导入本次部署的 `AUTH_BCRYPT_COST`。不要把应用使用的、可能携带密码的 `DATABASE_URL` 导入运维 shell 或放进 `psql` argv。`PGSERVICEFILE` 只能包含 host、port、dbname、user、SSL mode/root certificate 和 writable-session selection 等非秘密 authoritative-writer 元数据，明确不能包含 `password` 或 `passfile`；`PGPASSFILE` 必须由 secret manager 挂载或供应，不能在 shell history 中构造、不能打印，且权限必须精确为 `0600`。两份文件必须描述同一目标，并与应用单独管理的 `DATABASE_URL` 指向同一个 authoritative writer；只读/延迟副本、其他环境或空错库上的“0 条不兼容”不能证明真实用户数据兼容。

例如，由配置管理部署的 `/run/content-platform/postgresql/pg_service.conf` 只包含以下类型的非秘密数据，不包含 `password`：

```ini
[content-platform-authoritative-writer]
host=writer.example.internal
port=5432
dbname=content_platform
user=content_platform_writer
sslmode=verify-full
sslrootcert=/run/content-platform/postgresql/authoritative-writer-ca.pem
target_session_attrs=read-write
```

secret manager 供应的 `PGPASSFILE` 条目必须匹配这里的 host、port、dbname 和 user；文档、命令输出与 shell history 均不得展示或构造其 password 字段。下面的整个 workflow 在 subshell 中运行，退出后不会把 authoritative-writer 连接环境留在操作员 shell。

以下 Bash 脚本只输出 `incompatible_password_hashes` 计数，不读取或输出原始 hash。它会把 NULL、未知/非法 bcrypt prefix 或 version、非 60-byte hash、位置 7 不是 `$`、后 53 字符不属于 bcrypt Base64 alphabet，以及 cost 不一致全部计为不兼容；`2a`、`2b`、`2y` 是唯一允许的版本，`2x` 和其他版本都会被拒绝。任何 SQL/psql 失败、非数字输出或非零计数都阻止部署：

```bash
(
case "$-" in
  *x*) echo 'shell xtrace must be disabled before this controlled psql workflow' >&2; exit 1 ;;
esac
for variable in \
  DATABASE_URL PGPASSWORD PGHOST PGHOSTADDR PGPORT PGDATABASE PGUSER \
  PGSSLMODE PGOPTIONS PGSERVICE PGSERVICEFILE PGPASSFILE \
  PGSSLROOTCERT PGSSLCERT PGSSLKEY PGSSLCRL PGSSLCRLDIR PGSSLSNI \
  PGCHANNELBINDING PGREQUIREAUTH PGTARGETSESSIONATTRS PGLOADBALANCEHOSTS
do
  if [[ -v $variable ]]; then
    printf 'unset %s before running this controlled psql workflow\n' "$variable" >&2
    exit 1
  fi
done

PGSERVICE=content-platform-authoritative-writer
PGSERVICEFILE=/run/content-platform/postgresql/pg_service.conf
PGPASSFILE=/run/secrets/content-platform-writer.pgpass
export PGSERVICE PGSERVICEFILE PGPASSFILE

[[ -f "$PGSERVICEFILE" && -r "$PGSERVICEFILE" ]] || {
  echo 'controlled PGSERVICEFILE must be a readable regular file' >&2
  exit 1
}
[[ -f "$PGPASSFILE" && -r "$PGPASSFILE" ]] || {
  echo 'secret-manager PGPASSFILE must be a readable regular file' >&2
  exit 1
}
pgpass_mode="$(stat -Lc '%a' -- "$PGPASSFILE")" || {
  echo 'cannot inspect PGPASSFILE mode' >&2
  exit 1
}
[[ "$pgpass_mode" == 600 ]] || {
  echo 'PGPASSFILE must have mode 0600' >&2
  exit 1
}

: "${AUTH_BCRYPT_COST:?AUTH_BCRYPT_COST is required}"
case "$AUTH_BCRYPT_COST" in
  10|11|12|13|14|15) ;;
  *) echo 'AUTH_BCRYPT_COST must be between 10 and 15' >&2; exit 1 ;;
esac
incompatible_password_hashes="$(
  psql --no-psqlrc --no-password \
    --set=ON_ERROR_STOP=1 --set=bcrypt_cost="$AUTH_BCRYPT_COST" \
    --quiet --tuples-only --no-align <<'SQL'
SELECT count(*) AS incompatible_password_hashes
FROM public.users
WHERE octet_length(password_hash) IS DISTINCT FROM 60
   OR (left(password_hash, 4) IN ('$2a$', '$2b$', '$2y$')) IS DISTINCT FROM TRUE
   OR substring(password_hash FROM 7 FOR 1) IS DISTINCT FROM '$'
   OR (substring(password_hash FROM 8 FOR 53)
       ~ '^[./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789]{53}$') IS DISTINCT FROM TRUE
   OR substring(password_hash FROM 5 FOR 2)
      IS DISTINCT FROM lpad(:'bcrypt_cost', 2, '0');
SQL
)" || exit 1
case "$incompatible_password_hashes" in
  ''|*[!0-9]*) echo 'bcrypt predeployment check did not return a numeric count' >&2; exit 1 ;;
esac
printf 'incompatible_password_hashes=%s\n' "$incompatible_password_hashes"
if [ "$incompatible_password_hashes" -ne 0 ]; then
  echo 'deployment blocked: incompatible_password_hashes must be 0' >&2
  exit 1
fi
)
```

空 `users` 表的计数为 `0`，此时可以在允许范围内完成首次初始化；非空表只能继续使用所有现存密码 hash 已采用的同一 cost。

## 准备依赖

项目不提供 Docker Compose。请使用本机服务或自行管理的容器准备：

1. PostgreSQL，并创建 `content_platform` 数据库；
2. Redis，可选但建议用于完整 readiness 验收。

PostgreSQL 是核心依赖：初始连接失败时 server 启动失败。Redis 是可降级依赖：初始连接失败时记录警告，server 继续启动；它只参与 readiness/checker，M2 Identity 的用户、session、token 轮换、状态和审计正确性不依赖 Redis。

## Migration

Server 启动时不会自动执行 migration。使用独立命令：

```bash
go run ./cmd/migrate up
go run ./cmd/migrate status
go run ./cmd/migrate version
go run ./cmd/migrate down-one
```

或使用 Makefile：

```bash
make migrate-up
make migrate-status
make migrate-down-one
```

默认目录为 `./migrations`，可以通过 `MIGRATIONS_DIR` 覆盖。`00001_m1_baseline.sql` 只让 goose 建立版本基线，不创建业务对象；`00002_identity.sql` 创建 `users`、`user_sessions` 和 `audit_logs` 及其约束/索引。

`user_sessions.token_hash` 只保存 refresh secret 原始 32 bytes 的 SHA-256，不保存 refresh token 或其 Base64URL 文本。Session 的 `expires_at` 在登录时确定，是绝对过期时间；refresh 不延长它。

`00002` 的 Down 会依次删除 `audit_logs`、`user_sessions` 和 `users`，从而删除全部 Identity 用户、会话和审计数据。这是破坏性操作；共享环境中不得把 `down-one` 当作普通回滚机制。详细规则见 `migrations/README.md`。

## 启动服务

```bash
go run ./cmd/server
```

或：

```bash
make run
```

默认监听 `:8080`。HTTP server 显式配置请求头、读取、写入、空闲和关闭超时。

## Identity API

M2 实现九个 Identity API：

| Method | Path | 认证边界 | 成功状态 | 用途 |
| --- | --- | --- | ---: | --- |
| `POST` | `/register` | 公开 | 201 | 创建固定为 `role=user,status=active` 的账户，不自动登录。 |
| `POST` | `/login` | 公开 | 200 | 校验凭据，创建绝对过期 session，签发 access/refresh token。 |
| `POST` | `/logout` | 只要求 access JWT 本身有效 | 200 | 幂等撤销 JWT 指向的当前 session。 |
| `POST` | `/token/refresh` | 公开，提交 refresh token | 200 | 一次性轮换 refresh secret 并签发新 access token。 |
| `GET` | `/me` | 严格认证 | 200 | 读取当前用户完整安全视图。 |
| `PUT` | `/me` | 严格认证 | 200 | 修改 display name/bio；absent 或 `null` 表示不修改。 |
| `DELETE` | `/me` | 严格认证 | 200 | 软删除当前账户并撤销其全部 active sessions。 |
| `GET` | `/users/{id}` | 公开 | 200 | 读取六字段公开视图；deleted 用户立即匿名化。 |
| `PUT` | `/admin/users/{id}/status` | 严格认证 + admin | 200 | 修改普通用户状态并写审计；ban 时撤销全部 active sessions。 |

所有成功响应使用 `data + meta`，所有错误使用 `error + meta`；响应 `meta.request_id` 与 `X-Request-ID` 关联。已知路径上的错误方法返回统一 JSON `405 method_not_allowed` 和单一规范 `Allow` header。

有 JSON body 的 Identity 请求遵循同一严格边界：

- 实际读取上限为 64 KiB；
- 必须恰好提供一个 `Content-Type` header 值，其 media type 必须是 `application/json`；
- body 必须是单个 JSON object，拒绝第二个 JSON 值；
- 顶层字段名必须与 DTO 的 canonical JSON 名完全一致且区分大小写；
- 未知字段、大小写 alias、重复字段和转义后等价的重复字段都返回 `400 invalid_request`。

`{id}` 必须是无符号、无空白、无前导零且不溢出 int64 的规范正十进制字符串；非法 path ID 返回 `400 validation_failed`，合法但不存在的用户才返回 `404 user_not_found`。

### 认证边界

JWT middleware 只验证唯一 Bearer header、token 长度、HS256 签名、issuer、audience、time claims 以及 canonical user/session IDs，然后把 `UserID` 和 `SessionID` 写入 context。JWT 不携带 email、role、status 或其他可变授权状态。

除 logout 外，受保护 API 必须继续在 service 或其写事务内从 PostgreSQL 重验：

- session 存在、属于 token user、未撤销且未绝对过期；
- user 存在，且不是 `banned` 或 `deleted`；
- 当前最新 role/status 是否允许该操作；
- 到期 mute 是否需要事务性懒恢复。

因此“JWT 签名有效”不等于“会话仍可授权”。任一服务端 user/session 严格校验失败统一返回 `401 session_invalid`。

Logout 是刻意保留的例外：它只要求 JWT 本身的签名、claims、issuer/audience 和时间仍有效，然后执行条件 `UPDATE`。即使 session 已撤销、已删除、不属于现存行，或用户后来被 banned/deleted，影响 0 行仍返回 `200`，且统一 envelope 的 `data.logged_out` 为 `true`。这保证客户端可安全重试登出；其他 protected API 不采用该宽松语义。

## Token 与 session

### Access token

- Access token 是 HS256 JWT；
- claims 包含 `iss`、唯一 `aud`、字符串 user ID `sub`、字符串 session ID `sid`、`iat`、`exp` 和随机 `jti`；
- user/session ID 必须是规范正十进制字符串；完整 Bearer token 最大 4096 bytes；
- access JWT 不包含 role/status，授权始终读取服务端最新 user/session 状态；
- access expiry 为 `min(now + AUTH_ACCESS_TOKEN_TTL, session.expires_at)`，永远不会超过 session 的绝对 expiry。

### Refresh token

Refresh token 外部格式为：

```text
<positive-session-id>.<base64url-encoded-secret>
```

Secret 由 32-byte CSPRNG 生成，并使用无 padding Base64URL 编码。数据库只存储 secret 原始 bytes 的 SHA-256；按 session ID 定位后，以常量时间比较哈希。

每次成功 refresh 都生成新 secret 并替换数据库 hash，旧 refresh token 立即失效；同一 token 并发 refresh 最多一个成功。Session 的绝对 `expires_at` 在 login 时固定，轮换不会滑动续期。客户端收到 refresh 成功响应后，必须把新的 access token 和 refresh token 作为一个原子凭据组持久化，不能只保存其中一个。提交后网络中断可能使客户端收不到已轮换的新 token，这是一次性轮换的固有边界；M2 不提供 grace window。

## 用户状态、审计与锁顺序

表中的“账户注销”特指 `DELETE /me`，不是 `POST /logout`：

| 状态 | 登录/刷新 | 读取自己 | 修改资料 | 账户注销 | M3+ 内容写操作 |
| --- | ---: | ---: | ---: | ---: | ---: |
| `pending` | 允许 | 允许 | 允许 | 允许 | 禁止，直到激活 |
| `active` | 允许 | 允许 | 允许 | 允许 | 允许 |
| `muted` | 允许 | 允许 | 允许 | 允许 | 禁止文章、评论、互动、转发和私信 |
| `frozen` | 允许 | 允许 | 禁止 | 禁止 | 全部禁止 |
| `banned` | 禁止 | 禁止 | 禁止 | 禁止 | 全部禁止 |
| `deleted` | 禁止 | 禁止 | 禁止 | 已完成 | 全部禁止 |

`POST /logout` 不由该业务状态矩阵限制：只要 access JWT 本身仍有效，就按上一节的幂等特例处理。

管理员状态接口只允许 admin 操作普通用户，不能操作自己，也不能操作其他 admin。Frozen admin 不能执行状态写操作。可请求的目标状态为 `active`、`muted`、`frozen`、`banned`；pending 用户只能转为 active，banned 用户只能保持 banned（no-op）或恢复为 active。将用户设为 `banned` 时会撤销该用户全部 active sessions。

管理员状态变更在一个事务中完成 user 更新、必要的 session revoke 和 `user.status_changed` audit；audit insert 失败会回滚状态和 session 撤销，不会留下部分提交。

当读取到 `status=muted && muted_until <= now` 时，以下入口会复用同一懒恢复能力：login、refresh、`GET /me`、`GET /users/{id}`、`PUT /me`、`DELETE /me` 和管理员状态修改。恢复在事务内把状态条件更新为 `active`，随后插入 actor 为 system 的 `user.mute_expired` audit：

- 并发请求最多成功恢复一次、最多写入一条该 audit；
- 已在写事务中的入口复用当前事务；只读入口开启短事务；
- audit detail 包含 old/new status、old/new muted until 和 request ID；
- audit insert 失败会回滚 mute 恢复。

所有 Identity 写事务遵循同一锁顺序：

```text
users（ID 升序） -> user_sessions（ID 升序） -> audit_logs（只 insert）
```

锁内重新校验 user/session，不依赖事务外旧状态。该顺序覆盖 login、refresh、资料更新、账户注销、ban/session revoke 和 mute recovery。

## 初始管理员

公开注册只会创建 `role=user`，请求中的隐藏/额外 `role` 字段会被严格 JSON 边界拒绝。M2 不提供隐藏 admin API、邮箱白名单或可由客户端触发的角色提升。

初始 admin 必须通过受控运维流程提升已经注册且处于 active 状态的用户。连接使用与上一节相同的 libpq service 模型：`PGSERVICEFILE` 只保存非秘密 authoritative-writer 元数据，不能包含 `password` 或 `passfile`；secret manager 供应且以精确 `0600` 权限挂载唯一的 `PGPASSFILE`，两者必须匹配同一目标，并与应用单独管理的 `DATABASE_URL` 指向同一个 authoritative writer。不要把该 password-bearing URL 导入运维 shell 或放进进程 argv，也不能使用只读/延迟副本、其他环境或空错库。以下命令通过 psql literal `:'admin_email'` 参数化邮箱，不把 shell 值拼接进 SQL。整个 workflow 在 subshell 中运行，退出后不会把 authoritative-writer 连接环境留在操作员 shell：

```bash
(
case "$-" in
  *x*) echo 'shell xtrace must be disabled before this controlled psql workflow' >&2; exit 1 ;;
esac
for variable in \
  DATABASE_URL PGPASSWORD PGHOST PGHOSTADDR PGPORT PGDATABASE PGUSER \
  PGSSLMODE PGOPTIONS PGSERVICE PGSERVICEFILE PGPASSFILE \
  PGSSLROOTCERT PGSSLCERT PGSSLKEY PGSSLCRL PGSSLCRLDIR PGSSLSNI \
  PGCHANNELBINDING PGREQUIREAUTH PGTARGETSESSIONATTRS PGLOADBALANCEHOSTS
do
  if [[ -v $variable ]]; then
    printf 'unset %s before running this controlled psql workflow\n' "$variable" >&2
    exit 1
  fi
done

PGSERVICE=content-platform-authoritative-writer
PGSERVICEFILE=/run/content-platform/postgresql/pg_service.conf
PGPASSFILE=/run/secrets/content-platform-writer.pgpass
export PGSERVICE PGSERVICEFILE PGPASSFILE

[[ -f "$PGSERVICEFILE" && -r "$PGSERVICEFILE" ]] || {
  echo 'controlled PGSERVICEFILE must be a readable regular file' >&2
  exit 1
}
[[ -f "$PGPASSFILE" && -r "$PGPASSFILE" ]] || {
  echo 'secret-manager PGPASSFILE must be a readable regular file' >&2
  exit 1
}
pgpass_mode="$(stat -Lc '%a' -- "$PGPASSFILE")" || {
  echo 'cannot inspect PGPASSFILE mode' >&2
  exit 1
}
[[ "$pgpass_mode" == 600 ]] || {
  echo 'PGPASSFILE must have mode 0600' >&2
  exit 1
}

: "${ADMIN_EMAIL:?ADMIN_EMAIL is required}"
psql --no-psqlrc --no-password \
  --set=ON_ERROR_STOP=1 --set=admin_email="$ADMIN_EMAIL" <<'SQL'
BEGIN;
UPDATE public.users
SET role = 'admin',
    updated_at = date_trunc('second', CURRENT_TIMESTAMP)
WHERE email = lower(btrim(:'admin_email'))
  AND role = 'user'
  AND status = 'active'
  AND deleted_at IS NULL
RETURNING id
\gset admin_
COMMIT;
SQL
)
```

提升脚本显式开启事务，并用 `UPDATE ... RETURNING id` 配合 `\gset` 要求恰好返回一行；成功路径的数据库 command tag 为 `UPDATE 1` 并提交。零行或多行会使 `\gset` 在 `ON_ERROR_STOP=1` 下失败，未提交的事务随后回滚并返回非零。出现异常必须停止并调查邮箱归一化、用户状态/角色、目标环境和 writer 连接；不得把 no-op 当作成功，也不得绕过检查临时增加隐藏接口或白名单。大于 `1` 还必须调查数据库完整性。

## 健康检查

### Liveness

```bash
curl -i http://localhost:8080/healthz
```

`/healthz` 不访问 PostgreSQL 或 Redis。进程能够处理 HTTP 时返回 `200`：

```json
{
  "data": {"status": "ok"},
  "meta": {"request_id": "..."}
}
```

### Readiness

```bash
curl -i http://localhost:8080/readyz
```

| PostgreSQL | Redis | HTTP | 状态 |
| --- | --- | ---: | --- |
| up | up | 200 | `ready` |
| up | down | 200 | `degraded` |
| down | up/down | 503 | `not_ready` |

Readiness 响应只暴露依赖的 `up/down`，不会返回 DSN、Redis 地址、凭据或原始驱动错误。

## HTTP 基线

- 每个请求都有 `X-Request-ID`；合法客户端 ID 会透传，非法或缺失时由服务端生成。
- 成功响应统一使用 `data + meta`；错误响应统一使用 `error + meta`。
- 未知路由返回 JSON `404 not_found`。
- 已知路径上的错误方法返回 JSON `405 method_not_allowed` 和 `Allow` header。
- 所有 `401` Identity 响应设置 `WWW-Authenticate: Bearer`。
- panic 会被恢复，客户端收到通用 JSON `500`，服务端日志包含 request ID 和 stack trace。
- 访问日志使用 `RemoteAddr`，当前不信任未经配置的 `X-Forwarded-For`。
- Go-redis 和 goose 的内部运行日志通过 `slog` 输出，不会混入标准库默认的非结构化日志。

## 测试

默认测试、race、vet 和 build 不需要 PostgreSQL、Redis 或 Docker：

```bash
go test -count=1 ./...
go test -race -count=1 ./...
go vet ./...
go build ./...
```

Makefile 提供日常便捷入口；这些默认 target 可能复用 Go test cache，不能替代上面的显式 fresh release gate：

```bash
make test
make test-race
make vet
```

### Tagged 测试与真实外部验收

直接运行 integration tag 会编译并执行全部 tagged 测试；若外部变量缺失，PostgreSQL/Redis 测试会逐项 `Skip`：

```bash
go test -v -count=1 -tags=integration ./...
```

这种“命令成功且列出 Skip”只证明 tagged 代码可编译、缺失依赖时的 Skip policy 正常，不等于真实 PostgreSQL 或 Redis acceptance。

只验收 PostgreSQL（包括 Identity migration、repository、事务和并发不变量）时，使用专用测试库并执行：

```bash
export TEST_DATABASE_URL='postgres://postgres:postgres@localhost:5432/content_platform_test?sslmode=disable'
make test-integration-postgres
```

`make test-integration-postgres` 只需要 `TEST_DATABASE_URL`。缺失、ASCII 空白或 Unicode blank（例如 U+00A0）都会在 Make/Go 的 required policy 中导致非零失败，而不是全量 Skip 后假绿。直接 `go test -tags=integration` 没有该 required sentinel，缺变量仍会 Skip，因此不能替代这个 acceptance target。

全量 integration 还要求 Redis：

```bash
export TEST_DATABASE_URL='postgres://postgres:postgres@localhost:5432/content_platform_test?sslmode=disable'
export TEST_REDIS_ADDR='localhost:6379'
make test-integration
```

`make test-integration` 会向 Go helper 传入 PostgreSQL 与 Redis 的 required sentinel；缺失、ASCII 空白或 Unicode blank 都会导致非零失败，而不是全部 Skip 后假绿。Redis 测试仅验收 Redis readiness/checker；Redis 不进入 M2 Identity 的正确性路径。

## 优雅关闭

进程响应 `SIGINT` 和 `SIGTERM`：

1. 停止接收新请求；
2. 在 `HTTP_SHUTDOWN_TIMEOUT` 内等待在途请求；
3. 超时后强制关闭 HTTP server；
4. 依次关闭 Redis 与 PostgreSQL；
5. 输出关闭完成日志并退出。

## M2 范围边界

M2 已实现 Identity，但仍明确不实现：

- 邮箱验证、pending 激活邮件；
- 忘记密码、重置密码、修改密码或 bcrypt 在线/离线 rehash；
- MFA、OAuth、OIDC 或第三方登录；
- Cookie session 或浏览器 CSRF 机制；
- Redis 认证缓存、token denylist、Redis session 或 refresh grace window；
- 设备管理、会话列表、管理员创建 API、通用 RBAC/ABAC；
- 审计日志查询 API、登录限流、验证码和异常设备检测；
- 文章、评论、互动、转发、私信、举报以及 M3+ 内容写 API。
