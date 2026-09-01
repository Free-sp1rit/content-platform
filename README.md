# content-platform

`content-platform` 是一个使用 Go 标准库 `net/http` 构建的内容平台后端。当前分支交付 M1 基础工程骨架：配置、结构化日志、PostgreSQL、可降级 Redis、统一 JSON、健康检查、migration、优雅关闭和测试工具。M1 不包含用户、文章、评论、私信或举报业务。

## 技术基线

- Go `1.26.4`
- HTTP：标准库 `net/http` 与 `http.ServeMux`
- 数据库抽象：标准库 `database/sql`
- PostgreSQL driver：`github.com/jackc/pgx/v5 v5.10.0`
- Redis：`github.com/redis/go-redis/v9 v9.21.0`
- Migration：`github.com/pressly/goose/v3 v3.27.1`
- 配置：`github.com/caarlos0/env/v11 v11.4.1`
- 并发辅助（间接版本约束）：`golang.org/x/sync v0.21.0`
- 日志：标准库 `log/slog`

Go module：

```text
github.com/Free-sp1rit/content-platform
```

## 目录边界

```text
cmd/server                         HTTP 服务入口
cmd/migrate                        独立 migration 入口
internal/app                       依赖组装、路由和生命周期
internal/system/service            健康检查业务编排
internal/system/handler            健康检查 HTTP 适配
internal/platform                  通用错误、JSON、Request ID、中间件
internal/infra                     配置、日志、PostgreSQL、Redis、migration
internal/testkit                   build-tagged 集成测试工具
migrations                         SQL migration 目录
```

后续业务模块按 `identity`、`article`、`comment`、`messaging`、`moderation` 逐步加入；不采用全局 `handler/service/repository` 大包。

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

`DATABASE_URL` 必填。配置错误会让进程立即退出，但错误信息不会输出数据库 URL 或 Redis 密码。

`.env` 已被 Git 忽略；不要提交真实密码、token 或生产连接信息。

配置加载会去除 `APP_ENV`、HTTP 地址、数据库 URL 和 Redis 地址的首尾空白，并把日志级别与日志格式转换为小写；`REDIS_PASSWORD` 始终原样保留。

数据库连接池规则：

- `DATABASE_MAX_OPEN_CONNS` 必须大于零。Go 的 `database/sql` 会把零解释为不限制连接数，因此应用拒绝该值；
- `DATABASE_MAX_IDLE_CONNS` 可以为零，表示不保留空闲连接，但不能为负数或超过最大打开连接数。

不要记录完整 `Config`，也不要单独记录数据库 URL 或 Redis 密码。配置类型为 `slog` 提供了脱敏表示作为误用防护，但这不替代字段级日志设计和代码审查。

### bcrypt cost 部署约束

`AUTH_BCRYPT_COST` 允许 `10..15`，默认值为 `12`。只能在 `users` 表为空、创建首个用户之前选择该值；首个用户创建后，该值即为不可变的持久化契约。同一环境的所有实例必须始终使用相同值，普通 rolling deploy、扩缩容和回滚均不得改变它。

bcrypt 不能在没有用户明文密码的情况下离线提高已有 hash 的 cost。未来如需升级 cost，必须另行设计受控的密码重置或凭据升级流程；当前实现不支持 rehash。若实例配置与存量 hash 的 cost 不一致，password adapter 会执行当前配置 cost 的 dummy workload，并将其作为普通凭据不匹配安全失败。这是违反部署不变量时的保护行为，不是迁移机制。

部署、扩缩容或回滚前先导入目标环境的 `DATABASE_URL` 和 `AUTH_BCRYPT_COST`，再执行以下检查。空 `users` 表可以选择任意 `10..15` 的 cost；非空表只能继续使用所有现存密码 hash 已采用的同一值：

```bash
case "$AUTH_BCRYPT_COST" in
  10|11|12|13|14|15) ;;
  *) echo 'AUTH_BCRYPT_COST must be between 10 and 15' >&2; exit 1 ;;
esac

incompatible_password_hashes="$(
  psql "$DATABASE_URL" \
    --set=ON_ERROR_STOP=1 \
    --set=bcrypt_cost="$AUTH_BCRYPT_COST" \
    --tuples-only \
    --no-align <<'SQL'
SELECT count(*) AS incompatible_password_hashes
FROM users
WHERE split_part(password_hash, '$', 3) <> lpad(:'bcrypt_cost', 2, '0');
SQL
)" || exit 1

if [ "$incompatible_password_hashes" != "0" ]; then
  echo "deployment blocked: ${incompatible_password_hashes} password hash(es) do not use AUTH_BCRYPT_COST=${AUTH_BCRYPT_COST}" >&2
  exit 1
fi
```

查询结果必须为 `0`；任何非零结果都必须停止部署。不要通过普通 rolling deploy 修改 cost。

## 准备依赖

M1 不提供 Docker Compose。请使用本机服务或自行管理的容器准备：

1. PostgreSQL，并创建 `content_platform` 数据库；
2. Redis，可选但建议用于完整 readiness 验收。

PostgreSQL 是核心依赖：初始连接失败时 server 启动失败。Redis 是加速层：初始连接失败时记录警告，server 继续以降级模式启动。

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

默认目录为 `./migrations`，可以通过 `MIGRATIONS_DIR` 覆盖。M1 的 `00001_m1_baseline.sql` 只执行 `SELECT 1`，让 goose 在空数据库建立版本表，不创建业务对象；M2 从 `00002` 开始添加用户和会话 migration。详细规则见 `migrations/README.md`。

## 启动服务

```bash
go run ./cmd/server
```

或：

```bash
make run
```

默认监听 `:8080`。HTTP server 显式配置请求头、读取、写入、空闲和关闭超时。

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
- 成功响应统一使用 `data + meta`。
- 错误响应统一使用 `error + meta`。
- 未知路由返回 JSON `404 not_found`。
- 已知路径上的错误方法返回 JSON `405 method_not_allowed` 和 `Allow` header。
- panic 会被恢复，客户端收到通用 JSON `500`，服务端日志包含 request ID 和 stack trace。
- 访问日志使用 `RemoteAddr`，M1 不信任未经配置的 `X-Forwarded-For`。
- Go-redis 和 goose 的内部运行日志通过 `slog` 输出，不会混入标准库默认的非结构化日志。

## 测试

默认单元测试不需要 PostgreSQL、Redis 或 Docker：

```bash
go test ./...
make test
```

Race 测试：

```bash
go test -race ./...
make test-race
```

静态检查与格式化：

```bash
go vet ./...
make vet
make fmt
```

集成测试使用 build tag，并要求专用测试依赖：

```bash
export TEST_DATABASE_URL='postgres://postgres:postgres@localhost:5432/content_platform_test?sslmode=disable'
export TEST_REDIS_ADDR='localhost:6379'
go test -count=1 -tags=integration ./...
```

`make test-integration` 会在环境变量缺失时直接失败，避免把全部跳过误判为集成测试通过：

```bash
make test-integration
```

## 优雅关闭

进程响应 `SIGINT` 和 `SIGTERM`：

1. 停止接收新请求；
2. 在 `HTTP_SHUTDOWN_TIMEOUT` 内等待在途请求；
3. 超时后强制关闭 HTTP server；
4. 依次关闭 Redis 与 PostgreSQL；
5. 输出关闭完成日志并退出。

## M1 范围边界

当前未实现：

- 注册、登录、JWT 和 refresh token；
- 用户、文章、评论、互动、私信、举报或审计表；
- Redis 业务缓存；
- Docker Compose、完整 CI 和业务 smoke 脚本；
- Prometheus、tracing、消息队列或通用 Repository 泛型。

下一步 M2 从 `identity` 模块开始，先实现 `User`、`UserSession`、注册、登录和用户状态控制。
