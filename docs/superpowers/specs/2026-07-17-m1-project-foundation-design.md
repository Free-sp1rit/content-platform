# M1 基础工程骨架设计

- 状态：已确认，待书面复核
- 日期：2026-07-17
- 分支：`feat/project-foundation`
- Go Module：`github.com/Free-sp1rit/content-platform`
- 需求来源：`内容平台——开发需求文档.md`

## 1. 背景

`content-platform` 将逐步实现用户与认证、文章、互动计数、评论、私信、举报和自动治理。项目使用 Go 标准库 `net/http` 与 `database/sql`，不引入第三方 HTTP 框架。

M1 不实现业务功能，而是建立后续里程碑共同依赖的最小可运行工程基线。完成后，服务必须能够读取并校验配置、输出结构化日志、连接 PostgreSQL、以 Redis 不可用的降级模式运行、执行 migration、暴露统一 JSON 健康检查、优雅退出，并具备不依赖外部服务的默认测试和显式运行的集成测试。

## 2. 目标与非目标

### 2.1 目标

M1 交付以下能力：

1. 初始化 Go 1.26.4 module，并只引入 M1 实际使用的固定版本依赖。
2. 建立业务模块优先、模块内分层、基础设施集中实现的目录基线。
3. 建立配置加载、校验和敏感信息保护规则。
4. 建立基于 `log/slog` 的结构化日志。
5. 使用 `http.ServeMux` 启动带超时配置和优雅关闭能力的 HTTP server。
6. 建立统一 JSON 成功响应、错误响应、request ID、访问日志和 panic recovery。
7. 实现 `/healthz` 与 `/readyz`，明确 PostgreSQL 与 Redis 的不同依赖语义。
8. 使用 `database/sql` 与 pgx driver 管理 PostgreSQL 连接。
9. 使用 `go-redis/v9` 管理 Redis 客户端。
10. 提供独立 migration 命令，server 启动时不自动迁移。
11. 建立单元测试、race 测试、集成测试和 Makefile 命令基线。
12. 编写 README，确保新开发者可以复现运行和测试流程。

### 2.2 非目标

M1 不实现：

- 用户、认证、JWT、密码哈希和用户表；
- 文章、评论、互动、私信、举报或审计业务；
- Redis 业务缓存；
- Docker Compose、完整 CI、业务 smoke 脚本和 OpenAPI 文档；
- Prometheus、分布式 tracing、消息队列或事件总线；
- 通用 Repository 泛型、依赖注入框架或 Testcontainers；
- 所有未来业务模块的空目录或占位接口。

以上能力在对应里程碑由真实需求驱动加入，避免 M1 膨胀或提前抽象。

## 3. 架构选择

### 3.1 已评估方案

#### 全局横向分层

将所有 handler、service、domain 和 repository 放入全局同名目录。该方案初期直观，但会让一个业务功能散落在多个顶层包中，并随着模块增加形成全局 service/repository 大包。因此不采用。

#### 业务模块优先的混合架构

按业务能力组织代码，每个复杂模块内部按 `domain`、`service`、`handler` 分层；具体技术实现集中在 `infra`；共享协议机制放入 `platform`；依赖组装放入 `app`。该方案在模块内聚、测试便利和复杂度之间平衡最好，因此采用。

#### 完整六边形架构

每个模块都建立 application、port、inbound adapter 和 outbound adapter。该方案边界严格，但会在学习早期引入过多结构性代码。M1 只采用其依赖倒置原则，不采用完整目录形式。

### 3.2 依赖方向

业务模块遵循：

```text
handler -> service -> domain
              ^
              |
        infra adapter
```

全局组装遵循：

```text
cmd/server -> app -> module handlers/services + infra
```

规则如下：

- `domain` 不依赖 HTTP、SQL、Redis、JWT 或配置加载库。
- `service` 负责编排业务规则，并定义自己消费的最小端口接口。
- `handler` 只处理 HTTP 协议，并通过接口依赖 service。
- `infra` 实现 service 所需端口，不向上层泄露驱动错误。
- `app` 是组合根，创建并注入所有具体依赖。
- 禁止使用包级全局数据库、Redis client 或 service singleton。

## 4. 目录设计

M1 建立以下实际目录：

```text
content-platform/
├── cmd/
│   ├── server/
│   │   └── main.go
│   └── migrate/
│       └── main.go
├── internal/
│   ├── app/
│   │   ├── app.go
│   │   ├── lifecycle.go
│   │   └── routes.go
│   ├── system/
│   │   ├── service/
│   │   │   └── health.go
│   │   └── handler/
│   │       └── http.go
│   ├── platform/
│   │   ├── apperror/
│   │   │   └── error.go
│   │   ├── httpx/
│   │   │   ├── decode.go
│   │   │   ├── middleware.go
│   │   │   └── response.go
│   │   └── requestid/
│   │       └── requestid.go
│   ├── infra/
│   │   ├── config/
│   │   │   └── config.go
│   │   ├── logging/
│   │   │   └── logging.go
│   │   ├── postgres/
│   │   │   └── postgres.go
│   │   └── redis/
│   │       └── redis.go
│   └── testkit/
│       └── integration.go
├── migrations/
│   └── README.md
├── .env.example
├── Makefile
├── README.md
├── go.mod
└── go.sum
```

文件可以在实现时根据单一职责进一步拆分；不为满足目录图而创建无内容文件。

未来业务模块按所有权引入：

| 模块 | 主要所有权 | 引入里程碑 |
| --- | --- | --- |
| `identity` | User、UserSession、注册、登录、资料、用户状态 | M2 |
| `article` | Article、Revision、View、Reaction、Share | M3/M4 |
| `comment` | Comment、CommentReaction | M5 |
| `messaging` | Conversation、Message | M6 |
| `moderation` | Report、AuditLog、自动治理 | M7 |
| `system` | health、readiness、后续测试时钟入口 | M1 |

模块按照业务规则和一致性所有权划分，而不是机械对应 URL 前缀或里程碑。

## 5. 启动与关闭流程

启动顺序为：

```text
signal.NotifyContext
  -> config.Load + Validate
  -> logging.New
  -> postgres.Open + initial PingContext
  -> redis.Open + initial Ping
  -> system service
  -> system handler
  -> routes and middleware
  -> http.Server.Serve
```

行为规则：

- 配置缺失或格式错误时立即失败。
- PostgreSQL 是最终事实来源；初始连接失败时 server 启动失败。
- Redis 是加速层；初始连接失败时记录 `WARN`，server 以降级模式启动。
- `sql.Open` 成功不代表连接成功，启动时必须执行带 timeout 的 `PingContext`。
- server 启动时不自动运行 migration。

关闭顺序为：

```text
SIGINT/SIGTERM
  -> cancel root context
  -> http.Server.Shutdown with timeout
  -> close Redis client
  -> close sql.DB
  -> log completion
```

应用必须停止接收新请求，并在配置的 shutdown timeout 内等待在途请求。`cmd/server/main.go` 保持薄，只负责根上下文、顶层调用和退出码；具体依赖组装由 `internal/app` 完成。

## 6. 配置设计

配置使用 `github.com/caarlos0/env/v11` 从环境变量加载，根结构分为：

```text
Config
├── Environment
├── HTTP
├── Database
├── Redis
└── Log
```

环境变量基线：

```dotenv
APP_ENV=local

HTTP_ADDR=:8080
HTTP_READ_HEADER_TIMEOUT=5s
HTTP_READ_TIMEOUT=10s
HTTP_WRITE_TIMEOUT=15s
HTTP_IDLE_TIMEOUT=60s
HTTP_SHUTDOWN_TIMEOUT=10s

DATABASE_URL=postgres://postgres:postgres@localhost:5432/content_platform?sslmode=disable
DATABASE_MAX_OPEN_CONNS=20
DATABASE_MAX_IDLE_CONNS=5
DATABASE_CONN_MAX_LIFETIME=30m
DATABASE_PING_TIMEOUT=3s

REDIS_ADDR=localhost:6379
REDIS_PASSWORD=
REDIS_DB=0
REDIS_PING_TIMEOUT=2s

LOG_LEVEL=info
LOG_FORMAT=json
```

规则：

- `DATABASE_URL` 必填。
- timeout 必须大于零。
- 连接数不能为负数，idle 数不能超过 open 数。
- Redis DB 不能为负数。
- 日志级别只允许 `debug`、`info`、`warn`、`error`。
- 日志格式只允许 `json`、`text`。
- `.env.example` 只包含无秘密的示例值。
- 应用不自动读取工作目录中的 `.env`；本地运行由 shell 或 Makefile 导入环境。
- 错误和日志不得输出数据库密码、Redis 密码、token 或完整 `Authorization` header。

## 7. 日志与 HTTP 基线

日志使用标准库 `log/slog`。本地允许 text 输出，类生产环境默认 JSON。基础字段至少包含 `service` 和 `environment`。

请求中间件顺序为：

```text
Request ID -> Recovery -> Access Log -> ServeMux
```

请求完成日志包含：

- `request_id`
- `method`
- `path`
- `status`
- `duration_ms`
- `remote_ip`
- `user_agent`

M1 的 `remote_ip` 只从 `http.Request.RemoteAddr` 提取，不信任客户端可伪造的 `X-Forwarded-For` 或 `X-Real-IP`。部署到可信反向代理之后，再单独设计代理信任列表。禁止记录密码、token、完整请求体或其他敏感业务正文。Recovery middleware 捕获 panic，记录 request ID 与 stack trace，并仅向客户端返回通用 `500`。

HTTP server 显式配置：

- `ReadHeaderTimeout`
- `ReadTimeout`
- `WriteTimeout`
- `IdleTimeout`
- `ShutdownTimeout`

路由使用 Go 1.26 `http.ServeMux` 方法与路径匹配能力，不引入 Gin、Echo 或 Chi。

## 8. Request ID 与响应契约

Request ID 规则：

- 优先接受匹配 `^[A-Za-z0-9._:-]{1,128}$` 的 `X-Request-ID`。
- 缺失或非法时由服务端生成不可预测的标识。
- 写入 request context、响应头、响应 meta 和访问日志。
- 不使用仅在单进程内唯一的自增整数。

成功响应：

```json
{
  "data": {
    "status": "ok"
  },
  "meta": {
    "request_id": "..."
  }
}
```

错误响应：

```json
{
  "error": {
    "code": "invalid_argument",
    "message": "request body is invalid"
  },
  "meta": {
    "request_id": "..."
  }
}
```

`platform/apperror` 只定义通用错误类别与包装能力；具体业务错误以后由各模块定义。应用错误包含 `Kind`、公开 `Code`、安全的公开 `Message`、可选安全 `Details` 和不公开的 `Cause`。`Kind` 决定 HTTP status，`Code` 表达稳定的客户端错误码。M1 中二者可以同名；以后例如 `article_version_conflict` 的 `Kind` 为 `conflict`。基础类别包括：

| 类别 | HTTP 状态 |
| --- | ---: |
| `invalid_argument` | 400 |
| `unauthenticated` | 401 |
| `permission_denied` | 403 |
| `not_found` | 404 |
| `conflict` | 409 |
| `rate_limited` | 429 |
| `internal_error` | 500 |
| `dependency_unavailable` | 503 |

未知路由返回统一 JSON `404`；已知路径上的错误方法返回统一 JSON `405`。路由层为每个已知路径注册方法兜底 handler，并为 `/` 注册全局未找到 handler，避免 `http.ServeMux` 输出默认纯文本错误。内部错误不向客户端暴露 SQL、驱动错误、表名、索引名、Redis 地址、stack trace 或文件路径。

## 9. 健康检查语义

### 9.1 `GET /healthz`

`/healthz` 只表示进程与 HTTP server 存活：

- 不访问 PostgreSQL；
- 不访问 Redis；
- 不执行耗时操作；
- 正常时返回 `200` 和 `status=ok`。

### 9.2 `GET /readyz`

`/readyz` 通过 system service 并发执行带短 timeout 的 PostgreSQL 与 Redis 检查。Handler 只依赖 service interface，不直接访问客户端。

| PostgreSQL | Redis | HTTP 状态 | 服务状态 |
| --- | --- | ---: | --- |
| up | up | 200 | `ready` |
| up | down | 200 | `degraded` |
| down | up/down | 503 | `not_ready` |

Redis 降级响应仍然返回成功数据；PostgreSQL 失败返回 `dependency_unavailable`，依赖检查结果位于错误 `details.checks` 中。响应不返回 DSN、地址、凭据或原始驱动错误。

Health service 依赖最小 checker 接口，以 fake checker 单元测试所有组合和 timeout 行为。

## 10. PostgreSQL 与 Redis

PostgreSQL 使用 `database/sql` 与 `github.com/jackc/pgx/v5/stdlib`，不在项目中混用 `*sql.DB` 和 `*pgxpool.Pool`。初始化时设置最大连接数、最大 idle 连接数和连接最大生命周期，并执行初始 `PingContext`。

Redis 使用 `github.com/redis/go-redis/v9`。M1 只建立 client、ping、close 和 readiness 能力，不设计缓存 key。以后 service 定义缓存端口，Redis adapter 实现端口；service 不直接依赖 `*redis.Client`。

## 11. Migration

Migration 使用 `github.com/pressly/goose/v3`，由独立的 `cmd/migrate` 入口执行：

```bash
go run ./cmd/migrate up
go run ./cmd/migrate status
go run ./cmd/migrate version
go run ./cmd/migrate down-one
```

M1 建立工具、目录和文档，不创建无业务意义的探针表。M2 的用户与会话表将成为首批业务 migration。

规则：

- server 不自动迁移；
- 已在共享环境执行的 migration 不修改，通过新 migration 修复；
- migration 与依赖它的代码在同一里程碑交付；
- 唯一约束、外键和索引进入 migration；
- `down` 或 `down-one` 在共享环境中谨慎使用；
- 空 migration 集合也必须能完成 `up` 与 `status` 验证。

## 12. 测试策略

默认测试：

```bash
go test ./...
go test -race ./...
```

默认测试不得依赖 PostgreSQL、Redis、Docker、执行顺序或共享可变状态。M1 单元测试至少覆盖：

- 配置默认值与校验失败；
- 日志级别和格式解析；
- JSON 成功与错误响应；
- 无效 JSON；
- request ID 生成与透传；
- recovery middleware；
- health service 的依赖状态矩阵与 timeout；
- health handler 的 HTTP status 和 JSON。

集成测试显式运行：

```bash
go test -tags=integration ./...
```

集成测试通过 `TEST_DATABASE_URL` 和 `TEST_REDIS_ADDR` 访问专用测试依赖，至少覆盖真实连接、migration、readiness checker 与资源关闭。直接执行带 build tag 的 Go 测试时，缺少相应环境变量的测试明确 `Skip`；`make test-integration` 在执行前校验两个变量，缺失时以非零状态失败，避免误把全部跳过当成通过。M1 不引入 Testcontainers，也不预建业务 fixture。

## 13. 依赖版本策略

Go module 使用：

```text
module github.com/Free-sp1rit/content-platform
go 1.26.4
```

M1 只直接引入实际使用的固定版本：

| 依赖 | 版本 |
| --- | --- |
| `github.com/jackc/pgx/v5` | `v5.10.0` |
| `github.com/redis/go-redis/v9` | `v9.21.0` |
| `github.com/pressly/goose/v3` | `v3.27.1` |
| `github.com/caarlos0/env/v11` | `v11.4.1` |
| `github.com/stretchr/testify` | `v1.11.1`，仅在测试实际使用时 |

JWT、crypto、validator、sync 和 redismock 在对应功能真正使用时引入。每次依赖变化后执行 `go mod tidy` 与 `go mod verify`，不保留未使用的 direct dependency。

## 14. 开发命令

Makefile 最小命令：

```text
run
fmt
vet
test
test-race
test-integration
migrate-up
migrate-status
migrate-down-one
```

README 同时列出底层 Go 命令，避免 Makefile 隐藏关键行为。

## 15. 验收标准

M1 完成时必须满足：

1. `go build ./...` 成功。
2. `go vet ./...` 成功。
3. `go test ./...` 成功且不需要外部依赖。
4. `go test -race ./...` 成功。
5. `go mod tidy` 后工作区不产生新的 module 变更。
6. `go mod verify` 成功。
7. 配置错误时进程以明确错误失败，且不泄露秘密。
8. PostgreSQL 可用时 server 可以启动。
9. PostgreSQL 初始连接失败时 server 启动失败。
10. Redis 初始连接失败时 server 记录警告并降级启动。
11. `/healthz` 返回统一 JSON `200`，且不检查外部依赖。
12. `/readyz` 按 PostgreSQL/Redis 状态矩阵返回结果。
13. 未知路由返回统一 JSON `404`，错误方法返回统一 JSON `405`。
14. panic 被恢复、记录 request ID，并返回通用 JSON `500`。
15. migration 命令能在空数据库执行 `up` 与 `status`。
16. server 启动时不自动执行 migration。
17. SIGINT/SIGTERM 触发有 timeout 的优雅关闭并释放资源。
18. README 能指导开发者配置、启动、迁移、测试和理解 Redis 降级行为。

## 16. Git 与 PR 交付规范

实现继续使用已存在且语义正确的分支：

```text
feat/project-foundation
```

提交按可独立审查、可单独验证的逻辑切分，预计包括：

1. `docs: add M1 project foundation design`
2. `chore: initialize Go module and development commands`
3. `feat: add configuration and structured logging`
4. `feat: add database and Redis infrastructure`
5. `feat: add HTTP foundation and health endpoints`
6. `feat: add migration command and integration test tooling`
7. `docs: document local development workflow`

提交前检查每个 commit 只包含相关变更，不混入用户尚未明确纳入版本控制的编辑器缓冲区或无关文件。最终执行完整验收命令，推送分支，并创建目标为 `main` 的 PR。

PR 描述必须包含：

- M1 范围与关键架构决策；
- PostgreSQL 必需、Redis 可降级的运行语义；
- migration 与 server 解耦策略；
- 已运行的验证命令及结果；
- 明确未包含的业务范围；
- 后续 M2 的建议入口。
