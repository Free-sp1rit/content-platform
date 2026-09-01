# M2 用户与认证设计

日期：2026-09-01
状态：已批准，待实现

## 1. 背景

M1 已建立可运行的 Go 服务基线：环境配置与校验、结构化日志、PostgreSQL、可降级 Redis、统一 JSON 响应、request ID、健康检查、migration、优雅关闭和测试工具。M2 在该基线上引入第一个真实业务模块 `identity`，交付用户、认证会话、资料、软注销和管理员状态控制。

M2 必须继续遵循已确定的目录和依赖方向：业务模块优先，模块内按 Domain / Service / Handler 分层，具体 PostgreSQL、JWT、密码哈希、时钟和随机数实现集中在 `internal/infra`，跨模块认证上下文放在 `internal/platform`。

## 2. 目标

M2 交付完整 Identity 能力：

1. 注册用户，强制邮箱归一化和全局唯一性，只存储密码哈希。
2. 登录用户，通过统一错误和固定 bcrypt 路径降低用户枚举风险。
3. 签发短期 JWT access token。
4. 使用可撤销、绝对过期、每次轮换的 opaque refresh token 管理 `UserSession`。
5. 登出当前 session，并保持重复登出幂等。
6. 返回当前用户和公开用户资料。
7. 编辑当前用户资料，遵循 absent / `null` / no-op 契约。
8. 软删除当前用户并撤销其全部 session，公开资料立即匿名化。
9. 允许管理员切换普通用户状态，状态变更、session 撤销和审计写入保持事务原子性。
10. 对过期禁言执行可并发的懒恢复，恢复操作写入 system audit。
11. 为后续 article、comment、messaging 和 moderation 模块提供可复用的认证主体和最新用户状态授权边界。

## 3. 非目标

M2 不实现：

- 邮箱验证和 `pending` 用户激活邮件；
- 忘记密码、重置密码和修改密码；
- MFA、OAuth、OIDC 或第三方登录；
- Cookie session 或者浏览器 CSRF 机制；
- Redis 认证缓存、token denylist 或 Redis session；
- Refresh token grace window、设备管理和会话列表 API；
- 通用 RBAC/ABAC 框架；
- 管理员创建 API 或公开注册时指定角色；
- 审计日志查询 API 和 M7 的完整治理流程；
- 登录限流、验证码、IP 风险评分和异常设备检测；
- 用户、认证和状态以外的文章、评论、互动、私信或举报功能。

`pending` 作为领域状态和后续邮箱验证入口保留，但 M2 公开注册默认创建 `active` 用户。

## 4. 范围与 HTTP 接口

M2 实现以下全部接口：

| Method | Path | 认证 | 成功状态 |
| --- | --- | --- | ---: |
| `POST` | `/register` | 公开 | 201 |
| `POST` | `/login` | 公开 | 200 |
| `POST` | `/logout` | 有效 access JWT，允许 session 已撤销 | 200 |
| `POST` | `/token/refresh` | 公开，提交 refresh token | 200 |
| `GET` | `/me` | 严格认证 | 200 |
| `PUT` | `/me` | 严格认证 | 200 |
| `DELETE` | `/me` | 严格认证 | 200 |
| `GET` | `/users/{id}` | 公开 | 200 |
| `PUT` | `/admin/users/{id}/status` | 严格认证 + admin | 200 |

所有响应继续使用 M1 的统一 JSON envelope 和 request ID。每个已知路径都注册 method fallback，错误方法返回统一 JSON `405` 和 `Allow` header。Identity 请求体上限为 64 KiB，拒绝未知 JSON 字段和多个 JSON 值。有 JSON body 的请求必须使用 `Content-Type: application/json`；缺失或其他 media type 返回 `400 invalid_request`。

`{id}` 路径参数必须是匹配 `^[1-9][0-9]*$` 且不溢出 int64 的规范十进制字符串。非法 ID 返回 `400 validation_failed`，合法但不存在的 ID 才返回 `404 user_not_found`。

## 5. 架构与目录边界

M2 引入：

```text
internal/
├── identity/
│   ├── domain/
│   │   ├── user.go
│   │   ├── session.go
│   │   └── validation.go
│   ├── service/
│   │   ├── service.go
│   │   ├── ports.go
│   │   ├── auth.go
│   │   ├── profile.go
│   │   └── status.go
│   └── handler/
│       ├── handler.go
│       ├── auth.go
│       ├── profile.go
│       └── status.go
├── platform/
│   └── authn/
│       ├── context.go
│       └── middleware.go
└── infra/
    ├── clock/
    │   └── clock.go
    ├── password/
    │   └── bcrypt.go
    ├── token/
    │   ├── access.go
    │   └── refresh.go
    └── postgres/
        └── identity/
            ├── repository.go
            ├── user.go
            ├── session.go
            └── audit.go
```

依赖方向：

```text
identity/handler -> identity/service -> identity/domain
                              ^
                              |
               infra adapters implement ports
```

规则：

- `domain` 不依赖 HTTP、SQL、JWT、bcrypt、配置或驱动库。
- `service` 编排业务规则和事务，定义 Repository、PasswordHasher、AccessTokenManager、RefreshTokenGenerator 和 Clock 最小端口。
- `handler` 只处理 HTTP 方法、路径参数、JSON DTO、Bearer 认证和响应映射。
- `platform/authn` 校验 access JWT 后只将 `UserID` 和 `SessionID` 写入 context，不查询数据库。
- `infra/postgres/identity` 实现 service 的数据与事务端口，不向上层泄露 SQL 或约束名。
- `app` 继续是唯一组合根，不使用全局 repository、service 或数据库变量。
- M2 不将 Redis 用于认证；PostgreSQL 是用户、session 和审计事实的唯一真相源。

## 6. 领域模型与状态能力

### 6.1 User

```go
type Role string

const (
	RoleUser  Role = "user"
	RoleAdmin Role = "admin"
)

type Status string

const (
	StatusPending Status = "pending"
	StatusActive  Status = "active"
	StatusMuted   Status = "muted"
	StatusFrozen  Status = "frozen"
	StatusBanned  Status = "banned"
	StatusDeleted Status = "deleted"
)
```

`User` 包含需求文档中的 id、email、password hash、display name、bio、role、status、muted until、violation count、created/updated/deleted time。密码哈希只在 repository 与认证 service 内部流转，不进入 handler 响应 DTO。

### 6.2 状态能力矩阵

| 状态 | 登录/刷新 | 读取自己 | 修改资料 | 注销 | 后续内容写操作 |
| --- | ---: | ---: | ---: | ---: | ---: |
| `pending` | 允许 | 允许 | 允许 | 允许 | 默认禁止，直到激活 |
| `active` | 允许 | 允许 | 允许 | 允许 | 允许 |
| `muted` | 允许 | 允许 | 允许 | 允许 | 禁止文章、评论、互动、转发、私信 |
| `frozen` | 允许 | 允许 | 禁止 | 禁止 | 全部禁止 |
| `banned` | 禁止 | 禁止 | 禁止 | 禁止 | 全部禁止 |
| `deleted` | 禁止 | 禁止 | 禁止 | 已完成 | 全部禁止 |

### 6.3 字段标准化

- 邮箱在 service 边界先 `strings.TrimSpace`，再转小写。
- 邮箱必须通过 `go-playground/validator` 的 `required,email` 格式校验，且 UTF-8 编码长度为 `1..320` 字节。Validator 只负责邮箱结构，字节/rune 长度和标准化由领域函数显式实现。
- 注册密码按 UTF-8 字节数计算，必须为 `8..72` 字节。
- Display name 执行 `strings.TrimSpace`，必须为 `1..100` 个 Unicode rune。
- Bio 未提供或 `null` 时不修改，显式空字符串表示清空，最大 1000 个 Unicode rune。
- `PUT` 字段 absent 和 `null` 都表示不修改，`{}` 是合法 no-op。
- 数据库必须只接收 service 已标准化的值。
- Service 业务时间统一使用 `Clock.Now().UTC().Truncate(time.Second)`，数据库时间、JWT NumericDate、过期比较和响应时间均以该秒精度时间为准。

### 6.4 响应视图

自身/管理视图 `UserView` 固定包含：

- `id`
- `email`
- `display_name`
- `bio`
- `role`
- `status`
- `muted_until`
- `violation_count`
- `created_at`
- `updated_at`
- `deleted_at`

`muted_until` 和 `deleted_at` 未发生时必须返回 JSON `null`。`bio` 未设置时返回 `""`。Password hash 永远不属于任何响应视图。

所有响应时间使用 UTC RFC3339 且精确到秒。

公开视图 `PublicUserView` 仅包含第 7.8 节列出的六个字段。

## 7. API 契约

### 7.1 `POST /register`

请求：

```json
{
  "email": " User@Example.com ",
  "password": "secret-password",
  "display_name": "Alice"
}
```

规则：

- 只允许客户端提供 email、password 和 display name。
- 新用户固定为 `role=user`、`status=active`、`bio=""`、`violation_count=0`。
- 密码使用 bcrypt 哈希后写入数据库。
- 注册可先做友好的存在性查询，但并发唯一性最终依赖 `users_email_uidx`；repository 只将该明确约束冲突映射为领域重复错误。
- 重复邮箱返回 `409 email_already_registered`，不返回约束名或 SQL 错误。
- 注册成功不自动登录，返回 201 和安全的当前用户数据。
- 响应不包含 access token、refresh token 或 password hash。

响应 `data` 为第 6.4 节的 `UserView`。

### 7.2 `POST /login`

请求：

```json
{
  "email": "user@example.com",
  "password": "secret-password"
}
```

成功响应数据：

```json
{
  "token_type": "Bearer",
  "access_token": "...",
  "expires_in": 900,
  "refresh_token": "123....",
  "refresh_expires_at": "2026-10-01T12:00:00Z",
  "user": {
    "id": 1,
    "email": "user@example.com",
    "display_name": "Alice",
    "bio": "",
    "role": "user",
    "status": "active",
    "muted_until": null,
    "violation_count": 0,
    "created_at": "...",
    "updated_at": "...",
    "deleted_at": null
  }
}
```

`expires_in` 是 access JWT 的 `exp - iat` 整数秒数。`refresh_expires_at` 是 session 的绝对过期时间。`user` 为第 6.4 节的 `UserView`。

邮箱不存在、密码错误、凭据字段非法、用户为 `banned` 或 `deleted` 时统一返回 `401 invalid_credentials`。每个成功解码并进入 service 的登录请求必须恰好执行一次 bcrypt compare，详细规则见第 12 节。

### 7.3 `POST /token/refresh`

请求：

```json
{
  "refresh_token": "123.base64url-secret"
}
```

规则：

- 不需要有效 access token。
- 每次成功都轮换 refresh secret，旧 secret 立即失效。
- 同一旧 token 并发刷新最多一个成功。
- 轮换不延长 session 绝对过期时间。
- 新 access token 不晚于 session 过期。
- Token、session 或用户任一校验失败统一返回 `401 invalid_refresh_token`。

成功响应 `data` 只包含 `token_type`、`access_token`、`expires_in`、`refresh_token` 和 `refresh_expires_at`，不重复返回 user；客户端需要最新资料时调用 `GET /me`。

### 7.4 `POST /logout`

- 要求 Bearer access JWT 的签名、算法、时间和 claims 有效。
- 不要求对应 session 仍未撤销。
- 按 token 中的 user ID 和 session ID 做条件撤销。
- Session 不存在、已撤销或刚被撤销都返回 200：

```json
{
  "logged_out": true
}
```

### 7.5 `GET /me`

- 要求严格 session 认证。
- 从数据库读取最新用户状态和当前 session。
- Session 或用户不可用统一返回 `401 session_invalid`。
- `active`、`pending`、`muted`、`frozen` 可读取自己资料。
- 成功响应 `data` 为第 6.4 节的 `UserView`。

### 7.6 `PUT /me`

请求：

```json
{
  "display_name": "New Name",
  "bio": "new bio"
}
```

- 字段缺省或 `null` 不修改。
- `{}` 为 200 no-op。
- Display name 显式空值非法；bio 可显式清空。
- `active`、`pending`、`muted` 可修改。
- `frozen` 返回 `403 user_frozen`。
- `banned` 和 `deleted` 由严格认证统一返回 `401 session_invalid`。
- 成功响应 `data` 为更新后的 `UserView`。

### 7.7 `DELETE /me`

- 软删除当前用户，设置 `status=deleted` 和 `deleted_at`。
- 同一事务撤销该用户全部 active session。
- 公开资料立即匿名化。
- 邮箱仍保留并继续受全局唯一约束，不允许用相同邮箱重新注册。
- `frozen` 返回 `403 user_frozen`。
- 成功返回 200 和 `{"deleted": true}`。

### 7.8 `GET /users/{id}`

公开字段固定为：

- `id`
- `display_name`
- `bio`
- `role`
- `status`
- `created_at`

不返回 email、password hash、muted until、violation count、updated/deleted time、session、audit 或管理原因。

软删除用户返回稳定匿名资料：

```json
{
  "id": 1,
  "display_name": "Deleted User",
  "bio": "",
  "role": "user",
  "status": "deleted",
  "created_at": "..."
}
```

匿名化固定将 display name 设为 `Deleted User`、bio 设为空字符串、role 设为 `user`、status 设为 `deleted`，不保留原始 admin 角色或资料。

用户不存在返回 `404 user_not_found`。

### 7.9 `PUT /admin/users/{id}/status`

请求：

```json
{
  "status": "muted",
  "reason": "repeated abuse",
  "muted_until": "2026-09-02T12:00:00Z"
}
```

规则：

- 操作者的最新数据库 role 必须为 admin。
- Admin 不能操作自己或其他 admin。
- Frozen admin 不能产生管理写操作。
- 目标必须为未删除的普通用户。
- M2 可设置 `active`、`muted`、`frozen`、`banned`。
- `reason` 缺省或 `null` 时视为空字符串；非空时执行 `strings.TrimSpace`，最大 1000 个 Unicode rune。
- `muted_until` 只接受 JSON RFC3339 字符串或 `null`，解析后转换为 UTC 并截断到秒；缺省与 `null` 都表示未提供。
- `pending -> active` 和 `banned -> active` 合法。
- `muted` 必须提供晚于当前时间的 muted until。
- 非 `muted` 状态传入非 null muted until 返回 `400 validation_failed`。
- 字段校验先于 no-op 判断。
- 相同状态和相同 muted until 为 200 no-op，不重复写 audit。
- 变为 banned 时在同一事务撤销目标全部 session。
- 状态更新和 audit log 在同一事务。
- 成功和 no-op 响应 `data` 都为目标用户的 `UserView`。

## 8. 数据库模型

M2 新增 `migrations/00002_identity.sql`，在同一 migration 中先创建 users，再创建 user sessions 和最小 audit logs。Down 按反向依赖顺序删除。

### 8.1 users

```sql
CREATE TABLE users (
    id              BIGSERIAL PRIMARY KEY,
    email           TEXT NOT NULL,
    password_hash   TEXT NOT NULL,
    display_name    TEXT NOT NULL,
    bio             TEXT NOT NULL DEFAULT '',
    role            TEXT NOT NULL DEFAULT 'user',
    status          TEXT NOT NULL DEFAULT 'active',
    muted_until     TIMESTAMPTZ NULL,
    violation_count INTEGER NOT NULL DEFAULT 0,
    created_at      TIMESTAMPTZ NOT NULL,
    updated_at      TIMESTAMPTZ NOT NULL,
    deleted_at      TIMESTAMPTZ NULL,
    CHECK (email <> ''),
    CHECK (email = lower(btrim(email))),
    CHECK (octet_length(email) <= 320),
    CHECK (password_hash <> ''),
    CHECK (char_length(display_name) BETWEEN 1 AND 100),
    CHECK (display_name = btrim(display_name)),
    CHECK (char_length(bio) <= 1000),
    CHECK (role IN ('user', 'admin')),
    CHECK (status IN ('pending', 'active', 'muted', 'frozen', 'banned', 'deleted')),
    CHECK (violation_count >= 0),
    CHECK (updated_at >= created_at),
    CHECK (deleted_at IS NULL OR deleted_at >= created_at),
    CHECK (
        (status = 'muted' AND muted_until IS NOT NULL)
        OR
        (status <> 'muted' AND muted_until IS NULL)
    ),
    CHECK ((status = 'deleted') = (deleted_at IS NOT NULL))
);

CREATE UNIQUE INDEX users_email_uidx ON users (email);
```

Go `strings.TrimSpace` 与 PostgreSQL `btrim` 的 Unicode 覆盖不完全相同。Service 标准化是主要契约，DDL 是最后防线。

### 8.2 user_sessions

```sql
CREATE TABLE user_sessions (
    id          BIGSERIAL PRIMARY KEY,
    user_id     BIGINT NOT NULL REFERENCES users(id),
    token_hash  BYTEA NOT NULL,
    expires_at  TIMESTAMPTZ NOT NULL,
    revoked_at  TIMESTAMPTZ NULL,
    created_at  TIMESTAMPTZ NOT NULL,
    CHECK (octet_length(token_hash) = 32),
    CHECK (expires_at > created_at),
    CHECK (revoked_at IS NULL OR revoked_at >= created_at)
);

CREATE INDEX user_sessions_user_created_idx
    ON user_sessions (user_id, created_at DESC);

CREATE INDEX user_sessions_active_user_idx
    ON user_sessions (user_id, id)
    WHERE revoked_at IS NULL;
```

### 8.3 audit_logs

```sql
CREATE TABLE audit_logs (
    id          BIGSERIAL PRIMARY KEY,
    actor_type  TEXT NOT NULL,
    actor_id    BIGINT NULL REFERENCES users(id),
    action      TEXT NOT NULL,
    target_type TEXT NOT NULL,
    target_id   BIGINT NOT NULL,
    detail      JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at  TIMESTAMPTZ NOT NULL,
    CHECK (action <> ''),
    CHECK (target_type <> ''),
    CHECK (target_id > 0),
    CHECK (jsonb_typeof(detail) = 'object'),
    CHECK (actor_type IN ('user', 'admin', 'system')),
    CHECK (
        (actor_type = 'system' AND actor_id IS NULL)
        OR
        (actor_type IN ('user', 'admin') AND actor_id IS NOT NULL)
    )
);

CREATE INDEX audit_logs_target_created_idx
    ON audit_logs (target_type, target_id, created_at DESC);
```

M2 只写入 `user.status_changed` 和 `user.mute_expired`，不开放审计查询 API。

## 9. Token 与密码安全

### 9.1 Access token

Access token 是 HS256 JWT，至少包含：

```json
{
  "sub": "123",
  "sid": "456",
  "iss": "content-platform",
  "aud": ["content-platform-api"],
  "iat": 1788235200,
  "exp": 1788236100,
  "jti": "base64url-csprng-value"
}
```

规则：

- `sub` 和 `sid` 使用规范十进制字符串，必须匹配 `^[1-9][0-9]*$` 且不溢出 int64。
- 拒绝 `0`、负数、正号、空白和前导零。
- `jti` 使用 CSPRNG 和无填充 Base64URL，长度为 `16..128` 字符。
- 只接受 HS256，issuer 和 audience 必须匹配配置。
- `iat`、`exp`、`sub`、`sid`、`jti` 必须存在。
- `exp > iat`、`exp > Clock.Now()`、`iat <= Clock.Now() + 30s`。
- JWT 验证中的 30 秒只用于容忍签发方 `iat` 略微超前；已达 `exp` 的 token 立即失效，不为过期 token 增加额外宽限。
- 完整 Bearer token 最大 4096 字节。
- Access token 不包含 email、role、status、password 或其他可变授权信息。

### 9.2 Refresh token

外部格式：

```text
<positive-session-id>.<base64url-encoded-32-byte-random-secret>
```

规则：

- Secret 是 32 字节 CSPRNG，使用无填充 Base64URL。
- Session ID 使用与 access token `sid` 相同的规范正整数字符串规则，拒绝前导零、符号、空白和 int64 溢出。
- 完整 refresh token 最大 256 字节，必须恰好包含一个 `.`。
- 数据库只存储 `SHA-256(raw secret)`。
- 按 session ID 定位，在锁内使用 `subtle.ConstantTimeCompare` 比较哈希。
- 成功刷新每次都替换 secret，旧 secret 立即失效。
- `expires_at` 在登录时确定，刷新不延长绝对生命期。
- 新 access token 的过期时间为 `min(now + access TTL, session.expires_at)`。

### 9.3 Password

- 使用 `golang.org/x/crypto/bcrypt`。
- Bcrypt cost 来自配置，允许 `10..15`，默认 12。
- 密码只以 hash 形式进入数据库。
- 正常日志、错误、响应和测试失败信息不输出密码或 hash。
- Password adapter 启动时使用正式 cost 生成 dummy hash。
- Dummy candidate 是固定、非敏感且为 `8..72` 字节的内部值。

## 10. Auth 配置

新增：

```text
AUTH_JWT_SECRET
AUTH_JWT_ISSUER
AUTH_JWT_AUDIENCE
AUTH_ACCESS_TOKEN_TTL
AUTH_REFRESH_TOKEN_TTL
AUTH_BCRYPT_COST
```

默认值：

```text
AUTH_JWT_ISSUER=content-platform
AUTH_JWT_AUDIENCE=content-platform-api
AUTH_ACCESS_TOKEN_TTL=15m
AUTH_REFRESH_TOKEN_TTL=720h
AUTH_BCRYPT_COST=12
```

`AUTH_JWT_SECRET` 必填、无默认值、至少 32 字节，不自动 trim。Access/refresh TTL 必须大于零，refresh TTL 必须大于 access TTL。Auth config 的 `slog.LogValue()` 必须将 JWT secret 输出为 `[REDACTED]`。

Issuer 和 audience 执行 `strings.TrimSpace` 后必须非空；JWT secret 始终保留原始字节。Auth 校验在根 `Config.Validate()` 的 Redis 之后、Log 之前执行，保持稳定 fail-fast 顺序：

```text
Environment -> HTTP -> Database -> Redis -> Auth -> Log
```

`.env.example` 只放明显的开发占位值，并说明生产环境必须使用独立 CSPRNG secret。

## 11. 认证边界

### 11.1 JWT 中间件

`platform/authn` 只做：

- Bearer header 和 4096 字节上限；
- JWT 签名、HS256 算法、issuer、audience、time claims 和 ID claims；
- 向 context 写入 `Principal{UserID, SessionID}`。

它不查询数据库，也不把 role/status 当作 JWT 授权信息。

### 11.2 严格认证

普通受保护接口在 service 内检查：

- session 存在且属于 token user；
- session 未撤销、未过期；
- user 存在；
- user 不是 banned/deleted；
- 如果 mute 已过期，执行懒恢复。

任一服务端 user/session 校验失败统一返回 `401 session_invalid`。

只读接口以完成 user/session 校验的数据库读取作为线性化点。如果需要恢复过期 mute，则进入第 14.6 节的短事务，并返回恢复后用户。写接口不允许只依赖事务外的严格认证，必须在各自写事务的锁内重验。

### 11.3 Logout 特例

Logout 只要求 JWT 本身有效，使用条件 update 幂等撤销 session，不调用严格 session 认证。

## 12. Login 固定 bcrypt 与事务

对每个成功解码并进入 service 的 login 请求，恰好调用一次 `PasswordHasher.Compare`。

事务外：

1. 标准化邮箱并记录凭据字段是否合法。
2. 查询用户和 password hash。
3. 选择真实或 dummy hash/candidate。
4. 恰好执行一次 bcrypt compare。
5. Repository 查询内部错误时，compare 之后返回安全 500。
6. Hash 格式错误或 adapter 内部错误返回安全 500。
7. 正常凭据/状态失败统一返回 `401 invalid_credentials`。

凭据验证通过后开启事务：

```text
锁定 user
→ 重验 user 存在、status、deleted_at 和 password_hash 未变
→ 在当前事务恢复过期 mute
→ 生成 refresh secret
→ INSERT session RETURNING id
→ 生成 jti 并签名 access JWT
→ commit
```

签名失败回滚 session insert、mute 恢复和 audit。

并发不变量：

- 封禁/注销先获得 user 锁时，login 不得创建 session。
- Login 先获得 user 锁并创建 session 时，后续封禁/注销必须撤销该 session。
- Banned/deleted 用户最终不得存在未撤销且未过期 session。

## 13. Refresh 事务

Refresh token 只包含 session ID，因此先无锁预读 session.user ID，但不使用预读数据授权。

事务内：

```text
锁定 user
→ 锁定 session
→ 重新校验 user/session/token hash
→ 在当前事务恢复过期 mute
→ 生成新 refresh secret
→ 生成 jti 并签名新 access JWT
→ 更新 session.token_hash
→ commit
```

必须先成功生成随机数和签名 JWT，再更新 token hash。内部错误回滚 hash、mute 恢复和 audit。提交后网络中断导致客户端未收到新 token 是一次性轮换的固有边界，M2 不引入 grace token。

## 14. 全局锁顺序与事务

Identity 写事务的全局顺序：

```text
users（ID 升序）
→ user_sessions（ID 升序）
→ audit_logs（只 insert）
```

规则：

- 只锁定实际需要修改或决定事务结果的行。
- 多个 user/session 必须按 ID 升序锁定。
- 锁定后重新校验，不依赖锁外旧数据。
- 禁止 repository 事务方法内再开启嵌套事务。
- 禁言恢复复用调用方当前事务。
- Audit insert 始终在领域行和 session 更新之后。
- 锁等待受 context deadline 限制。

### 14.1 管理员状态事务

```text
解析 JWT
→ 拒绝 actor ID == target ID
→ 开启事务
→ 按 ID 升序锁 actor/target users
→ 按 ID 升序锁 actor session 与必要的 target sessions
→ 事务内重验 actor role/status/session 和 target role/status
→ 修改 target
→ banned 时撤销 target sessions
→ insert audit
→ commit
```

Actor 必须为 admin，不得是 frozen/banned/deleted，且 session 必须未撤销、未过期。Target 必须为未删除普通用户。

### 14.2 批量 session 撤销

```sql
WITH locked_sessions AS (
    SELECT id
    FROM user_sessions
    WHERE user_id = $1
      AND revoked_at IS NULL
    ORDER BY id
    FOR UPDATE
)
UPDATE user_sessions AS s
SET revoked_at = $2
FROM locked_sessions AS l
WHERE s.id = l.id;
```

管理员封禁和用户注销复用同一个事务内 repository 能力。如果调用方已锁定 session ID 集合，使用已锁 ID 的内部更新方法，不重复锁定。

### 14.3 Logout

Logout 只操作 session，不等待 user 锁：

```sql
UPDATE user_sessions
SET revoked_at = $now
WHERE id = $sid
  AND user_id = $user_id
  AND revoked_at IS NULL;
```

影响 0/1 行都返回幂等成功。

### 14.4 资料更新事务

`PUT /me` 在完成请求字段校验后执行：

```text
开启事务
→ 锁定当前 user
→ 锁定当前 session
→ 锁内重验 session 归属/撤销/过期与 user 状态
→ 在当前事务恢复过期 mute
→ frozen 返回 403 并回滚
→ 有实际 patch 时更新 display name/bio/updated at
→ commit
```

`{}` 或所有字段都为 `null` 仍然执行严格认证，但除必要的过期 mute 恢复外不更新 `updated_at`。字段值与现有值完全相同也是 no-op，不制造无意义行版本。

### 14.5 注销事务

```text
严格认证
→ 锁定当前 user
→ 按 session ID 升序锁定该 user 的 active sessions
→ 锁内重验当前 session 和 user 状态
→ 设置 deleted/deleted at
→ 撤销全部 sessions
→ commit
```

### 14.6 禁言到期恢复

如果 `status=muted && muted_until <= Clock.Now()`，service 要求 repository 执行条件更新和 system audit。只有实际更新一行的事务写审计，并发请求最多产生一条 audit。

Audit detail 固定包含 old/new status、old/new muted until 和 request ID。HTTP 请求写 request ID；未来任务可写任务执行 ID；没有执行标识时写空字符串，不省略字段。

`GET /me`、`GET /users/{id}`、login、refresh、资料更新、注销和管理状态修改都使用同一恢复能力。已处于事务的调用方传入当前 transaction；只读路径发现过期 mute 时开启一个锁定目标 user、条件恢复并插入 audit 的短事务。

## 15. 错误契约

| 场景 | HTTP | Code |
| --- | ---: | --- |
| JSON 非法、未知字段、body 超限 | 400 | `invalid_request` |
| Content-Type 缺失/非 JSON | 400 | `invalid_request` |
| 路径用户 ID 非法 | 400 | `validation_failed` |
| 注册/更新字段校验失败 | 400 | `validation_failed` |
| Muted 缺失/过期 muted until | 400 | `validation_failed` |
| 非 muted 传非 null muted until | 400 | `validation_failed` |
| 不可设置的状态值 | 400 | `validation_failed` |
| 邮箱已存在 | 409 | `email_already_registered` |
| 登录失败 | 401 | `invalid_credentials` |
| Bearer/JWT 失败 | 401 | `invalid_access_token` |
| JWT 有效但服务端身份不可用 | 401 | `session_invalid` |
| Refresh 失败 | 401 | `invalid_refresh_token` |
| Frozen 用户写操作 | 403 | `user_frozen` |
| 非 admin | 403 | `admin_required` |
| Admin 操作自己或其他 admin | 403 | `admin_target_forbidden` |
| 用户不存在 | 404 | `user_not_found` |
| 目标已 deleted | 409 | `invalid_status_transition` |
| 内部依赖错误 | 500 | `internal_error` |

`session_invalid` 统一覆盖 session 不存在/不属于 user/已撤销/已过期、user 不存在/banned/deleted。`invalid_refresh_token` 统一覆盖 refresh token 格式、hash、session 和 user 失败。

错误不返回 email 存在性、具体被封禁/删除状态、password/hash、access/refresh token、SQL、表名、约束名、驱动错误、数据库 URL、JWT secret、文件路径或 stack trace。

## 16. 审计契约

### 16.1 管理员状态变更

Action 为 `user.status_changed`，actor type 为 admin，target type 为 user。Detail：

```json
{
  "old_status": "active",
  "new_status": "muted",
  "reason": "...",
  "old_muted_until": null,
  "new_muted_until": "...",
  "request_id": "..."
}
```

### 16.2 禁言到期

Action 为 `user.mute_expired`，actor type 为 system，actor ID 为 null。Detail：

```json
{
  "old_status": "muted",
  "new_status": "active",
  "old_muted_until": "...",
  "new_muted_until": null,
  "request_id": "..."
}
```

相同状态与相同 muted until 的 no-op 不重复写 audit。Audit insert 失败必须回滚用户状态和 session 撤销。

## 17. 管理员初始化

公开注册永远创建 `role=user`，不接受 role 字段。初始 admin 通过受控运维流程提升。README 使用 `psql` 变量字面量绑定，不鼓励应用隐藏接口或邮箱白名单：

```bash
psql "$DATABASE_URL" --set=admin_email='admin@example.com'
```

```sql
UPDATE users
SET role = 'admin',
    updated_at = CURRENT_TIMESTAMP
WHERE email = lower(btrim(:'admin_email'))
  AND status = 'active'
  AND deleted_at IS NULL;
```

生产环境应通过受控 migration、运维脚本或数据库管理流程执行。

## 18. 测试策略

所有新行为按 TDD 实现：先编写会因功能缺失而失败的测试，确认预期 RED，再写最小实现并确认 GREEN，最后重构。

### 18.1 Domain 和基础设施单元测试

覆盖：

- 邮箱标准化和 UTF-8 字节边界；
- Display name/bio rune 边界；
- 状态能力矩阵和公开匿名资料；
- bcrypt 哈希、compare、72 字节、cost 和 dummy hash；
- JWT 签发/验证、算法、issuer/audience、claims、时间、字符串 ID、token 大小和 jti；
- Refresh token 格式、长度、哈希、常量时间比较；
- Auth config 边界和 JWT secret 日志脱敏。

### 18.2 Service 单元测试

覆盖：

- 注册、标准化、hash 和重复邮箱；
- Login 每条 service 失败路径恰好一次 compare；
- Login 事务内重验 hash 和状态；
- Login 签名失败的 session/mute/audit 回滚；
- Session 绝对过期；
- Refresh 轮换、旧 secret 失效、并发最多一个成功；
- Access token 不超过 session 过期；
- Refresh 签名失败的 hash/mute/audit 回滚；
- Logout 幂等和普通接口 session 严格失效；
- 资料 patch、null/absent/no-op 和 frozen 限制；
- 软删除和全部 session 撤销；
- Admin 角色/目标/session 事务内重验；
- Pending 和 banned 恢复到 active；
- Muted 参数和 no-op；
- 过期 mute 恢复并只审计一次；
- 状态或 audit 失败时不部分提交。

### 18.3 Handler 和 App 测试

覆盖：

- 全部路由、method fallback 和 `Allow`；
- Body 上限、未知字段、null/absent；
- Bearer header 和 JWT 错误；
- HTTP status、业务 code、响应 envelope 和 request ID；
- 响应字段白名单和秘密不泄露；
- Identity 组装和旧 health/readiness 路由回归；
- Auth 配置失败时安全启动失败。

### 18.4 PostgreSQL 集成与并发测试

通过 `//go:build integration` 运行，只连接显式 `TEST_DATABASE_URL`，每个并发测试有 context timeout。覆盖：

- 空库执行 `00001` 和 `00002`；
- 邮箱唯一和 DDL CHECK；
- Refresh hash 不保存明文；
- Session 绝对过期；
- 状态/audit 和封禁/session 原子性；
- 注销/session 原子性；
- 禁言恢复 audit 恰好一条；
- Refresh 与 logout 并发；
- Refresh 与封禁并发；
- Refresh 与禁言恢复并发；
- 注销与 refresh 并发；
- Login 与封禁/注销/禁言恢复并发；
- 管理员操作与自己注销并发；
- 两个管理员同时修改同一普通用户；
- 两个管理员互相操作无死锁且都失败。

最终不变量：

- Banned/deleted 用户无 active session；
- 旧 refresh secret 不可重用；
- 并发 refresh 最多一个成功；
- 禁言恢复 audit 恰好一条；
- 失败事务不局部修改 user/session/audit；
- JWT 签名失败回滚 session/hash/mute/audit；
- Audit insert 失败回滚状态和 session 撤销。

## 19. 依赖和配置文档

M2 实际使用并固定：

```text
github.com/golang-jwt/jwt/v5 v5.3.1
golang.org/x/crypto v0.53.0
github.com/go-playground/validator/v10 v10.30.3
```

同步更新：

- `go.mod` / `go.sum`；
- `.env.example` 的 auth 配置；
- README 的 auth 配置、migration、路由、运维提升 admin、单元/集成测试和 M2 范围；
- `migrations/README.md` 的 `00002` 说明。

依赖变更审查并提交后，再执行 `go mod tidy` 和 `git diff --exit-code -- go.mod go.sum` 检查无后续漂移。

## 20. Git 和 PR 交付

M2 使用独立分支：

```text
feat/identity-auth
```

实现使用隔离 worktree、TDD 和按可独立审查的逻辑提交。设计、计划、配置/密码/token、migration/domain、repository/service、handler/app、集成测试和文档分开提交。

提交和 PR 不包含用户未跟踪的 `内容平台——开发需求文档.md`。PR 目标为 `main`，描述必须包含 M2 API、会话安全、状态矩阵、并发锁顺序、migration、验证命令、未运行的外部集成测试和 M3 入口。

## 21. 完成验收

M2 完成时必须满足：

1. 第 4 节的 9 个 HTTP 接口全部实现并使用统一 JSON/request ID。
2. 密码只存储 bcrypt hash，任何响应和日志不泄露密码/hash。
3. Access token 按第 9 节的 HS256、claims、时间、字符串 ID 和长度规则签发/验证。
4. Refresh token 使用 `sid.secret`，数据库只存 SHA-256，每次轮换且不滑动续期。
5. Logout 幂等，普通受保护接口严格拒绝失效 session。
6. 公开/自身资料字段边界固定，删除用户公开资料匿名化。
7. Frozen/banned/deleted/muted/pending/active 按状态矩阵生效。
8. Admin 不能操作自己或其他 admin，frozen admin 不能写，封禁撤销全部 session。
9. 状态修改、session 撤销和 audit 在同一事务，audit 失败不局部提交。
10. 过期 mute 懒恢复并在并发下最多写一条 system audit。
11. Login、refresh、logout、封禁、注销和禁言恢复遵循全局锁顺序和文档化线性化结果。
12. 默认测试不需要 PostgreSQL/Redis/Docker，并覆盖 service/handler 业务契约。
13. 显式 integration 测试覆盖 migration、DDL、repository、原子性和并发不变量。
14. `go test -count=1 ./...`、`go test -race -count=1 ./...`、`go vet ./...`、`go build ./...` 全部通过。
15. `go mod tidy` 后无未审查依赖漂移，`go mod verify` 通过。
16. README、`.env.example`、migration 文档和 API/运维说明与实现一致。
17. 用户未跟踪需求文档未被修改或提交。
