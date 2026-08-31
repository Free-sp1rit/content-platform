# M1 配置校验与敏感信息保护加固设计

日期：2026-08-06
状态：已实现

## 1. 背景

M1 已经通过 `github.com/caarlos0/env/v11` 完成环境变量加载，并为 HTTP、PostgreSQL、Redis 和日志配置提供启动前校验。当前实现可以满足基础启动需求，但代码审查发现以下问题：

- 根 `Config.Validate()` 集中维护所有子配置规则，后续扩展时职责会持续膨胀；
- 现有无效配置测试只覆盖部分代表场景，零值、负值、字段关系、格式和标准化边界不完整；
- `DATABASE_MAX_OPEN_CONNS=0` 当前会通过校验，而 `database/sql` 会把它解释为不限制连接数；
- 测试失败信息会通过 `%#v` 输出完整配置，可能把数据库凭据和 Redis 密码写入 CI 日志；
- 日志级别与格式使用裸字符串，配置包和日志包重复维护同一组魔法字符串；
- HTTP、Redis 地址只检查非空，数据库连接信息直到基础设施初始化时才验证实际格式；
- 字符串配置的首尾空白和大小写处理缺少统一策略。

本次变更是对 M1 基础工程的定向加固，不改变“业务模块优先、模块内分层、基础设施集中实现”的整体架构。

## 2. 目标

本次设计需要达到以下目标：

1. 让每个子配置类型维护自己的不变量；
2. 明确所有配置零值、边界值和关联字段语义；
3. 在连接基础设施之前尽早拒绝明显错误的地址和数据库连接配置；
4. 防止通过标准结构化日志或测试失败信息泄漏数据库 URL 和 Redis 密码；
5. 用命名类型和常量表达有限集合，减少配置包与日志包之间的字符串重复；
6. 明确环境变量加载时的标准化规则；
7. 保持启动错误短小、确定且不包含敏感原值；
8. 使用表格驱动测试完整覆盖新增契约。

## 3. 非目标

本次不处理以下内容：

- 不把多个配置错误汇总为一个错误，仍返回第一个错误；
- 不把 `APP_ENV` 限制为固定环境枚举；
- 不引入通用配置框架、反射式验证器或第三方校验库；
- 不把密码和数据库 URL 改造成必须显式 `Reveal()` 的不透明秘密类型；
- 不支持运行时热更新配置；
- 不读取 `.env`、YAML、JSON 或远程配置中心；
- 不修改 PostgreSQL、Redis、HTTP 生命周期和 readiness 行为；
- 不重写已经推送的历史提交，也不强制推送分支。

## 4. 配置类型

### 4.1 Environment

`Environment` 使用命名字符串类型：

```go
type Environment string

const EnvironmentLocal Environment = "local"
```

`APP_ENV` 只要求标准化后非空，不使用 allowlist。这样可以继续支持 `preview`、`qa`、`sandbox`、`production-cn` 和蓝绿部署环境名。

环境名称保留用户提供的大小写，只去除首尾空白。日志中的 `environment` 字段使用标准化后的值。

### 4.2 LogLevel

日志级别使用命名类型和常量：

```go
type LogLevel string

const (
    LogLevelDebug LogLevel = "debug"
    LogLevelInfo  LogLevel = "info"
    LogLevelWarn  LogLevel = "warn"
    LogLevelError LogLevel = "error"
)
```

`LogConfig.Validate()` 只接受以上四个标准值。日志包的级别转换使用这些常量，不再重复硬编码裸字符串。

### 4.3 LogFormat

日志格式使用命名类型和常量：

```go
type LogFormat string

const (
    LogFormatJSON LogFormat = "json"
    LogFormatText LogFormat = "text"
)
```

`LogConfig.Validate()` 和 `logging.New()` 都使用上述常量。

日志包的相关签名同步使用配置类型：

```go
func ParseLevel(value config.LogLevel) (slog.Level, error)
func New(cfg config.LogConfig, output io.Writer, environment config.Environment) (*slog.Logger, error)
```

写入 `slog` 字段时显式把 `Environment` 转成字符串，避免依赖 handler 对命名字符串类型的隐式处理。

## 5. 加载、标准化与校验流程

`Load()` 按固定顺序执行：

```text
env.Parse
  -> normalize
  -> Config.Validate
  -> return Config
```

标准化发生在环境变量输入边界。`Validate()` 本身不修改接收者，直接构造配置的内部调用方应使用规范化值和已定义常量。

标准化规则如下：

| 字段 | 标准化规则 |
|---|---|
| `APP_ENV` | `strings.TrimSpace`，保留大小写 |
| `HTTP_ADDR` | `strings.TrimSpace` |
| `DATABASE_URL` | `strings.TrimSpace` |
| `REDIS_ADDR` | `strings.TrimSpace` |
| `REDIS_PASSWORD` | 完全保留原值，不去除空白、不改变大小写 |
| `LOG_LEVEL` | `strings.TrimSpace` 后转小写 |
| `LOG_FORMAT` | `strings.TrimSpace` 后转小写 |

整数和 duration 继续由 `env/v11` 解析。配置包不再为它们增加第二套字符串转换逻辑。

标准化作为 `Load()` 的内部步骤实现，不新增公开、可变的全局状态。

## 6. 校验职责

### 6.1 根配置

根配置只负责环境名称，并按确定顺序调用子配置：

```go
func (c Config) Validate() error
```

校验顺序保持为：

```text
Environment
  -> HTTP
  -> Database
  -> Redis
  -> Log
```

如果某一步失败，立即返回该错误，不再执行后续校验。

### 6.2 HTTPConfig

```go
func (c HTTPConfig) Validate() error
```

规则：

- `Address` 必须是合法 TCP `host:port` 结构；
- 使用 `net.SplitHostPort` 支持 `:8080`、`127.0.0.1:8080` 和 `[::1]:8080`；
- HTTP 监听地址允许空 host，表示监听所有适用接口；
- port 必须是十进制整数，并处于 `1..65535`；
- `ReadHeaderTimeout`、`ReadTimeout`、`WriteTimeout`、`IdleTimeout`、`ShutdownTimeout` 都必须大于零。

`HTTP_ADDR=:0` 不作为 M1 部署配置支持；需要随机端口的单元测试直接构造测试 listener，不通过生产环境配置启用。

HTTP 和 Redis 共用一个未导出的 TCP 地址解析辅助函数。辅助函数只返回解析结果或无敏感原值的错误，由调用方负责生成包含 `HTTP_ADDR` 或 `REDIS_ADDR` 的稳定错误消息。

### 6.3 DatabaseConfig

```go
func (c DatabaseConfig) Validate() error
```

规则：

- `URL` 必填；
- URL scheme 只能是 `postgres` 或 `postgresql`；
- URL path 去除开头的 `/` 后必须非空，数据库名不能只通过 query 参数提供；
- 使用 `pgx.ParseConfig` 再验证一次驱动实际接受的连接配置；
- `MaxOpenConns` 必须大于零；
- `MaxIdleConns` 可以为零，但不能为负数；
- `MaxIdleConns` 不能超过 `MaxOpenConns`；
- `ConnMaxLifetime` 和 `PingTimeout` 必须大于零。

连接池参数语义明确为：

| 参数 | 值 | 语义 |
|---|---:|---|
| `MaxOpenConns` | `< 0` | 非法，拒绝启动 |
| `MaxOpenConns` | `0` | 非法，拒绝启动，避免 `database/sql` 的无限连接语义 |
| `MaxOpenConns` | `> 0` | 最大打开连接数 |
| `MaxIdleConns` | `< 0` | 非法，拒绝启动 |
| `MaxIdleConns` | `0` | 合法，不保留空闲连接 |
| `MaxIdleConns` | `1..MaxOpenConns` | 合法，最大空闲连接数 |

`postgres.Open()` 保留现有 `pgx.ParseConfig`。配置层负责启动前反馈，基础设施层负责防御绕过 `Load()` 的直接调用。

数据库格式错误使用固定消息，不包装可能包含原始连接信息的解析错误。

### 6.4 RedisConfig

```go
func (c RedisConfig) Validate() error
```

规则：

- `Address` 必须是合法 TCP `host:port` 结构；
- 使用 `net.SplitHostPort`，支持域名、IPv4 和带方括号的 IPv6；
- host 不能为空；
- port 必须是十进制整数，并处于 `1..65535`；
- `DB` 不能为负数；
- `PingTimeout` 必须大于零；
- `Password` 可以为空，也可以包含首尾空白，配置层不修改密码。

M1 的 Redis 配置只支持 TCP 地址，不新增 Unix socket 配置。

### 6.5 LogConfig

```go
func (c LogConfig) Validate() error
```

规则：

- `Level` 必须是已定义的 `LogLevel` 常量；
- `Format` 必须是已定义的 `LogFormat` 常量。

从环境变量加载时会先执行去空白和小写标准化，因此 `LOG_LEVEL=" INFO "` 最终得到 `LogLevelInfo`。直接在 Go 代码中构造配置时应使用常量。

## 7. 错误策略

本次继续返回第一个配置错误。错误必须满足：

- 包含对应的环境变量名；
- 描述接受的范围或格式；
- 不包含数据库 URL、Redis 密码或其他敏感原值；
- 校验顺序确定，测试不依赖 map 遍历顺序；
- `env.Parse` 的类型解析错误继续包装为 `parse configuration: ...`；
- 自定义格式校验错误不包装底层 URL 或 pgx 解析错误。

示例：

```text
DATABASE_MAX_OPEN_CONNS must be greater than zero
DATABASE_MAX_IDLE_CONNS must not exceed DATABASE_MAX_OPEN_CONNS
DATABASE_URL must be a valid PostgreSQL URL
HTTP_ADDR must be a valid TCP address
REDIS_ADDR must be a valid TCP address with a host
```

多错误汇总推迟到真实部署反馈证明有必要时再设计。

## 8. 敏感信息保护

### 8.1 代码规则

应用代码和测试不得通过 `%v`、`%+v`、`%#v` 或等价方式输出完整 `Config`、`DatabaseConfig`、`RedisConfig`。

不得单独记录：

- `DatabaseConfig.URL`；
- `RedisConfig.Password`。

### 8.2 slog 防御

以下类型实现 `slog.LogValuer`：

- `Config`；
- `HTTPConfig`；
- `DatabaseConfig`；
- `RedisConfig`；
- `LogConfig`。

其中：

- 数据库 URL 统一输出为 `[REDACTED]`；
- Redis 密码统一输出为 `[REDACTED]`；
- 不输出秘密是否为空、长度、前缀或哈希；
- 其他连接池、超时、地址、Redis DB、日志级别和日志格式可以作为结构化字段输出。

根配置的安全日志结构固定为：

```text
config
├── environment
├── http
│   ├── address
│   └── 各 timeout
├── database
│   ├── url = [REDACTED]
│   ├── max_open_conns
│   ├── max_idle_conns
│   ├── conn_max_lifetime
│   └── ping_timeout
├── redis
│   ├── address
│   ├── password = [REDACTED]
│   ├── db
│   └── ping_timeout
└── log
    ├── level
    └── format
```

实现 `slog.LogValuer` 是误用防御，不代表应用应在正常启动路径主动记录完整配置。

Go 的导出字段无法从编译期绝对阻止 `fmt.Printf`，因此还需要通过字段级测试断言、代码审查和文档规范共同保证。

### 8.3 测试失败信息

配置测试只输出正在检查的字段，不输出整个对象。例如：

```go
t.Fatalf("Database.MaxOpenConns = %d, want %d", got, want)
```

涉及密码的测试只判断是否保持原值，不在失败消息中打印 `got` 或 `want`。

## 9. 测试设计

所有新增行为按 TDD 实现，先增加会因当前行为缺失而失败的测试，再写最小实现。

### 9.1 加载测试

表格驱动覆盖：

- 完整默认配置；
- 每组环境变量覆盖；
- 环境、HTTP 地址、数据库 URL、Redis 地址的首尾空白去除；
- 日志级别和格式的去空白及小写转换；
- Redis 密码原样保留；
- 非法整数和 duration 的解析错误；
- `Load()` 返回标准化后的命名类型。

### 9.2 子配置边界测试

每个 `Validate()` 使用独立表格，至少覆盖：

- 所有 duration 的零值和负值；
- HTTP/Redis 地址缺少端口、非法端口、越界端口和 IPv6；
- 数据库 URL 缺失、非法 scheme、缺少数据库名和 pgx 不接受的格式；
- 格式错误消息不回显包含密码的数据库 URL；
- `MaxOpenConns` 的负数、零和最小合法值；
- `MaxIdleConns` 的负数、零、等于 open 和超过 open；
- Redis DB 的负数与零；
- 所有合法、非法日志级别和格式；
- 根 `Config.Validate()` 的委托顺序和第一个错误语义。

### 9.3 脱敏测试

使用包含唯一秘密标记的配置，例如：

```text
db-password-do-not-log
redis-password-do-not-log
```

分别把根配置、数据库子配置和 Redis 子配置传给 JSON `slog` handler，并断言：

- 输出中不包含任何秘密标记；
- 对应敏感字段输出为 `[REDACTED]`；
- 非敏感字段仍可用于诊断；
- 测试失败消息本身不插入秘密值。

### 9.4 回归验证

实现完成后至少运行：

```bash
go test -count=1 ./internal/infra/config ./internal/infra/logging ./internal/infra/postgres
go test -count=1 ./...
go test -race -count=1 ./...
go vet ./...
go build ./...
```

如果改动影响集成配置，再运行现有 build-tagged integration tests。

## 10. 文档变更

实现时同步更新：

- M1 总体设计中的连接池规则；
- README 中 `MaxOpenConns=0` 和 `MaxIdleConns=0` 的语义；
- README 中输入标准化与敏感配置日志规则；
- `.env.example` 中为 `DATABASE_MAX_OPEN_CONNS` 和 `DATABASE_MAX_IDLE_CONNS` 增加零值语义注释。

不会向 `.env.example` 写入真实凭据，也不会提交本地 `.env`。

## 11. 兼容性与交付

这是 M1 尚未合并前的配置契约加固，不需要兼容已经发布的生产配置。

可能影响现有本地环境的行为变化包括：

- `DATABASE_MAX_OPEN_CONNS=0` 将从允许变为拒绝；
- 非法或缺少端口的 HTTP/Redis 地址会在 `Load()` 阶段失败；
- 非 PostgreSQL URL 形式的数据库连接字符串会被拒绝；
- 日志级别和格式现在接受首尾空白及大小写变体，并返回规范化值。

当前功能分支和 PR 已存在。设计文档作为独立文档提交；实现使用新的修复提交，不修改或强制重写已经推送的 `bdf509e chore: initialize Go module and configuration`。

## 12. 验收标准

满足以下条件时，本次配置加固完成：

1. 根配置只负责根规则和子配置委托；
2. 每个子配置拥有独立、可直接测试的 `Validate()`；
3. `MaxOpenConns=0` 被拒绝，`MaxIdleConns=0` 被允许并有文档；
4. 地址和数据库 URL 在配置加载阶段完成语法校验；
5. 日志级别与格式由命名类型和常量表达；
6. 标准化规则与密码保留规则由自动化测试固定；
7. 通过 `slog` 记录根配置或敏感子配置不会出现数据库 URL 或 Redis 密码；
8. 配置测试失败信息不再输出完整配置；
9. 错误保持 fail-fast、确定且不包含敏感原值；
10. 单元测试、race、vet 和 build 全部通过；
11. M1 设计文档和 README 与实现语义一致。
