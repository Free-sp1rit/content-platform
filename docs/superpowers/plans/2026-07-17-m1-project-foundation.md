# M1 Project Foundation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a runnable, observable, migratable, and testable Go service foundation for M2–M8 without implementing business features.

**Architecture:** Use `system` as the only M1 business module, with its service and HTTP handler kept together. Put concrete configuration, logging, PostgreSQL, Redis, and migration adapters under `internal/infra`, reusable HTTP mechanics under `internal/platform`, and all dependency assembly and lifecycle control under `internal/app`.

**Tech Stack:** Go 1.26.4, `net/http`, `database/sql`, `log/slog`, pgx v5.10.0, go-redis v9.21.0, goose v3.27.1, caarlos0/env v11.4.1.

---

## File and responsibility map

| Path | Responsibility |
| --- | --- |
| `go.mod`, `go.sum` | Module identity, Go version, pinned M1 dependencies |
| `cmd/server/main.go` | Signal-aware server entry point and exit code |
| `cmd/migrate/main.go` | Explicit migration entry point |
| `internal/infra/config/config.go` | Environment loading, defaults, and validation |
| `internal/infra/logging/logging.go` | `slog` level/format parsing and construction |
| `internal/infra/postgres/postgres.go` | `database/sql` setup, initial ping, pool settings, readiness adapter |
| `internal/infra/redis/redis.go` | Redis construction and readiness adapter |
| `internal/infra/postgres/migration/migration.go` | Allowed goose commands and execution |
| `internal/platform/requestid/requestid.go` | Request ID validation, generation, context, and response header |
| `internal/platform/apperror/error.go` | Stable error kind/code/message/details/cause model |
| `internal/platform/httpx/response.go` | Uniform JSON success and error envelopes |
| `internal/platform/httpx/decode.go` | Size-limited strict JSON decoding |
| `internal/platform/httpx/middleware.go` | Chain, access log, recovery, and status capture |
| `internal/system/service/health.go` | Liveness/readiness orchestration and dependency state matrix |
| `internal/system/handler/http.go` | Health HTTP translation through a service interface |
| `internal/app/routes.go` | ServeMux routes, JSON 404/405, middleware order |
| `internal/app/app.go` | Concrete dependency construction |
| `internal/app/lifecycle.go` | Listen, graceful shutdown, resource cleanup |
| `internal/testkit/integration.go` | Build-tagged integration environment helpers |
| `migrations/README.md` | Migration naming, execution, and immutability rules |
| `.env.example`, `.gitignore` | Non-secret local environment template and tracking exception |
| `Makefile`, `README.md` | Reproducible development, test, migration, and operation workflow |

Tests live beside implementation packages. Files with `_integration_test.go` and `internal/testkit/integration.go` use the `integration` build tag and do not affect `go test ./...`.

## Task 1: Initialize the module and configuration contract

**Files:**
- Create: `go.mod`
- Create: `go.sum`
- Create: `internal/infra/config/config.go`
- Test: `internal/infra/config/config_test.go`

- [ ] **Step 1: Initialize the module and add the configuration dependency**

```bash
go mod init github.com/Free-sp1rit/content-platform
go get github.com/caarlos0/env/v11@v11.4.1
```

Expected: `go.mod` identifies the GitHub module and the installed Go 1.26.4 toolchain.

- [ ] **Step 2: Write failing configuration tests**

Create table tests for these exact behaviors:

```go
func TestLoadUsesDefaults(t *testing.T) {
    clearConfigEnvironment(t)
    t.Setenv("DATABASE_URL", "postgres://postgres:postgres@localhost/content_platform?sslmode=disable")
    cfg, err := Load()
    if err != nil {
        t.Fatalf("Load() error = %v", err)
    }
    if cfg.Environment != "local" || cfg.HTTP.Address != ":8080" {
        t.Fatalf("unexpected defaults: %#v", cfg)
    }
    if cfg.HTTP.ReadHeaderTimeout != 5*time.Second || cfg.Database.MaxOpenConns != 20 {
        t.Fatalf("unexpected timeout/pool defaults: %#v", cfg)
    }
    if cfg.Log.Level != "info" || cfg.Log.Format != "json" {
        t.Fatalf("unexpected log defaults: %#v", cfg.Log)
    }
}

func TestLoadRejectsInvalidConfiguration(t *testing.T) {
    tests := []struct {
        name    string
        env     map[string]string
        wantErr string
    }{
        {name: "missing database URL", env: map[string]string{}, wantErr: "DATABASE_URL is required"},
        {name: "invalid log level", env: map[string]string{"DATABASE_URL": "postgres://localhost/db", "LOG_LEVEL": "verbose"}, wantErr: "LOG_LEVEL"},
        {name: "invalid log format", env: map[string]string{"DATABASE_URL": "postgres://localhost/db", "LOG_FORMAT": "yaml"}, wantErr: "LOG_FORMAT"},
        {name: "idle exceeds open", env: map[string]string{"DATABASE_URL": "postgres://localhost/db", "DATABASE_MAX_OPEN_CONNS": "2", "DATABASE_MAX_IDLE_CONNS": "3"}, wantErr: "DATABASE_MAX_IDLE_CONNS"},
        {name: "zero shutdown timeout", env: map[string]string{"DATABASE_URL": "postgres://localhost/db", "HTTP_SHUTDOWN_TIMEOUT": "0s"}, wantErr: "HTTP_SHUTDOWN_TIMEOUT"},
    }
    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            clearConfigEnvironment(t)
            for key, value := range tt.env {
                t.Setenv(key, value)
            }
            _, err := Load()
            if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
                t.Fatalf("Load() error = %v, want substring %q", err, tt.wantErr)
            }
        })
    }
}
```

Use this test helper so host environment variables cannot make tests nondeterministic:

```go
func clearConfigEnvironment(t *testing.T) {
    t.Helper()
    keys := []string{
        "APP_ENV", "HTTP_ADDR", "HTTP_READ_HEADER_TIMEOUT", "HTTP_READ_TIMEOUT",
        "HTTP_WRITE_TIMEOUT", "HTTP_IDLE_TIMEOUT", "HTTP_SHUTDOWN_TIMEOUT",
        "DATABASE_URL", "DATABASE_MAX_OPEN_CONNS", "DATABASE_MAX_IDLE_CONNS",
        "DATABASE_CONN_MAX_LIFETIME", "DATABASE_PING_TIMEOUT", "REDIS_ADDR",
        "REDIS_PASSWORD", "REDIS_DB", "REDIS_PING_TIMEOUT", "LOG_LEVEL", "LOG_FORMAT",
    }
    for _, key := range keys {
        value, exists := os.LookupEnv(key)
        if err := os.Unsetenv(key); err != nil {
            t.Fatalf("Unsetenv(%q): %v", key, err)
        }
        t.Cleanup(func() {
            if exists {
                _ = os.Setenv(key, value)
                return
            }
            _ = os.Unsetenv(key)
        })
    }
}
```

- [ ] **Step 3: Verify the tests fail**

```bash
go test ./internal/infra/config -run 'TestLoad' -v
```

Expected: FAIL because `Load` and the configuration types do not exist.

- [ ] **Step 4: Implement configuration loading and validation**

Create these types and APIs:

```go
type Config struct {
    Environment string `env:"APP_ENV" envDefault:"local"`
    HTTP        HTTPConfig
    Database    DatabaseConfig
    Redis       RedisConfig
    Log         LogConfig
}

type HTTPConfig struct {
    Address           string        `env:"HTTP_ADDR" envDefault:":8080"`
    ReadHeaderTimeout time.Duration `env:"HTTP_READ_HEADER_TIMEOUT" envDefault:"5s"`
    ReadTimeout       time.Duration `env:"HTTP_READ_TIMEOUT" envDefault:"10s"`
    WriteTimeout      time.Duration `env:"HTTP_WRITE_TIMEOUT" envDefault:"15s"`
    IdleTimeout       time.Duration `env:"HTTP_IDLE_TIMEOUT" envDefault:"60s"`
    ShutdownTimeout   time.Duration `env:"HTTP_SHUTDOWN_TIMEOUT" envDefault:"10s"`
}

type DatabaseConfig struct {
    URL             string        `env:"DATABASE_URL"`
    MaxOpenConns    int           `env:"DATABASE_MAX_OPEN_CONNS" envDefault:"20"`
    MaxIdleConns    int           `env:"DATABASE_MAX_IDLE_CONNS" envDefault:"5"`
    ConnMaxLifetime time.Duration `env:"DATABASE_CONN_MAX_LIFETIME" envDefault:"30m"`
    PingTimeout     time.Duration `env:"DATABASE_PING_TIMEOUT" envDefault:"3s"`
}

type RedisConfig struct {
    Address     string        `env:"REDIS_ADDR" envDefault:"localhost:6379"`
    Password    string        `env:"REDIS_PASSWORD"`
    DB          int           `env:"REDIS_DB" envDefault:"0"`
    PingTimeout time.Duration `env:"REDIS_PING_TIMEOUT" envDefault:"2s"`
}

type LogConfig struct {
    Level  string `env:"LOG_LEVEL" envDefault:"info"`
    Format string `env:"LOG_FORMAT" envDefault:"json"`
}

func Load() (Config, error)
func (c Config) Validate() error
```

`Load` calls `env.Parse(&cfg)`, wraps parse failure as `parse configuration: %w`, then calls `Validate`. Validate every positive timeout, database URL presence, non-negative pool/Redis values, `idle <= open`, and the exact log level/format allowlists. Never include the database URL or Redis password in returned errors.

- [ ] **Step 5: Run tests and commit**

```bash
go test ./internal/infra/config -v
go test ./...
git add go.mod go.sum internal/infra/config
git commit -m "chore: initialize Go module and configuration"
```

Expected: PASS and one configuration-focused commit.

## Task 2: Add structured logging

**Files:**
- Create: `internal/infra/logging/logging.go`
- Test: `internal/infra/logging/logging_test.go`

- [ ] **Step 1: Write failing logger tests**

```go
func TestParseLevel(t *testing.T) {
    tests := []struct { input string; want slog.Level }{
        {input: "debug", want: slog.LevelDebug},
        {input: "info", want: slog.LevelInfo},
        {input: "warn", want: slog.LevelWarn},
        {input: "error", want: slog.LevelError},
    }
    for _, tt := range tests {
        got, err := ParseLevel(tt.input)
        if err != nil || got != tt.want {
            t.Fatalf("ParseLevel(%q) = %v, %v", tt.input, got, err)
        }
    }
    if _, err := ParseLevel("verbose"); err == nil {
        t.Fatal("ParseLevel(verbose) expected error")
    }
}

func TestNewJSONLoggerIncludesBaseFields(t *testing.T) {
    var output bytes.Buffer
    logger, err := New(config.LogConfig{Level: "info", Format: "json"}, &output, "test")
    if err != nil {
        t.Fatalf("New() error = %v", err)
    }
    logger.Info("started")
    for _, want := range []string{`"msg":"started"`, `"service":"content-platform"`, `"environment":"test"`} {
        if !strings.Contains(output.String(), want) {
            t.Fatalf("log output %q missing %q", output.String(), want)
        }
    }
}
```

- [ ] **Step 2: Verify red state**

```bash
go test ./internal/infra/logging -v
```

Expected: FAIL because the logging package does not exist.

- [ ] **Step 3: Implement logger construction**

```go
func ParseLevel(value string) (slog.Level, error)

func New(cfg config.LogConfig, output io.Writer, environment string) (*slog.Logger, error) {
    level, err := ParseLevel(cfg.Level)
    if err != nil {
        return nil, err
    }
    options := &slog.HandlerOptions{Level: level}
    var handler slog.Handler
    switch cfg.Format {
    case "json":
        handler = slog.NewJSONHandler(output, options)
    case "text":
        handler = slog.NewTextHandler(output, options)
    default:
        return nil, fmt.Errorf("unsupported log format %q", cfg.Format)
    }
    return slog.New(handler).With("service", "content-platform", "environment", environment), nil
}
```

`ParseLevel` uses an explicit switch for `debug`, `info`, `warn`, and `error`.

- [ ] **Step 4: Run tests and commit**

```bash
go test ./internal/infra/logging -v
git add internal/infra/logging
git commit -m "feat: add structured logging"
```

Expected: PASS.
 Expected: PASS.

## Task 3: Add request ID propagation

**Files:**
- Create: `internal/platform/requestid/requestid.go`
- Test: `internal/platform/requestid/requestid_test.go`

- [ ] **Step 1: Write failing request ID tests**

```go
func TestMiddlewarePropagatesValidRequestID(t *testing.T) {
    var contextID string
    next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        contextID = FromContext(r.Context())
        w.WriteHeader(http.StatusNoContent)
    })
    request := httptest.NewRequest(http.MethodGet, "/", nil)
    request.Header.Set(Header, "client-id_123")
    response := httptest.NewRecorder()
    Middleware(next).ServeHTTP(response, request)
    if contextID != "client-id_123" || response.Header().Get(Header) != contextID {
        t.Fatalf("context/header IDs differ: %q / %q", contextID, response.Header().Get(Header))
    }
}

func TestMiddlewareReplacesInvalidRequestID(t *testing.T) {
    request := httptest.NewRequest(http.MethodGet, "/", nil)
    request.Header.Set(Header, "invalid request id with spaces")
    response := httptest.NewRecorder()
    var contextID string
    Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        contextID = FromContext(r.Context())
    })).ServeHTTP(response, request)
    if contextID == "" || contextID == request.Header.Get(Header) || !Valid(contextID) {
        t.Fatalf("expected valid generated ID, got %q", contextID)
    }
}
```

- [ ] **Step 2: Verify red state**

```bash
go test ./internal/platform/requestid -v
```

Expected: FAIL because the package and functions do not exist.

- [ ] **Step 3: Implement the request ID package**

```go
const Header = "X-Request-ID"

func Valid(value string) bool
func WithContext(ctx context.Context, value string) context.Context
func FromContext(ctx context.Context) string
func Middleware(next http.Handler) http.Handler
```

Compile `^[A-Za-z0-9._:-]{1,128}$` once. Middleware accepts a valid incoming header or calls `crypto/rand.Text()`, stores the value under an unexported context key, and sets the response header before invoking the next handler. `WithContext` is used by tests and non-HTTP callers attaching an already validated ID.

- [ ] **Step 4: Run tests and commit**

```bash
go test ./internal/platform/requestid -v
git add internal/platform/requestid
git commit -m "feat: add request ID propagation"
```

Expected: PASS.

## Task 4: Add application errors and uniform JSON responses

**Files:**
- Create: `internal/platform/apperror/error.go`
- Test: `internal/platform/apperror/error_test.go`
- Create: `internal/platform/httpx/response.go`
- Create: `internal/platform/httpx/decode.go`
- Test: `internal/platform/httpx/response_test.go`
- Test: `internal/platform/httpx/decode_test.go`

- [ ] **Step 1: Write a failing application error test**

```go
func TestErrorWrapsCauseAndDetails(t *testing.T) {
    cause := errors.New("driver detail")
    err := Wrap(Conflict, "version_conflict", "resource version conflict", cause).
        WithDetails(map[string]any{"expected": 2})
    if !errors.Is(err, cause) {
        t.Fatal("wrapped cause is not discoverable")
    }
    got, ok := From(err)
    if !ok || got.Kind != Conflict || got.Code != "version_conflict" {
        t.Fatalf("From() = %#v, %v", got, ok)
    }
    if strings.Contains(err.Error(), "driver detail") {
        t.Fatalf("Error() leaks private cause: %q", err.Error())
    }
}
```

- [ ] **Step 2: Implement the application error model**

```go
type Kind string

const (
    InvalidArgument       Kind = "invalid_argument"
    Unauthenticated       Kind = "unauthenticated"
    PermissionDenied      Kind = "permission_denied"
    NotFound              Kind = "not_found"
    MethodNotAllowed      Kind = "method_not_allowed"
    Conflict              Kind = "conflict"
    RateLimited           Kind = "rate_limited"
    Internal              Kind = "internal_error"
    DependencyUnavailable Kind = "dependency_unavailable"
)

type Error struct {
    Kind    Kind
    Code    string
    Message string
    Details any
    cause   error
}

func New(kind Kind, code, message string) *Error
func Wrap(kind Kind, code, message string, cause error) *Error
func (e *Error) WithDetails(details any) *Error
func (e *Error) Error() string
func (e *Error) Unwrap() error
func From(err error) (*Error, bool)
```

`Error()` returns only the safe public message. `From` uses `errors.As` so wrapped application errors remain discoverable.

- [ ] **Step 3: Write failing response and decoder tests**

```go
func TestWriteDataUsesEnvelope(t *testing.T) {
    ctx := requestid.WithContext(context.Background(), "request-123")
    response := httptest.NewRecorder()
    WriteData(ctx, response, http.StatusOK, map[string]string{"status": "ok"})
    if response.Code != http.StatusOK || response.Header().Get("Content-Type") != "application/json; charset=utf-8" {
        t.Fatalf("unexpected metadata: %d %q", response.Code, response.Header().Get("Content-Type"))
    }
    if !strings.Contains(response.Body.String(), `"request_id":"request-123"`) {
        t.Fatalf("missing request ID: %s", response.Body.String())
    }
}

func TestWriteErrorHidesUnknownCause(t *testing.T) {
    response := httptest.NewRecorder()
    logger := slog.New(slog.NewTextHandler(io.Discard, nil))
    WriteError(context.Background(), response, logger, errors.New("secret SQL error"))
    if response.Code != http.StatusInternalServerError || strings.Contains(response.Body.String(), "secret SQL error") {
        t.Fatalf("unsafe response: %d %s", response.Code, response.Body.String())
    }
}

func TestDecodeJSONRejectsUnknownAndTrailingValues(t *testing.T) {
    type input struct { Name string `json:"name"` }
    for _, body := range []string{`{"name":"ok","extra":true}`, `{"name":"ok"}{"name":"two"}`} {
        request := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
        response := httptest.NewRecorder()
        var dst input
        if err := DecodeJSON(response, request, &dst, 1024); err == nil {
            t.Fatalf("DecodeJSON(%q) expected error", body)
        }
    }
}

func TestDecodeJSONRejectsOversizedBody(t *testing.T) {
    request := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"name":"too long"}`))
    response := httptest.NewRecorder()
    var dst map[string]string
    if err := DecodeJSON(response, request, &dst, 8); err == nil {
        t.Fatal("DecodeJSON() expected body-size error")
    }
}
```

- [ ] **Step 4: Implement response and decoder APIs**

```go
func WriteData(ctx context.Context, w http.ResponseWriter, status int, data any)
func WriteError(ctx context.Context, w http.ResponseWriter, logger *slog.Logger, err error)
func DecodeJSON(w http.ResponseWriter, r *http.Request, dst any, maxBytes int64) error
```

Success JSON is `{"data":...,"meta":{"request_id":"..."}}`. Error JSON is `{"error":{"code":"...","message":"...","details":...},"meta":{"request_id":"..."}}`, with details omitted when nil. Map kinds to the status table in the design. Unknown errors are logged with request ID and become `500 internal_error`. `DecodeJSON` applies `http.MaxBytesReader`, calls `DisallowUnknownFields`, requires exactly one JSON value, and returns `invalid_argument` with safe message `request body is invalid` for all client decode failures.

- [ ] **Step 5: Run platform tests and commit**

```bash
go test ./internal/platform/... -v
git add internal/platform/apperror internal/platform/httpx internal/platform/requestid
git commit -m "feat: add application errors and JSON responses"
```

Expected: PASS.

## Task 5: Add access logging and panic recovery

**Files:**
- Create: `internal/platform/httpx/middleware.go`
- Test: `internal/platform/httpx/middleware_test.go`

- [ ] **Step 1: Write failing middleware tests**

```go
func TestRecoveryProduces500AndAccessLogRecords500(t *testing.T) {
    var logs bytes.Buffer
    logger := slog.New(slog.NewJSONHandler(&logs, nil))
    handler := Chain(
        http.HandlerFunc(func(http.ResponseWriter, *http.Request) { panic("boom") }),
        requestid.Middleware,
        AccessLog(logger),
        Recovery(logger),
    )
    response := httptest.NewRecorder()
    handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/panic", nil))
    if response.Code != http.StatusInternalServerError {
        t.Fatalf("status = %d", response.Code)
    }
    if !strings.Contains(logs.String(), `"status":500`) || !strings.Contains(logs.String(), `"request_id":`) {
        t.Fatalf("unexpected logs: %s", logs.String())
    }
}

func TestAccessLogUsesRemoteAddr(t *testing.T) {
    var logs bytes.Buffer
    request := httptest.NewRequest(http.MethodGet, "/", nil)
    request.RemoteAddr = "192.0.2.10:4567"
    request.Header.Set("X-Forwarded-For", "203.0.113.9")
    response := httptest.NewRecorder()
    AccessLog(slog.New(slog.NewJSONHandler(&logs, nil)))(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
        w.WriteHeader(http.StatusNoContent)
    })).ServeHTTP(response, request)
    if !strings.Contains(logs.String(), `"remote_ip":"192.0.2.10"`) || strings.Contains(logs.String(), "203.0.113.9") {
        t.Fatalf("unexpected remote IP log: %s", logs.String())
    }
}
```

- [ ] **Step 2: Verify red state**

```bash
go test ./internal/platform/httpx -run 'TestRecovery|TestAccessLog' -v
```

Expected: FAIL because middleware primitives do not exist.

- [ ] **Step 3: Implement middleware primitives**

```go
type Middleware func(http.Handler) http.Handler

func Chain(handler http.Handler, middleware ...Middleware) http.Handler
func AccessLog(logger *slog.Logger) Middleware
func Recovery(logger *slog.Logger) Middleware
```

`Chain` applies the list in reverse so its written order is the inbound order. The response recorder captures the first status, defaults to `200` on body write, and implements `Unwrap() http.ResponseWriter`. AccessLog logs exactly once after completion with `request_id`, `method`, `path`, `status`, `duration_ms`, `remote_ip`, and `user_agent`; remote IP comes only from `RemoteAddr`. Recovery logs the panic, request ID, and `debug.Stack()`, then uses `WriteError` with an internal application error.

- [ ] **Step 4: Run tests and commit**

```bash
go test ./internal/platform/httpx -v
git add internal/platform/httpx
git commit -m "feat: add HTTP middleware foundation"
```

Expected: PASS and the panic access log reports status 500.
 Expected: PASS and the panic access log reports status 500.

## Task 6: Add PostgreSQL and Redis infrastructure

**Files:**
- Create: `internal/infra/postgres/postgres.go`
- Test: `internal/infra/postgres/postgres_test.go`
- Create: `internal/infra/redis/redis.go`
- Test: `internal/infra/redis/redis_test.go`
- Modify: `go.mod`
- Modify: `go.sum`

- [ ] **Step 1: Add pinned client dependencies**

```bash
go get github.com/jackc/pgx/v5@v5.10.0
go get github.com/redis/go-redis/v9@v9.21.0
```

- [ ] **Step 2: Write failing deterministic unit tests**

PostgreSQL pool configuration is tested without establishing a network connection:

```go
func TestConfigurePool(t *testing.T) {
    db, err := sql.Open("pgx", "postgres://localhost/content_platform?sslmode=disable")
    if err != nil {
        t.Fatal(err)
    }
    t.Cleanup(func() { _ = db.Close() })
    cfg := config.DatabaseConfig{MaxOpenConns: 12, MaxIdleConns: 4, ConnMaxLifetime: time.Minute}
    configurePool(db, cfg)
    if got := db.Stats().MaxOpenConnections; got != 12 {
        t.Fatalf("MaxOpenConnections = %d", got)
    }
}

func TestOpenRejectsMalformedURLWithoutLeakingIt(t *testing.T) {
    secretURL := "not-a-postgres-url-with-secret"
    _, err := Open(context.Background(), config.DatabaseConfig{URL: secretURL, PingTimeout: time.Second})
    if err == nil || strings.Contains(err.Error(), secretURL) {
        t.Fatalf("Open() error is missing or leaks URL: %v", err)
    }
}
```

Redis construction is tested without connecting:

```go
func TestNewUsesConfiguration(t *testing.T) {
    client := New(config.RedisConfig{Address: "redis.example:6380", Password: "secret", DB: 3})
    t.Cleanup(func() { _ = client.Close() })
    options := client.Options()
    if options.Addr != "redis.example:6380" || options.Password != "secret" || options.DB != 3 {
        t.Fatalf("unexpected Redis options: %#v", options)
    }
}
```

- [ ] **Step 3: Verify red state**

```bash
go test ./internal/infra/postgres ./internal/infra/redis -v
```

Expected: FAIL because constructors and checkers do not exist.

- [ ] **Step 4: Implement PostgreSQL setup**

```go
func Open(ctx context.Context, cfg config.DatabaseConfig) (*sql.DB, error)

type Checker struct { DB *sql.DB }
func (c Checker) Ping(ctx context.Context) error
```

`Open` validates the DSN with `pgx.ParseConfig`, opens `database/sql` through `pgx/v5/stdlib`, applies pool settings, and performs initial `PingContext` under `cfg.PingTimeout`. Close the DB on ping failure. Errors name the stage (`parse database configuration`, `open database`, or `ping database`) but never interpolate the DSN.

- [ ] **Step 5: Implement Redis setup**

```go
func New(cfg config.RedisConfig) *redis.Client

type Checker struct { Client *redis.Client }
func (c Checker) Ping(ctx context.Context) error
```

`New` only constructs the client. The initial ping and degraded startup decision remain in `internal/app`.

- [ ] **Step 6: Run tests, tidy, verify, and commit**

```bash
go test ./internal/infra/postgres ./internal/infra/redis -v
go mod tidy
go mod verify
git add go.mod go.sum internal/infra/postgres internal/infra/redis
git commit -m "feat: add database and Redis infrastructure"
```

Expected: PASS with pgx and go-redis pinned at the required versions.

## Task 7: Add health service, handlers, and routes

**Files:**
- Create: `internal/system/service/health.go`
- Test: `internal/system/service/health_test.go`
- Create: `internal/system/handler/http.go`
- Test: `internal/system/handler/http_test.go`
- Create: `internal/app/routes.go`
- Test: `internal/app/routes_test.go`

- [ ] **Step 1: Write failing readiness service tests**

```go
func TestReadinessMatrix(t *testing.T) {
    tests := []struct {
        name      string
        postgres error
        redis    error
        want      Status
    }{
        {name: "ready", want: Ready},
        {name: "Redis degraded", redis: errors.New("down"), want: Degraded},
        {name: "PostgreSQL unavailable", postgres: errors.New("down"), want: NotReady},
        {name: "both unavailable", postgres: errors.New("down"), redis: errors.New("down"), want: NotReady},
    }
    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            service := New(fakeChecker{err: tt.postgres}, fakeChecker{err: tt.redis}, time.Second, time.Second)
            got := service.Readiness(context.Background())
            if got.Status != tt.want {
                t.Fatalf("status = %q, want %q", got.Status, tt.want)
            }
        })
    }
}

func TestReadinessHonorsDependencyTimeout(t *testing.T) {
    service := New(blockingChecker{}, fakeChecker{}, 10*time.Millisecond, time.Second)
    started := time.Now()
    got := service.Readiness(context.Background())
    if got.Status != NotReady || time.Since(started) > 250*time.Millisecond {
        t.Fatalf("timeout result = %#v after %s", got, time.Since(started))
    }
}
```

The fake checker returns its configured error. The blocking checker waits for `ctx.Done()` and returns `ctx.Err()`.

- [ ] **Step 2: Implement the health service**

```go
type Checker interface { Ping(context.Context) error }
type Status string
type DependencyState string

const (
    Ready    Status = "ready"
    Degraded Status = "degraded"
    NotReady Status = "not_ready"
    Up       DependencyState = "up"
    Down     DependencyState = "down"
)

type Liveness struct { Status string `json:"status"` }
type Readiness struct {
    Status Status                     `json:"status"`
    Checks map[string]DependencyState `json:"checks"`
}

type Service struct {
    postgres        Checker
    redis           Checker
    postgresTimeout time.Duration
    redisTimeout    time.Duration
}

func New(postgres, redis Checker, postgresTimeout, redisTimeout time.Duration) *Service
func (s *Service) Liveness(context.Context) Liveness
func (s *Service) Readiness(context.Context) Readiness
```

Readiness runs both checks concurrently with separate timeout contexts, exposes only `up/down`, and derives status from PostgreSQL first and Redis second.

- [ ] **Step 3: Write failing handler and route tests**

Handler tests use a fake service and assert `200 ready`, `200 degraded`, and `503 dependency_unavailable`. Route tests assert uniform JSON fallbacks:

```go
func TestRoutesReturnUniformNotFoundAndMethodNotAllowed(t *testing.T) {
    logger := slog.New(slog.NewTextHandler(io.Discard, nil))
    routes := Routes(logger, handler.New(fakeHealthService{}))
    tests := []struct {
        method string
        path   string
        status int
        code   string
    }{
        {method: http.MethodGet, path: "/missing", status: http.StatusNotFound, code: "not_found"},
        {method: http.MethodPost, path: "/healthz", status: http.StatusMethodNotAllowed, code: "method_not_allowed"},
    }
    for _, tt := range tests {
        response := httptest.NewRecorder()
        routes.ServeHTTP(response, httptest.NewRequest(tt.method, tt.path, nil))
        if response.Code != tt.status || !strings.Contains(response.Body.String(), `"code":"`+tt.code+`"`) {
            t.Fatalf("%s %s = %d %s", tt.method, tt.path, response.Code, response.Body.String())
        }
    }
}
```

- [ ] **Step 4: Implement the health handler**

```go
type HealthService interface {
    Liveness(context.Context) service.Liveness
    Readiness(context.Context) service.Readiness
}

type Handler struct { service HealthService }
func New(service HealthService) *Handler
func (h *Handler) Health(w http.ResponseWriter, r *http.Request)
func (h *Handler) Ready(w http.ResponseWriter, r *http.Request)
```

Ready writes data for ready/degraded. For not-ready it writes a dependency-unavailable application error with code `dependency_unavailable`, message `service is not ready`, and `details.checks` from the service result.

- [ ] **Step 5: Implement routes and the corrected middleware order**

```go
func Routes(logger *slog.Logger, health *handler.Handler) http.Handler
```

Register `GET /healthz`, `/healthz` method fallback, `GET /readyz`, `/readyz` method fallback, and `/` not-found fallback. Method fallback returns JSON code `method_not_allowed` and 405. Not-found returns JSON code `not_found` and 404. Wrap the mux with:

```go
httpx.Chain(mux,
    requestid.Middleware,
    httpx.AccessLog(logger),
    httpx.Recovery(logger),
)
```

- [ ] **Step 6: Run tests and commit**

```bash
go test ./internal/system/... ./internal/app -run 'TestReadiness|TestHealth|TestReady|TestRoutes' -v
git add internal/system internal/app/routes.go internal/app/routes_test.go
git commit -m "feat: add health and readiness endpoints"
```

Expected: PASS with the exact readiness matrix and uniform 404/405 responses.

## Task 8: Assemble the application and graceful lifecycle

**Files:**
- Create: `internal/app/app.go`
- Create: `internal/app/lifecycle.go`
- Test: `internal/app/lifecycle_test.go`
- Create: `cmd/server/main.go`

- [ ] **Step 1: Write a failing lifecycle test**

```go
func TestServeShutsDownAndClosesResources(t *testing.T) {
    listener, err := net.Listen("tcp", "127.0.0.1:0")
    if err != nil {
        t.Fatal(err)
    }
    first := &recordingCloser{}
    second := &recordingCloser{}
    application := &App{
        server: &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
            w.WriteHeader(http.StatusNoContent)
        })},
        logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
        shutdownTimeout: time.Second,
        closers: []io.Closer{first, second},
    }
    ctx, cancel := context.WithCancel(context.Background())
    done := make(chan error, 1)
    go func() { done <- application.Serve(ctx, listener) }()
    cancel()
    if err := <-done; err != nil {
        t.Fatalf("Serve() error = %v", err)
    }
    if !first.closed || !second.closed {
        t.Fatalf("resources not closed: first=%v second=%v", first.closed, second.closed)
    }
}
```

- [ ] **Step 2: Verify red state**

```bash
go test ./internal/app -run TestServeShutsDownAndClosesResources -v
```

Expected: FAIL because `App` and `Serve` do not exist.

- [ ] **Step 3: Implement concrete application assembly**

```go
type App struct {
    server          *http.Server
    logger          *slog.Logger
    shutdownTimeout time.Duration
    closers         []io.Closer
}

func New(ctx context.Context, cfg config.Config, logger *slog.Logger) (*App, error)
func (a *App) Run(ctx context.Context) error
func (a *App) Serve(ctx context.Context, listener net.Listener) error
```

New opens and pings PostgreSQL, constructs Redis, performs an initial Redis ping under its configured timeout, logs WARN and continues on Redis failure, creates service/handler/routes, and constructs `http.Server` with all configured timeouts. Store Redis then PostgreSQL in the closer list. If construction fails after a resource opens, close all already-created resources before returning.

- [ ] **Step 4: Implement graceful run and cleanup**

`Run` creates a TCP listener for `server.Addr` and calls `Serve`. Serve starts `server.Serve` in a buffered channel and selects between serve failure and root cancellation. On cancellation, call `server.Shutdown` with timeout, force `server.Close` if shutdown fails, wait for the serve goroutine, close every resource exactly once, and return `errors.Join` of non-`http.ErrServerClosed` failures. If serving fails before context cancellation, close the same resources before returning that serve error.

- [ ] **Step 5: Implement the signal-aware entry point**

```go
func main() { os.Exit(runMain()) }

func runMain() int {
    ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
    defer stop()
    cfg, err := config.Load()
    if err != nil {
        fmt.Fprintf(os.Stderr, "load configuration: %v\n", err)
        return 1
    }
    logger, err := logging.New(cfg.Log, os.Stdout, cfg.Environment)
    if err != nil {
        fmt.Fprintf(os.Stderr, "initialize logging: %v\n", err)
        return 1
    }
    application, err := app.New(ctx, cfg, logger)
    if err != nil {
        logger.Error("initialize application", "error", err)
        return 1
    }
    if err := application.Run(ctx); err != nil {
        logger.Error("run application", "error", err)
        return 1
    }
    return 0
}
```

- [ ] **Step 6: Run lifecycle tests, build, and commit**

```bash
go test ./internal/app -v
go build -o /tmp/content-platform-server ./cmd/server
git add cmd/server internal/app
git commit -m "feat: add server lifecycle and dependency assembly"
```

Expected: PASS and the server command builds.

## Task 9: Add migration and integration test tooling

**Files:**
- Create: `internal/infra/postgres/migration/migration.go`
- Test: `internal/infra/postgres/migration/migration_test.go`
- Create: `cmd/migrate/main.go`
- Create: `internal/testkit/integration.go`
- Create: `internal/infra/postgres/postgres_integration_test.go`
- Create: `internal/infra/redis/redis_integration_test.go`
- Create: `internal/infra/postgres/migration/migration_integration_test.go`
- Create: `migrations/00001_m1_baseline.sql`
- Create: `migrations/README.md`
- Modify: `go.mod`
- Modify: `go.sum`

- [ ] **Step 1: Add goose at the required version**

```bash
go get github.com/pressly/goose/v3@v3.27.1
```

- [ ] **Step 2: Write failing command validation tests**

```go
func TestValidateCommand(t *testing.T) {
    for _, command := range []string{"up", "status", "version", "down-one"} {
        if err := ValidateCommand(command); err != nil {
            t.Fatalf("ValidateCommand(%q) error = %v", command, err)
        }
    }
    if err := ValidateCommand("reset"); err == nil {
        t.Fatal("ValidateCommand(reset) expected error")
    }
}
```

- [ ] **Step 3: Implement migration execution**

```go
func ValidateCommand(command string) error
func Run(ctx context.Context, db *sql.DB, directory, command string) error
```

Validate only `up`, `status`, `version`, and `down-one`. Run sets the goose dialect to PostgreSQL and calls `goose.RunContext(ctx, command, db, directory)`. Errors include the command name but not database configuration.

- [ ] **Step 4: Implement `cmd/migrate`**

Accept exactly one positional command. Read `MIGRATIONS_DIR`, defaulting to `./migrations`. Load application config, initialize logging, open PostgreSQL, defer close, and call `migration.Run`. Do not initialize Redis or HTTP. Return a non-zero exit code for argument, connection, or migration failures.

- [ ] **Step 5: Add build-tagged integration helpers and tests**

`internal/testkit/integration.go` starts with:

```go
//go:build integration
```

and defines:

```go
func DatabaseURL(t testing.TB) string
func RedisAddress(t testing.TB) string
```

Each helper calls `t.Helper()`, returns `TEST_DATABASE_URL` or `TEST_REDIS_ADDR`, and calls `t.Skip` with a precise message when absent.

All integration test files use the same build tag:

- PostgreSQL: open with `TEST_DATABASE_URL`, ping, and close.
- Redis: create with `TEST_REDIS_ADDR`, ping through the checker, and close.
- Migration: locate the repository `migrations` directory, open PostgreSQL, call `Run(..., "up")`, then `Run(..., "status")`; the baseline must create only goose's version table.

- [ ] **Step 6: Document migration rules**

Create `00001_m1_baseline.sql` with `SELECT 1` in both goose Up and Down sections. `migrations/README.md` explains that the baseline exists because goose rejects an empty directory, defines the `00002_description.sql` convention for the first business migration, and records immutability and repair-through-new-migration rules.

- [ ] **Step 7: Run unit checks, build, tidy, and commit**

```bash
go test ./internal/infra/postgres/migration -v
go build -o /tmp/content-platform-migrate ./cmd/migrate
go mod tidy
go mod verify
git add cmd/migrate internal/infra/postgres/migration internal/infra/postgres/postgres_integration_test.go internal/infra/redis/redis_integration_test.go internal/testkit migrations go.mod go.sum
git commit -m "feat: add migration and integration test tooling"
```

Expected: unit tests and build PASS. Integration tests run in Task 10 when dependencies are available.

## Task 10: Add developer workflow and run complete verification

**Files:**
- Modify: `.gitignore`
- Create: `.env.example`
- Create: `Makefile`
- Modify: `README.md`
- Modify: `docs/superpowers/specs/2026-07-17-m1-project-foundation-design.md`

- [ ] **Step 1: Allow and create the environment template**

Add after `.env.*`:

```gitignore
!.env.example
```

Create `.env.example` with every variable from the design and only non-secret local values.

- [ ] **Step 2: Create the Makefile**

```make
.PHONY: run fmt vet test test-race test-integration migrate-up migrate-status migrate-down-one

run:
	go run ./cmd/server

fmt:
	gofmt -w $$(find . -name '*.go' -not -path './vendor/*')

vet:
	go vet ./...

test:
	go test ./...

test-race:
	go test -race ./...

test-integration:
	@test -n "$$TEST_DATABASE_URL" || (echo "TEST_DATABASE_URL is required" >&2; exit 1)
	@test -n "$$TEST_REDIS_ADDR" || (echo "TEST_REDIS_ADDR is required" >&2; exit 1)
	go test -count=1 -tags=integration ./...

migrate-up:
	go run ./cmd/migrate up

migrate-status:
	go run ./cmd/migrate status

migrate-down-one:
	go run ./cmd/migrate down-one
```

- [ ] **Step 3: Write the README**

Include executable sections for Go 1.26.4, module path, exporting `.env`, preparing PostgreSQL and optional Redis without Docker Compose, running server/migrations, liveness versus readiness, the ready/degraded/not-ready matrix, unit/race/integration tests, graceful shutdown, M1 exclusions, and the M2 `identity` entry point.

- [ ] **Step 4: Run formatting and deterministic module checks**

```bash
make fmt
go mod tidy
git diff --exit-code -- go.mod go.sum
go mod verify
```

Expected: PASS and tidy leaves module files unchanged.

- [ ] **Step 5: Run the complete default suite**

```bash
go build ./...
go vet ./...
go test ./...
go test -race ./...
```

Expected: every command exits 0.

- [ ] **Step 6: Run integration and live checks when dependencies are available**

```bash
make test-integration
go run ./cmd/migrate up
go run ./cmd/migrate status
```

Start the server, call `/healthz` and `/readyz`, send SIGINT, and confirm shutdown logs. Stop Redis temporarily and confirm `200 degraded`; stop PostgreSQL after startup and confirm `503 not_ready`. If dependencies cannot be provided, do not claim these checks passed; record the exact environment blocker in the PR.

- [ ] **Step 7: Mark the design implemented after verification**

Only after required verification passes, change the design status from `已确认，待实现` to `已实现并验证`.

- [ ] **Step 8: Commit workflow documentation**

```bash
git add .gitignore .env.example Makefile README.md docs/superpowers/specs/2026-07-17-m1-project-foundation-design.md
git commit -m "docs: document M1 development workflow"
```

- [ ] **Step 9: Review branch scope**

```bash
git status --short
git log --oneline --decorate origin/main..HEAD
git diff --stat origin/main...HEAD
git diff --check origin/main...HEAD
```

Expected: only M1 implementation and documentation are committed. The user-authored untracked requirements document remains untouched unless separately authorized for version control.

## Task 11: Push the branch and create the PR

**Files:**
- No source changes expected.

- [ ] **Step 1: Run fresh completion verification**

Invoke `superpowers:verification-before-completion`, rerun build, vet, default tests, race tests, module verification, and every available integration/live check. Capture fresh exact results.

- [ ] **Step 2: Request code review**

Invoke `superpowers:requesting-code-review` against `origin/main...HEAD`. Fix each confirmed correctness, security, scope, test, or maintainability issue and rerun affected verification.

- [ ] **Step 3: Push without force**

```bash
git push -u origin feat/project-foundation
```

- [ ] **Step 4: Create a PR targeting main**

```bash
gh pr create --base main --head feat/project-foundation --title "feat: establish M1 project foundation" --body-file /tmp/content-platform-m1-pr.md
```

The PR body includes architecture, PostgreSQL-required/Redis-degraded semantics, separate migration process, exact verification results, unrun environment-dependent checks, explicit exclusions, and the recommended M2 entry point.

- [ ] **Step 5: Confirm PR state and hand off**

```bash
gh pr view --json number,url,title,baseRefName,headRefName,state,statusCheckRollup
```

Expected: an open PR from `feat/project-foundation` to `main`. Report its URL, commits, verification evidence, untracked files left untouched, and pending remote checks.
