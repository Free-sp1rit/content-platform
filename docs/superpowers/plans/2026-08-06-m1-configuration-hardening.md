# M1 Configuration Hardening Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Harden M1 configuration loading, validation, typing, and structured-log redaction without changing application lifecycle or infrastructure behavior.

**Architecture:** Keep `config.go` responsible for configuration types, environment loading, normalization, and root delegation. Move field and cross-field rules into `validate.go`, and isolate safe `slog.LogValuer` representations in `log_value.go`; mirror those boundaries with focused test files. Preserve fail-fast validation order and retain defensive PostgreSQL parsing in `postgres.Open`.

**Tech Stack:** Go 1.26.4, `github.com/caarlos0/env/v11`, `github.com/jackc/pgx/v5`, standard-library `net`, `net/url`, `strconv`, `strings`, and `log/slog`.

---

## File map

| File | Responsibility |
|---|---|
| `internal/infra/config/config.go` | Configuration types, constants, `Load`, normalization, root validation delegation |
| `internal/infra/config/config_test.go` | Environment loading, defaults, overrides, normalization, parser failures, safe test diagnostics |
| `internal/infra/config/validate.go` | HTTP, PostgreSQL, Redis, and log validation plus private address/URL helpers |
| `internal/infra/config/validate_test.go` | Table-driven validation boundary tests and fail-fast ordering |
| `internal/infra/config/log_value.go` | Safe `slog.LogValuer` implementations and redaction marker |
| `internal/infra/config/log_value_test.go` | Root and child configuration log-redaction tests |
| `internal/infra/logging/logging.go` | Conversion from typed configuration values to `slog` handlers |
| `internal/infra/logging/logging_test.go` | Typed log-level/format behavior and base logger fields |
| `.env.example` | Operator-facing connection-pool zero-value comments |
| `README.md` | Configuration semantics, normalization, and logging safety |
| `docs/superpowers/specs/2026-07-17-m1-project-foundation-design.md` | M1 baseline rules aligned with the hardened contract |
| `docs/superpowers/specs/2026-08-06-m1-configuration-hardening-design.md` | Design status updated after implementation |

## Task 1: Add typed values and normalize environment input

**Files:**

- Modify: `internal/infra/config/config.go:11-124`
- Modify: `internal/infra/config/config_test.go:31-120`
- Modify: `internal/infra/logging/logging.go:11-46`
- Modify: `internal/infra/logging/logging_test.go:11-76`

- [ ] **Step 1: Replace unsafe whole-config test diagnostics**

Before running any new failing test, replace `TestLoadUsesDefaults` and `TestLoadParsesEnvironment` in `internal/infra/config/config_test.go` with safe field-level diagnostics:

```go
func TestLoadUsesDefaults(t *testing.T) {
    clearConfigEnvironment(t)
    t.Setenv("DATABASE_URL", "postgres://postgres:postgres@localhost/content_platform?sslmode=disable")

    cfg, err := Load()
    if err != nil {
        t.Fatalf("Load() error = %v", err)
    }

    if cfg.Environment != "local" {
        t.Fatalf("Environment = %q, want %q", cfg.Environment, "local")
    }
    if cfg.HTTP.Address != ":8080" {
        t.Fatalf("HTTP.Address = %q, want %q", cfg.HTTP.Address, ":8080")
    }
    if cfg.HTTP.ReadHeaderTimeout != 5*time.Second {
        t.Fatalf("HTTP.ReadHeaderTimeout = %v, want %v", cfg.HTTP.ReadHeaderTimeout, 5*time.Second)
    }
    if cfg.Database.MaxOpenConns != 20 {
        t.Fatalf("Database.MaxOpenConns = %d, want %d", cfg.Database.MaxOpenConns, 20)
    }
    if cfg.Log.Level != "info" {
        t.Fatalf("Log.Level = %q, want %q", cfg.Log.Level, "info")
    }
    if cfg.Log.Format != "json" {
        t.Fatalf("Log.Format = %q, want %q", cfg.Log.Format, "json")
    }
}

func TestLoadParsesEnvironment(t *testing.T) {
    clearConfigEnvironment(t)
    environment := map[string]string{
        "APP_ENV":                    "staging",
        "HTTP_ADDR":                  ":9090",
        "HTTP_READ_HEADER_TIMEOUT":   "2s",
        "HTTP_READ_TIMEOUT":          "3s",
        "HTTP_WRITE_TIMEOUT":         "4s",
        "HTTP_IDLE_TIMEOUT":          "5s",
        "HTTP_SHUTDOWN_TIMEOUT":      "6s",
        "DATABASE_URL":               "postgres://localhost/custom",
        "DATABASE_MAX_OPEN_CONNS":    "9",
        "DATABASE_MAX_IDLE_CONNS":    "3",
        "DATABASE_CONN_MAX_LIFETIME": "7m",
        "DATABASE_PING_TIMEOUT":      "8s",
        "REDIS_ADDR":                 "redis.example:6380",
        "REDIS_PASSWORD":             "secret",
        "REDIS_DB":                   "4",
        "REDIS_PING_TIMEOUT":         "9s",
        "LOG_LEVEL":                  "debug",
        "LOG_FORMAT":                 "text",
    }
    for key, value := range environment {
        t.Setenv(key, value)
    }

    cfg, err := Load()
    if err != nil {
        t.Fatalf("Load() error = %v", err)
    }

    if cfg.Environment != "staging" {
        t.Fatalf("Environment = %q, want %q", cfg.Environment, "staging")
    }
    if cfg.HTTP.Address != ":9090" {
        t.Fatalf("HTTP.Address = %q, want %q", cfg.HTTP.Address, ":9090")
    }
    if cfg.Database.MaxOpenConns != 9 {
        t.Fatalf("Database.MaxOpenConns = %d, want %d", cfg.Database.MaxOpenConns, 9)
    }
    if cfg.Database.ConnMaxLifetime != 7*time.Minute {
        t.Fatalf("Database.ConnMaxLifetime = %v, want %v", cfg.Database.ConnMaxLifetime, 7*time.Minute)
    }
    if cfg.Redis.Address != "redis.example:6380" {
        t.Fatalf("Redis.Address = %q, want %q", cfg.Redis.Address, "redis.example:6380")
    }
    if cfg.Redis.Password != "secret" {
        t.Fatal("Redis.Password did not preserve configured value")
    }
    if cfg.Redis.DB != 4 {
        t.Fatalf("Redis.DB = %d, want %d", cfg.Redis.DB, 4)
    }
    if cfg.Log.Level != "debug" {
        t.Fatalf("Log.Level = %q, want %q", cfg.Log.Level, "debug")
    }
    if cfg.Log.Format != "text" {
        t.Fatalf("Log.Format = %q, want %q", cfg.Log.Format, "text")
    }
}
```

Do not interpolate a database URL or Redis password into any failure message. This test-only safety change must precede RED runs so an unrelated failure cannot publish secrets to terminal or CI output.

- [ ] **Step 2: Verify the diagnostic-only change stays GREEN**

Run:

```bash
gofmt -w internal/infra/config/config_test.go
go test -count=1 ./internal/infra/config
```

Expected: PASS. This step changes test diagnostics only and must not alter configuration behavior.

- [ ] **Step 3: Write failing tests for typed constants and normalization**

Add this test to `internal/infra/config/config_test.go`:

```go
func TestLoadNormalizesNonSecretStringsAndPreservesPassword(t *testing.T) {
    clearConfigEnvironment(t)
    t.Setenv("APP_ENV", " Staging-Blue ")
    t.Setenv("HTTP_ADDR", " :9090 ")
    t.Setenv("DATABASE_URL", " postgres://localhost/custom ")
    t.Setenv("REDIS_ADDR", " redis.example:6380 ")
    t.Setenv("REDIS_PASSWORD", " secret with spaces ")
    t.Setenv("LOG_LEVEL", " WARN ")
    t.Setenv("LOG_FORMAT", " TEXT ")

    cfg, err := Load()
    if err != nil {
        t.Fatalf("Load() error = %v", err)
    }

    if cfg.Environment != Environment("Staging-Blue") {
        t.Fatalf("Environment = %q, want %q", cfg.Environment, "Staging-Blue")
    }
    if cfg.HTTP.Address != ":9090" {
        t.Fatalf("HTTP.Address = %q, want %q", cfg.HTTP.Address, ":9090")
    }
    if cfg.Database.URL != "postgres://localhost/custom" {
        t.Fatal("Database.URL was not normalized")
    }
    if cfg.Redis.Address != "redis.example:6380" {
        t.Fatalf("Redis.Address = %q, want %q", cfg.Redis.Address, "redis.example:6380")
    }
    if cfg.Redis.Password != " secret with spaces " {
        t.Fatal("Redis.Password was modified")
    }
    if cfg.Log.Level != LogLevelWarn {
        t.Fatalf("Log.Level = %q, want %q", cfg.Log.Level, LogLevelWarn)
    }
    if cfg.Log.Format != LogFormatText {
        t.Fatalf("Log.Format = %q, want %q", cfg.Log.Format, LogFormatText)
    }
}
```

Add a table-driven characterization test for existing `env/v11` parser failures:

```go
func TestLoadRejectsParserErrors(t *testing.T) {
    tests := []struct {
        name  string
        key   string
        value string
    }{
        {name: "invalid HTTP duration", key: "HTTP_READ_TIMEOUT", value: "not-a-duration"},
        {name: "invalid database pool size", key: "DATABASE_MAX_OPEN_CONNS", value: "many"},
        {name: "invalid Redis database", key: "REDIS_DB", value: "db-zero"},
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            clearConfigEnvironment(t)
            t.Setenv("DATABASE_URL", "postgres://localhost/content_platform")
            t.Setenv(tt.key, tt.value)

            _, err := Load()
            if err == nil || !strings.Contains(err.Error(), "parse configuration") {
                t.Fatalf("Load() error = %v, want parse configuration error", err)
            }
        })
    }
}
```

Change the default assertions in `TestLoadUsesDefaults` to use `EnvironmentLocal`, `LogLevelInfo`, and `LogFormatJSON`. Change `TestLoadParsesEnvironment` to compare its typed fields against `Environment("staging")`, `LogLevelDebug`, and `LogFormatText`.

Change `TestParseLevel` in `internal/infra/logging/logging_test.go` to use typed inputs:

```go
func TestParseLevel(t *testing.T) {
    tests := []struct {
        input config.LogLevel
        want  slog.Level
    }{
        {input: config.LogLevelDebug, want: slog.LevelDebug},
        {input: config.LogLevelInfo, want: slog.LevelInfo},
        {input: config.LogLevelWarn, want: slog.LevelWarn},
        {input: config.LogLevelError, want: slog.LevelError},
    }

    for _, tt := range tests {
        t.Run(string(tt.input), func(t *testing.T) {
            got, err := ParseLevel(tt.input)
            if err != nil {
                t.Fatalf("ParseLevel(%q) error = %v", tt.input, err)
            }
            if got != tt.want {
                t.Fatalf("ParseLevel(%q) = %v, want %v", tt.input, got, tt.want)
            }
        })
    }

    if _, err := ParseLevel(config.LogLevel("verbose")); err == nil {
        t.Fatal("ParseLevel(verbose) expected error")
    }
}
```

Use `config.LogLevelInfo`, `config.LogLevelWarn`, `config.LogFormatJSON`, `config.LogFormatText`, and `config.Environment("test")` in the remaining logger tests.

- [ ] **Step 4: Run the focused tests and verify RED**

Run:

```bash
go test -count=1 ./internal/infra/config ./internal/infra/logging
```

Expected: FAIL to compile because `Environment`, `LogLevel`, `LogFormat`, and their constants do not exist yet. Do not write production code until this failure is observed.

- [ ] **Step 5: Add the named types, constants, and normalization**

Add these definitions above `Config` in `internal/infra/config/config.go` and change the affected struct fields to the named types:

```go
type Environment string

const EnvironmentLocal Environment = "local"

type LogLevel string

const (
    LogLevelDebug LogLevel = "debug"
    LogLevelInfo  LogLevel = "info"
    LogLevelWarn  LogLevel = "warn"
    LogLevelError LogLevel = "error"
)

type LogFormat string

const (
    LogFormatJSON LogFormat = "json"
    LogFormatText LogFormat = "text"
)

type Config struct {
    Environment Environment `env:"APP_ENV" envDefault:"local"`
    HTTP        HTTPConfig
    Database    DatabaseConfig
    Redis       RedisConfig
    Log         LogConfig
}

type LogConfig struct {
    Level  LogLevel  `env:"LOG_LEVEL" envDefault:"info"`
    Format LogFormat `env:"LOG_FORMAT" envDefault:"json"`
}
```

Update `Load()` and add the private normalization method:

```go
func Load() (Config, error) {
    var cfg Config
    if err := env.Parse(&cfg); err != nil {
        return Config{}, fmt.Errorf("parse configuration: %w", err)
    }
    cfg.normalize()
    if err := cfg.Validate(); err != nil {
        return Config{}, err
    }
    return cfg, nil
}

func (c *Config) normalize() {
    c.Environment = Environment(strings.TrimSpace(string(c.Environment)))
    c.HTTP.Address = strings.TrimSpace(c.HTTP.Address)
    c.Database.URL = strings.TrimSpace(c.Database.URL)
    c.Redis.Address = strings.TrimSpace(c.Redis.Address)
    c.Log.Level = LogLevel(strings.ToLower(strings.TrimSpace(string(c.Log.Level))))
    c.Log.Format = LogFormat(strings.ToLower(strings.TrimSpace(string(c.Log.Format))))
}
```

Until Task 4 removes `oneOf`, make the existing root validation compile by converting named strings explicitly:

```go
if strings.TrimSpace(string(c.Environment)) == "" {
    return fmt.Errorf("APP_ENV must not be empty")
}
if !oneOf(string(c.Log.Level), "debug", "info", "warn", "error") {
    return fmt.Errorf("LOG_LEVEL must be one of debug, info, warn, or error")
}
if !oneOf(string(c.Log.Format), "json", "text") {
    return fmt.Errorf("LOG_FORMAT must be one of json or text")
}
```

- [ ] **Step 6: Update the logging adapter to consume typed values**

Replace the public signatures and switches in `internal/infra/logging/logging.go` with:

```go
func ParseLevel(value config.LogLevel) (slog.Level, error) {
    switch value {
    case config.LogLevelDebug:
        return slog.LevelDebug, nil
    case config.LogLevelInfo:
        return slog.LevelInfo, nil
    case config.LogLevelWarn:
        return slog.LevelWarn, nil
    case config.LogLevelError:
        return slog.LevelError, nil
    default:
        return 0, fmt.Errorf("unsupported log level %q", value)
    }
}

func New(cfg config.LogConfig, output io.Writer, environment config.Environment) (*slog.Logger, error) {
    level, err := ParseLevel(cfg.Level)
    if err != nil {
        return nil, err
    }

    options := &slog.HandlerOptions{Level: level}
    var handler slog.Handler
    switch cfg.Format {
    case config.LogFormatJSON:
        handler = slog.NewJSONHandler(output, options)
    case config.LogFormatText:
        handler = slog.NewTextHandler(output, options)
    default:
        return nil, fmt.Errorf("unsupported log format %q", cfg.Format)
    }

    return slog.New(handler).With(
        "service", "content-platform",
        "environment", string(environment),
    ), nil
}
```

- [ ] **Step 7: Run focused and dependent tests and verify GREEN**

Run:

```bash
gofmt -w internal/infra/config/config.go internal/infra/config/config_test.go internal/infra/logging/logging.go internal/infra/logging/logging_test.go
go test -count=1 ./internal/infra/config ./internal/infra/logging ./cmd/server ./cmd/migrate ./internal/app
```

Expected: PASS. The server, migration command, and app packages must compile with `config.Environment` flowing into `logging.New`.

- [ ] **Step 8: Commit the typed loading boundary**

```bash
git add internal/infra/config/config.go internal/infra/config/config_test.go internal/infra/logging/logging.go internal/infra/logging/logging_test.go
git commit -m "refactor: type and normalize configuration values"
```

## Task 2: Extract and harden HTTP validation

**Files:**

- Create: `internal/infra/config/validate.go`
- Create: `internal/infra/config/validate_test.go`
- Modify: `internal/infra/config/config.go` in `Config.Validate`

- [ ] **Step 1: Write the failing table-driven HTTP validation test**

Create `internal/infra/config/validate_test.go` with:

```go
package config

import (
    "strings"
    "testing"
    "time"
)

func TestHTTPConfigValidate(t *testing.T) {
    tests := []struct {
        name    string
        mutate  func(*HTTPConfig)
        wantErr string
    }{
        {name: "valid wildcard address", mutate: func(*HTTPConfig) {}},
        {name: "valid IPv4", mutate: func(c *HTTPConfig) { c.Address = "127.0.0.1:8080" }},
        {name: "valid IPv6", mutate: func(c *HTTPConfig) { c.Address = "[::1]:8080" }},
        {name: "missing port", mutate: func(c *HTTPConfig) { c.Address = "localhost" }, wantErr: "HTTP_ADDR"},
        {name: "named port", mutate: func(c *HTTPConfig) { c.Address = "localhost:http" }, wantErr: "HTTP_ADDR"},
        {name: "zero port", mutate: func(c *HTTPConfig) { c.Address = ":0" }, wantErr: "HTTP_ADDR"},
        {name: "port too large", mutate: func(c *HTTPConfig) { c.Address = ":65536" }, wantErr: "HTTP_ADDR"},
        {name: "zero read header timeout", mutate: func(c *HTTPConfig) { c.ReadHeaderTimeout = 0 }, wantErr: "HTTP_READ_HEADER_TIMEOUT"},
        {name: "negative read header timeout", mutate: func(c *HTTPConfig) { c.ReadHeaderTimeout = -time.Second }, wantErr: "HTTP_READ_HEADER_TIMEOUT"},
        {name: "zero read timeout", mutate: func(c *HTTPConfig) { c.ReadTimeout = 0 }, wantErr: "HTTP_READ_TIMEOUT"},
        {name: "negative read timeout", mutate: func(c *HTTPConfig) { c.ReadTimeout = -time.Second }, wantErr: "HTTP_READ_TIMEOUT"},
        {name: "zero write timeout", mutate: func(c *HTTPConfig) { c.WriteTimeout = 0 }, wantErr: "HTTP_WRITE_TIMEOUT"},
        {name: "negative write timeout", mutate: func(c *HTTPConfig) { c.WriteTimeout = -time.Second }, wantErr: "HTTP_WRITE_TIMEOUT"},
        {name: "zero idle timeout", mutate: func(c *HTTPConfig) { c.IdleTimeout = 0 }, wantErr: "HTTP_IDLE_TIMEOUT"},
        {name: "negative idle timeout", mutate: func(c *HTTPConfig) { c.IdleTimeout = -time.Second }, wantErr: "HTTP_IDLE_TIMEOUT"},
        {name: "zero shutdown timeout", mutate: func(c *HTTPConfig) { c.ShutdownTimeout = 0 }, wantErr: "HTTP_SHUTDOWN_TIMEOUT"},
        {name: "negative shutdown timeout", mutate: func(c *HTTPConfig) { c.ShutdownTimeout = -time.Second }, wantErr: "HTTP_SHUTDOWN_TIMEOUT"},
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            cfg := validHTTPConfig()
            tt.mutate(&cfg)

            err := cfg.Validate()
            if tt.wantErr == "" {
                if err != nil {
                    t.Fatalf("Validate() error = %v", err)
                }
                return
            }
            if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
                t.Fatalf("Validate() error = %v, want substring %q", err, tt.wantErr)
            }
        })
    }
}

func validHTTPConfig() HTTPConfig {
    return HTTPConfig{
        Address:           ":8080",
        ReadHeaderTimeout: 5 * time.Second,
        ReadTimeout:       10 * time.Second,
        WriteTimeout:      15 * time.Second,
        IdleTimeout:       60 * time.Second,
        ShutdownTimeout:   10 * time.Second,
    }
}
```

- [ ] **Step 2: Run the HTTP test and verify RED**

Run:

```bash
go test -count=1 ./internal/infra/config -run TestHTTPConfigValidate
```

Expected: FAIL to compile with `cfg.Validate undefined` because `HTTPConfig.Validate` does not exist.

- [ ] **Step 3: Implement the TCP helper and HTTP validator**

Create `internal/infra/config/validate.go`:

```go
package config

import (
    "fmt"
    "net"
    "strconv"
    "strings"
)

func (c HTTPConfig) Validate() error {
    if !validTCPAddress(c.Address, false) {
        return fmt.Errorf("HTTP_ADDR must be a valid TCP address")
    }
    if c.ReadHeaderTimeout <= 0 {
        return fmt.Errorf("HTTP_READ_HEADER_TIMEOUT must be greater than zero")
    }
    if c.ReadTimeout <= 0 {
        return fmt.Errorf("HTTP_READ_TIMEOUT must be greater than zero")
    }
    if c.WriteTimeout <= 0 {
        return fmt.Errorf("HTTP_WRITE_TIMEOUT must be greater than zero")
    }
    if c.IdleTimeout <= 0 {
        return fmt.Errorf("HTTP_IDLE_TIMEOUT must be greater than zero")
    }
    if c.ShutdownTimeout <= 0 {
        return fmt.Errorf("HTTP_SHUTDOWN_TIMEOUT must be greater than zero")
    }
    return nil
}

func validTCPAddress(address string, requireHost bool) bool {
    host, port, err := net.SplitHostPort(address)
    if err != nil {
        return false
    }
    if requireHost && strings.TrimSpace(host) == "" {
        return false
    }
    portNumber, err := strconv.Atoi(port)
    return err == nil && portNumber >= 1 && portNumber <= 65535
}
```

In `Config.Validate`, replace the existing HTTP address and timeout checks with:

```go
if err := c.HTTP.Validate(); err != nil {
    return err
}
```

Only replace the contiguous HTTP validation block. The database block beginning with `DATABASE_URL`, the Redis block beginning with `REDIS_ADDR`, and the two log checks remain byte-for-byte unchanged in this commit.

- [ ] **Step 4: Run the HTTP and full configuration tests and verify GREEN**

Run:

```bash
gofmt -w internal/infra/config/config.go internal/infra/config/validate.go internal/infra/config/validate_test.go
go test -count=1 ./internal/infra/config
```

Expected: PASS, including existing `Load()` tests using `:8080` and `:9090`.

- [ ] **Step 5: Commit HTTP validation**

```bash
git add internal/infra/config/config.go internal/infra/config/validate.go internal/infra/config/validate_test.go
git commit -m "refactor: isolate HTTP configuration validation"
```

## Task 3: Extract database validation and forbid unlimited pools

**Files:**

- Modify: `internal/infra/config/validate.go`
- Modify: `internal/infra/config/validate_test.go`
- Modify: `internal/infra/config/config.go` in `Config.Validate`

- [ ] **Step 1: Write failing database URL and pool-boundary tests**

Append to `internal/infra/config/validate_test.go`:

```go
func TestDatabaseConfigValidate(t *testing.T) {
    tests := []struct {
        name    string
        mutate  func(*DatabaseConfig)
        wantErr string
    }{
        {name: "valid postgres URL", mutate: func(*DatabaseConfig) {}},
        {name: "valid postgresql URL", mutate: func(c *DatabaseConfig) { c.URL = "postgresql://localhost/content_platform" }},
        {name: "missing URL", mutate: func(c *DatabaseConfig) { c.URL = "" }, wantErr: "DATABASE_URL"},
        {name: "unsupported scheme", mutate: func(c *DatabaseConfig) { c.URL = "mysql://localhost/content_platform" }, wantErr: "DATABASE_URL"},
        {name: "missing database name", mutate: func(c *DatabaseConfig) { c.URL = "postgres://localhost/" }, wantErr: "DATABASE_URL"},
        {name: "database name only in query", mutate: func(c *DatabaseConfig) { c.URL = "postgres://localhost?dbname=content_platform" }, wantErr: "DATABASE_URL"},
        {name: "invalid driver port", mutate: func(c *DatabaseConfig) { c.URL = "postgres://localhost:notaport/content_platform" }, wantErr: "DATABASE_URL"},
        {name: "negative max open", mutate: func(c *DatabaseConfig) { c.MaxOpenConns = -1 }, wantErr: "DATABASE_MAX_OPEN_CONNS"},
        {name: "zero max open", mutate: func(c *DatabaseConfig) { c.MaxOpenConns = 0 }, wantErr: "DATABASE_MAX_OPEN_CONNS"},
        {name: "one max open", mutate: func(c *DatabaseConfig) { c.MaxOpenConns = 1; c.MaxIdleConns = 1 }},
        {name: "negative max idle", mutate: func(c *DatabaseConfig) { c.MaxIdleConns = -1 }, wantErr: "DATABASE_MAX_IDLE_CONNS"},
        {name: "zero max idle", mutate: func(c *DatabaseConfig) { c.MaxIdleConns = 0 }},
        {name: "idle equals open", mutate: func(c *DatabaseConfig) { c.MaxIdleConns = c.MaxOpenConns }},
        {name: "idle exceeds open", mutate: func(c *DatabaseConfig) { c.MaxIdleConns = c.MaxOpenConns + 1 }, wantErr: "DATABASE_MAX_IDLE_CONNS"},
        {name: "zero max lifetime", mutate: func(c *DatabaseConfig) { c.ConnMaxLifetime = 0 }, wantErr: "DATABASE_CONN_MAX_LIFETIME"},
        {name: "negative max lifetime", mutate: func(c *DatabaseConfig) { c.ConnMaxLifetime = -time.Second }, wantErr: "DATABASE_CONN_MAX_LIFETIME"},
        {name: "zero ping timeout", mutate: func(c *DatabaseConfig) { c.PingTimeout = 0 }, wantErr: "DATABASE_PING_TIMEOUT"},
        {name: "negative ping timeout", mutate: func(c *DatabaseConfig) { c.PingTimeout = -time.Second }, wantErr: "DATABASE_PING_TIMEOUT"},
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            cfg := validDatabaseConfig()
            tt.mutate(&cfg)

            err := cfg.Validate()
            if tt.wantErr == "" {
                if err != nil {
                    t.Fatalf("Validate() error = %v", err)
                }
                return
            }
            if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
                t.Fatalf("Validate() error = %v, want substring %q", err, tt.wantErr)
            }
        })
    }
}

func TestDatabaseConfigValidateDoesNotExposeURL(t *testing.T) {
    cfg := validDatabaseConfig()
    cfg.URL = "mysql://user:db-password-do-not-log@localhost/content_platform"

    err := cfg.Validate()
    if err == nil {
        t.Fatal("Validate() expected error")
    }
    if strings.Contains(err.Error(), "db-password-do-not-log") || strings.Contains(err.Error(), cfg.URL) {
        t.Fatal("Validate() exposed DATABASE_URL")
    }
}

func validDatabaseConfig() DatabaseConfig {
    return DatabaseConfig{
        URL:             "postgres://localhost/content_platform",
        MaxOpenConns:    20,
        MaxIdleConns:    5,
        ConnMaxLifetime: 30 * time.Minute,
        PingTimeout:     3 * time.Second,
    }
}
```

Add these cases to the existing table in `TestLoadRejectsInvalidConfiguration` so the public loading boundary is covered as well as the child validator:

```go
{
    name: "invalid database URL",
    env: map[string]string{
        "DATABASE_URL": "mysql://user:db-password-do-not-log@localhost/content_platform",
    },
    wantErr: "DATABASE_URL",
},
{
    name: "zero max open connections",
    env: map[string]string{
        "DATABASE_URL":            "postgres://localhost/content_platform",
        "DATABASE_MAX_OPEN_CONNS": "0",
    },
    wantErr: "DATABASE_MAX_OPEN_CONNS",
},
```

- [ ] **Step 2: Run the database tests and verify RED**

Run:

```bash
go test -count=1 ./internal/infra/config -run 'TestDatabaseConfigValidate'
```

Expected: FAIL to compile because `DatabaseConfig.Validate` does not exist.

- [ ] **Step 3: Implement database URL and pool validation**

Add `net/url` and `github.com/jackc/pgx/v5` to `validate.go`, then add:

```go
func (c DatabaseConfig) Validate() error {
    if !validDatabaseURL(c.URL) {
        return fmt.Errorf("DATABASE_URL must be a valid PostgreSQL URL")
    }
    if c.MaxOpenConns <= 0 {
        return fmt.Errorf("DATABASE_MAX_OPEN_CONNS must be greater than zero")
    }
    if c.MaxIdleConns < 0 {
        return fmt.Errorf("DATABASE_MAX_IDLE_CONNS must not be negative")
    }
    if c.MaxIdleConns > c.MaxOpenConns {
        return fmt.Errorf("DATABASE_MAX_IDLE_CONNS must not exceed DATABASE_MAX_OPEN_CONNS")
    }
    if c.ConnMaxLifetime <= 0 {
        return fmt.Errorf("DATABASE_CONN_MAX_LIFETIME must be greater than zero")
    }
    if c.PingTimeout <= 0 {
        return fmt.Errorf("DATABASE_PING_TIMEOUT must be greater than zero")
    }
    return nil
}

func validDatabaseURL(value string) bool {
    parsed, err := url.ParseRequestURI(value)
    if err != nil {
        return false
    }
    if parsed.Scheme != "postgres" && parsed.Scheme != "postgresql" {
        return false
    }
    if strings.Trim(parsed.Path, "/") == "" {
        return false
    }
    _, err = pgx.ParseConfig(value)
    return err == nil
}
```

The complete `validate.go` import block must be:

```go
import (
    "fmt"
    "net"
    "net/url"
    "strconv"
    "strings"

    "github.com/jackc/pgx/v5"
)
```

In `Config.Validate`, replace the database checks with:

```go
if err := c.Database.Validate(); err != nil {
    return err
}
```

- [ ] **Step 4: Run database, PostgreSQL, and command tests and verify GREEN**

Run:

```bash
gofmt -w internal/infra/config/config.go internal/infra/config/validate.go internal/infra/config/validate_test.go
go test -count=1 ./internal/infra/config ./internal/infra/postgres ./cmd/server ./cmd/migrate
```

Expected: PASS. Existing database errors remain generic, and existing valid URLs continue to load.

- [ ] **Step 5: Commit database validation**

```bash
git add internal/infra/config/config.go internal/infra/config/validate.go internal/infra/config/validate_test.go
git commit -m "fix: reject unsafe database pool configuration"
```

## Task 4: Extract Redis and log validation and preserve fail-fast order

**Files:**

- Modify: `internal/infra/config/validate.go`
- Modify: `internal/infra/config/validate_test.go`
- Modify: `internal/infra/config/config.go:59-124`

- [ ] **Step 1: Write failing Redis, log, and root-order tests**

Append to `internal/infra/config/validate_test.go`:

```go
func TestRedisConfigValidate(t *testing.T) {
    tests := []struct {
        name    string
        mutate  func(*RedisConfig)
        wantErr string
    }{
        {name: "valid hostname", mutate: func(*RedisConfig) {}},
        {name: "valid IPv4", mutate: func(c *RedisConfig) { c.Address = "127.0.0.1:6379" }},
        {name: "valid IPv6", mutate: func(c *RedisConfig) { c.Address = "[::1]:6379" }},
        {name: "missing host", mutate: func(c *RedisConfig) { c.Address = ":6379" }, wantErr: "REDIS_ADDR"},
        {name: "missing port", mutate: func(c *RedisConfig) { c.Address = "localhost" }, wantErr: "REDIS_ADDR"},
        {name: "named port", mutate: func(c *RedisConfig) { c.Address = "localhost:redis" }, wantErr: "REDIS_ADDR"},
        {name: "zero port", mutate: func(c *RedisConfig) { c.Address = "localhost:0" }, wantErr: "REDIS_ADDR"},
        {name: "port too large", mutate: func(c *RedisConfig) { c.Address = "localhost:65536" }, wantErr: "REDIS_ADDR"},
        {name: "zero database", mutate: func(c *RedisConfig) { c.DB = 0 }},
        {name: "negative database", mutate: func(c *RedisConfig) { c.DB = -1 }, wantErr: "REDIS_DB"},
        {name: "zero ping timeout", mutate: func(c *RedisConfig) { c.PingTimeout = 0 }, wantErr: "REDIS_PING_TIMEOUT"},
        {name: "negative ping timeout", mutate: func(c *RedisConfig) { c.PingTimeout = -time.Second }, wantErr: "REDIS_PING_TIMEOUT"},
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            cfg := validRedisConfig()
            tt.mutate(&cfg)

            err := cfg.Validate()
            if tt.wantErr == "" {
                if err != nil {
                    t.Fatalf("Validate() error = %v", err)
                }
                return
            }
            if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
                t.Fatalf("Validate() error = %v, want substring %q", err, tt.wantErr)
            }
        })
    }
}

func TestLogConfigValidate(t *testing.T) {
    tests := []struct {
        name    string
        cfg     LogConfig
        wantErr string
    }{
        {name: "debug JSON", cfg: LogConfig{Level: LogLevelDebug, Format: LogFormatJSON}},
        {name: "info text", cfg: LogConfig{Level: LogLevelInfo, Format: LogFormatText}},
        {name: "warn JSON", cfg: LogConfig{Level: LogLevelWarn, Format: LogFormatJSON}},
        {name: "error text", cfg: LogConfig{Level: LogLevelError, Format: LogFormatText}},
        {name: "invalid level", cfg: LogConfig{Level: LogLevel("verbose"), Format: LogFormatJSON}, wantErr: "LOG_LEVEL"},
        {name: "invalid format", cfg: LogConfig{Level: LogLevelInfo, Format: LogFormat("yaml")}, wantErr: "LOG_FORMAT"},
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            err := tt.cfg.Validate()
            if tt.wantErr == "" {
                if err != nil {
                    t.Fatalf("Validate() error = %v", err)
                }
                return
            }
            if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
                t.Fatalf("Validate() error = %v, want substring %q", err, tt.wantErr)
            }
        })
    }
}

func TestConfigValidateReturnsFirstErrorInStableOrder(t *testing.T) {
    tests := []struct {
        name    string
        mutate  func(*Config)
        wantErr string
    }{
        {
            name: "environment before HTTP",
            mutate: func(c *Config) {
                c.Environment = ""
                c.HTTP.Address = "invalid"
            },
            wantErr: "APP_ENV",
        },
        {
            name: "HTTP before database",
            mutate: func(c *Config) {
                c.HTTP.Address = "invalid"
                c.Database.URL = ""
            },
            wantErr: "HTTP_ADDR",
        },
        {
            name: "database before Redis",
            mutate: func(c *Config) {
                c.Database.URL = ""
                c.Redis.Address = "invalid"
            },
            wantErr: "DATABASE_URL",
        },
        {
            name: "Redis before log",
            mutate: func(c *Config) {
                c.Redis.Address = "invalid"
                c.Log.Level = LogLevel("verbose")
            },
            wantErr: "REDIS_ADDR",
        },
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            cfg := validConfig()
            tt.mutate(&cfg)

            err := cfg.Validate()
            if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
                t.Fatalf("Validate() error = %v, want substring %q", err, tt.wantErr)
            }
        })
    }
}

func validRedisConfig() RedisConfig {
    return RedisConfig{
        Address:     "localhost:6379",
        Password:    "",
        DB:          0,
        PingTimeout: 2 * time.Second,
    }
}

func validConfig() Config {
    return Config{
        Environment: EnvironmentLocal,
        HTTP:        validHTTPConfig(),
        Database:    validDatabaseConfig(),
        Redis:       validRedisConfig(),
        Log: LogConfig{
            Level:  LogLevelInfo,
            Format: LogFormatJSON,
        },
    }
}
```

- [ ] **Step 2: Run the new validators and verify RED**

Run:

```bash
go test -count=1 ./internal/infra/config -run 'Test(RedisConfig|LogConfig|ConfigValidateReturnsFirst)'
```

Expected: FAIL to compile because `RedisConfig.Validate` and `LogConfig.Validate` do not exist.

- [ ] **Step 3: Implement Redis and log validators**

Add to `internal/infra/config/validate.go`:

```go
func (c RedisConfig) Validate() error {
    if !validTCPAddress(c.Address, true) {
        return fmt.Errorf("REDIS_ADDR must be a valid TCP address with a host")
    }
    if c.DB < 0 {
        return fmt.Errorf("REDIS_DB must not be negative")
    }
    if c.PingTimeout <= 0 {
        return fmt.Errorf("REDIS_PING_TIMEOUT must be greater than zero")
    }
    return nil
}

func (c LogConfig) Validate() error {
    switch c.Level {
    case LogLevelDebug, LogLevelInfo, LogLevelWarn, LogLevelError:
    default:
        return fmt.Errorf("LOG_LEVEL must be one of debug, info, warn, or error")
    }

    switch c.Format {
    case LogFormatJSON, LogFormatText:
    default:
        return fmt.Errorf("LOG_FORMAT must be one of json or text")
    }
    return nil
}
```

- [ ] **Step 4: Reduce root validation to root rules and delegation**

Replace `Config.Validate()` in `internal/infra/config/config.go` with:

```go
func (c Config) Validate() error {
    if strings.TrimSpace(string(c.Environment)) == "" {
        return fmt.Errorf("APP_ENV must not be empty")
    }
    if err := c.HTTP.Validate(); err != nil {
        return err
    }
    if err := c.Database.Validate(); err != nil {
        return err
    }
    if err := c.Redis.Validate(); err != nil {
        return err
    }
    if err := c.Log.Validate(); err != nil {
        return err
    }
    return nil
}
```

Delete `oneOf` from `config.go`; it has no remaining callers.

- [ ] **Step 5: Run configuration and application tests and verify GREEN**

Run:

```bash
gofmt -w internal/infra/config/config.go internal/infra/config/validate.go internal/infra/config/validate_test.go
go test -count=1 ./internal/infra/config ./internal/infra/redis ./internal/infra/logging ./internal/app ./cmd/server ./cmd/migrate
```

Expected: PASS. `Config.Validate()` must report the first invalid group in the documented order.

- [ ] **Step 6: Commit the remaining validation split**

```bash
git add internal/infra/config/config.go internal/infra/config/validate.go internal/infra/config/validate_test.go
git commit -m "refactor: delegate configuration validation"
```

## Task 5: Add safe structured-log representations

**Files:**

- Create: `internal/infra/config/log_value.go`
- Create: `internal/infra/config/log_value_test.go`
- Verify: `internal/infra/config/config_test.go`

- [ ] **Step 1: Write the failing redaction test**

Create `internal/infra/config/log_value_test.go`:

```go
package config

import (
    "bytes"
    "log/slog"
    "strings"
    "testing"
)

func TestLogValueRedactsSensitiveConfiguration(t *testing.T) {
    cfg := validConfig()
    cfg.Database.URL = "postgres://dbuser:db-password-do-not-log@localhost/content_platform"
    cfg.Redis.Password = "redis-password-do-not-log"

    tests := []struct {
        name         string
        value        any
        safeText     string
        wantRedacted bool
    }{
        {name: "root", value: cfg, safeText: `"environment":"local"`, wantRedacted: true},
        {name: "HTTP", value: cfg.HTTP, safeText: `"address":":8080"`},
        {name: "database", value: cfg.Database, safeText: `"max_open_conns":20`, wantRedacted: true},
        {name: "Redis", value: cfg.Redis, safeText: `"db":0`, wantRedacted: true},
        {name: "log", value: cfg.Log, safeText: `"level":"info"`},
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            var output bytes.Buffer
            logger := slog.New(slog.NewJSONHandler(&output, nil))
            logger.Info("configuration", "config", tt.value)

            logged := output.String()
            if strings.Contains(logged, "db-password-do-not-log") {
                t.Fatal("structured log exposed database credentials")
            }
            if strings.Contains(logged, "redis-password-do-not-log") {
                t.Fatal("structured log exposed Redis password")
            }
            if tt.wantRedacted && !strings.Contains(logged, `"[REDACTED]"`) {
                t.Fatal("structured log does not contain redaction marker")
            }
            if !strings.Contains(logged, tt.safeText) {
                t.Fatalf("structured log missing safe field %q", tt.safeText)
            }
        })
    }
}
```

- [ ] **Step 2: Run the redaction test and verify RED**

Run:

```bash
go test -count=1 ./internal/infra/config -run TestLogValueRedactsSensitiveConfiguration
```

Expected: FAIL because `slog` serializes the exported `URL` and `Password` fields before `LogValue` methods exist.

- [ ] **Step 3: Implement safe LogValuer methods**

Create `internal/infra/config/log_value.go`:

```go
package config

import "log/slog"

const redactedValue = "[REDACTED]"

func (c Config) LogValue() slog.Value {
    return slog.GroupValue(
        slog.String("environment", string(c.Environment)),
        slog.Any("http", c.HTTP),
        slog.Any("database", c.Database),
        slog.Any("redis", c.Redis),
        slog.Any("log", c.Log),
    )
}

func (c HTTPConfig) LogValue() slog.Value {
    return slog.GroupValue(
        slog.String("address", c.Address),
        slog.Duration("read_header_timeout", c.ReadHeaderTimeout),
        slog.Duration("read_timeout", c.ReadTimeout),
        slog.Duration("write_timeout", c.WriteTimeout),
        slog.Duration("idle_timeout", c.IdleTimeout),
        slog.Duration("shutdown_timeout", c.ShutdownTimeout),
    )
}

func (c DatabaseConfig) LogValue() slog.Value {
    return slog.GroupValue(
        slog.String("url", redactedValue),
        slog.Int("max_open_conns", c.MaxOpenConns),
        slog.Int("max_idle_conns", c.MaxIdleConns),
        slog.Duration("conn_max_lifetime", c.ConnMaxLifetime),
        slog.Duration("ping_timeout", c.PingTimeout),
    )
}

func (c RedisConfig) LogValue() slog.Value {
    return slog.GroupValue(
        slog.String("address", c.Address),
        slog.String("password", redactedValue),
        slog.Int("db", c.DB),
        slog.Duration("ping_timeout", c.PingTimeout),
    )
}

func (c LogConfig) LogValue() slog.Value {
    return slog.GroupValue(
        slog.String("level", string(c.Level)),
        slog.String("format", string(c.Format)),
    )
}
```

- [ ] **Step 4: Verify no whole-config diagnostic remains in configuration tests**

Run:

```bash
rg -n '(%#v|%\+v|%v).*\b(cfg|Config|Database|Redis)\b' internal/infra/config
```

Expected: no matches. If a match is a full configuration diagnostic, replace it with a field-level assertion without printing URL or password. Do not add a source-scanning unit test.

- [ ] **Step 5: Run configuration and logging tests and verify GREEN**

Run:

```bash
gofmt -w internal/infra/config/log_value.go internal/infra/config/log_value_test.go
go test -count=1 ./internal/infra/config ./internal/infra/logging
```

Expected: PASS. All five configuration types use the documented lowercase structured fields; root, database, and Redis logs contain `[REDACTED]`, and no output contains a secret marker.

- [ ] **Step 6: Commit log redaction**

```bash
git add internal/infra/config/config_test.go internal/infra/config/log_value.go internal/infra/config/log_value_test.go
git commit -m "fix: redact sensitive configuration logs"
```

## Task 6: Document the hardened configuration contract

**Files:**

- Modify: `.env.example:10-12`
- Modify: `README.md` after the local configuration safety paragraph
- Modify: `docs/superpowers/specs/2026-07-17-m1-project-foundation-design.md:233-243`
- Modify: `docs/superpowers/specs/2026-08-06-m1-configuration-hardening-design.md:1-4`

- [ ] **Step 1: Add explicit pool comments to `.env.example`**

Replace the pool section with:

```dotenv
DATABASE_URL=postgres://postgres:postgres@localhost:5432/content_platform?sslmode=disable
# Must be greater than zero; zero would make database/sql connections unlimited.
DATABASE_MAX_OPEN_CONNS=20
# Zero keeps no idle connections; must not exceed DATABASE_MAX_OPEN_CONNS.
DATABASE_MAX_IDLE_CONNS=5
DATABASE_CONN_MAX_LIFETIME=30m
DATABASE_PING_TIMEOUT=3s
```

- [ ] **Step 2: Add the operator-facing semantics to README**

After “`.env` 已被 Git 忽略；不要提交真实密码、token 或生产连接信息。” add:

```markdown
配置加载会去除 `APP_ENV`、HTTP 地址、数据库 URL 和 Redis 地址的首尾空白，并把日志级别与日志格式转换为小写；`REDIS_PASSWORD` 始终原样保留。

数据库连接池规则：

- `DATABASE_MAX_OPEN_CONNS` 必须大于零。Go 的 `database/sql` 会把零解释为不限制连接数，因此应用拒绝该值；
- `DATABASE_MAX_IDLE_CONNS` 可以为零，表示不保留空闲连接，但不能为负数或超过最大打开连接数。

不要记录完整 `Config`，也不要单独记录数据库 URL 或 Redis 密码。配置类型为 `slog` 提供了脱敏表示作为误用防护，但这不替代字段级日志设计和代码审查。
```

- [ ] **Step 3: Align the M1 foundation design**

Replace the existing connection and logging rules in `docs/superpowers/specs/2026-07-17-m1-project-foundation-design.md` with these bullets:

```markdown
- `DATABASE_URL` 必填，只接受包含数据库名的 `postgres://` 或 `postgresql://` URL。
- 所有 timeout 必须大于零。
- `DATABASE_MAX_OPEN_CONNS` 必须大于零；零在 `database/sql` 中表示无限连接，因此不允许。
- `DATABASE_MAX_IDLE_CONNS` 可以为零，不能为负数，也不能超过 open 数。
- Redis DB 不能为负数。
- HTTP 和 Redis 地址必须使用带数值端口的 TCP `host:port` 形式。
- 日志级别只允许 `debug`、`info`、`warn`、`error`。
- 日志格式只允许 `json`、`text`。
- 非敏感字符串在加载边界去除首尾空白，日志级别和格式再转换为小写；Redis 密码原样保留。
- `.env.example` 只包含无秘密的示例值。
- 应用不自动读取工作目录中的 `.env`；本地运行由 shell 或 Makefile 导入环境。
- 错误和日志不得输出数据库 URL、Redis 密码、token 或完整 `Authorization` header；配置的 `slog` 表示必须脱敏。
```

- [ ] **Step 4: Mark the hardening design implemented**

After all code tests pass, change the hardening design status line to:

```markdown
状态：已实现
```

- [ ] **Step 5: Check documentation formatting**

Run:

```bash
git diff --check
```

Expected: exit code 0 with no whitespace errors.

- [ ] **Step 6: Commit documentation**

```bash
git add .env.example README.md docs/superpowers/specs/2026-07-17-m1-project-foundation-design.md docs/superpowers/specs/2026-08-06-m1-configuration-hardening-design.md
git commit -m "docs: document hardened configuration semantics"
```

## Task 7: Run complete verification and inspect the review delta

**Files:**

- Verify: all Go and documentation files changed by Tasks 1-6
- Preserve: `内容平台——开发需求文档.md` as untracked user-owned input

- [ ] **Step 1: Format all changed Go files**

Run:

```bash
gofmt -w internal/infra/config/config.go internal/infra/config/config_test.go internal/infra/config/validate.go internal/infra/config/validate_test.go internal/infra/config/log_value.go internal/infra/config/log_value_test.go internal/infra/logging/logging.go internal/infra/logging/logging_test.go
```

Expected: exit code 0.

- [ ] **Step 2: Verify module metadata remains tidy**

Run:

```bash
go mod tidy
git diff --exit-code -- go.mod go.sum
go mod verify
```

Expected: `go mod tidy` does not change `go.mod` or `go.sum`, and `go mod verify` reports that all modules are verified.

- [ ] **Step 3: Run targeted tests without cache**

Run:

```bash
go test -count=1 ./internal/infra/config ./internal/infra/logging ./internal/infra/postgres ./internal/infra/redis ./cmd/server ./cmd/migrate ./internal/app
```

Expected: PASS for every listed package.

- [ ] **Step 4: Run the complete unit suite without cache**

Run:

```bash
go test -count=1 ./...
```

Expected: PASS.

- [ ] **Step 5: Run race detection**

Run:

```bash
go test -race -count=1 ./...
```

Expected: PASS with no race reports.

- [ ] **Step 6: Run static and build checks**

Run:

```bash
go vet ./...
go build ./...
```

Expected: both commands exit 0 without warnings or errors.

- [ ] **Step 7: Compile and run build-tagged integration tests**

Run:

```bash
go test -count=1 -tags=integration ./...
```

Expected: PASS. Tests that require `TEST_DATABASE_URL` or `TEST_REDIS_ADDR` may explicitly report `SKIP` when those variables are absent, but every integration test package must compile with the new named configuration types.

- [ ] **Step 8: Check sensitive-value and whole-config logging patterns**

Run:

```bash
rg -n '(Database\.URL|Redis\.Password|%#v.*cfg|%\+v.*cfg)' --glob '*.go' cmd internal
```

Expected: only legitimate infrastructure consumption and explicit redaction tests appear. No runtime log statement or whole-config test diagnostic may include a database URL or Redis password.

- [ ] **Step 9: Review the full configuration-hardening delta**

Run:

```bash
git diff 00db151..HEAD -- internal/infra/config internal/infra/logging .env.example README.md docs/superpowers/specs
git diff --check 00db151..HEAD
```

Expected: the delta is limited to the approved specification. Confirm each acceptance criterion in `docs/superpowers/specs/2026-08-06-m1-configuration-hardening-design.md` maps to code, tests, or documentation.

- [ ] **Step 10: Confirm repository state**

Run:

```bash
git status --short --branch
git log --oneline --decorate 00db151..HEAD
```

Expected: only the user-owned `内容平台——开发需求文档.md` remains untracked; all implementation and documentation changes are committed as the task-specific commits above.

## Task 8: Request review and update the existing PR

**Files:**

- Review: commits created by Tasks 1-6
- Remote: `origin/feat/project-foundation`
- PR: `https://github.com/Free-sp1rit/content-platform/pull/1`

- [ ] **Step 1: Invoke completion verification and code-review workflows**

Use `superpowers:verification-before-completion` to verify every success claim against the fresh Task 7 output. Then use `superpowers:requesting-code-review` for an inline, specification-based review; do not spawn subagents unless the user explicitly changes the standing inline-execution preference.

Expected: no Critical or Important finding remains. Any behavior fix must start with a failing regression test and receive its own focused commit.

- [ ] **Step 2: Push the reviewed commits**

Run:

```bash
git push origin feat/project-foundation
```

Expected: the remote branch advances without force-push and PR #1 updates with the configuration-hardening commits.

- [ ] **Step 3: Inspect the updated PR**

Run:

```bash
gh pr view 1 --json url,state,isDraft,mergeable,headRefName,baseRefName,commits,statusCheckRollup
```

Expected:

```text
state = OPEN
isDraft = false
headRefName = feat/project-foundation
baseRefName = main
```

If `statusCheckRollup` is empty, report that no remote CI checks are configured; do not describe an empty check list as a passing CI system.

- [ ] **Step 4: Report the review decisions and evidence**

Report:

- which review suggestions were implemented and which remained deferred;
- the exact `MaxOpenConns=0` and `MaxIdleConns=0` semantics;
- the files responsible for normalization, validation, and redaction;
- every verification command and its observed result;
- the new commit list and PR URL;
- that the user-owned untracked requirements document was not modified or committed.
