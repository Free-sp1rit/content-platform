package config

import (
	"os"
	"strings"
	"testing"
	"time"
)

var configEnvironmentKeys = []string{
	"APP_ENV",
	"HTTP_ADDR",
	"HTTP_READ_HEADER_TIMEOUT",
	"HTTP_READ_TIMEOUT",
	"HTTP_WRITE_TIMEOUT",
	"HTTP_IDLE_TIMEOUT",
	"HTTP_SHUTDOWN_TIMEOUT",
	"DATABASE_URL",
	"DATABASE_MAX_OPEN_CONNS",
	"DATABASE_MAX_IDLE_CONNS",
	"DATABASE_CONN_MAX_LIFETIME",
	"DATABASE_PING_TIMEOUT",
	"REDIS_ADDR",
	"REDIS_PASSWORD",
	"REDIS_DB",
	"REDIS_PING_TIMEOUT",
	"AUTH_JWT_SECRET",
	"AUTH_JWT_ISSUER",
	"AUTH_JWT_AUDIENCE",
	"AUTH_ACCESS_TOKEN_TTL",
	"AUTH_REFRESH_TOKEN_TTL",
	"AUTH_BCRYPT_COST",
	"LOG_LEVEL",
	"LOG_FORMAT",
}

const validJWTSecret = "0123456789abcdef0123456789abcdef"

func TestLoadUsesDefaults(t *testing.T) {
	clearConfigEnvironment(t)
	t.Setenv("DATABASE_URL", "postgres://postgres:postgres@localhost/content_platform?sslmode=disable")
	t.Setenv("AUTH_JWT_SECRET", validJWTSecret)

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	if cfg.Environment != EnvironmentLocal {
		t.Fatalf("Environment = %q, want %q", cfg.Environment, EnvironmentLocal)
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
	if cfg.Auth.JWTSecret != validJWTSecret {
		t.Fatal("Auth.JWTSecret did not preserve configured value")
	}
	if cfg.Auth.JWTIssuer != "content-platform" {
		t.Fatalf("Auth.JWTIssuer = %q, want %q", cfg.Auth.JWTIssuer, "content-platform")
	}
	if cfg.Auth.JWTAudience != "content-platform-api" {
		t.Fatalf("Auth.JWTAudience = %q, want %q", cfg.Auth.JWTAudience, "content-platform-api")
	}
	if cfg.Auth.AccessTokenTTL != 15*time.Minute {
		t.Fatalf("Auth.AccessTokenTTL = %v, want %v", cfg.Auth.AccessTokenTTL, 15*time.Minute)
	}
	if cfg.Auth.RefreshTokenTTL != 720*time.Hour {
		t.Fatalf("Auth.RefreshTokenTTL = %v, want %v", cfg.Auth.RefreshTokenTTL, 720*time.Hour)
	}
	if cfg.Auth.BcryptCost != 12 {
		t.Fatalf("Auth.BcryptCost = %d, want %d", cfg.Auth.BcryptCost, 12)
	}
	if cfg.Log.Level != LogLevelInfo {
		t.Fatalf("Log.Level = %q, want %q", cfg.Log.Level, LogLevelInfo)
	}
	if cfg.Log.Format != LogFormatJSON {
		t.Fatalf("Log.Format = %q, want %q", cfg.Log.Format, LogFormatJSON)
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
		"AUTH_JWT_SECRET":            "configured-jwt-secret-0123456789abcdef",
		"AUTH_JWT_ISSUER":            "identity-service",
		"AUTH_JWT_AUDIENCE":          "content-clients",
		"AUTH_ACCESS_TOKEN_TTL":      "20m",
		"AUTH_REFRESH_TOKEN_TTL":     "48h",
		"AUTH_BCRYPT_COST":           "15",
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

	if cfg.Environment != Environment("staging") {
		t.Fatalf("Environment = %q, want %q", cfg.Environment, Environment("staging"))
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
	if cfg.Auth.JWTSecret != environment["AUTH_JWT_SECRET"] {
		t.Fatal("Auth.JWTSecret did not preserve configured value")
	}
	if cfg.Auth.JWTIssuer != "identity-service" {
		t.Fatalf("Auth.JWTIssuer = %q, want %q", cfg.Auth.JWTIssuer, "identity-service")
	}
	if cfg.Auth.JWTAudience != "content-clients" {
		t.Fatalf("Auth.JWTAudience = %q, want %q", cfg.Auth.JWTAudience, "content-clients")
	}
	if cfg.Auth.AccessTokenTTL != 20*time.Minute {
		t.Fatalf("Auth.AccessTokenTTL = %v, want %v", cfg.Auth.AccessTokenTTL, 20*time.Minute)
	}
	if cfg.Auth.RefreshTokenTTL != 48*time.Hour {
		t.Fatalf("Auth.RefreshTokenTTL = %v, want %v", cfg.Auth.RefreshTokenTTL, 48*time.Hour)
	}
	if cfg.Auth.BcryptCost != 15 {
		t.Fatalf("Auth.BcryptCost = %d, want %d", cfg.Auth.BcryptCost, 15)
	}
	if cfg.Log.Level != LogLevelDebug {
		t.Fatalf("Log.Level = %q, want %q", cfg.Log.Level, LogLevelDebug)
	}
	if cfg.Log.Format != LogFormatText {
		t.Fatalf("Log.Format = %q, want %q", cfg.Log.Format, LogFormatText)
	}
}

func TestLoadNormalizesNonSecretStringsAndPreservesPassword(t *testing.T) {
	clearConfigEnvironment(t)
	jwtSecret := " 0123456789abcdef0123456789abcdef "
	t.Setenv("APP_ENV", " Staging-Blue ")
	t.Setenv("HTTP_ADDR", " :9090 ")
	t.Setenv("DATABASE_URL", " postgres://localhost/custom ")
	t.Setenv("REDIS_ADDR", " redis.example:6380 ")
	t.Setenv("REDIS_PASSWORD", " secret with spaces ")
	t.Setenv("AUTH_JWT_SECRET", jwtSecret)
	t.Setenv("AUTH_JWT_ISSUER", " identity-service ")
	t.Setenv("AUTH_JWT_AUDIENCE", " content-clients ")
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
	if cfg.Auth.JWTSecret != jwtSecret {
		t.Fatal("Auth.JWTSecret was modified")
	}
	if cfg.Auth.JWTIssuer != "identity-service" {
		t.Fatalf("Auth.JWTIssuer = %q, want %q", cfg.Auth.JWTIssuer, "identity-service")
	}
	if cfg.Auth.JWTAudience != "content-clients" {
		t.Fatalf("Auth.JWTAudience = %q, want %q", cfg.Auth.JWTAudience, "content-clients")
	}
	if cfg.Log.Level != LogLevelWarn {
		t.Fatalf("Log.Level = %q, want %q", cfg.Log.Level, LogLevelWarn)
	}
	if cfg.Log.Format != LogFormatText {
		t.Fatalf("Log.Format = %q, want %q", cfg.Log.Format, LogFormatText)
	}
}

func TestLoadRejectsParserErrors(t *testing.T) {
	tests := []struct {
		name  string
		key   string
		value string
	}{
		{name: "invalid HTTP duration", key: "HTTP_READ_TIMEOUT", value: "not-a-duration"},
		{name: "invalid database pool size", key: "DATABASE_MAX_OPEN_CONNS", value: "many"},
		{name: "invalid Redis database", key: "REDIS_DB", value: "db-zero"},
		{name: "invalid auth duration", key: "AUTH_ACCESS_TOKEN_TTL", value: "not-a-duration"},
		{name: "invalid bcrypt cost", key: "AUTH_BCRYPT_COST", value: "expensive"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			clearConfigEnvironment(t)
			t.Setenv("DATABASE_URL", "postgres://localhost/content_platform")
			t.Setenv("AUTH_JWT_SECRET", validJWTSecret)
			t.Setenv(tt.key, tt.value)

			_, err := Load()
			if err == nil || !strings.Contains(err.Error(), "parse configuration") {
				t.Fatalf("Load() error = %v, want parse configuration error", err)
			}
		})
	}
}

func TestLoadRejectsInvalidConfiguration(t *testing.T) {
	tests := []struct {
		name    string
		env     map[string]string
		wantErr string
	}{
		{name: "missing database URL", env: map[string]string{}, wantErr: "DATABASE_URL is required"},
		{name: "invalid database URL", env: map[string]string{"DATABASE_URL": "mysql://user:db-password-do-not-log@localhost/content_platform"}, wantErr: "DATABASE_URL"},
		{name: "zero max open connections", env: map[string]string{"DATABASE_URL": "postgres://localhost/content_platform", "DATABASE_MAX_OPEN_CONNS": "0"}, wantErr: "DATABASE_MAX_OPEN_CONNS"},
		{name: "invalid log level", env: map[string]string{"DATABASE_URL": "postgres://localhost/db", "LOG_LEVEL": "verbose"}, wantErr: "LOG_LEVEL"},
		{name: "invalid log format", env: map[string]string{"DATABASE_URL": "postgres://localhost/db", "LOG_FORMAT": "yaml"}, wantErr: "LOG_FORMAT"},
		{name: "idle exceeds open", env: map[string]string{"DATABASE_URL": "postgres://localhost/db", "DATABASE_MAX_OPEN_CONNS": "2", "DATABASE_MAX_IDLE_CONNS": "3"}, wantErr: "DATABASE_MAX_IDLE_CONNS"},
		{name: "zero shutdown timeout", env: map[string]string{"DATABASE_URL": "postgres://localhost/db", "HTTP_SHUTDOWN_TIMEOUT": "0s"}, wantErr: "HTTP_SHUTDOWN_TIMEOUT"},
		{name: "negative Redis database", env: map[string]string{"DATABASE_URL": "postgres://localhost/db", "REDIS_DB": "-1"}, wantErr: "REDIS_DB"},
		{name: "missing JWT secret", env: map[string]string{"DATABASE_URL": "postgres://localhost/db", "AUTH_JWT_SECRET": ""}, wantErr: "AUTH_JWT_SECRET"},
		{name: "31 byte JWT secret", env: map[string]string{"DATABASE_URL": "postgres://localhost/db", "AUTH_JWT_SECRET": "1234567890123456789012345678901"}, wantErr: "AUTH_JWT_SECRET"},
		{name: "blank JWT issuer", env: map[string]string{"DATABASE_URL": "postgres://localhost/db", "AUTH_JWT_ISSUER": " "}, wantErr: "AUTH_JWT_ISSUER"},
		{name: "blank JWT audience", env: map[string]string{"DATABASE_URL": "postgres://localhost/db", "AUTH_JWT_AUDIENCE": " "}, wantErr: "AUTH_JWT_AUDIENCE"},
		{name: "equal token TTLs", env: map[string]string{"DATABASE_URL": "postgres://localhost/db", "AUTH_ACCESS_TOKEN_TTL": "1h", "AUTH_REFRESH_TOKEN_TTL": "1h"}, wantErr: "AUTH_REFRESH_TOKEN_TTL"},
		{name: "bcrypt cost below range", env: map[string]string{"DATABASE_URL": "postgres://localhost/db", "AUTH_BCRYPT_COST": "9"}, wantErr: "AUTH_BCRYPT_COST"},
		{name: "bcrypt cost above range", env: map[string]string{"DATABASE_URL": "postgres://localhost/db", "AUTH_BCRYPT_COST": "16"}, wantErr: "AUTH_BCRYPT_COST"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			clearConfigEnvironment(t)
			t.Setenv("AUTH_JWT_SECRET", validJWTSecret)
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

func clearConfigEnvironment(t *testing.T) {
	t.Helper()

	for _, key := range configEnvironmentKeys {
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
