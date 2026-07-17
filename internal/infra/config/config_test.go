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
	"LOG_LEVEL",
	"LOG_FORMAT",
}

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
		t.Fatalf("unexpected timeout or pool defaults: %#v", cfg)
	}
	if cfg.Log.Level != "info" || cfg.Log.Format != "json" {
		t.Fatalf("unexpected log defaults: %#v", cfg.Log)
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

	if cfg.Environment != "staging" || cfg.HTTP.Address != ":9090" {
		t.Fatalf("unexpected top-level config: %#v", cfg)
	}
	if cfg.Database.MaxOpenConns != 9 || cfg.Database.ConnMaxLifetime != 7*time.Minute {
		t.Fatalf("unexpected database config: %#v", cfg.Database)
	}
	if cfg.Redis.Address != "redis.example:6380" || cfg.Redis.Password != "secret" || cfg.Redis.DB != 4 {
		t.Fatalf("unexpected Redis config: %#v", cfg.Redis)
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
		{name: "negative Redis database", env: map[string]string{"DATABASE_URL": "postgres://localhost/db", "REDIS_DB": "-1"}, wantErr: "REDIS_DB"},
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
