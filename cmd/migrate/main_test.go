package main

import (
	"bytes"
	"context"
	"io"
	"strings"
	"testing"
)

func TestRunRejectsMissingCommand(t *testing.T) {
	var stderr bytes.Buffer

	code := run(context.Background(), nil, io.Discard, &stderr)

	if code != 2 || !strings.Contains(stderr.String(), "usage:") {
		t.Fatalf("run() = %d, stderr = %q", code, stderr.String())
	}
}

func TestRunRejectsUnsupportedCommandBeforeLoadingConfig(t *testing.T) {
	t.Setenv("DATABASE_URL", "")
	var stderr bytes.Buffer

	code := run(context.Background(), []string{"reset"}, io.Discard, &stderr)

	if code != 2 || !strings.Contains(stderr.String(), "unsupported migration command") {
		t.Fatalf("run() = %d, stderr = %q", code, stderr.String())
	}
	if strings.Contains(stderr.String(), "DATABASE_URL") {
		t.Fatalf("configuration loaded before command validation: %q", stderr.String())
	}
}

func TestLoadMigrationConfigDoesNotRequireAuthenticationConfig(t *testing.T) {
	t.Setenv("APP_ENV", "local")
	t.Setenv("DATABASE_URL", "postgres://localhost/content_platform")
	t.Setenv("DATABASE_MAX_OPEN_CONNS", "20")
	t.Setenv("DATABASE_MAX_IDLE_CONNS", "5")
	t.Setenv("DATABASE_CONN_MAX_LIFETIME", "30m")
	t.Setenv("DATABASE_PING_TIMEOUT", "3s")
	t.Setenv("LOG_LEVEL", "info")
	t.Setenv("LOG_FORMAT", "json")
	t.Setenv("AUTH_JWT_SECRET", "")
	t.Setenv("AUTH_ACCESS_TOKEN_TTL", "not-a-duration")
	t.Setenv("HTTP_ADDR", "not-a-valid-address")
	t.Setenv("REDIS_ADDR", "not-a-valid-address")

	cfg, err := loadMigrationConfig()
	if err != nil {
		t.Fatalf("loadMigrationConfig() error = %v", err)
	}
	if cfg.Database.URL != "postgres://localhost/content_platform" {
		t.Fatalf("Database.URL = %q", cfg.Database.URL)
	}
}

func TestRunUsesMigrationScopedConfiguration(t *testing.T) {
	resetMigrationConfigEnvironment(t)
	t.Setenv("DATABASE_URL", "")
	t.Setenv("AUTH_JWT_SECRET", "")
	t.Setenv("AUTH_ACCESS_TOKEN_TTL", "not-a-duration")
	t.Setenv("HTTP_ADDR", "not-a-valid-address")
	t.Setenv("REDIS_ADDR", "not-a-valid-address")
	var stderr bytes.Buffer

	code := run(context.Background(), []string{"status"}, io.Discard, &stderr)

	if code != 1 {
		t.Fatalf("run() = %d, stderr = %q", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), "DATABASE_URL is required") {
		t.Fatalf("run() stderr = %q, want DATABASE_URL error", stderr.String())
	}
	for _, unrelated := range []string{"AUTH_ACCESS_TOKEN_TTL", "HTTP_ADDR", "REDIS_ADDR"} {
		if strings.Contains(stderr.String(), unrelated) {
			t.Fatalf("run() stderr = %q, unexpectedly contains %s", stderr.String(), unrelated)
		}
	}
}

func resetMigrationConfigEnvironment(t *testing.T) {
	t.Helper()

	for _, key := range []string{
		"APP_ENV",
		"DATABASE_URL",
		"DATABASE_MAX_OPEN_CONNS",
		"DATABASE_MAX_IDLE_CONNS",
		"DATABASE_CONN_MAX_LIFETIME",
		"DATABASE_PING_TIMEOUT",
		"LOG_LEVEL",
		"LOG_FORMAT",
	} {
		t.Setenv(key, "")
	}
}
