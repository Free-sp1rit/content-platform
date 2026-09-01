package main

import (
	"bytes"
	"context"
	"io"
	"strings"
	"testing"
)

func TestRunReportsConfigurationFailure(t *testing.T) {
	resetServerConfigEnvironment(t)
	t.Setenv("DATABASE_URL", "")
	var stderr bytes.Buffer

	code := run(context.Background(), io.Discard, &stderr)

	if code != 1 {
		t.Fatalf("run() code = %d", code)
	}
	if !strings.Contains(stderr.String(), "DATABASE_URL is required") {
		t.Fatalf("run() stderr = %q", stderr.String())
	}
}

func TestRunRequiresAuthenticationConfig(t *testing.T) {
	resetServerConfigEnvironment(t)
	t.Setenv("DATABASE_URL", "postgres://localhost/content_platform")
	var stderr bytes.Buffer

	code := run(context.Background(), io.Discard, &stderr)

	if code != 1 {
		t.Fatalf("run() code = %d", code)
	}
	if !strings.Contains(stderr.String(), "AUTH_JWT_SECRET") {
		t.Fatalf("run() stderr = %q", stderr.String())
	}
}

func resetServerConfigEnvironment(t *testing.T) {
	t.Helper()

	keys := []string{
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
	for _, key := range keys {
		t.Setenv(key, "")
	}
}
