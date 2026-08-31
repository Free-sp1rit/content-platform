//go:build integration

package testkit

import (
	"os"
	"strings"
	"testing"
)

func DatabaseURL(t testing.TB) string {
	t.Helper()
	value := strings.TrimSpace(os.Getenv("TEST_DATABASE_URL"))
	if value == "" {
		t.Skip("TEST_DATABASE_URL is not set; skipping PostgreSQL integration test")
	}
	return value
}

func RedisAddress(t testing.TB) string {
	t.Helper()
	value := strings.TrimSpace(os.Getenv("TEST_REDIS_ADDR"))
	if value == "" {
		t.Skip("TEST_REDIS_ADDR is not set; skipping Redis integration test")
	}
	return value
}
