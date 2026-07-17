//go:build integration

package postgres_test

import (
	"context"
	"testing"
	"time"

	"github.com/Free-sp1rit/content-platform/internal/infra/config"
	"github.com/Free-sp1rit/content-platform/internal/infra/postgres"
	"github.com/Free-sp1rit/content-platform/internal/testkit"
)

func TestOpenIntegration(t *testing.T) {
	db, err := postgres.Open(context.Background(), config.DatabaseConfig{
		URL:             testkit.DatabaseURL(t),
		MaxOpenConns:    5,
		MaxIdleConns:    2,
		ConnMaxLifetime: time.Minute,
		PingTimeout:     3 * time.Second,
	})
	if err != nil {
		t.Fatalf("postgres.Open() error = %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("db.Close() error = %v", err)
	}
}
