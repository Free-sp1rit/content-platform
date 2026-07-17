//go:build integration

package migration_test

import (
	"context"
	"testing"
	"time"

	"github.com/Free-sp1rit/content-platform/internal/infra/config"
	"github.com/Free-sp1rit/content-platform/internal/infra/postgres"
	"github.com/Free-sp1rit/content-platform/internal/infra/postgres/migration"
	"github.com/Free-sp1rit/content-platform/internal/testkit"
)

func TestEmptyMigrationDirectoryIntegration(t *testing.T) {
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
	t.Cleanup(func() { _ = db.Close() })

	directory := t.TempDir()
	if err := migration.Run(context.Background(), db, directory, "up"); err != nil {
		t.Fatalf("migration up error = %v", err)
	}
	if err := migration.Run(context.Background(), db, directory, "status"); err != nil {
		t.Fatalf("migration status error = %v", err)
	}
}
