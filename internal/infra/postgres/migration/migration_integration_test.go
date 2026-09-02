//go:build integration

package migration_test

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"testing"
	"time"

	"github.com/Free-sp1rit/content-platform/internal/infra/postgres/migration"
	"github.com/Free-sp1rit/content-platform/internal/testkit"
)

const migrationIntegrationTimeout = 30 * time.Second

func TestBaselineMigrationIntegration(t *testing.T) {
	// Do not call t.Parallel: migration.Run serializes goose's process-global state and this test runs DDL.
	ctx, db, _, directory := openIsolatedMigrationDatabase(t)
	if err := migration.Run(ctx, db, directory, "up"); err != nil {
		t.Fatalf("migration up error = %v", err)
	}
	if err := migration.Run(ctx, db, directory, "status"); err != nil {
		t.Fatalf("migration status error = %v", err)
	}
}

func openIsolatedMigrationDatabase(t *testing.T) (context.Context, *sql.DB, string, string) {
	t.Helper()
	fixture := testkit.OpenPostgresFixture(t, testkit.PostgresFixtureOptions{
		SchemaPrefix:   "migration_test",
		Timeout:        migrationIntegrationTimeout,
		CleanupTimeout: migrationIntegrationTimeout,
		MaxOpenConns:   5,
		MaxIdleConns:   2,
	})
	return fixture.Context, fixture.DB, fixture.Schema, fixture.MigrationsDirectory
}

func randomMigrationTestSuffix(t *testing.T) string {
	t.Helper()
	var random [8]byte
	if _, err := rand.Read(random[:]); err != nil {
		t.Fatalf("generate isolated test identifier: %v", err)
	}
	return hex.EncodeToString(random[:])
}
