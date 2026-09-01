//go:build integration

package migration_test

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/Free-sp1rit/content-platform/internal/infra/config"
	"github.com/Free-sp1rit/content-platform/internal/infra/postgres"
	"github.com/Free-sp1rit/content-platform/internal/infra/postgres/migration"
	"github.com/Free-sp1rit/content-platform/internal/testkit"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
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
	databaseURL := testkit.DatabaseURL(t)
	ctx, cancel := context.WithTimeout(context.Background(), migrationIntegrationTimeout)
	t.Cleanup(cancel)

	adminDB, err := postgres.Open(ctx, config.DatabaseConfig{
		URL:             databaseURL,
		MaxOpenConns:    5,
		MaxIdleConns:    2,
		ConnMaxLifetime: time.Minute,
		PingTimeout:     3 * time.Second,
	})
	if err != nil {
		t.Fatalf("postgres.Open() error = %v", err)
	}

	schema := newMigrationTestSchema(t)
	if _, err := adminDB.ExecContext(ctx, "CREATE SCHEMA "+quoteIdentifier(schema)); err != nil {
		_ = adminDB.Close()
		t.Fatalf("create isolated test schema: %v", err)
	}

	var db *sql.DB
	t.Cleanup(func() {
		if db != nil {
			_ = db.Close()
		}
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), migrationIntegrationTimeout)
		defer cleanupCancel()
		if _, err := adminDB.ExecContext(cleanupCtx, "DROP SCHEMA IF EXISTS "+quoteIdentifier(schema)+" CASCADE"); err != nil {
			t.Errorf("drop isolated test schema: %v", err)
		}
		if err := adminDB.Close(); err != nil {
			t.Errorf("close PostgreSQL admin connection: %v", err)
		}
	})

	isolatedConfig, err := pgx.ParseConfig(databaseURL)
	if err != nil {
		t.Fatalf("parse isolated PostgreSQL configuration: %v", err)
	}
	isolatedConfig.RuntimeParams["search_path"] = schema
	db = stdlib.OpenDB(*isolatedConfig)
	db.SetMaxOpenConns(5)
	db.SetMaxIdleConns(2)
	db.SetConnMaxLifetime(time.Minute)
	pingCtx, pingCancel := context.WithTimeout(ctx, 3*time.Second)
	err = db.PingContext(pingCtx)
	pingCancel()
	if err != nil {
		t.Fatalf("ping isolated PostgreSQL connection: %v", err)
	}

	return ctx, db, schema, migrationsDirectory(t)
}

func migrationsDirectory(t *testing.T) string {
	t.Helper()
	_, sourceFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller() could not locate integration test")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(sourceFile), "..", "..", "..", "..", "migrations"))
}

func newMigrationTestSchema(t *testing.T) string {
	t.Helper()
	return "migration_test_" + randomMigrationTestSuffix(t)
}

func randomMigrationTestSuffix(t *testing.T) string {
	t.Helper()
	var random [8]byte
	if _, err := rand.Read(random[:]); err != nil {
		t.Fatalf("generate isolated test identifier: %v", err)
	}
	return hex.EncodeToString(random[:])
}

func quoteIdentifier(identifier string) string {
	return `"` + strings.ReplaceAll(identifier, `"`, `""`) + `"`
}
