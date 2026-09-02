//go:build integration

package testkit

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
	postgresinfra "github.com/Free-sp1rit/content-platform/internal/infra/postgres"
	"github.com/Free-sp1rit/content-platform/internal/infra/postgres/migration"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
)

const (
	defaultPostgresFixtureTimeout        = 30 * time.Second
	defaultPostgresFixtureCleanupTimeout = 30 * time.Second
	defaultPostgresFixtureMaxOpenConns   = 8
	defaultPostgresFixtureMaxIdleConns   = 4
	postgresFixturePingTimeout           = 3 * time.Second
)

type PostgresFixtureOptions struct {
	SchemaPrefix    string
	Timeout         time.Duration
	CleanupTimeout  time.Duration
	MaxOpenConns    int
	MaxIdleConns    int
	ApplyMigrations bool
}

type PostgresFixture struct {
	Context             context.Context
	DB                  *sql.DB
	DatabaseURL         string
	Schema              string
	MigrationsDirectory string

	timeout time.Duration
}

func OpenPostgresFixture(t testing.TB, options PostgresFixtureOptions) *PostgresFixture {
	t.Helper()
	options = normalizePostgresFixtureOptions(t, options)
	databaseURL := DatabaseURL(t)
	ctx, cancel := context.WithTimeout(context.Background(), options.Timeout)
	t.Cleanup(cancel)

	adminDB, err := postgresinfra.Open(ctx, config.DatabaseConfig{
		URL:             databaseURL,
		MaxOpenConns:    5,
		MaxIdleConns:    2,
		ConnMaxLifetime: time.Minute,
		PingTimeout:     postgresFixturePingTimeout,
	})
	if err != nil {
		t.Fatalf("open PostgreSQL fixture admin connection: %v", err)
	}

	schema := options.SchemaPrefix + "_" + randomPostgresFixtureSuffix(t)
	if _, err := adminDB.ExecContext(ctx, "CREATE SCHEMA "+quotePostgresIdentifier(schema)); err != nil {
		_ = adminDB.Close()
		t.Fatalf("create isolated PostgreSQL schema: %v", err)
	}

	fixture := &PostgresFixture{
		Context:             ctx,
		DatabaseURL:         databaseURL,
		Schema:              schema,
		MigrationsDirectory: postgresMigrationsDirectory(t),
		timeout:             options.CleanupTimeout,
	}
	t.Cleanup(func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), options.CleanupTimeout)
		defer cleanupCancel()
		if _, err := adminDB.ExecContext(cleanupCtx, "DROP SCHEMA IF EXISTS "+quotePostgresIdentifier(schema)+" CASCADE"); err != nil {
			t.Errorf("drop isolated PostgreSQL schema: %v", err)
		}
		if err := adminDB.Close(); err != nil {
			t.Errorf("close PostgreSQL fixture admin connection: %v", err)
		}
	})

	fixture.DB = fixture.OpenPool(t, "", options.MaxOpenConns, options.MaxIdleConns)
	if options.ApplyMigrations {
		fixture.ApplyMigrations(t)
	}
	return fixture
}

func (fixture *PostgresFixture) ApplyMigrations(t testing.TB) {
	t.Helper()
	if err := migration.Run(fixture.Context, fixture.DB, fixture.MigrationsDirectory, "up"); err != nil {
		t.Fatalf("apply PostgreSQL fixture migrations: %v", err)
	}
}

func (fixture *PostgresFixture) OpenPool(t testing.TB, applicationName string, maxOpenConns, maxIdleConns int) *sql.DB {
	t.Helper()
	parsed, err := pgx.ParseConfig(fixture.DatabaseURL)
	if err != nil {
		t.Fatalf("parse PostgreSQL fixture configuration: %v", err)
	}
	parsed.RuntimeParams["search_path"] = fixture.Schema
	if applicationName = strings.TrimSpace(applicationName); applicationName != "" {
		parsed.RuntimeParams["application_name"] = applicationName
	}

	db := stdlib.OpenDB(*parsed)
	if maxOpenConns <= 0 {
		maxOpenConns = defaultPostgresFixtureMaxOpenConns
	}
	if maxIdleConns < 0 {
		maxIdleConns = 0
	}
	if maxIdleConns > maxOpenConns {
		maxIdleConns = maxOpenConns
	}
	db.SetMaxOpenConns(maxOpenConns)
	db.SetMaxIdleConns(maxIdleConns)
	db.SetConnMaxLifetime(time.Minute)
	t.Cleanup(func() {
		if err := db.Close(); err != nil {
			t.Errorf("close isolated PostgreSQL pool: %v", err)
		}
	})

	pingTimeout := postgresFixturePingTimeout
	if fixture.timeout > 0 && fixture.timeout < pingTimeout {
		pingTimeout = fixture.timeout
	}
	pingCtx, cancel := context.WithTimeout(fixture.Context, pingTimeout)
	defer cancel()
	if err := db.PingContext(pingCtx); err != nil {
		t.Fatalf("ping isolated PostgreSQL pool: %v", err)
	}
	return db
}

func normalizePostgresFixtureOptions(t testing.TB, options PostgresFixtureOptions) PostgresFixtureOptions {
	t.Helper()
	options.SchemaPrefix = strings.TrimSpace(options.SchemaPrefix)
	if options.SchemaPrefix == "" {
		options.SchemaPrefix = "postgres_test"
	}
	if len(options.SchemaPrefix) > 46 || !validPostgresFixtureIdentifier(options.SchemaPrefix) {
		t.Fatalf("invalid PostgreSQL fixture schema prefix %q", options.SchemaPrefix)
	}
	if options.Timeout <= 0 {
		options.Timeout = defaultPostgresFixtureTimeout
	}
	if options.CleanupTimeout <= 0 {
		options.CleanupTimeout = defaultPostgresFixtureCleanupTimeout
	}
	if options.MaxOpenConns <= 0 {
		options.MaxOpenConns = defaultPostgresFixtureMaxOpenConns
	}
	if options.MaxIdleConns < 0 {
		options.MaxIdleConns = 0
	} else if options.MaxIdleConns == 0 {
		options.MaxIdleConns = defaultPostgresFixtureMaxIdleConns
	}
	if options.MaxIdleConns > options.MaxOpenConns {
		options.MaxIdleConns = options.MaxOpenConns
	}
	return options
}

func validPostgresFixtureIdentifier(value string) bool {
	for index := range value {
		character := value[index]
		if (character < 'a' || character > 'z') && (character < '0' || character > '9') && character != '_' {
			return false
		}
	}
	return true
}

func randomPostgresFixtureSuffix(t testing.TB) string {
	t.Helper()
	var random [8]byte
	if _, err := rand.Read(random[:]); err != nil {
		t.Fatalf("generate isolated PostgreSQL schema suffix: %v", err)
	}
	return hex.EncodeToString(random[:])
}

func postgresMigrationsDirectory(t testing.TB) string {
	t.Helper()
	_, sourceFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("locate PostgreSQL fixture source file")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(sourceFile), "..", "..", "migrations"))
}

func quotePostgresIdentifier(identifier string) string {
	return `"` + strings.ReplaceAll(identifier, `"`, `""`) + `"`
}
