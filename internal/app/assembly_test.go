package app

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/Free-sp1rit/content-platform/internal/infra/config"
	_ "github.com/jackc/pgx/v5/stdlib"
	goredis "github.com/redis/go-redis/v9"
)

func TestNewRejectsInvalidDatabaseConfigWithoutLeakingIt(t *testing.T) {
	cfg := validConfig()
	cfg.Database.URL = "invalid-database-url-with-secret"

	_, err := New(context.Background(), cfg, slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil)))

	if err == nil {
		t.Fatal("New() expected database initialization error")
	}
	if strings.Contains(err.Error(), cfg.Database.URL) {
		t.Fatalf("New() leaked database URL: %v", err)
	}
}

func TestNewWithDependenciesAllowsRedisDegradedStartup(t *testing.T) {
	cfg := validConfig()
	db, err := sql.Open("pgx", "postgres://localhost/content_platform?sslmode=disable")
	if err != nil {
		t.Fatal(err)
	}
	client := goredis.NewClient(&goredis.Options{Addr: cfg.Redis.Address})
	var logs bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logs, nil))
	redisErr := errors.New("Redis unavailable")
	deps := startupDependencies{
		openPostgres: func(context.Context, config.DatabaseConfig) (*sql.DB, error) {
			return db, nil
		},
		newRedis: func(config.RedisConfig) *goredis.Client {
			return client
		},
		pingRedis: func(context.Context, *goredis.Client) error {
			return redisErr
		},
	}

	application, err := newWithDependencies(context.Background(), cfg, logger, deps)

	if err != nil {
		t.Fatalf("newWithDependencies() error = %v", err)
	}
	t.Cleanup(func() { _ = application.closeResources() })
	if !strings.Contains(logs.String(), "Redis unavailable; starting in degraded mode") {
		t.Fatalf("missing degraded startup log: %s", logs.String())
	}
	if application.server.Addr != cfg.HTTP.Address || application.server.ReadHeaderTimeout != cfg.HTTP.ReadHeaderTimeout {
		t.Fatalf("unexpected HTTP server config: %#v", application.server)
	}
	if len(application.closers) != 2 || application.closers[0] != client || application.closers[1] != db {
		t.Fatalf("unexpected resource order: %#v", application.closers)
	}
}

func validConfig() config.Config {
	return config.Config{
		Environment: "test",
		HTTP: config.HTTPConfig{
			Address:           ":8080",
			ReadHeaderTimeout: time.Second,
			ReadTimeout:       2 * time.Second,
			WriteTimeout:      3 * time.Second,
			IdleTimeout:       4 * time.Second,
			ShutdownTimeout:   5 * time.Second,
		},
		Database: config.DatabaseConfig{
			URL:             "postgres://localhost/content_platform?sslmode=disable",
			MaxOpenConns:    5,
			MaxIdleConns:    2,
			ConnMaxLifetime: time.Minute,
			PingTimeout:     time.Second,
		},
		Redis: config.RedisConfig{
			Address:     "localhost:6379",
			PingTimeout: time.Second,
		},
		Log: config.LogConfig{Level: "info", Format: "json"},
	}
}
