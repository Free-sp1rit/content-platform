package app

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
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

	register := httptest.NewRecorder()
	application.server.Handler.ServeHTTP(register, httptest.NewRequest(http.MethodPost, "/register", strings.NewReader(`{}`)))
	if register.Code != http.StatusBadRequest || !strings.Contains(register.Body.String(), `"code":"invalid_request"`) {
		t.Fatalf("identity register route not assembled: status=%d body=%s", register.Code, register.Body.String())
	}
	me := httptest.NewRecorder()
	application.server.Handler.ServeHTTP(me, httptest.NewRequest(http.MethodGet, "/me", nil))
	if me.Code != http.StatusUnauthorized || !strings.Contains(me.Body.String(), `"code":"invalid_access_token"`) {
		t.Fatalf("identity auth route not assembled: status=%d body=%s", me.Code, me.Body.String())
	}
	if me.Header().Get("WWW-Authenticate") != "Bearer" {
		t.Fatalf("WWW-Authenticate = %q", me.Header().Get("WWW-Authenticate"))
	}
}

func TestNewWithDependenciesClosesDatabaseOnSafeIdentityConstructorFailure(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*config.Config)
		secret string
	}{
		{
			name: "bcrypt",
			mutate: func(cfg *config.Config) {
				cfg.Auth.BcryptCost = 9
			},
		},
		{
			name: "access token",
			mutate: func(cfg *config.Config) {
				cfg.Auth.JWTSecret = "short-jwt-secret-do-not-leak"
			},
			secret: "short-jwt-secret-do-not-leak",
		},
		{
			name: "identity service",
			mutate: func(cfg *config.Config) {
				cfg.Auth.RefreshTokenTTL = cfg.Auth.AccessTokenTTL
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := validConfig()
			tt.mutate(&cfg)
			db, err := sql.Open("pgx", "postgres://localhost/content_platform?sslmode=disable")
			if err != nil {
				t.Fatal(err)
			}
			redisCreated := false
			deps := startupDependencies{
				openPostgres: func(context.Context, config.DatabaseConfig) (*sql.DB, error) {
					return db, nil
				},
				newRedis: func(config.RedisConfig) *goredis.Client {
					redisCreated = true
					return goredis.NewClient(&goredis.Options{Addr: "localhost:6379"})
				},
				pingRedis: func(context.Context, *goredis.Client) error { return nil },
			}

			application, err := newWithDependencies(context.Background(), cfg, slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil)), deps)

			if err == nil || application != nil {
				t.Fatalf("newWithDependencies() = %#v, %v, want failure", application, err)
			}
			if tt.secret != "" && strings.Contains(err.Error(), tt.secret) {
				t.Fatalf("startup error leaked secret: %v", err)
			}
			if strings.Contains(err.Error(), cfg.Database.URL) {
				t.Fatalf("startup error leaked database URL: %v", err)
			}
			if pingErr := db.PingContext(context.Background()); pingErr == nil {
				t.Fatal("database remained open after identity constructor failure")
			}
			if redisCreated {
				t.Fatal("Redis was created before identity composition completed")
			}
		})
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
		Auth: config.AuthConfig{
			JWTSecret:       "0123456789abcdef0123456789abcdef",
			JWTIssuer:       "content-platform",
			JWTAudience:     "content-platform-api",
			AccessTokenTTL:  15 * time.Minute,
			RefreshTokenTTL: 24 * time.Hour,
			BcryptCost:      10,
		},
		Log: config.LogConfig{Level: "info", Format: "json"},
	}
}
