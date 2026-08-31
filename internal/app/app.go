package app

import (
	"context"
	"database/sql"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/Free-sp1rit/content-platform/internal/infra/config"
	"github.com/Free-sp1rit/content-platform/internal/infra/postgres"
	redisinfra "github.com/Free-sp1rit/content-platform/internal/infra/redis"
	systemhandler "github.com/Free-sp1rit/content-platform/internal/system/handler"
	systemservice "github.com/Free-sp1rit/content-platform/internal/system/service"
	goredis "github.com/redis/go-redis/v9"
)

type App struct {
	server          *http.Server
	logger          *slog.Logger
	shutdownTimeout time.Duration
	closers         []io.Closer

	closeOnce sync.Once
	closeErr  error
}

type startupDependencies struct {
	openPostgres func(context.Context, config.DatabaseConfig) (*sql.DB, error)
	newRedis     func(config.RedisConfig) *goredis.Client
	pingRedis    func(context.Context, *goredis.Client) error
}

func New(ctx context.Context, cfg config.Config, logger *slog.Logger) (*App, error) {
	redisinfra.ConfigureLogger(logger)
	return newWithDependencies(ctx, cfg, logger, startupDependencies{
		openPostgres: postgres.Open,
		newRedis:     redisinfra.New,
		pingRedis: func(ctx context.Context, client *goredis.Client) error {
			return client.Ping(ctx).Err()
		},
	})
}

func newWithDependencies(ctx context.Context, cfg config.Config, logger *slog.Logger, deps startupDependencies) (*App, error) {
	db, err := deps.openPostgres(ctx, cfg.Database)
	if err != nil {
		return nil, fmt.Errorf("initialize PostgreSQL: %w", err)
	}

	redisClient := deps.newRedis(cfg.Redis)
	pingContext, cancel := context.WithTimeout(ctx, cfg.Redis.PingTimeout)
	redisErr := deps.pingRedis(pingContext, redisClient)
	cancel()
	if redisErr != nil && logger != nil {
		logger.Warn("Redis unavailable; starting in degraded mode", "error", redisErr)
	}

	healthService := systemservice.New(
		postgres.Checker{DB: db},
		redisinfra.Checker{Client: redisClient},
		cfg.Database.PingTimeout,
		cfg.Redis.PingTimeout,
	)
	healthHandler := systemhandler.New(healthService)
	server := &http.Server{
		Addr:              cfg.HTTP.Address,
		Handler:           Routes(logger, healthHandler),
		ReadHeaderTimeout: cfg.HTTP.ReadHeaderTimeout,
		ReadTimeout:       cfg.HTTP.ReadTimeout,
		WriteTimeout:      cfg.HTTP.WriteTimeout,
		IdleTimeout:       cfg.HTTP.IdleTimeout,
	}

	return &App{
		server:          server,
		logger:          logger,
		shutdownTimeout: cfg.HTTP.ShutdownTimeout,
		closers:         []io.Closer{redisClient, db},
	}, nil
}
