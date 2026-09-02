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

	identityhandler "github.com/Free-sp1rit/content-platform/internal/identity/handler"
	identityservice "github.com/Free-sp1rit/content-platform/internal/identity/service"
	"github.com/Free-sp1rit/content-platform/internal/infra/clock"
	"github.com/Free-sp1rit/content-platform/internal/infra/config"
	"github.com/Free-sp1rit/content-platform/internal/infra/password"
	"github.com/Free-sp1rit/content-platform/internal/infra/postgres"
	identitypostgres "github.com/Free-sp1rit/content-platform/internal/infra/postgres/identity"
	redisinfra "github.com/Free-sp1rit/content-platform/internal/infra/redis"
	"github.com/Free-sp1rit/content-platform/internal/infra/token"
	"github.com/Free-sp1rit/content-platform/internal/platform/authn"
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
	closeDatabase := true
	defer func() {
		if closeDatabase {
			_ = db.Close()
		}
	}()

	passwordHasher, err := password.New(cfg.Auth.BcryptCost)
	if err != nil {
		return nil, fmt.Errorf("initialize password hashing: %w", err)
	}
	accessManager, err := token.NewAccessManager(
		cfg.Auth.JWTSecret,
		cfg.Auth.JWTIssuer,
		cfg.Auth.JWTAudience,
	)
	if err != nil {
		return nil, fmt.Errorf("initialize access tokens: %w", err)
	}
	serviceClock := clock.System{}
	identityService, err := identityservice.New(identityservice.Dependencies{
		Repository:            identitypostgres.New(db),
		PasswordHasher:        passwordHasher,
		AccessTokenManager:    accessManager,
		RefreshTokenGenerator: token.NewRefreshCodec(),
		Clock:                 serviceClock,
	}, identityservice.Config{
		AccessTokenTTL:  cfg.Auth.AccessTokenTTL,
		RefreshTokenTTL: cfg.Auth.RefreshTokenTTL,
	})
	if err != nil {
		return nil, fmt.Errorf("initialize identity service: %w", err)
	}
	identityHandler := identityhandler.New(identityService, logger)
	authenticate := authn.Middleware(accessManager, serviceClock, identityHandler.RejectAccessToken)

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
		Handler:           Routes(logger, healthHandler, identityHandler, authenticate),
		ReadHeaderTimeout: cfg.HTTP.ReadHeaderTimeout,
		ReadTimeout:       cfg.HTTP.ReadTimeout,
		WriteTimeout:      cfg.HTTP.WriteTimeout,
		IdleTimeout:       cfg.HTTP.IdleTimeout,
	}

	application := &App{
		server:          server,
		logger:          logger,
		shutdownTimeout: cfg.HTTP.ShutdownTimeout,
		closers:         []io.Closer{redisClient, db},
	}
	closeDatabase = false
	return application, nil
}
