package redis

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/Free-sp1rit/content-platform/internal/infra/config"
	goredis "github.com/redis/go-redis/v9"
)

func ConfigureLogger(logger *slog.Logger) {
	if logger == nil {
		return
	}
	goredis.SetLogger(&slogLogger{logger: logger})
}

func New(cfg config.RedisConfig) *goredis.Client {
	return goredis.NewClient(&goredis.Options{
		Addr:     cfg.Address,
		Password: cfg.Password,
		DB:       cfg.DB,
	})
}

type Checker struct {
	Client *goredis.Client
}

func (c Checker) Ping(ctx context.Context) error {
	return c.Client.Ping(ctx).Err()
}

type slogLogger struct {
	logger *slog.Logger
}

func (l *slogLogger) Printf(ctx context.Context, format string, values ...interface{}) {
	l.logger.WarnContext(ctx, "go-redis internal log", "detail", fmt.Sprintf(format, values...))
}
