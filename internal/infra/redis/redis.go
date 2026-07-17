package redis

import (
	"context"

	"github.com/Free-sp1rit/content-platform/internal/infra/config"
	goredis "github.com/redis/go-redis/v9"
)

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
