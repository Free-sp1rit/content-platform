//go:build integration

package redis_test

import (
	"context"
	"testing"
	"time"

	"github.com/Free-sp1rit/content-platform/internal/infra/config"
	redisinfra "github.com/Free-sp1rit/content-platform/internal/infra/redis"
	"github.com/Free-sp1rit/content-platform/internal/testkit"
)

func TestCheckerIntegration(t *testing.T) {
	client := redisinfra.New(config.RedisConfig{
		Address: testkit.RedisAddress(t),
	})
	t.Cleanup(func() { _ = client.Close() })

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := (redisinfra.Checker{Client: client}).Ping(ctx); err != nil {
		t.Fatalf("Redis Ping() error = %v", err)
	}
}
