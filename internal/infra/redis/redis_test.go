package redis

import (
	"testing"

	"github.com/Free-sp1rit/content-platform/internal/infra/config"
)

func TestNewUsesConfiguration(t *testing.T) {
	client := New(config.RedisConfig{
		Address:  "redis.example:6380",
		Password: "secret",
		DB:       3,
	})
	t.Cleanup(func() { _ = client.Close() })

	options := client.Options()
	if options.Addr != "redis.example:6380" || options.Password != "secret" || options.DB != 3 {
		t.Fatalf("unexpected Redis options: %#v", options)
	}
}
