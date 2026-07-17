package redis

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
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

func TestSlogLoggerProducesStructuredMessage(t *testing.T) {
	var output bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&output, nil))
	adapter := slogLogger{logger: logger}

	adapter.Printf(context.Background(), "connection failed: %s", "unavailable")

	text := output.String()
	if !strings.Contains(text, `"msg":"go-redis internal log"`) || !strings.Contains(text, `"detail":"connection failed: unavailable"`) {
		t.Fatalf("unexpected Redis log: %s", text)
	}
}
