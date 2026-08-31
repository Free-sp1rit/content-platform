package config

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"
)

func TestLogValueRedactsSensitiveConfiguration(t *testing.T) {
	cfg := validConfig()
	cfg.Database.URL = "postgres://dbuser:db-password-do-not-log@localhost/content_platform"
	cfg.Redis.Password = "redis-password-do-not-log"

	tests := []struct {
		name         string
		value        any
		safeText     string
		wantRedacted bool
	}{
		{name: "root", value: cfg, safeText: `"environment":"local"`, wantRedacted: true},
		{name: "HTTP", value: cfg.HTTP, safeText: `"address":":8080"`},
		{name: "database", value: cfg.Database, safeText: `"max_open_conns":20`, wantRedacted: true},
		{name: "Redis", value: cfg.Redis, safeText: `"db":0`, wantRedacted: true},
		{name: "log", value: cfg.Log, safeText: `"level":"info"`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var output bytes.Buffer
			logger := slog.New(slog.NewJSONHandler(&output, nil))
			logger.Info("configuration", "config", tt.value)

			logged := output.String()
			if strings.Contains(logged, "db-password-do-not-log") {
				t.Fatal("structured log exposed database credentials")
			}
			if strings.Contains(logged, "redis-password-do-not-log") {
				t.Fatal("structured log exposed Redis password")
			}
			if tt.wantRedacted && !strings.Contains(logged, `"[REDACTED]"`) {
				t.Fatal("structured log does not contain redaction marker")
			}
			if !strings.Contains(logged, tt.safeText) {
				t.Fatalf("structured log missing safe field %q", tt.safeText)
			}
		})
	}
}
