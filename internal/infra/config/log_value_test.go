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
	cfg.Auth.JWTSecret = "jwt-secret-do-not-log-0123456789abcdef"
	migrationCfg := MigrationConfig{
		Environment: cfg.Environment,
		Database:    cfg.Database,
		Log:         cfg.Log,
	}

	tests := []struct {
		name         string
		value        any
		safeText     []string
		wantRedacted bool
	}{
		{name: "root", value: cfg, safeText: []string{`"environment":"local"`, `"jwt_secret":"[REDACTED]"`, `"jwt_issuer":"content-platform"`}, wantRedacted: true},
		{name: "migration root", value: migrationCfg, safeText: []string{`"environment":"local"`, `"url":"[REDACTED]"`, `"level":"info"`}, wantRedacted: true},
		{name: "HTTP", value: cfg.HTTP, safeText: []string{`"address":":8080"`}},
		{name: "database", value: cfg.Database, safeText: []string{`"max_open_conns":20`}, wantRedacted: true},
		{name: "Redis", value: cfg.Redis, safeText: []string{`"db":0`}, wantRedacted: true},
		{name: "auth", value: cfg.Auth, safeText: []string{`"jwt_secret":"[REDACTED]"`, `"jwt_issuer":"content-platform"`, `"bcrypt_cost":12`}, wantRedacted: true},
		{name: "log", value: cfg.Log, safeText: []string{`"level":"info"`}},
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
			if strings.Contains(logged, "jwt-secret-do-not-log") {
				t.Fatal("structured log exposed JWT secret")
			}
			if tt.wantRedacted && !strings.Contains(logged, `"[REDACTED]"`) {
				t.Fatal("structured log does not contain redaction marker")
			}
			for _, safeText := range tt.safeText {
				if !strings.Contains(logged, safeText) {
					t.Fatalf("structured log missing safe field %q", safeText)
				}
			}
		})
	}
}
