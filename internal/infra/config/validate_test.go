package config

import (
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

func TestHTTPConfigValidate(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(*HTTPConfig)
		wantErr string
	}{
		{name: "valid wildcard address", mutate: func(*HTTPConfig) {}},
		{name: "valid IPv4", mutate: func(c *HTTPConfig) { c.Address = "127.0.0.1:8080" }},
		{name: "valid IPv6", mutate: func(c *HTTPConfig) { c.Address = "[::1]:8080" }},
		{name: "missing port", mutate: func(c *HTTPConfig) { c.Address = "localhost" }, wantErr: "HTTP_ADDR"},
		{name: "named port", mutate: func(c *HTTPConfig) { c.Address = "localhost:http" }, wantErr: "HTTP_ADDR"},
		{name: "zero port", mutate: func(c *HTTPConfig) { c.Address = ":0" }, wantErr: "HTTP_ADDR"},
		{name: "port too large", mutate: func(c *HTTPConfig) { c.Address = ":65536" }, wantErr: "HTTP_ADDR"},
		{name: "zero read header timeout", mutate: func(c *HTTPConfig) { c.ReadHeaderTimeout = 0 }, wantErr: "HTTP_READ_HEADER_TIMEOUT"},
		{name: "negative read header timeout", mutate: func(c *HTTPConfig) { c.ReadHeaderTimeout = -time.Second }, wantErr: "HTTP_READ_HEADER_TIMEOUT"},
		{name: "zero read timeout", mutate: func(c *HTTPConfig) { c.ReadTimeout = 0 }, wantErr: "HTTP_READ_TIMEOUT"},
		{name: "negative read timeout", mutate: func(c *HTTPConfig) { c.ReadTimeout = -time.Second }, wantErr: "HTTP_READ_TIMEOUT"},
		{name: "zero write timeout", mutate: func(c *HTTPConfig) { c.WriteTimeout = 0 }, wantErr: "HTTP_WRITE_TIMEOUT"},
		{name: "negative write timeout", mutate: func(c *HTTPConfig) { c.WriteTimeout = -time.Second }, wantErr: "HTTP_WRITE_TIMEOUT"},
		{name: "zero idle timeout", mutate: func(c *HTTPConfig) { c.IdleTimeout = 0 }, wantErr: "HTTP_IDLE_TIMEOUT"},
		{name: "negative idle timeout", mutate: func(c *HTTPConfig) { c.IdleTimeout = -time.Second }, wantErr: "HTTP_IDLE_TIMEOUT"},
		{name: "zero shutdown timeout", mutate: func(c *HTTPConfig) { c.ShutdownTimeout = 0 }, wantErr: "HTTP_SHUTDOWN_TIMEOUT"},
		{name: "negative shutdown timeout", mutate: func(c *HTTPConfig) { c.ShutdownTimeout = -time.Second }, wantErr: "HTTP_SHUTDOWN_TIMEOUT"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := validHTTPConfig()
			tt.mutate(&cfg)

			err := cfg.Validate()
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("Validate() error = %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("Validate() error = %v, want substring %q", err, tt.wantErr)
			}
		})
	}
}

func validHTTPConfig() HTTPConfig {
	return HTTPConfig{
		Address:           ":8080",
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
		ShutdownTimeout:   10 * time.Second,
	}
}

func TestDatabaseConfigValidate(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(*DatabaseConfig)
		wantErr string
	}{
		{name: "valid postgres URL", mutate: func(*DatabaseConfig) {}},
		{name: "valid postgresql URL", mutate: func(c *DatabaseConfig) { c.URL = "postgresql://localhost/content_platform" }},
		{name: "missing URL", mutate: func(c *DatabaseConfig) { c.URL = "" }, wantErr: "DATABASE_URL"},
		{name: "unsupported scheme", mutate: func(c *DatabaseConfig) { c.URL = "mysql://localhost/content_platform" }, wantErr: "DATABASE_URL"},
		{name: "missing database name", mutate: func(c *DatabaseConfig) { c.URL = "postgres://localhost/" }, wantErr: "DATABASE_URL"},
		{name: "database name only in query", mutate: func(c *DatabaseConfig) { c.URL = "postgres://localhost?dbname=content_platform" }, wantErr: "DATABASE_URL"},
		{name: "invalid driver port", mutate: func(c *DatabaseConfig) { c.URL = "postgres://localhost:notaport/content_platform" }, wantErr: "DATABASE_URL"},
		{name: "negative max open", mutate: func(c *DatabaseConfig) { c.MaxOpenConns = -1 }, wantErr: "DATABASE_MAX_OPEN_CONNS"},
		{name: "zero max open", mutate: func(c *DatabaseConfig) { c.MaxOpenConns = 0 }, wantErr: "DATABASE_MAX_OPEN_CONNS"},
		{name: "one max open", mutate: func(c *DatabaseConfig) { c.MaxOpenConns = 1; c.MaxIdleConns = 1 }},
		{name: "negative max idle", mutate: func(c *DatabaseConfig) { c.MaxIdleConns = -1 }, wantErr: "DATABASE_MAX_IDLE_CONNS"},
		{name: "zero max idle", mutate: func(c *DatabaseConfig) { c.MaxIdleConns = 0 }},
		{name: "idle equals open", mutate: func(c *DatabaseConfig) { c.MaxIdleConns = c.MaxOpenConns }},
		{name: "idle exceeds open", mutate: func(c *DatabaseConfig) { c.MaxIdleConns = c.MaxOpenConns + 1 }, wantErr: "DATABASE_MAX_IDLE_CONNS"},
		{name: "zero max lifetime", mutate: func(c *DatabaseConfig) { c.ConnMaxLifetime = 0 }, wantErr: "DATABASE_CONN_MAX_LIFETIME"},
		{name: "negative max lifetime", mutate: func(c *DatabaseConfig) { c.ConnMaxLifetime = -time.Second }, wantErr: "DATABASE_CONN_MAX_LIFETIME"},
		{name: "zero ping timeout", mutate: func(c *DatabaseConfig) { c.PingTimeout = 0 }, wantErr: "DATABASE_PING_TIMEOUT"},
		{name: "negative ping timeout", mutate: func(c *DatabaseConfig) { c.PingTimeout = -time.Second }, wantErr: "DATABASE_PING_TIMEOUT"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := validDatabaseConfig()
			tt.mutate(&cfg)

			err := cfg.Validate()
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("Validate() error = %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("Validate() error = %v, want substring %q", err, tt.wantErr)
			}
		})
	}
}

func TestDatabaseConfigValidateDoesNotExposeURL(t *testing.T) {
	cfg := validDatabaseConfig()
	cfg.URL = "mysql://user:db-password-do-not-log@localhost/content_platform"

	err := cfg.Validate()
	if err == nil {
		t.Fatal("Validate() expected error")
	}
	if strings.Contains(err.Error(), "db-password-do-not-log") || strings.Contains(err.Error(), cfg.URL) {
		t.Fatal("Validate() exposed DATABASE_URL")
	}
}

func validDatabaseConfig() DatabaseConfig {
	return DatabaseConfig{
		URL:             "postgres://localhost/content_platform",
		MaxOpenConns:    20,
		MaxIdleConns:    5,
		ConnMaxLifetime: 30 * time.Minute,
		PingTimeout:     3 * time.Second,
	}
}

func TestRedisConfigValidate(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(*RedisConfig)
		wantErr string
	}{
		{name: "valid hostname", mutate: func(*RedisConfig) {}},
		{name: "valid IPv4", mutate: func(c *RedisConfig) { c.Address = "127.0.0.1:6379" }},
		{name: "valid IPv6", mutate: func(c *RedisConfig) { c.Address = "[::1]:6379" }},
		{name: "missing host", mutate: func(c *RedisConfig) { c.Address = ":6379" }, wantErr: "REDIS_ADDR"},
		{name: "missing port", mutate: func(c *RedisConfig) { c.Address = "localhost" }, wantErr: "REDIS_ADDR"},
		{name: "named port", mutate: func(c *RedisConfig) { c.Address = "localhost:redis" }, wantErr: "REDIS_ADDR"},
		{name: "zero port", mutate: func(c *RedisConfig) { c.Address = "localhost:0" }, wantErr: "REDIS_ADDR"},
		{name: "port too large", mutate: func(c *RedisConfig) { c.Address = "localhost:65536" }, wantErr: "REDIS_ADDR"},
		{name: "zero database", mutate: func(c *RedisConfig) { c.DB = 0 }},
		{name: "negative database", mutate: func(c *RedisConfig) { c.DB = -1 }, wantErr: "REDIS_DB"},
		{name: "zero ping timeout", mutate: func(c *RedisConfig) { c.PingTimeout = 0 }, wantErr: "REDIS_PING_TIMEOUT"},
		{name: "negative ping timeout", mutate: func(c *RedisConfig) { c.PingTimeout = -time.Second }, wantErr: "REDIS_PING_TIMEOUT"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := validRedisConfig()
			tt.mutate(&cfg)

			err := cfg.Validate()
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("Validate() error = %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("Validate() error = %v, want substring %q", err, tt.wantErr)
			}
		})
	}
}

func TestAuthConfigValidate(t *testing.T) {
	const exact32ByteUTF8Secret = "你好世界你好世界你好ab"
	if got := len(exact32ByteUTF8Secret); got != 32 {
		t.Fatalf("test secret byte length = %d, want 32", got)
	}
	if got := utf8.RuneCountInString(exact32ByteUTF8Secret); got >= 32 {
		t.Fatalf("test secret rune count = %d, want fewer than 32", got)
	}

	tests := []struct {
		name    string
		mutate  func(*AuthConfig)
		wantErr string
	}{
		{name: "32 byte secret", mutate: func(*AuthConfig) {}},
		{name: "32 byte multibyte secret", mutate: func(c *AuthConfig) { c.JWTSecret = exact32ByteUTF8Secret }},
		{name: "missing secret", mutate: func(c *AuthConfig) { c.JWTSecret = "" }, wantErr: "AUTH_JWT_SECRET"},
		{name: "31 byte secret", mutate: func(c *AuthConfig) { c.JWTSecret = "1234567890123456789012345678901" }, wantErr: "AUTH_JWT_SECRET"},
		{name: "blank issuer", mutate: func(c *AuthConfig) { c.JWTIssuer = " " }, wantErr: "AUTH_JWT_ISSUER"},
		{name: "blank audience", mutate: func(c *AuthConfig) { c.JWTAudience = " " }, wantErr: "AUTH_JWT_AUDIENCE"},
		{name: "zero access TTL", mutate: func(c *AuthConfig) { c.AccessTokenTTL = 0 }, wantErr: "AUTH_ACCESS_TOKEN_TTL"},
		{name: "negative access TTL", mutate: func(c *AuthConfig) { c.AccessTokenTTL = -time.Second }, wantErr: "AUTH_ACCESS_TOKEN_TTL"},
		{name: "zero refresh TTL", mutate: func(c *AuthConfig) { c.RefreshTokenTTL = 0 }, wantErr: "AUTH_REFRESH_TOKEN_TTL must be greater than zero"},
		{name: "negative refresh TTL", mutate: func(c *AuthConfig) { c.RefreshTokenTTL = -time.Second }, wantErr: "AUTH_REFRESH_TOKEN_TTL must be greater than zero"},
		{name: "refresh equals access", mutate: func(c *AuthConfig) { c.RefreshTokenTTL = c.AccessTokenTTL }, wantErr: "AUTH_REFRESH_TOKEN_TTL must be greater than AUTH_ACCESS_TOKEN_TTL"},
		{name: "refresh shorter than access", mutate: func(c *AuthConfig) { c.AccessTokenTTL = 2 * time.Hour; c.RefreshTokenTTL = time.Hour }, wantErr: "AUTH_REFRESH_TOKEN_TTL must be greater than AUTH_ACCESS_TOKEN_TTL"},
		{name: "bcrypt cost 9", mutate: func(c *AuthConfig) { c.BcryptCost = 9 }, wantErr: "AUTH_BCRYPT_COST"},
		{name: "bcrypt cost 10", mutate: func(c *AuthConfig) { c.BcryptCost = 10 }},
		{name: "bcrypt cost 15", mutate: func(c *AuthConfig) { c.BcryptCost = 15 }},
		{name: "bcrypt cost 16", mutate: func(c *AuthConfig) { c.BcryptCost = 16 }, wantErr: "AUTH_BCRYPT_COST"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := validAuthConfig()
			tt.mutate(&cfg)

			err := cfg.Validate()
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("Validate() error = %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("Validate() error = %v, want substring %q", err, tt.wantErr)
			}
		})
	}
}

func TestAuthConfigValidateDoesNotExposeJWTSecret(t *testing.T) {
	const (
		secretMarker = "jwt-secret-do-not-log"
		secret       = secretMarker + "-123456"
	)
	cfg := validAuthConfig()
	cfg.JWTSecret = secret

	err := cfg.Validate()
	if err == nil {
		t.Fatal("Validate() expected error")
	}
	if !strings.Contains(err.Error(), "AUTH_JWT_SECRET") {
		t.Fatalf("Validate() error = %v, want AUTH_JWT_SECRET", err)
	}
	if strings.Contains(err.Error(), secretMarker) {
		t.Fatal("Validate() exposed AUTH_JWT_SECRET")
	}
}

func TestLogConfigValidate(t *testing.T) {
	tests := []struct {
		name    string
		cfg     LogConfig
		wantErr string
	}{
		{name: "debug JSON", cfg: LogConfig{Level: LogLevelDebug, Format: LogFormatJSON}},
		{name: "info text", cfg: LogConfig{Level: LogLevelInfo, Format: LogFormatText}},
		{name: "warn JSON", cfg: LogConfig{Level: LogLevelWarn, Format: LogFormatJSON}},
		{name: "error text", cfg: LogConfig{Level: LogLevelError, Format: LogFormatText}},
		{name: "invalid level", cfg: LogConfig{Level: LogLevel("verbose"), Format: LogFormatJSON}, wantErr: "LOG_LEVEL"},
		{name: "invalid format", cfg: LogConfig{Level: LogLevelInfo, Format: LogFormat("yaml")}, wantErr: "LOG_FORMAT"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.cfg.Validate()
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("Validate() error = %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("Validate() error = %v, want substring %q", err, tt.wantErr)
			}
		})
	}
}

func TestConfigValidateReturnsFirstErrorInStableOrder(t *testing.T) {
	tests := []struct {
		name     string
		mutate   func(*Config)
		wantErr  string
		laterErr string
	}{
		{
			name: "environment before HTTP",
			mutate: func(c *Config) {
				c.Environment = ""
				c.HTTP.Address = "invalid"
			},
			wantErr:  "APP_ENV",
			laterErr: "HTTP_ADDR",
		},
		{
			name: "HTTP before database",
			mutate: func(c *Config) {
				c.HTTP.Address = "invalid"
				c.Database.URL = ""
			},
			wantErr:  "HTTP_ADDR",
			laterErr: "DATABASE_URL",
		},
		{
			name: "database before Redis",
			mutate: func(c *Config) {
				c.Database.URL = ""
				c.Redis.Address = "invalid"
			},
			wantErr:  "DATABASE_URL",
			laterErr: "REDIS_ADDR",
		},
		{
			name: "Redis before auth",
			mutate: func(c *Config) {
				c.Redis.Address = "invalid"
				c.Auth.JWTSecret = ""
			},
			wantErr:  "REDIS_ADDR",
			laterErr: "AUTH_JWT_SECRET",
		},
		{
			name: "auth before log",
			mutate: func(c *Config) {
				c.Auth.JWTSecret = ""
				c.Log.Level = LogLevel("verbose")
			},
			wantErr:  "AUTH_JWT_SECRET",
			laterErr: "LOG_LEVEL",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := validConfig()
			tt.mutate(&cfg)

			err := cfg.Validate()
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("Validate() error = %v, want substring %q", err, tt.wantErr)
			}
			if strings.Contains(err.Error(), tt.laterErr) {
				t.Fatalf("Validate() error = %v, unexpectedly contains later error %q", err, tt.laterErr)
			}
		})
	}
}

func validRedisConfig() RedisConfig {
	return RedisConfig{
		Address:     "localhost:6379",
		Password:    "",
		DB:          0,
		PingTimeout: 2 * time.Second,
	}
}

func validAuthConfig() AuthConfig {
	return AuthConfig{
		JWTSecret:       validJWTSecret,
		JWTIssuer:       "content-platform",
		JWTAudience:     "content-platform-api",
		AccessTokenTTL:  15 * time.Minute,
		RefreshTokenTTL: 720 * time.Hour,
		BcryptCost:      12,
	}
}

func validConfig() Config {
	return Config{
		Environment: EnvironmentLocal,
		HTTP:        validHTTPConfig(),
		Database:    validDatabaseConfig(),
		Redis:       validRedisConfig(),
		Auth:        validAuthConfig(),
		Log: LogConfig{
			Level:  LogLevelInfo,
			Format: LogFormatJSON,
		},
	}
}
