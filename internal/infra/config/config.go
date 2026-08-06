package config

import (
	"fmt"
	"strings"
	"time"

	"github.com/caarlos0/env/v11"
)

type Environment string

const EnvironmentLocal Environment = "local"

type LogLevel string

const (
	LogLevelDebug LogLevel = "debug"
	LogLevelInfo  LogLevel = "info"
	LogLevelWarn  LogLevel = "warn"
	LogLevelError LogLevel = "error"
)

type LogFormat string

const (
	LogFormatJSON LogFormat = "json"
	LogFormatText LogFormat = "text"
)

type Config struct {
	Environment Environment `env:"APP_ENV" envDefault:"local"`
	HTTP        HTTPConfig
	Database    DatabaseConfig
	Redis       RedisConfig
	Log         LogConfig
}

type HTTPConfig struct {
	Address           string        `env:"HTTP_ADDR" envDefault:":8080"`
	ReadHeaderTimeout time.Duration `env:"HTTP_READ_HEADER_TIMEOUT" envDefault:"5s"`
	ReadTimeout       time.Duration `env:"HTTP_READ_TIMEOUT" envDefault:"10s"`
	WriteTimeout      time.Duration `env:"HTTP_WRITE_TIMEOUT" envDefault:"15s"`
	IdleTimeout       time.Duration `env:"HTTP_IDLE_TIMEOUT" envDefault:"60s"`
	ShutdownTimeout   time.Duration `env:"HTTP_SHUTDOWN_TIMEOUT" envDefault:"10s"`
}

type DatabaseConfig struct {
	URL             string        `env:"DATABASE_URL"`
	MaxOpenConns    int           `env:"DATABASE_MAX_OPEN_CONNS" envDefault:"20"`
	MaxIdleConns    int           `env:"DATABASE_MAX_IDLE_CONNS" envDefault:"5"`
	ConnMaxLifetime time.Duration `env:"DATABASE_CONN_MAX_LIFETIME" envDefault:"30m"`
	PingTimeout     time.Duration `env:"DATABASE_PING_TIMEOUT" envDefault:"3s"`
}

type RedisConfig struct {
	Address     string        `env:"REDIS_ADDR" envDefault:"localhost:6379"`
	Password    string        `env:"REDIS_PASSWORD"`
	DB          int           `env:"REDIS_DB" envDefault:"0"`
	PingTimeout time.Duration `env:"REDIS_PING_TIMEOUT" envDefault:"2s"`
}

type LogConfig struct {
	Level  LogLevel  `env:"LOG_LEVEL" envDefault:"info"`
	Format LogFormat `env:"LOG_FORMAT" envDefault:"json"`
}

func Load() (Config, error) {
	var cfg Config
	if err := env.Parse(&cfg); err != nil {
		return Config{}, fmt.Errorf("parse configuration: %w", err)
	}
	cfg.normalize()
	if err := cfg.Validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func (c *Config) normalize() {
	c.Environment = Environment(strings.TrimSpace(string(c.Environment)))
	c.HTTP.Address = strings.TrimSpace(c.HTTP.Address)
	c.Database.URL = strings.TrimSpace(c.Database.URL)
	c.Redis.Address = strings.TrimSpace(c.Redis.Address)
	c.Log.Level = LogLevel(strings.ToLower(strings.TrimSpace(string(c.Log.Level))))
	c.Log.Format = LogFormat(strings.ToLower(strings.TrimSpace(string(c.Log.Format))))
}

func (c Config) Validate() error {
	if strings.TrimSpace(string(c.Environment)) == "" {
		return fmt.Errorf("APP_ENV must not be empty")
	}
	if strings.TrimSpace(c.HTTP.Address) == "" {
		return fmt.Errorf("HTTP_ADDR must not be empty")
	}
	if c.HTTP.ReadHeaderTimeout <= 0 {
		return fmt.Errorf("HTTP_READ_HEADER_TIMEOUT must be greater than zero")
	}
	if c.HTTP.ReadTimeout <= 0 {
		return fmt.Errorf("HTTP_READ_TIMEOUT must be greater than zero")
	}
	if c.HTTP.WriteTimeout <= 0 {
		return fmt.Errorf("HTTP_WRITE_TIMEOUT must be greater than zero")
	}
	if c.HTTP.IdleTimeout <= 0 {
		return fmt.Errorf("HTTP_IDLE_TIMEOUT must be greater than zero")
	}
	if c.HTTP.ShutdownTimeout <= 0 {
		return fmt.Errorf("HTTP_SHUTDOWN_TIMEOUT must be greater than zero")
	}
	if strings.TrimSpace(c.Database.URL) == "" {
		return fmt.Errorf("DATABASE_URL is required")
	}
	if c.Database.MaxOpenConns < 0 {
		return fmt.Errorf("DATABASE_MAX_OPEN_CONNS must not be negative")
	}
	if c.Database.MaxIdleConns < 0 {
		return fmt.Errorf("DATABASE_MAX_IDLE_CONNS must not be negative")
	}
	if c.Database.MaxOpenConns > 0 && c.Database.MaxIdleConns > c.Database.MaxOpenConns {
		return fmt.Errorf("DATABASE_MAX_IDLE_CONNS must not exceed DATABASE_MAX_OPEN_CONNS")
	}
	if c.Database.ConnMaxLifetime <= 0 {
		return fmt.Errorf("DATABASE_CONN_MAX_LIFETIME must be greater than zero")
	}
	if c.Database.PingTimeout <= 0 {
		return fmt.Errorf("DATABASE_PING_TIMEOUT must be greater than zero")
	}
	if strings.TrimSpace(c.Redis.Address) == "" {
		return fmt.Errorf("REDIS_ADDR must not be empty")
	}
	if c.Redis.DB < 0 {
		return fmt.Errorf("REDIS_DB must not be negative")
	}
	if c.Redis.PingTimeout <= 0 {
		return fmt.Errorf("REDIS_PING_TIMEOUT must be greater than zero")
	}
	if !oneOf(string(c.Log.Level), "debug", "info", "warn", "error") {
		return fmt.Errorf("LOG_LEVEL must be one of debug, info, warn, or error")
	}
	if !oneOf(string(c.Log.Format), "json", "text") {
		return fmt.Errorf("LOG_FORMAT must be one of json or text")
	}
	return nil
}

func oneOf(value string, allowed ...string) bool {
	for _, candidate := range allowed {
		if value == candidate {
			return true
		}
	}
	return false
}
