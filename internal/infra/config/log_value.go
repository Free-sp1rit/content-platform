package config

import "log/slog"

const redactedValue = "[REDACTED]"

func (c Config) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("environment", string(c.Environment)),
		slog.Any("http", c.HTTP),
		slog.Any("database", c.Database),
		slog.Any("redis", c.Redis),
		slog.Any("auth", c.Auth),
		slog.Any("log", c.Log),
	)
}

func (c MigrationConfig) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("environment", string(c.Environment)),
		slog.Any("database", c.Database),
		slog.Any("log", c.Log),
	)
}

func (c HTTPConfig) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("address", c.Address),
		slog.Duration("read_header_timeout", c.ReadHeaderTimeout),
		slog.Duration("read_timeout", c.ReadTimeout),
		slog.Duration("write_timeout", c.WriteTimeout),
		slog.Duration("idle_timeout", c.IdleTimeout),
		slog.Duration("shutdown_timeout", c.ShutdownTimeout),
	)
}

func (c DatabaseConfig) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("url", redactedValue),
		slog.Int("max_open_conns", c.MaxOpenConns),
		slog.Int("max_idle_conns", c.MaxIdleConns),
		slog.Duration("conn_max_lifetime", c.ConnMaxLifetime),
		slog.Duration("ping_timeout", c.PingTimeout),
	)
}

func (c RedisConfig) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("address", c.Address),
		slog.String("password", redactedValue),
		slog.Int("db", c.DB),
		slog.Duration("ping_timeout", c.PingTimeout),
	)
}

func (c AuthConfig) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("jwt_secret", redactedValue),
		slog.String("jwt_issuer", c.JWTIssuer),
		slog.String("jwt_audience", c.JWTAudience),
		slog.Duration("access_token_ttl", c.AccessTokenTTL),
		slog.Duration("refresh_token_ttl", c.RefreshTokenTTL),
		slog.Int("bcrypt_cost", c.BcryptCost),
	)
}

func (c LogConfig) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("level", string(c.Level)),
		slog.String("format", string(c.Format)),
	)
}
