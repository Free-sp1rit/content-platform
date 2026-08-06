package config

import "log/slog"

const redactedValue = "[REDACTED]"

func (c Config) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("environment", string(c.Environment)),
		slog.Any("http", c.HTTP),
		slog.Any("database", c.Database),
		slog.Any("redis", c.Redis),
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

func (c LogConfig) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("level", string(c.Level)),
		slog.String("format", string(c.Format)),
	)
}
