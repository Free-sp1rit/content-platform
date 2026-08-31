package logging

import (
	"fmt"
	"io"
	"log/slog"

	"github.com/Free-sp1rit/content-platform/internal/infra/config"
)

func ParseLevel(value string) (slog.Level, error) {
	switch value {
	case "debug":
		return slog.LevelDebug, nil
	case "info":
		return slog.LevelInfo, nil
	case "warn":
		return slog.LevelWarn, nil
	case "error":
		return slog.LevelError, nil
	default:
		return 0, fmt.Errorf("unsupported log level %q", value)
	}
}

func New(cfg config.LogConfig, output io.Writer, environment string) (*slog.Logger, error) {
	level, err := ParseLevel(cfg.Level)
	if err != nil {
		return nil, err
	}

	options := &slog.HandlerOptions{Level: level}
	var handler slog.Handler
	switch cfg.Format {
	case "json":
		handler = slog.NewJSONHandler(output, options)
	case "text":
		handler = slog.NewTextHandler(output, options)
	default:
		return nil, fmt.Errorf("unsupported log format %q", cfg.Format)
	}

	return slog.New(handler).With(
		"service", "content-platform",
		"environment", environment,
	), nil
}
