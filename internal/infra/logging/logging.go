package logging

import (
	"fmt"
	"io"
	"log/slog"

	"github.com/Free-sp1rit/content-platform/internal/infra/config"
)

func ParseLevel(value config.LogLevel) (slog.Level, error) {
	switch value {
	case config.LogLevelDebug:
		return slog.LevelDebug, nil
	case config.LogLevelInfo:
		return slog.LevelInfo, nil
	case config.LogLevelWarn:
		return slog.LevelWarn, nil
	case config.LogLevelError:
		return slog.LevelError, nil
	default:
		return 0, fmt.Errorf("unsupported log level %q", value)
	}
}

func New(cfg config.LogConfig, output io.Writer, environment config.Environment) (*slog.Logger, error) {
	level, err := ParseLevel(cfg.Level)
	if err != nil {
		return nil, err
	}

	options := &slog.HandlerOptions{Level: level}
	var handler slog.Handler
	switch cfg.Format {
	case config.LogFormatJSON:
		handler = slog.NewJSONHandler(output, options)
	case config.LogFormatText:
		handler = slog.NewTextHandler(output, options)
	default:
		return nil, fmt.Errorf("unsupported log format %q", cfg.Format)
	}

	return slog.New(handler).With(
		"service", "content-platform",
		"environment", string(environment),
	), nil
}
