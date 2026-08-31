package migration

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"strings"
	"sync"

	"github.com/pressly/goose/v3"
)

var (
	runMu            sync.Mutex
	loggerConfigured bool
)

func ConfigureLogger(logger *slog.Logger) {
	runMu.Lock()
	defer runMu.Unlock()

	if logger == nil {
		goose.SetLogger(goose.NopLogger())
	} else {
		goose.SetLogger(&slogLogger{logger: logger})
	}
	loggerConfigured = true
}

func ValidateCommand(command string) error {
	switch command {
	case "up", "status", "version", "down-one":
		return nil
	default:
		return fmt.Errorf("unsupported migration command %q", command)
	}
}

func Run(ctx context.Context, db *sql.DB, directory, command string) error {
	if err := ValidateCommand(command); err != nil {
		return err
	}

	runMu.Lock()
	defer runMu.Unlock()
	if !loggerConfigured {
		goose.SetLogger(goose.NopLogger())
		loggerConfigured = true
	}

	if err := goose.SetDialect("postgres"); err != nil {
		return fmt.Errorf("set migration dialect: %w", err)
	}
	if err := goose.RunContext(ctx, command, db, directory); err != nil {
		return fmt.Errorf("run migration command %q: %w", command, err)
	}
	return nil
}

type slogLogger struct {
	logger *slog.Logger
}

func (l *slogLogger) Printf(format string, values ...any) {
	l.logger.Info("goose migration log", "detail", strings.TrimSpace(fmt.Sprintf(format, values...)))
}

func (l *slogLogger) Fatalf(format string, values ...any) {
	l.logger.Error("goose migration fatal log", "detail", strings.TrimSpace(fmt.Sprintf(format, values...)))
}
