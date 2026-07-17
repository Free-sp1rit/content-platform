package migration

import (
	"context"
	"database/sql"
	"fmt"
	"sync"

	"github.com/pressly/goose/v3"
)

var runMu sync.Mutex

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

	if err := goose.SetDialect("postgres"); err != nil {
		return fmt.Errorf("set migration dialect: %w", err)
	}
	if err := goose.RunContext(ctx, command, db, directory); err != nil {
		return fmt.Errorf("run migration command %q: %w", command, err)
	}
	return nil
}
