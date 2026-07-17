package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/Free-sp1rit/content-platform/internal/infra/config"
	"github.com/Free-sp1rit/content-platform/internal/infra/logging"
	"github.com/Free-sp1rit/content-platform/internal/infra/postgres"
	"github.com/Free-sp1rit/content-platform/internal/infra/postgres/migration"
)

func main() {
	os.Exit(runMain())
}

func runMain() int {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return run(ctx, os.Args[1:], os.Stdout, os.Stderr)
}

func run(ctx context.Context, args []string, stdout, stderr io.Writer) (code int) {
	if len(args) != 1 {
		_, _ = fmt.Fprintln(stderr, "usage: migrate <up|status|version|down-one>")
		return 2
	}
	command := args[0]
	if err := migration.ValidateCommand(command); err != nil {
		_, _ = fmt.Fprintln(stderr, err)
		return 2
	}

	cfg, err := config.Load()
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "load configuration: %v\n", err)
		return 1
	}
	logger, err := logging.New(cfg.Log, stdout, cfg.Environment)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "initialize logging: %v\n", err)
		return 1
	}

	db, err := postgres.Open(ctx, cfg.Database)
	if err != nil {
		logger.Error("initialize PostgreSQL", "error", err)
		return 1
	}
	defer func() {
		if err := db.Close(); err != nil {
			logger.Error("close PostgreSQL", "error", err)
			code = 1
		}
	}()

	directory := strings.TrimSpace(os.Getenv("MIGRATIONS_DIR"))
	if directory == "" {
		directory = "./migrations"
	}
	if err := migration.Run(ctx, db, directory, command); err != nil {
		logger.Error("run migration", "command", command, "error", err)
		return 1
	}
	logger.Info("migration completed", "command", command)
	return 0
}
