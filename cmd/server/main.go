package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"

	"github.com/Free-sp1rit/content-platform/internal/app"
	"github.com/Free-sp1rit/content-platform/internal/infra/config"
	"github.com/Free-sp1rit/content-platform/internal/infra/logging"
)

func main() {
	os.Exit(runMain())
}

func runMain() int {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return run(ctx, os.Stdout, os.Stderr)
}

func run(ctx context.Context, stdout, stderr io.Writer) int {
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

	application, err := app.New(ctx, cfg, logger)
	if err != nil {
		logger.Error("initialize application", "error", err)
		return 1
	}
	if err := application.Run(ctx); err != nil {
		logger.Error("run application", "error", err)
		return 1
	}
	return 0
}
