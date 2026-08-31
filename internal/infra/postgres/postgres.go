package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/Free-sp1rit/content-platform/internal/infra/config"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
)

func Open(ctx context.Context, cfg config.DatabaseConfig) (*sql.DB, error) {
	pgxConfig, err := pgx.ParseConfig(cfg.URL)
	if err != nil {
		return nil, errors.New("parse database configuration")
	}

	db := stdlib.OpenDB(*pgxConfig)
	configurePool(db, cfg)

	pingContext, cancel := context.WithTimeout(ctx, cfg.PingTimeout)
	defer cancel()
	if err := db.PingContext(pingContext); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("ping database: %w", err)
	}
	return db, nil
}

type Checker struct {
	DB *sql.DB
}

func (c Checker) Ping(ctx context.Context) error {
	return c.DB.PingContext(ctx)
}

func configurePool(db *sql.DB, cfg config.DatabaseConfig) {
	db.SetMaxOpenConns(cfg.MaxOpenConns)
	db.SetMaxIdleConns(cfg.MaxIdleConns)
	db.SetConnMaxLifetime(cfg.ConnMaxLifetime)
}
