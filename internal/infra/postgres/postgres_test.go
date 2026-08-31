package postgres

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/Free-sp1rit/content-platform/internal/infra/config"
	_ "github.com/jackc/pgx/v5/stdlib"
)

func TestConfigurePool(t *testing.T) {
	db, err := sql.Open("pgx", "postgres://localhost/content_platform?sslmode=disable")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	cfg := config.DatabaseConfig{
		MaxOpenConns:    12,
		MaxIdleConns:    4,
		ConnMaxLifetime: time.Minute,
	}

	configurePool(db, cfg)

	if got := db.Stats().MaxOpenConnections; got != 12 {
		t.Fatalf("MaxOpenConnections = %d", got)
	}
}

func TestOpenRejectsMalformedURLWithoutLeakingIt(t *testing.T) {
	secretURL := "not-a-postgres-url-with-secret"
	_, err := Open(context.Background(), config.DatabaseConfig{
		URL:         secretURL,
		PingTimeout: time.Second,
	})
	if err == nil {
		t.Fatal("Open() expected malformed URL error")
	}
	if strings.Contains(err.Error(), secretURL) {
		t.Fatalf("Open() leaked URL in error: %v", err)
	}
}

func TestCheckerDelegatesPing(t *testing.T) {
	wantErr := errors.New("database unavailable")
	db := sql.OpenDB(pingConnector{err: wantErr})
	t.Cleanup(func() { _ = db.Close() })

	err := (Checker{DB: db}).Ping(context.Background())
	if !errors.Is(err, wantErr) {
		t.Fatalf("Ping() error = %v, want %v", err, wantErr)
	}
}

type pingConnector struct {
	err error
}

func (c pingConnector) Connect(context.Context) (driver.Conn, error) {
	return pingConn{err: c.err}, nil
}

func (c pingConnector) Driver() driver.Driver {
	return pingDriver{err: c.err}
}

type pingDriver struct {
	err error
}

func (d pingDriver) Open(string) (driver.Conn, error) {
	return pingConn{err: d.err}, nil
}

type pingConn struct {
	err error
}

func (c pingConn) Prepare(string) (driver.Stmt, error) {
	return nil, errors.New("not implemented")
}

func (pingConn) Close() error {
	return nil
}

func (pingConn) Begin() (driver.Tx, error) {
	return nil, errors.New("not implemented")
}

func (c pingConn) Ping(context.Context) error {
	return c.err
}
