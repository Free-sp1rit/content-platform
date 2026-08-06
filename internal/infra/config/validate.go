package config

import (
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"

	"github.com/jackc/pgx/v5"
)

func (c HTTPConfig) Validate() error {
	if !validTCPAddress(c.Address, false) {
		return fmt.Errorf("HTTP_ADDR must be a valid TCP address")
	}
	if c.ReadHeaderTimeout <= 0 {
		return fmt.Errorf("HTTP_READ_HEADER_TIMEOUT must be greater than zero")
	}
	if c.ReadTimeout <= 0 {
		return fmt.Errorf("HTTP_READ_TIMEOUT must be greater than zero")
	}
	if c.WriteTimeout <= 0 {
		return fmt.Errorf("HTTP_WRITE_TIMEOUT must be greater than zero")
	}
	if c.IdleTimeout <= 0 {
		return fmt.Errorf("HTTP_IDLE_TIMEOUT must be greater than zero")
	}
	if c.ShutdownTimeout <= 0 {
		return fmt.Errorf("HTTP_SHUTDOWN_TIMEOUT must be greater than zero")
	}
	return nil
}

func (c DatabaseConfig) Validate() error {
	if strings.TrimSpace(c.URL) == "" {
		return fmt.Errorf("DATABASE_URL is required")
	}
	if !validDatabaseURL(c.URL) {
		return fmt.Errorf("DATABASE_URL must be a valid PostgreSQL URL")
	}
	if c.MaxOpenConns <= 0 {
		return fmt.Errorf("DATABASE_MAX_OPEN_CONNS must be greater than zero")
	}
	if c.MaxIdleConns < 0 {
		return fmt.Errorf("DATABASE_MAX_IDLE_CONNS must not be negative")
	}
	if c.MaxIdleConns > c.MaxOpenConns {
		return fmt.Errorf("DATABASE_MAX_IDLE_CONNS must not exceed DATABASE_MAX_OPEN_CONNS")
	}
	if c.ConnMaxLifetime <= 0 {
		return fmt.Errorf("DATABASE_CONN_MAX_LIFETIME must be greater than zero")
	}
	if c.PingTimeout <= 0 {
		return fmt.Errorf("DATABASE_PING_TIMEOUT must be greater than zero")
	}
	return nil
}

func validDatabaseURL(value string) bool {
	parsed, err := url.ParseRequestURI(value)
	if err != nil {
		return false
	}
	if parsed.Scheme != "postgres" && parsed.Scheme != "postgresql" {
		return false
	}
	if strings.Trim(parsed.Path, "/") == "" {
		return false
	}
	_, err = pgx.ParseConfig(value)
	return err == nil
}

func validTCPAddress(address string, requireHost bool) bool {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return false
	}
	if requireHost && strings.TrimSpace(host) == "" {
		return false
	}
	portNumber, err := strconv.Atoi(port)
	return err == nil && portNumber >= 1 && portNumber <= 65535
}
