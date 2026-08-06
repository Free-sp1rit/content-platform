package config

import (
	"strings"
	"testing"
	"time"
)

func TestHTTPConfigValidate(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(*HTTPConfig)
		wantErr string
	}{
		{name: "valid wildcard address", mutate: func(*HTTPConfig) {}},
		{name: "valid IPv4", mutate: func(c *HTTPConfig) { c.Address = "127.0.0.1:8080" }},
		{name: "valid IPv6", mutate: func(c *HTTPConfig) { c.Address = "[::1]:8080" }},
		{name: "missing port", mutate: func(c *HTTPConfig) { c.Address = "localhost" }, wantErr: "HTTP_ADDR"},
		{name: "named port", mutate: func(c *HTTPConfig) { c.Address = "localhost:http" }, wantErr: "HTTP_ADDR"},
		{name: "zero port", mutate: func(c *HTTPConfig) { c.Address = ":0" }, wantErr: "HTTP_ADDR"},
		{name: "port too large", mutate: func(c *HTTPConfig) { c.Address = ":65536" }, wantErr: "HTTP_ADDR"},
		{name: "zero read header timeout", mutate: func(c *HTTPConfig) { c.ReadHeaderTimeout = 0 }, wantErr: "HTTP_READ_HEADER_TIMEOUT"},
		{name: "negative read header timeout", mutate: func(c *HTTPConfig) { c.ReadHeaderTimeout = -time.Second }, wantErr: "HTTP_READ_HEADER_TIMEOUT"},
		{name: "zero read timeout", mutate: func(c *HTTPConfig) { c.ReadTimeout = 0 }, wantErr: "HTTP_READ_TIMEOUT"},
		{name: "negative read timeout", mutate: func(c *HTTPConfig) { c.ReadTimeout = -time.Second }, wantErr: "HTTP_READ_TIMEOUT"},
		{name: "zero write timeout", mutate: func(c *HTTPConfig) { c.WriteTimeout = 0 }, wantErr: "HTTP_WRITE_TIMEOUT"},
		{name: "negative write timeout", mutate: func(c *HTTPConfig) { c.WriteTimeout = -time.Second }, wantErr: "HTTP_WRITE_TIMEOUT"},
		{name: "zero idle timeout", mutate: func(c *HTTPConfig) { c.IdleTimeout = 0 }, wantErr: "HTTP_IDLE_TIMEOUT"},
		{name: "negative idle timeout", mutate: func(c *HTTPConfig) { c.IdleTimeout = -time.Second }, wantErr: "HTTP_IDLE_TIMEOUT"},
		{name: "zero shutdown timeout", mutate: func(c *HTTPConfig) { c.ShutdownTimeout = 0 }, wantErr: "HTTP_SHUTDOWN_TIMEOUT"},
		{name: "negative shutdown timeout", mutate: func(c *HTTPConfig) { c.ShutdownTimeout = -time.Second }, wantErr: "HTTP_SHUTDOWN_TIMEOUT"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := validHTTPConfig()
			tt.mutate(&cfg)

			err := cfg.Validate()
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("Validate() error = %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("Validate() error = %v, want substring %q", err, tt.wantErr)
			}
		})
	}
}

func validHTTPConfig() HTTPConfig {
	return HTTPConfig{
		Address:           ":8080",
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
		ShutdownTimeout:   10 * time.Second,
	}
}
