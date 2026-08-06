package config

import (
	"fmt"
	"net"
	"strconv"
	"strings"
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
