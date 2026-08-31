package main

import (
	"bytes"
	"context"
	"io"
	"strings"
	"testing"
)

func TestRunRejectsMissingCommand(t *testing.T) {
	var stderr bytes.Buffer

	code := run(context.Background(), nil, io.Discard, &stderr)

	if code != 2 || !strings.Contains(stderr.String(), "usage:") {
		t.Fatalf("run() = %d, stderr = %q", code, stderr.String())
	}
}

func TestRunRejectsUnsupportedCommandBeforeLoadingConfig(t *testing.T) {
	t.Setenv("DATABASE_URL", "")
	var stderr bytes.Buffer

	code := run(context.Background(), []string{"reset"}, io.Discard, &stderr)

	if code != 2 || !strings.Contains(stderr.String(), "unsupported migration command") {
		t.Fatalf("run() = %d, stderr = %q", code, stderr.String())
	}
	if strings.Contains(stderr.String(), "DATABASE_URL") {
		t.Fatalf("configuration loaded before command validation: %q", stderr.String())
	}
}
