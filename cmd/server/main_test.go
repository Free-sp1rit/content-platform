package main

import (
	"bytes"
	"context"
	"io"
	"strings"
	"testing"
)

func TestRunReportsConfigurationFailure(t *testing.T) {
	t.Setenv("DATABASE_URL", "")
	var stderr bytes.Buffer

	code := run(context.Background(), io.Discard, &stderr)

	if code != 1 {
		t.Fatalf("run() code = %d", code)
	}
	if !strings.Contains(stderr.String(), "DATABASE_URL is required") {
		t.Fatalf("run() stderr = %q", stderr.String())
	}
}
