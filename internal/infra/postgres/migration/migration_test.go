package migration

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"testing"
)

func TestValidateCommand(t *testing.T) {
	for _, command := range []string{"up", "status", "version", "down-one"} {
		t.Run(command, func(t *testing.T) {
			if err := ValidateCommand(command); err != nil {
				t.Fatalf("ValidateCommand(%q) error = %v", command, err)
			}
		})
	}
}

func TestGooseCommand(t *testing.T) {
	for _, testCase := range []struct {
		command string
		want    string
	}{
		{command: "down-one", want: "down"},
		{command: "up", want: "up"},
		{command: "status", want: "status"},
		{command: "version", want: "version"},
		{command: "reset", want: "reset"},
	} {
		t.Run(testCase.command, func(t *testing.T) {
			if got := gooseCommand(testCase.command); got != testCase.want {
				t.Fatalf("gooseCommand(%q) = %q, want %q", testCase.command, got, testCase.want)
			}
		})
	}
}

func TestSlogLoggerProducesStructuredOutput(t *testing.T) {
	var output bytes.Buffer
	adapter := slogLogger{logger: slog.New(slog.NewJSONHandler(&output, nil))}

	adapter.Printf("applied migration %s", "00001_m1_baseline.sql")
	adapter.Fatalf("migration failure: %s", "broken")

	text := output.String()
	for _, want := range []string{
		`"msg":"goose migration log"`,
		`"detail":"applied migration 00001_m1_baseline.sql"`,
		`"msg":"goose migration fatal log"`,
		`"detail":"migration failure: broken"`,
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("migration log %q missing %q", text, want)
		}
	}
}

func TestValidateCommandRejectsDestructiveOrUnknownCommands(t *testing.T) {
	for _, command := range []string{"", "down", "reset", "create"} {
		t.Run(command, func(t *testing.T) {
			if err := ValidateCommand(command); err == nil {
				t.Fatalf("ValidateCommand(%q) expected error", command)
			}
		})
	}
}

func TestRunValidatesBeforeUsingDatabase(t *testing.T) {
	err := Run(context.Background(), nil, t.TempDir(), "reset")
	if err == nil || !strings.Contains(err.Error(), "unsupported migration command") {
		t.Fatalf("Run() error = %v", err)
	}
}
