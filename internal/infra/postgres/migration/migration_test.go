package migration

import (
	"context"
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
