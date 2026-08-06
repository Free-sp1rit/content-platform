package logging

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"

	"github.com/Free-sp1rit/content-platform/internal/infra/config"
)

func TestParseLevel(t *testing.T) {
	tests := []struct {
		input config.LogLevel
		want  slog.Level
	}{
		{input: config.LogLevelDebug, want: slog.LevelDebug},
		{input: config.LogLevelInfo, want: slog.LevelInfo},
		{input: config.LogLevelWarn, want: slog.LevelWarn},
		{input: config.LogLevelError, want: slog.LevelError},
	}

	for _, tt := range tests {
		t.Run(string(tt.input), func(t *testing.T) {
			got, err := ParseLevel(tt.input)
			if err != nil {
				t.Fatalf("ParseLevel(%q) error = %v", tt.input, err)
			}
			if got != tt.want {
				t.Fatalf("ParseLevel(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}

	if _, err := ParseLevel(config.LogLevel("verbose")); err == nil {
		t.Fatal("ParseLevel(verbose) expected error")
	}
}

func TestNewJSONLoggerIncludesBaseFields(t *testing.T) {
	var output bytes.Buffer
	logger, err := New(config.LogConfig{Level: config.LogLevelInfo, Format: config.LogFormatJSON}, &output, config.Environment("test"))
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	logger.Info("started")

	for _, want := range []string{`"msg":"started"`, `"service":"content-platform"`, `"environment":"test"`} {
		if !strings.Contains(output.String(), want) {
			t.Fatalf("log output %q missing %q", output.String(), want)
		}
	}
}

func TestNewHonorsLevelAndTextFormat(t *testing.T) {
	var output bytes.Buffer
	logger, err := New(config.LogConfig{Level: config.LogLevelWarn, Format: config.LogFormatText}, &output, config.EnvironmentLocal)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	logger.Info("hidden")
	logger.Warn("visible")

	text := output.String()
	if strings.Contains(text, "hidden") || !strings.Contains(text, "visible") {
		t.Fatalf("unexpected level filtering: %q", text)
	}
}

func TestNewRejectsUnsupportedFormat(t *testing.T) {
	if _, err := New(config.LogConfig{Level: config.LogLevelInfo, Format: config.LogFormat("yaml")}, &bytes.Buffer{}, config.Environment("test")); err == nil {
		t.Fatal("New() expected unsupported format error")
	}
}
