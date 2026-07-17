package httpx

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Free-sp1rit/content-platform/internal/platform/apperror"
	"github.com/Free-sp1rit/content-platform/internal/platform/requestid"
)

func TestWriteDataUsesEnvelope(t *testing.T) {
	ctx := requestid.WithContext(context.Background(), "request-123")
	response := httptest.NewRecorder()

	WriteData(ctx, response, http.StatusOK, map[string]string{"status": "ok"})

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d", response.Code)
	}
	if got := response.Header().Get("Content-Type"); got != "application/json; charset=utf-8" {
		t.Fatalf("Content-Type = %q", got)
	}
	var body struct {
		Data map[string]string `json:"data"`
		Meta struct {
			RequestID string `json:"request_id"`
		} `json:"meta"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if body.Data["status"] != "ok" || body.Meta.RequestID != "request-123" {
		t.Fatalf("unexpected response: %#v", body)
	}
}

func TestWriteErrorMapsKindsToStatuses(t *testing.T) {
	tests := []struct {
		kind apperror.Kind
		want int
	}{
		{kind: apperror.InvalidArgument, want: http.StatusBadRequest},
		{kind: apperror.Unauthenticated, want: http.StatusUnauthorized},
		{kind: apperror.PermissionDenied, want: http.StatusForbidden},
		{kind: apperror.NotFound, want: http.StatusNotFound},
		{kind: apperror.MethodNotAllowed, want: http.StatusMethodNotAllowed},
		{kind: apperror.Conflict, want: http.StatusConflict},
		{kind: apperror.RateLimited, want: http.StatusTooManyRequests},
		{kind: apperror.Internal, want: http.StatusInternalServerError},
		{kind: apperror.DependencyUnavailable, want: http.StatusServiceUnavailable},
	}

	for _, tt := range tests {
		t.Run(string(tt.kind), func(t *testing.T) {
			response := httptest.NewRecorder()
			logger := slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil))
			WriteError(context.Background(), response, logger, apperror.New(tt.kind, string(tt.kind), "safe message"))
			if response.Code != tt.want {
				t.Fatalf("status = %d, want %d", response.Code, tt.want)
			}
		})
	}
}

func TestWriteErrorIncludesSafeDetails(t *testing.T) {
	response := httptest.NewRecorder()
	err := apperror.New(apperror.Conflict, "version_conflict", "resource version conflict").
		WithDetails(map[string]int{"expected": 2})

	WriteError(context.Background(), response, slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil)), err)

	if !strings.Contains(response.Body.String(), `"details":{"expected":2}`) {
		t.Fatalf("details missing from response: %s", response.Body.String())
	}
}

func TestWriteErrorHidesUnknownCauseAndLogsIt(t *testing.T) {
	var logs bytes.Buffer
	response := httptest.NewRecorder()
	ctx := requestid.WithContext(context.Background(), "request-456")

	WriteError(ctx, response, slog.New(slog.NewJSONHandler(&logs, nil)), errors.New("secret SQL error"))

	body := response.Body.String()
	if response.Code != http.StatusInternalServerError || strings.Contains(body, "secret SQL error") {
		t.Fatalf("unsafe error response: %d %s", response.Code, body)
	}
	if !strings.Contains(body, `"code":"internal_error"`) || !strings.Contains(logs.String(), "secret SQL error") || !strings.Contains(logs.String(), "request-456") {
		t.Fatalf("unexpected response or logs: body=%s logs=%s", body, logs.String())
	}
}

func TestWriteErrorDoesNotMutateApplicationError(t *testing.T) {
	response := httptest.NewRecorder()
	err := apperror.New(apperror.Internal, "storage_failed", "safe internal context")

	WriteError(context.Background(), response, slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil)), err)

	if err.Message != "safe internal context" {
		t.Fatalf("WriteError() mutated application error message to %q", err.Message)
	}
	if strings.Contains(response.Body.String(), "safe internal context") {
		t.Fatalf("internal response leaked contextual message: %s", response.Body.String())
	}
}
