package httpx

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Free-sp1rit/content-platform/internal/platform/apperror"
)

type decodeInput struct {
	Name string `json:"name"`
}

func TestDecodeJSONAcceptsSingleKnownObject(t *testing.T) {
	request := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"name":"valid"}`))
	response := httptest.NewRecorder()
	var dst decodeInput

	if err := DecodeJSON(response, request, &dst, 1024); err != nil {
		t.Fatalf("DecodeJSON() error = %v", err)
	}
	if dst.Name != "valid" {
		t.Fatalf("decoded name = %q", dst.Name)
	}
}

func TestDecodeJSONRejectsInvalidBodies(t *testing.T) {
	tests := []struct {
		name     string
		body     string
		maxBytes int64
	}{
		{name: "empty", body: "", maxBytes: 1024},
		{name: "unknown field", body: `{"name":"ok","extra":true}`, maxBytes: 1024},
		{name: "trailing value", body: `{"name":"ok"}{"name":"two"}`, maxBytes: 1024},
		{name: "malformed", body: `{"name":`, maxBytes: 1024},
		{name: "oversized", body: `{"name":"too long"}`, maxBytes: 8},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(tt.body))
			response := httptest.NewRecorder()
			var dst decodeInput

			err := DecodeJSON(response, request, &dst, tt.maxBytes)
			appErr, ok := apperror.From(err)
			if !ok || appErr.Kind != apperror.InvalidArgument || appErr.Message != "request body is invalid" {
				t.Fatalf("DecodeJSON() error = %#v", err)
			}
		})
	}
}
