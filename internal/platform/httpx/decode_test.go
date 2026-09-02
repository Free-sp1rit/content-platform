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

func TestDecodeJSONAcceptsOneJSONObject(t *testing.T) {
	tests := []struct {
		name        string
		contentType string
		body        string
	}{
		{name: "plain JSON", contentType: "application/json", body: `{"name":"valid"}`},
		{name: "legal charset parameter", contentType: "application/json; charset=utf-8", body: `{"name":"valid"}`},
		{name: "trailing whitespace", contentType: "application/json", body: "{\"name\":\"valid\"} \n\t"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			request := decodeRequest(tt.contentType, tt.body)
			response := httptest.NewRecorder()
			var dst decodeInput

			if err := DecodeJSON(response, request, &dst, 1024); err != nil {
				t.Fatalf("DecodeJSON() error = %v", err)
			}
			if dst.Name != "valid" {
				t.Fatalf("decoded name = %q", dst.Name)
			}
		})
	}
}

func TestDecodeJSONRequiresOneApplicationJSONContentType(t *testing.T) {
	tests := []struct {
		name   string
		values []string
	}{
		{name: "missing"},
		{name: "empty", values: []string{""}},
		{name: "duplicate", values: []string{"application/json", "application/json"}},
		{name: "bad parameter", values: []string{"application/json; charset"}},
		{name: "problem JSON", values: []string{"application/problem+json"}},
		{name: "text JSON", values: []string{"text/json"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"name":"valid"}`))
			for _, value := range tt.values {
				request.Header.Add("Content-Type", value)
			}
			response := httptest.NewRecorder()
			var dst decodeInput

			assertInvalidRequest(t, DecodeJSON(response, request, &dst, 1024))
		})
	}
}

func TestDecodeJSONRejectsAnythingExceptOneKnownObject(t *testing.T) {
	tests := []struct {
		name string
		body string
	}{
		{name: "empty", body: ""},
		{name: "null", body: `null`},
		{name: "array", body: `[]`},
		{name: "string", body: `"value"`},
		{name: "number", body: `1`},
		{name: "boolean", body: `true`},
		{name: "unknown field", body: `{"name":"ok","extra":true}`},
		{name: "malformed", body: `{"name":`},
		{name: "second object", body: `{"name":"ok"}{"name":"two"}`},
		{name: "second null", body: `{"name":"ok"}null`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			request := decodeRequest("application/json", tt.body)
			response := httptest.NewRecorder()
			var dst decodeInput

			assertInvalidRequest(t, DecodeJSON(response, request, &dst, 1024))
		})
	}
}

func TestDecodeJSONEnforcesActualReadLimitAtExactBoundary(t *testing.T) {
	const maxBytes = int64(64 << 10)
	prefix := `{"name":"`
	suffix := `"}`
	exact := prefix + strings.Repeat("a", int(maxBytes)-len(prefix)-len(suffix)) + suffix

	request := decodeRequest("application/json", exact)
	response := httptest.NewRecorder()
	var dst decodeInput
	if err := DecodeJSON(response, request, &dst, maxBytes); err != nil {
		t.Fatalf("DecodeJSON() exact boundary error = %v", err)
	}
	if len(dst.Name) != len(exact)-len(prefix)-len(suffix) {
		t.Fatalf("decoded name length = %d", len(dst.Name))
	}

	request = decodeRequest("application/json", exact+" ")
	request.ContentLength = 1
	response = httptest.NewRecorder()
	dst = decodeInput{}
	assertInvalidRequest(t, DecodeJSON(response, request, &dst, maxBytes))
}

func decodeRequest(contentType, body string) *http.Request {
	request := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
	request.Header.Set("Content-Type", contentType)
	return request
}

func assertInvalidRequest(t *testing.T, err error) {
	t.Helper()
	appErr, ok := apperror.From(err)
	if !ok {
		t.Fatalf("error = %#v, want application error", err)
	}
	if appErr.Kind != apperror.InvalidArgument || appErr.Code != "invalid_request" || appErr.Message != "request body is invalid" {
		t.Fatalf("error = %#v, want invalid_request", err)
	}
}
