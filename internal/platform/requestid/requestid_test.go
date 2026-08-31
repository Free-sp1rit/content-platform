package requestid

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestValid(t *testing.T) {
	tests := []struct {
		name  string
		value string
		want  bool
	}{
		{name: "letters and separators", value: "client-ID_123:part.value", want: true},
		{name: "empty", value: "", want: false},
		{name: "spaces", value: "invalid request id", want: false},
		{name: "slash", value: "invalid/id", want: false},
		{name: "too long", value: strings.Repeat("a", 129), want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Valid(tt.value); got != tt.want {
				t.Fatalf("Valid(%q) = %v, want %v", tt.value, got, tt.want)
			}
		})
	}
}

func TestMiddlewarePropagatesValidRequestID(t *testing.T) {
	var contextID string
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		contextID = FromContext(r.Context())
		w.WriteHeader(http.StatusNoContent)
	})
	request := httptest.NewRequest(http.MethodGet, "/", nil)
	request.Header.Set(Header, "client-id_123")
	response := httptest.NewRecorder()

	Middleware(next).ServeHTTP(response, request)

	if contextID != "client-id_123" || response.Header().Get(Header) != contextID {
		t.Fatalf("context and header IDs differ: %q / %q", contextID, response.Header().Get(Header))
	}
}

func TestMiddlewareReplacesInvalidRequestID(t *testing.T) {
	request := httptest.NewRequest(http.MethodGet, "/", nil)
	request.Header.Set(Header, "invalid request id with spaces")
	response := httptest.NewRecorder()
	var contextID string

	Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		contextID = FromContext(r.Context())
	})).ServeHTTP(response, request)

	if contextID == "" || contextID == request.Header.Get(Header) || !Valid(contextID) {
		t.Fatalf("expected valid generated ID, got %q", contextID)
	}
	if response.Header().Get(Header) != contextID {
		t.Fatalf("response header ID = %q, want %q", response.Header().Get(Header), contextID)
	}
}

func TestWithContextAndFromContext(t *testing.T) {
	ctx := WithContext(context.Background(), "request-123")
	if got := FromContext(ctx); got != "request-123" {
		t.Fatalf("FromContext() = %q", got)
	}
	if got := FromContext(context.Background()); got != "" {
		t.Fatalf("FromContext(empty) = %q", got)
	}
}
