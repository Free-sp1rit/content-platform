package httpx

import (
	"bytes"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Free-sp1rit/content-platform/internal/platform/requestid"
)

func TestRecoveryProduces500AndAccessLogRecords500(t *testing.T) {
	var logs bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logs, nil))
	handler := Chain(
		http.HandlerFunc(func(http.ResponseWriter, *http.Request) { panic("boom") }),
		requestid.Middleware,
		AccessLog(logger),
		Recovery(logger),
	)
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/panic", nil))

	if response.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d", response.Code)
	}
	if !strings.Contains(response.Body.String(), `"code":"internal_error"`) {
		t.Fatalf("unexpected panic response: %s", response.Body.String())
	}
	if !strings.Contains(logs.String(), `"status":500`) || !strings.Contains(logs.String(), `"request_id":`) {
		t.Fatalf("unexpected logs: %s", logs.String())
	}
	if !strings.Contains(logs.String(), "panic recovered") || !strings.Contains(logs.String(), "boom") {
		t.Fatalf("panic detail missing from logs: %s", logs.String())
	}
}

func TestAccessLogUsesRemoteAddrNotForwardedHeaders(t *testing.T) {
	var logs bytes.Buffer
	request := httptest.NewRequest(http.MethodGet, "/articles?limit=10", nil)
	request.RemoteAddr = "192.0.2.10:4567"
	request.Header.Set("X-Forwarded-For", "203.0.113.9")
	request.Header.Set("X-Real-IP", "203.0.113.10")
	request.Header.Set("User-Agent", "test-agent")
	response := httptest.NewRecorder()

	AccessLog(slog.New(slog.NewJSONHandler(&logs, nil)))(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})).ServeHTTP(response, request)

	text := logs.String()
	for _, want := range []string{
		`"remote_ip":"192.0.2.10"`,
		`"method":"GET"`,
		`"path":"/articles"`,
		`"status":204`,
		`"user_agent":"test-agent"`,
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("access log %q missing %q", text, want)
		}
	}
	if strings.Contains(text, "203.0.113.9") || strings.Contains(text, "203.0.113.10") {
		t.Fatalf("access log trusted forwarded headers: %s", text)
	}
}

func TestAccessLogDefaultsStatusTo200WhenHandlerWritesBody(t *testing.T) {
	var logs bytes.Buffer
	response := httptest.NewRecorder()
	handler := AccessLog(slog.New(slog.NewJSONHandler(&logs, nil)))(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))

	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/", nil))

	if !strings.Contains(logs.String(), `"status":200`) {
		t.Fatalf("access log did not default status: %s", logs.String())
	}
}

func TestChainAppliesMiddlewareInListedOrder(t *testing.T) {
	var calls []string
	middleware := func(name string) Middleware {
		return func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls = append(calls, name+":before")
				next.ServeHTTP(w, r)
				calls = append(calls, name+":after")
			})
		}
	}
	handler := Chain(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		calls = append(calls, "handler")
	}), middleware("first"), middleware("second"))

	handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil))

	want := "first:before,second:before,handler,second:after,first:after"
	if got := strings.Join(calls, ","); got != want {
		t.Fatalf("call order = %q, want %q", got, want)
	}
}
