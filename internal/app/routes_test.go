package app

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Free-sp1rit/content-platform/internal/system/handler"
	"github.com/Free-sp1rit/content-platform/internal/system/service"
)

func TestRoutesExposeHealthEndpoints(t *testing.T) {
	routes := testRoutes(service.Ready)

	for _, path := range []string{"/healthz", "/readyz"} {
		response := httptest.NewRecorder()
		routes.ServeHTTP(response, httptest.NewRequest(http.MethodGet, path, nil))
		if response.Code != http.StatusOK {
			t.Fatalf("GET %s status = %d, body = %s", path, response.Code, response.Body.String())
		}
		if response.Header().Get("Content-Type") != "application/json; charset=utf-8" {
			t.Fatalf("GET %s Content-Type = %q", path, response.Header().Get("Content-Type"))
		}
		if response.Header().Get("X-Request-ID") == "" || !strings.Contains(response.Body.String(), `"request_id":`) {
			t.Fatalf("GET %s missing request ID: headers=%v body=%s", path, response.Header(), response.Body.String())
		}
	}
}

func TestRoutesReturnUniformNotFoundAndMethodNotAllowed(t *testing.T) {
	routes := testRoutes(service.Ready)
	tests := []struct {
		method string
		path   string
		status int
		code   string
	}{
		{method: http.MethodGet, path: "/missing", status: http.StatusNotFound, code: "not_found"},
		{method: http.MethodPost, path: "/healthz", status: http.StatusMethodNotAllowed, code: "method_not_allowed"},
	}

	for _, tt := range tests {
		response := httptest.NewRecorder()
		routes.ServeHTTP(response, httptest.NewRequest(tt.method, tt.path, nil))
		if response.Code != tt.status || !strings.Contains(response.Body.String(), `"code":"`+tt.code+`"`) {
			t.Fatalf("%s %s = %d %s", tt.method, tt.path, response.Code, response.Body.String())
		}
		if tt.status == http.StatusMethodNotAllowed && response.Header().Get("Allow") != http.MethodGet {
			t.Fatalf("Allow header = %q", response.Header().Get("Allow"))
		}
	}
}

func testRoutes(status service.Status) http.Handler {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	health := handler.New(routeHealthService{status: status})
	return Routes(logger, health)
}

type routeHealthService struct {
	status service.Status
}

func (routeHealthService) Liveness(context.Context) service.Liveness {
	return service.Liveness{Status: "ok"}
}

func (s routeHealthService) Readiness(context.Context) service.Readiness {
	return service.Readiness{
		Status: s.status,
		Checks: map[string]service.DependencyState{
			"postgres": service.Up,
			"redis":    service.Up,
		},
	}
}
