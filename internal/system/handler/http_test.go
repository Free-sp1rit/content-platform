package handler

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Free-sp1rit/content-platform/internal/system/service"
)

func TestHealthReturnsLiveness(t *testing.T) {
	handler := New(fakeHealthService{
		liveness: service.Liveness{Status: "ok"},
	})
	response := httptest.NewRecorder()

	handler.Health(response, httptest.NewRequest(http.MethodGet, "/healthz", nil))

	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"status":"ok"`) {
		t.Fatalf("Health() = %d %s", response.Code, response.Body.String())
	}
}

func TestReadyReturnsSuccessfulStates(t *testing.T) {
	for _, status := range []service.Status{service.Ready, service.Degraded} {
		t.Run(string(status), func(t *testing.T) {
			handler := New(fakeHealthService{
				readiness: service.Readiness{
					Status: status,
					Checks: map[string]service.DependencyState{
						"postgres": service.Up,
						"redis":    service.Up,
					},
				},
			})
			response := httptest.NewRecorder()

			handler.Ready(response, httptest.NewRequest(http.MethodGet, "/readyz", nil))

			if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"status":"`+string(status)+`"`) {
				t.Fatalf("Ready() = %d %s", response.Code, response.Body.String())
			}
		})
	}
}

func TestReadyReturnsDependencyUnavailable(t *testing.T) {
	handler := New(fakeHealthService{
		readiness: service.Readiness{
			Status: service.NotReady,
			Checks: map[string]service.DependencyState{
				"postgres": service.Down,
				"redis":    service.Up,
			},
		},
	})
	response := httptest.NewRecorder()

	handler.Ready(response, httptest.NewRequest(http.MethodGet, "/readyz", nil))

	body := response.Body.String()
	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("Ready() status = %d", response.Code)
	}
	for _, want := range []string{`"code":"dependency_unavailable"`, `"message":"service is not ready"`, `"postgres":"down"`} {
		if !strings.Contains(body, want) {
			t.Fatalf("Ready() body %s missing %s", body, want)
		}
	}
}

type fakeHealthService struct {
	liveness  service.Liveness
	readiness service.Readiness
}

func (f fakeHealthService) Liveness(context.Context) service.Liveness {
	return f.liveness
}

func (f fakeHealthService) Readiness(context.Context) service.Readiness {
	return f.readiness
}
