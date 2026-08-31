package handler

import (
	"context"
	"net/http"

	"github.com/Free-sp1rit/content-platform/internal/platform/apperror"
	"github.com/Free-sp1rit/content-platform/internal/platform/httpx"
	"github.com/Free-sp1rit/content-platform/internal/system/service"
)

type HealthService interface {
	Liveness(context.Context) service.Liveness
	Readiness(context.Context) service.Readiness
}

type Handler struct {
	health HealthService
}

func New(health HealthService) *Handler {
	return &Handler{health: health}
}

func (h *Handler) Health(w http.ResponseWriter, r *http.Request) {
	httpx.WriteData(r.Context(), w, http.StatusOK, h.health.Liveness(r.Context()))
}

func (h *Handler) Ready(w http.ResponseWriter, r *http.Request) {
	result := h.health.Readiness(r.Context())
	if result.Status == service.Ready || result.Status == service.Degraded {
		httpx.WriteData(r.Context(), w, http.StatusOK, result)
		return
	}

	err := apperror.New(
		apperror.DependencyUnavailable,
		string(apperror.DependencyUnavailable),
		"service is not ready",
	).WithDetails(map[string]any{"checks": result.Checks})
	httpx.WriteError(r.Context(), w, nil, err)
}
