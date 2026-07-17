package app

import (
	"log/slog"
	"net/http"

	"github.com/Free-sp1rit/content-platform/internal/platform/apperror"
	"github.com/Free-sp1rit/content-platform/internal/platform/httpx"
	"github.com/Free-sp1rit/content-platform/internal/platform/requestid"
	systemhandler "github.com/Free-sp1rit/content-platform/internal/system/handler"
)

func Routes(logger *slog.Logger, health *systemhandler.Handler) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", health.Health)
	mux.HandleFunc("/healthz", methodNotAllowed(logger, http.MethodGet))
	mux.HandleFunc("GET /readyz", health.Ready)
	mux.HandleFunc("/readyz", methodNotAllowed(logger, http.MethodGet))
	mux.HandleFunc("/", notFound(logger))

	return httpx.Chain(
		mux,
		requestid.Middleware,
		httpx.AccessLog(logger),
		httpx.Recovery(logger),
	)
}

func methodNotAllowed(logger *slog.Logger, allowed ...string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		for _, method := range allowed {
			w.Header().Add("Allow", method)
		}
		err := apperror.New(
			apperror.MethodNotAllowed,
			string(apperror.MethodNotAllowed),
			"method not allowed",
		)
		httpx.WriteError(r.Context(), w, logger, err)
	}
}

func notFound(logger *slog.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		err := apperror.New(apperror.NotFound, string(apperror.NotFound), "route not found")
		httpx.WriteError(r.Context(), w, logger, err)
	}
}
