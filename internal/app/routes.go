package app

import (
	"log/slog"
	"net/http"
	"strings"

	identityhandler "github.com/Free-sp1rit/content-platform/internal/identity/handler"
	"github.com/Free-sp1rit/content-platform/internal/platform/apperror"
	"github.com/Free-sp1rit/content-platform/internal/platform/httpx"
	"github.com/Free-sp1rit/content-platform/internal/platform/requestid"
	systemhandler "github.com/Free-sp1rit/content-platform/internal/system/handler"
)

func Routes(
	logger *slog.Logger,
	health *systemhandler.Handler,
	identity *identityhandler.Handler,
	authenticate func(http.Handler) http.Handler,
) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", health.Health)
	mux.HandleFunc("/healthz", methodNotAllowed(logger, http.MethodGet))
	mux.HandleFunc("GET /readyz", health.Ready)
	mux.HandleFunc("/readyz", methodNotAllowed(logger, http.MethodGet))

	mux.HandleFunc("POST /register", identity.Register)
	mux.HandleFunc("/register", methodNotAllowed(logger, http.MethodPost))
	mux.HandleFunc("POST /login", identity.Login)
	mux.HandleFunc("/login", methodNotAllowed(logger, http.MethodPost))
	mux.Handle("POST /logout", authenticate(http.HandlerFunc(identity.Logout)))
	mux.HandleFunc("/logout", methodNotAllowed(logger, http.MethodPost))
	mux.HandleFunc("POST /token/refresh", identity.Refresh)
	mux.HandleFunc("/token/refresh", methodNotAllowed(logger, http.MethodPost))

	mux.Handle("GET /me", authenticate(http.HandlerFunc(identity.Me)))
	mux.Handle("PUT /me", authenticate(http.HandlerFunc(identity.UpdateMe)))
	mux.Handle("DELETE /me", authenticate(http.HandlerFunc(identity.DeleteMe)))
	mux.HandleFunc("HEAD /me", methodNotAllowed(logger, http.MethodGet, http.MethodPut, http.MethodDelete))
	mux.HandleFunc("/me", methodNotAllowed(logger, http.MethodGet, http.MethodPut, http.MethodDelete))

	mux.HandleFunc("GET /users/{id}", identity.PublicUser)
	mux.HandleFunc("HEAD /users/{id}", methodNotAllowed(logger, http.MethodGet))
	mux.HandleFunc("/users/{id}", methodNotAllowed(logger, http.MethodGet))
	mux.Handle("PUT /admin/users/{id}/status", authenticate(http.HandlerFunc(identity.ChangeStatus)))
	mux.HandleFunc("/admin/users/{id}/status", methodNotAllowed(logger, http.MethodPut))

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
		w.Header().Set("Allow", strings.Join(allowed, ", "))
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
