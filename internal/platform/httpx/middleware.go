package httpx

import (
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"runtime/debug"
	"time"

	"github.com/Free-sp1rit/content-platform/internal/platform/apperror"
	"github.com/Free-sp1rit/content-platform/internal/platform/requestid"
)

type Middleware func(http.Handler) http.Handler

func Chain(handler http.Handler, middleware ...Middleware) http.Handler {
	for i := len(middleware) - 1; i >= 0; i-- {
		handler = middleware[i](handler)
	}
	return handler
}

func AccessLog(logger *slog.Logger) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			started := time.Now()
			recorder := &statusRecorder{ResponseWriter: w}
			next.ServeHTTP(recorder, r)

			if logger == nil {
				return
			}
			logger.InfoContext(r.Context(), "http request completed",
				"request_id", requestid.FromContext(r.Context()),
				"method", r.Method,
				"path", r.URL.Path,
				"status", recorder.Status(),
				"duration_ms", time.Since(started).Milliseconds(),
				"remote_ip", remoteIP(r.RemoteAddr),
				"user_agent", r.UserAgent(),
			)
		})
	}
}

func Recovery(logger *slog.Logger) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			defer func() {
				recovered := recover()
				if recovered == nil {
					return
				}

				if logger != nil {
					logger.ErrorContext(r.Context(), "panic recovered",
						"request_id", requestid.FromContext(r.Context()),
						"panic", fmt.Sprint(recovered),
						"stack", string(debug.Stack()),
					)
				}
				WriteError(
					r.Context(),
					w,
					logger,
					apperror.New(apperror.Internal, string(apperror.Internal), "internal server error"),
				)
			}()

			next.ServeHTTP(w, r)
		})
	}
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *statusRecorder) WriteHeader(status int) {
	if r.status != 0 {
		return
	}
	r.status = status
	r.ResponseWriter.WriteHeader(status)
}

func (r *statusRecorder) Write(body []byte) (int, error) {
	if r.status == 0 {
		r.WriteHeader(http.StatusOK)
	}
	return r.ResponseWriter.Write(body)
}

func (r *statusRecorder) Status() int {
	if r.status == 0 {
		return http.StatusOK
	}
	return r.status
}

func (r *statusRecorder) Unwrap() http.ResponseWriter {
	return r.ResponseWriter
}

func remoteIP(remoteAddress string) string {
	host, _, err := net.SplitHostPort(remoteAddress)
	if err != nil {
		return remoteAddress
	}
	return host
}
