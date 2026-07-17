package requestid

import (
	"context"
	"crypto/rand"
	"net/http"
	"regexp"
)

const Header = "X-Request-ID"

var validPattern = regexp.MustCompile(`^[A-Za-z0-9._:-]{1,128}$`)

type contextKey struct{}

func Valid(value string) bool {
	return validPattern.MatchString(value)
}

func WithContext(ctx context.Context, value string) context.Context {
	return context.WithValue(ctx, contextKey{}, value)
}

func FromContext(ctx context.Context) string {
	value, _ := ctx.Value(contextKey{}).(string)
	return value
}

func Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestID := r.Header.Get(Header)
		if !Valid(requestID) {
			requestID = rand.Text()
		}

		w.Header().Set(Header, requestID)
		next.ServeHTTP(w, r.WithContext(WithContext(r.Context(), requestID)))
	})
}
