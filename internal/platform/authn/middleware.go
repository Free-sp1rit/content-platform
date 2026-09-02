package authn

import (
	"errors"
	"net/http"
	"reflect"
	"strings"
	"time"
	"unicode"
)

const maxAccessTokenBytes = 4096

var ErrInvalidAccessToken = errors.New("invalid access token")

type AccessTokenVerifier interface {
	Verify(string, time.Time) (Principal, error)
}

type Clock interface {
	Now() time.Time
}

type ErrorHandler func(http.ResponseWriter, *http.Request, error)

func Middleware(verifier AccessTokenVerifier, clock Clock, reject ErrorHandler) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
			if request == nil || request.Context().Err() != nil || nilInterface(verifier) || nilInterface(clock) {
				rejectAccessToken(writer, request, reject)
				return
			}

			authorization, ok := singleAuthorizationHeader(request.Header)
			if !ok {
				rejectAccessToken(writer, request, reject)
				return
			}
			rawToken, ok := bearerToken(authorization)
			if !ok || len(rawToken) > maxAccessTokenBytes {
				rejectAccessToken(writer, request, reject)
				return
			}

			now := clock.Now().UTC().Truncate(time.Second)
			if !validMiddlewareTime(now) || request.Context().Err() != nil {
				rejectAccessToken(writer, request, reject)
				return
			}
			principal, err := verifier.Verify(rawToken, now)
			if err != nil || principal.UserID <= 0 || principal.SessionID <= 0 || request.Context().Err() != nil {
				rejectAccessToken(writer, request, reject)
				return
			}

			ctx := WithContext(request.Context(), principal)
			next.ServeHTTP(writer, request.WithContext(ctx))
		})
	}
}

func bearerToken(authorization string) (string, bool) {
	separator := strings.IndexByte(authorization, ' ')
	if separator <= 0 || !strings.EqualFold(authorization[:separator], "Bearer") {
		return "", false
	}
	start := separator
	for start < len(authorization) && authorization[start] == ' ' {
		start++
	}
	if start == len(authorization) {
		return "", false
	}
	rawToken := authorization[start:]
	if strings.IndexFunc(rawToken, unicode.IsSpace) >= 0 {
		return "", false
	}
	return rawToken, true
}

func singleAuthorizationHeader(header http.Header) (string, bool) {
	var value string
	count := 0
	for name, values := range header {
		if !strings.EqualFold(name, "Authorization") {
			continue
		}
		for _, candidate := range values {
			count++
			value = candidate
		}
	}
	return value, count == 1
}

func validMiddlewareTime(value time.Time) bool {
	if value.IsZero() {
		return false
	}
	year := value.Year()
	return year >= 0 && year <= 9999
}

func rejectAccessToken(writer http.ResponseWriter, request *http.Request, reject ErrorHandler) {
	if reject != nil {
		reject(writer, request, ErrInvalidAccessToken)
		return
	}
	writer.Header().Set("WWW-Authenticate", "Bearer")
	writer.WriteHeader(http.StatusUnauthorized)
}

func nilInterface(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return reflected.IsNil()
	default:
		return false
	}
}
