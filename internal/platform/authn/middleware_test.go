package authn

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestMiddlewareInjectsVerifiedPrincipal(t *testing.T) {
	wantPrincipal := Principal{UserID: 42, SessionID: 84}
	verifier := &accessVerifierSpy{principal: wantPrincipal}
	clock := &middlewareClockStub{now: time.Date(2026, time.September, 2, 16, 30, 45, 987654321, time.FixedZone("UTC+8", 8*60*60))}
	rejections := &middlewareRejectionSpy{}
	nextCalls := 0
	handler := Middleware(verifier, clock, rejections.Handle)(http.HandlerFunc(func(_ http.ResponseWriter, request *http.Request) {
		nextCalls++
		gotPrincipal, ok := FromContext(request.Context())
		if !ok {
			t.Fatal("next handler did not receive an authenticated principal")
		}
		if gotPrincipal != wantPrincipal {
			t.Fatalf("principal = %+v, want %+v", gotPrincipal, wantPrincipal)
		}
	}))
	request := httptest.NewRequest(http.MethodGet, "/me", nil)
	request.Header.Set("Authorization", "bEaReR    raw.access-token")

	handler.ServeHTTP(httptest.NewRecorder(), request)

	if nextCalls != 1 {
		t.Fatalf("next calls = %d, want 1", nextCalls)
	}
	if rejections.calls != 0 {
		t.Fatalf("rejection calls = %d, want 0", rejections.calls)
	}
	if verifier.calls != 1 {
		t.Fatalf("Verify() calls = %d, want 1", verifier.calls)
	}
	if clock.calls != 1 {
		t.Fatalf("Clock.Now() calls = %d, want 1", clock.calls)
	}
	if verifier.raw != "raw.access-token" {
		t.Fatalf("Verify() raw token = %q, want token unchanged", verifier.raw)
	}
	wantNow := time.Date(2026, time.September, 2, 8, 30, 45, 0, time.UTC)
	if !verifier.now.Equal(wantNow) || verifier.now.Location() != time.UTC || verifier.now.Nanosecond() != 0 {
		t.Fatalf("Verify() now = %v, want %v", verifier.now, wantNow)
	}
}

func TestMiddlewareRejectsMalformedAuthorizationBeforeVerification(t *testing.T) {
	tests := []struct {
		name      string
		configure func(*http.Request)
	}{
		{name: "missing", configure: func(*http.Request) {}},
		{name: "empty", configure: func(request *http.Request) {
			request.Header["Authorization"] = []string{""}
		}},
		{name: "whitespace only", configure: func(request *http.Request) {
			request.Header.Set("Authorization", " \t ")
		}},
		{name: "wrong scheme", configure: func(request *http.Request) {
			request.Header.Set("Authorization", "Basic access-token-do-not-log")
		}},
		{name: "missing token", configure: func(request *http.Request) {
			request.Header.Set("Authorization", "Bearer")
		}},
		{name: "extra field", configure: func(request *http.Request) {
			request.Header.Set("Authorization", "Bearer access-token-do-not-log extra")
		}},
		{name: "tab separator", configure: func(request *http.Request) {
			request.Header.Set("Authorization", "Bearer\taccess-token-do-not-log")
		}},
		{name: "unicode separator", configure: func(request *http.Request) {
			request.Header.Set("Authorization", "Bearer\u00a0access-token-do-not-log")
		}},
		{name: "trailing whitespace changes token", configure: func(request *http.Request) {
			request.Header.Set("Authorization", "Bearer access-token-do-not-log\t")
		}},
		{name: "repeated canonical header", configure: func(request *http.Request) {
			request.Header.Add("Authorization", "Bearer first-token-do-not-log")
			request.Header.Add("Authorization", "Bearer second-token-do-not-log")
		}},
		{name: "repeated differently cased header", configure: func(request *http.Request) {
			request.Header["Authorization"] = []string{"Bearer first-token-do-not-log"}
			request.Header["authorization"] = []string{"Bearer second-token-do-not-log"}
		}},
		{name: "oversized token", configure: func(request *http.Request) {
			request.Header.Set("Authorization", "Bearer "+strings.Repeat("x", 4097))
		}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			verifier := &accessVerifierSpy{principal: Principal{UserID: 1, SessionID: 2}}
			clock := &middlewareClockStub{now: time.Date(2026, time.September, 2, 8, 30, 45, 0, time.UTC)}
			rejections := &middlewareRejectionSpy{}
			nextCalls := 0
			handler := Middleware(verifier, clock, rejections.Handle)(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
				nextCalls++
			}))
			request := httptest.NewRequest(http.MethodGet, "/me", nil)
			tt.configure(request)

			handler.ServeHTTP(httptest.NewRecorder(), request)

			rejections.requireInvalidAccessToken(t, 1)
			if nextCalls != 0 {
				t.Fatalf("next calls = %d, want 0", nextCalls)
			}
			if verifier.calls != 0 {
				t.Fatalf("Verify() calls = %d, want 0", verifier.calls)
			}
		})
	}
}

func TestMiddlewareFailsClosedWithoutErrorHandler(t *testing.T) {
	verifierCause := errors.New("verifier secret cause do-not-log")
	verifier := &accessVerifierSpy{err: verifierCause}
	nextCalls := 0
	handler := Middleware(
		verifier,
		&middlewareClockStub{now: time.Date(2026, time.September, 2, 8, 30, 45, 0, time.UTC)},
		nil,
	)(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { nextCalls++ }))
	request := httptest.NewRequest(http.MethodGet, "/me", nil)
	request.Header.Set("Authorization", "Basic malformed-token-do-not-log")
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if response.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusUnauthorized)
	}
	if response.Header().Get("WWW-Authenticate") != "Bearer" {
		t.Fatalf("WWW-Authenticate = %q, want Bearer", response.Header().Get("WWW-Authenticate"))
	}
	if nextCalls != 0 {
		t.Fatalf("next calls = %d, want 0", nextCalls)
	}
	if verifier.calls != 0 {
		t.Fatalf("Verify() calls = %d, want 0 for malformed Authorization", verifier.calls)
	}
	body := strings.ToLower(response.Body.String())
	for _, forbidden := range []string{"malformed-token-do-not-log", "verifier secret cause", "do-not-log"} {
		if strings.Contains(body, forbidden) {
			t.Fatalf("fallback response body exposed %q", forbidden)
		}
	}
}

func TestMiddlewareAcceptsMaximumSizedToken(t *testing.T) {
	rawToken := strings.Repeat("x", 4096)
	verifier := &accessVerifierSpy{principal: Principal{UserID: 1, SessionID: 2}}
	rejections := &middlewareRejectionSpy{}
	nextCalls := 0
	handler := Middleware(
		verifier,
		&middlewareClockStub{now: time.Date(2026, time.September, 2, 8, 30, 45, 0, time.UTC)},
		rejections.Handle,
	)(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { nextCalls++ }))
	request := httptest.NewRequest(http.MethodGet, "/me", nil)
	request.Header.Set("Authorization", "Bearer "+rawToken)

	handler.ServeHTTP(httptest.NewRecorder(), request)

	if nextCalls != 1 || verifier.calls != 1 || verifier.raw != rawToken {
		t.Fatalf("maximum token boundary: next=%d verify=%d raw bytes=%d", nextCalls, verifier.calls, len(verifier.raw))
	}
	if rejections.calls != 0 {
		t.Fatalf("rejection calls = %d, want 0", rejections.calls)
	}
}

func TestMiddlewareFoldsVerifierFailuresAndInvalidPrincipals(t *testing.T) {
	secretCause := errors.New("verifier secret token cause do-not-log")
	tests := []struct {
		name      string
		principal Principal
		err       error
	}{
		{name: "verifier error", principal: Principal{UserID: 1, SessionID: 2}, err: secretCause},
		{name: "zero user", principal: Principal{UserID: 0, SessionID: 2}},
		{name: "negative user", principal: Principal{UserID: -1, SessionID: 2}},
		{name: "zero session", principal: Principal{UserID: 1, SessionID: 0}},
		{name: "negative session", principal: Principal{UserID: 1, SessionID: -1}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			verifier := &accessVerifierSpy{principal: tt.principal, err: tt.err}
			rejections := &middlewareRejectionSpy{}
			nextCalls := 0
			handler := Middleware(
				verifier,
				&middlewareClockStub{now: time.Date(2026, time.September, 2, 8, 30, 45, 0, time.UTC)},
				rejections.Handle,
			)(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { nextCalls++ }))
			request := httptest.NewRequest(http.MethodGet, "/me", nil)
			request.Header.Set("Authorization", "Bearer access-token-do-not-log")

			handler.ServeHTTP(httptest.NewRecorder(), request)

			rejections.requireInvalidAccessToken(t, 1)
			if rejections.err != ErrInvalidAccessToken {
				t.Fatalf("rejection error type = %T, want fixed ErrInvalidAccessToken", rejections.err)
			}
			if errors.Is(rejections.err, secretCause) {
				t.Fatal("rejection error exposed verifier cause")
			}
			for _, forbidden := range []string{"secret", "do-not-log", "access-token"} {
				if strings.Contains(strings.ToLower(rejections.err.Error()), forbidden) {
					t.Fatalf("rejection error exposed %q", forbidden)
				}
			}
			if nextCalls != 0 {
				t.Fatalf("next calls = %d, want 0", nextCalls)
			}
			if verifier.calls != 1 {
				t.Fatalf("Verify() calls = %d, want 1", verifier.calls)
			}
		})
	}
}

func TestMiddlewareRejectsInvalidRequestContextAndClockBeforeVerification(t *testing.T) {
	validNow := time.Date(2026, time.September, 2, 8, 30, 45, 0, time.UTC)
	tests := []struct {
		name    string
		request func() *http.Request
		clock   Clock
	}{
		{name: "nil request", request: func() *http.Request { return nil }, clock: &middlewareClockStub{now: validNow}},
		{name: "canceled context", request: func() *http.Request {
			request := httptest.NewRequest(http.MethodGet, "/me", nil)
			ctx, cancel := context.WithCancel(request.Context())
			cancel()
			return request.WithContext(ctx)
		}, clock: &middlewareClockStub{now: validNow}},
		{name: "expired deadline context", request: func() *http.Request {
			request := httptest.NewRequest(http.MethodGet, "/me", nil)
			ctx, cancel := context.WithDeadline(request.Context(), time.Now().Add(-time.Second))
			defer cancel()
			return request.WithContext(ctx)
		}, clock: &middlewareClockStub{now: validNow}},
		{name: "nil clock", request: func() *http.Request { return authorizedRequest() }, clock: nil},
		{name: "typed nil clock", request: func() *http.Request { return authorizedRequest() }, clock: (*middlewareClockStub)(nil)},
		{name: "zero clock", request: func() *http.Request { return authorizedRequest() }, clock: &middlewareClockStub{}},
		{name: "negative year clock", request: func() *http.Request { return authorizedRequest() }, clock: &middlewareClockStub{now: time.Date(-1, time.January, 1, 0, 0, 0, 0, time.UTC)}},
		{name: "out of range year clock", request: func() *http.Request { return authorizedRequest() }, clock: &middlewareClockStub{now: time.Date(10000, time.January, 1, 0, 0, 0, 0, time.UTC)}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			verifier := &accessVerifierSpy{principal: Principal{UserID: 1, SessionID: 2}}
			rejections := &middlewareRejectionSpy{}
			nextCalls := 0
			handler := Middleware(verifier, tt.clock, rejections.Handle)(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
				nextCalls++
			}))
			request := tt.request()

			handler.ServeHTTP(httptest.NewRecorder(), request)

			rejections.requireInvalidAccessToken(t, 1)
			if rejections.request != request {
				t.Fatal("rejection handler did not receive the original request")
			}
			if nextCalls != 0 || verifier.calls != 0 {
				t.Fatalf("invalid boundary called next=%d verifier=%d", nextCalls, verifier.calls)
			}
		})
	}
}

func TestMiddlewareRejectsNilVerifier(t *testing.T) {
	tests := []struct {
		name     string
		verifier AccessTokenVerifier
	}{
		{name: "nil", verifier: nil},
		{name: "typed nil", verifier: (*accessVerifierSpy)(nil)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rejections := &middlewareRejectionSpy{}
			nextCalls := 0
			handler := Middleware(
				tt.verifier,
				&middlewareClockStub{now: time.Date(2026, time.September, 2, 8, 30, 45, 0, time.UTC)},
				rejections.Handle,
			)(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { nextCalls++ }))

			handler.ServeHTTP(httptest.NewRecorder(), authorizedRequest())

			rejections.requireInvalidAccessToken(t, 1)
			if nextCalls != 0 {
				t.Fatalf("next calls = %d, want 0", nextCalls)
			}
		})
	}
}

func TestMiddlewareAcceptsNonZeroYearZeroClock(t *testing.T) {
	verifier := &accessVerifierSpy{principal: Principal{UserID: 1, SessionID: 2}}
	rejections := &middlewareRejectionSpy{}
	nextCalls := 0
	handler := Middleware(
		verifier,
		&middlewareClockStub{now: time.Date(0, time.December, 31, 23, 59, 59, 999, time.FixedZone("west", -7*60*60))},
		rejections.Handle,
	)(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { nextCalls++ }))

	handler.ServeHTTP(httptest.NewRecorder(), authorizedRequest())

	if nextCalls != 1 || verifier.calls != 1 {
		t.Fatalf("year-zero boundary called next=%d verifier=%d", nextCalls, verifier.calls)
	}
	if verifier.now.Location() != time.UTC || verifier.now.Nanosecond() != 0 || verifier.now.Year() != 1 {
		t.Fatalf("normalized year-zero boundary now = %v", verifier.now)
	}
	if rejections.calls != 0 {
		t.Fatalf("rejection calls = %d, want 0", rejections.calls)
	}
}

func authorizedRequest() *http.Request {
	request := httptest.NewRequest(http.MethodGet, "/me", nil)
	request.Header.Set("Authorization", "Bearer access-token-do-not-log")
	return request
}

type accessVerifierSpy struct {
	principal Principal
	err       error
	calls     int
	raw       string
	now       time.Time
}

func (v *accessVerifierSpy) Verify(raw string, now time.Time) (Principal, error) {
	v.calls++
	v.raw = raw
	v.now = now
	return v.principal, v.err
}

type middlewareClockStub struct {
	now   time.Time
	calls int
}

func (c *middlewareClockStub) Now() time.Time {
	c.calls++
	return c.now
}

type middlewareRejectionSpy struct {
	calls   int
	request *http.Request
	err     error
}

func (s *middlewareRejectionSpy) Handle(_ http.ResponseWriter, request *http.Request, err error) {
	s.calls++
	s.request = request
	s.err = err
}

func (s *middlewareRejectionSpy) requireInvalidAccessToken(t *testing.T, wantCalls int) {
	t.Helper()
	if s.calls != wantCalls {
		t.Fatalf("rejection calls = %d, want %d", s.calls, wantCalls)
	}
	if !errors.Is(s.err, ErrInvalidAccessToken) {
		t.Fatalf("rejection error type = %T, want ErrInvalidAccessToken", s.err)
	}
}
