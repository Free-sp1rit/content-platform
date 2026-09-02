package service

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/Free-sp1rit/content-platform/internal/identity/domain"
)

func TestLogoutUsesOnlyConditionalSessionRevocation(t *testing.T) {
	requestContext := context.WithValue(context.Background(), logoutContextKey{}, "request")
	repository := &logoutRepositoryFake{}
	clock := &logoutClockSpy{
		now: time.Date(2026, time.September, 2, 16, 30, 45, 987654321, time.FixedZone("UTC+8", 8*60*60)),
	}
	service := &Service{repository: repository, clock: clock}

	result, err := service.Logout(requestContext, LogoutInput{UserID: 42, SessionID: 84})

	if err != nil {
		t.Fatalf("Logout() error type = %T, want nil", err)
	}
	if result != (LogoutResult{LoggedOut: true}) {
		t.Fatalf("Logout() result = %+v, want logged out", result)
	}
	if repository.revokeCalls != 1 || len(repository.requests) != 1 {
		t.Fatalf("RevokeSession() calls = %d requests=%d", repository.revokeCalls, len(repository.requests))
	}
	request := repository.requests[0]
	if request.UserID != 42 || request.SessionID != 84 {
		t.Fatalf("RevokeSession() IDs = user:%d session:%d", request.UserID, request.SessionID)
	}
	wantNow := time.Date(2026, time.September, 2, 8, 30, 45, 0, time.UTC)
	if !request.RevokedAt.Equal(wantNow) || request.RevokedAt.Location() != time.UTC || request.RevokedAt.Nanosecond() != 0 {
		t.Fatalf("RevokeSession() revoked at = %v, want %v", request.RevokedAt, wantNow)
	}
	if repository.contexts[0] != requestContext {
		t.Fatal("RevokeSession() did not receive caller context")
	}
	if repository.unexpectedCalls != 0 {
		t.Fatalf("Logout() performed %d user/session reads or transactions", repository.unexpectedCalls)
	}
	if clock.calls != 1 {
		t.Fatalf("Clock.Now() calls = %d, want 1", clock.calls)
	}
}

func TestLogoutIsIdempotentWhenConditionalRevocationAffectsNoSession(t *testing.T) {
	repository := &logoutRepositoryFake{}
	clock := &logoutClockSpy{now: time.Date(2026, time.September, 2, 8, 30, 45, 0, time.UTC)}
	service := &Service{repository: repository, clock: clock}
	input := LogoutInput{UserID: 42, SessionID: 84}

	first, firstErr := service.Logout(context.Background(), input)
	second, secondErr := service.Logout(context.Background(), input)

	if firstErr != nil || secondErr != nil {
		t.Fatalf("repeated Logout() error types = first:%T second:%T", firstErr, secondErr)
	}
	if first != (LogoutResult{LoggedOut: true}) || second != (LogoutResult{LoggedOut: true}) {
		t.Fatalf("repeated Logout() results = first:%+v second:%+v", first, second)
	}
	if repository.revokeCalls != 2 || len(repository.requests) != 2 {
		t.Fatalf("RevokeSession() calls = %d requests=%d, want 2", repository.revokeCalls, len(repository.requests))
	}
	if repository.unexpectedCalls != 0 {
		t.Fatalf("repeated Logout() performed %d unexpected reads/transactions", repository.unexpectedCalls)
	}
	if clock.calls != 2 {
		t.Fatalf("Clock.Now() calls = %d, want 2", clock.calls)
	}
}

func TestLogoutRejectsInvalidPrincipalContextAndClockAsInternal(t *testing.T) {
	validNow := time.Date(2026, time.September, 2, 8, 30, 45, 0, time.UTC)
	t.Run("invalid principal", func(t *testing.T) {
		for _, input := range []LogoutInput{
			{UserID: 0, SessionID: 84},
			{UserID: -1, SessionID: 84},
			{UserID: 42, SessionID: 0},
			{UserID: 42, SessionID: -1},
		} {
			repository := &logoutRepositoryFake{}
			clock := &logoutClockSpy{now: validNow}
			service := &Service{repository: repository, clock: clock}

			result, err := service.Logout(context.Background(), input)

			assertLogoutInternalFailure(t, result, err, nil)
			if errors.Is(err, ErrSessionInvalid) {
				t.Fatalf("Logout(%+v) exposed strict session classification", input)
			}
			if repository.revokeCalls != 0 || repository.unexpectedCalls != 0 || clock.calls != 0 {
				t.Fatalf("invalid principal called revoke=%d unexpected=%d clock=%d", repository.revokeCalls, repository.unexpectedCalls, clock.calls)
			}
		}
	})

	t.Run("nil context", func(t *testing.T) {
		repository := &logoutRepositoryFake{}
		clock := &logoutClockSpy{now: validNow}
		service := &Service{repository: repository, clock: clock}

		result, err := service.Logout(nil, LogoutInput{UserID: 42, SessionID: 84})

		assertLogoutInternalFailure(t, result, err, nil)
		if repository.revokeCalls != 0 || clock.calls != 0 {
			t.Fatalf("nil context called revoke=%d clock=%d", repository.revokeCalls, clock.calls)
		}
	})

	t.Run("canceled context", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		repository := &logoutRepositoryFake{}
		clock := &logoutClockSpy{now: validNow}
		service := &Service{repository: repository, clock: clock}

		result, err := service.Logout(ctx, LogoutInput{UserID: 42, SessionID: 84})

		assertLogoutInternalFailure(t, result, err, context.Canceled)
		if repository.revokeCalls != 0 || clock.calls != 0 {
			t.Fatalf("canceled context called revoke=%d clock=%d", repository.revokeCalls, clock.calls)
		}
	})

	for _, tt := range []struct {
		name string
		now  time.Time
	}{
		{name: "zero clock", now: time.Time{}},
		{name: "negative year clock", now: time.Date(-1, time.January, 1, 0, 0, 0, 0, time.UTC)},
		{name: "out of range year clock", now: time.Date(10000, time.January, 1, 0, 0, 0, 0, time.UTC)},
	} {
		t.Run(tt.name, func(t *testing.T) {
			repository := &logoutRepositoryFake{}
			clock := &logoutClockSpy{now: tt.now}
			service := &Service{repository: repository, clock: clock}

			result, err := service.Logout(context.Background(), LogoutInput{UserID: 42, SessionID: 84})

			assertLogoutInternalFailure(t, result, err, nil)
			if repository.revokeCalls != 0 || clock.calls != 1 {
				t.Fatalf("invalid clock called revoke=%d clock=%d", repository.revokeCalls, clock.calls)
			}
		})
	}

	t.Run("context canceled by clock", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		repository := &logoutRepositoryFake{}
		clock := &logoutClockSpy{now: validNow, onNow: cancel}
		service := &Service{repository: repository, clock: clock}

		result, err := service.Logout(ctx, LogoutInput{UserID: 42, SessionID: 84})

		assertLogoutInternalFailure(t, result, err, context.Canceled)
		if repository.revokeCalls != 0 || clock.calls != 1 {
			t.Fatalf("clock cancellation called revoke=%d clock=%d", repository.revokeCalls, clock.calls)
		}
	})
}

func TestLogoutFoldsRepositoryFailureAndPreservesSuccessfulRevocation(t *testing.T) {
	secretCause := errors.New("database session hash secret do-not-log")
	t.Run("repository error", func(t *testing.T) {
		repository := &logoutRepositoryFake{revokeErrors: []error{secretCause}}
		service := &Service{repository: repository, clock: &logoutClockSpy{now: authenticateNow}}

		result, err := service.Logout(context.Background(), LogoutInput{UserID: 42, SessionID: 84})

		assertLogoutInternalFailure(t, result, err, nil)
		if errors.Is(err, secretCause) {
			t.Fatal("Logout() exposed repository cause through errors.Is")
		}
		if repository.revokeCalls != 1 || repository.unexpectedCalls != 0 {
			t.Fatalf("repository calls revoke=%d unexpected=%d", repository.revokeCalls, repository.unexpectedCalls)
		}
	})

	t.Run("successful repository result wins over post-write cancellation", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		repository := &logoutRepositoryFake{onRevoke: cancel}
		clock := &logoutClockSpy{now: authenticateNow}
		service := &Service{repository: repository, clock: clock}

		result, err := service.Logout(ctx, LogoutInput{UserID: 42, SessionID: 84})

		if err != nil {
			t.Fatalf("Logout() error type = %T, want nil after successful revocation", err)
		}
		if result != (LogoutResult{LoggedOut: true}) {
			t.Fatalf("Logout() result = %+v, want logged out", result)
		}
		if !errors.Is(ctx.Err(), context.Canceled) {
			t.Fatalf("test context error = %v, want context.Canceled", ctx.Err())
		}
		if repository.revokeCalls != 1 || repository.unexpectedCalls != 0 {
			t.Fatalf("repository calls revoke=%d unexpected=%d", repository.revokeCalls, repository.unexpectedCalls)
		}
		if clock.calls != 1 {
			t.Fatalf("Clock.Now() calls = %d, want 1", clock.calls)
		}
	})
}

func assertLogoutInternalFailure(t *testing.T, result LogoutResult, err error, contextErr error) {
	t.Helper()
	if !errors.Is(err, ErrInternal) {
		t.Fatalf("Logout() error type = %T, want ErrInternal", err)
	}
	if contextErr != nil && !errors.Is(err, contextErr) {
		t.Fatalf("Logout() error type = %T, want context classification %v", err, contextErr)
	}
	if result != (LogoutResult{}) {
		t.Fatalf("Logout() result = %+v, want zero", result)
	}
	for _, forbidden := range []string{"database", "session hash", "secret", "do-not-log"} {
		if strings.Contains(strings.ToLower(err.Error()), forbidden) {
			t.Fatalf("Logout() error type %T exposed %q", err, forbidden)
		}
	}
}

type logoutRepositoryFake struct {
	requests        []RevokeSessionRequest
	contexts        []context.Context
	revokeErrors    []error
	onRevoke        func()
	revokeCalls     int
	unexpectedCalls int
}

func (r *logoutRepositoryFake) RevokeSession(ctx context.Context, request RevokeSessionRequest) error {
	r.revokeCalls++
	r.contexts = append(r.contexts, ctx)
	r.requests = append(r.requests, request)
	if r.onRevoke != nil {
		r.onRevoke()
	}
	if len(r.revokeErrors) >= r.revokeCalls {
		return r.revokeErrors[r.revokeCalls-1]
	}
	return nil
}

func (r *logoutRepositoryFake) CreateUser(context.Context, CreateUserRecord) (domain.User, error) {
	r.unexpectedCalls++
	return domain.User{}, nil
}

func (r *logoutRepositoryFake) FindLoginCredential(context.Context, string) (LoginCredential, error) {
	r.unexpectedCalls++
	return LoginCredential{}, nil
}

func (r *logoutRepositoryFake) FindUser(context.Context, int64) (domain.User, error) {
	r.unexpectedCalls++
	return domain.User{}, nil
}

func (r *logoutRepositoryFake) FindAuthenticationState(context.Context, int64) (AuthenticationState, error) {
	r.unexpectedCalls++
	return AuthenticationState{}, nil
}

func (r *logoutRepositoryFake) FindSessionOwner(context.Context, int64) (int64, error) {
	r.unexpectedCalls++
	return 0, nil
}

func (r *logoutRepositoryFake) WithinTx(context.Context, func(context.Context, Tx) error) error {
	r.unexpectedCalls++
	return nil
}

type logoutClockSpy struct {
	now   time.Time
	onNow func()
	calls int
}

func (c *logoutClockSpy) Now() time.Time {
	c.calls++
	if c.onNow != nil {
		c.onNow()
	}
	return c.now
}

type logoutContextKey struct{}
