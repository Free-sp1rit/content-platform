package service

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/Free-sp1rit/content-platform/internal/identity/domain"
)

const (
	authenticateUserID    int64 = 42
	authenticateSessionID int64 = 84
)

var authenticateNow = time.Date(2026, time.September, 2, 8, 30, 45, 0, time.UTC)

func TestAuthenticateReturnsLatestUserForAllowedStatuses(t *testing.T) {
	tests := []domain.Status{
		domain.StatusPending,
		domain.StatusActive,
		domain.StatusMuted,
		domain.StatusFrozen,
	}

	for _, status := range tests {
		t.Run(string(status), func(t *testing.T) {
			state := validAuthenticationState(authenticateNow, status)
			repository := &authenticateRepositoryFake{state: state}
			clock := &authenticateClockSpy{
				now: time.Date(2026, time.September, 2, 16, 30, 45, 987654321, time.FixedZone("UTC+8", 8*60*60)),
			}
			service := &Service{repository: repository, clock: clock}

			result, err := service.Authenticate(context.Background(), AuthenticateInput{
				UserID:    authenticateUserID,
				SessionID: authenticateSessionID,
			})

			if err != nil {
				t.Fatalf("Authenticate() error type = %T, want nil", err)
			}
			if result.User != state.User {
				t.Fatal("Authenticate() did not return the latest repository user")
			}
			if repository.authenticationCalls != 1 || repository.sessionID != authenticateSessionID {
				t.Fatalf("authentication read calls=%d sessionID=%d", repository.authenticationCalls, repository.sessionID)
			}
			if repository.unexpectedCalls != 0 {
				t.Fatalf("unexpected repository calls = %d, want 0", repository.unexpectedCalls)
			}
			if clock.calls != 1 {
				t.Fatalf("Clock.Now() calls = %d, want 1", clock.calls)
			}
		})
	}
}

func TestAuthenticationStateUsesSecretFreeReadModels(t *testing.T) {
	sessionType := reflect.TypeOf(AuthenticationSession{})
	if _, ok := sessionType.FieldByName("TokenHash"); ok {
		t.Fatal("AuthenticationSession exposes TokenHash")
	}

	state := validAuthenticationState(authenticateNow, domain.StatusActive)
	service := &Service{
		repository: &authenticateRepositoryFake{state: state},
		clock:      &authenticateClockSpy{now: authenticateNow},
	}

	result, err := service.Authenticate(context.Background(), AuthenticateInput{
		UserID:    authenticateUserID,
		SessionID: authenticateSessionID,
	})

	if err != nil {
		t.Fatalf("Authenticate() error type = %T, want nil", err)
	}
	if result.User.PasswordHash != "" {
		t.Fatal("AuthenticateResult propagated a password hash from the strict-auth read model")
	}
}

func TestAuthenticateRejectsInvalidPrincipalBeforeDependencies(t *testing.T) {
	tests := []AuthenticateInput{
		{UserID: 0, SessionID: authenticateSessionID},
		{UserID: -1, SessionID: authenticateSessionID},
		{UserID: authenticateUserID, SessionID: 0},
		{UserID: authenticateUserID, SessionID: -1},
	}

	for _, input := range tests {
		repository := &authenticateRepositoryFake{state: validAuthenticationState(authenticateNow, domain.StatusActive)}
		clock := &authenticateClockSpy{now: authenticateNow}
		service := &Service{repository: repository, clock: clock}

		result, err := service.Authenticate(context.Background(), input)

		if err != ErrSessionInvalid {
			t.Fatalf("Authenticate(%+v) error type = %T, want exact ErrSessionInvalid", input, err)
		}
		if result != (AuthenticateResult{}) {
			t.Fatalf("Authenticate(%+v) returned a non-zero result", input)
		}
		if repository.authenticationCalls != 0 || repository.unexpectedCalls != 0 || clock.calls != 0 {
			t.Fatalf("invalid principal called read=%d unexpected=%d clock=%d", repository.authenticationCalls, repository.unexpectedCalls, clock.calls)
		}
	}
}

func TestAuthenticateFoldsUnavailableServerStateToExactSessionInvalid(t *testing.T) {
	revokedAt := authenticateNow.Add(-time.Minute)
	deletedAt := authenticateNow.Add(-time.Hour)
	tests := []struct {
		name            string
		mutate          func(*AuthenticationState)
		repositoryError error
		clockNow        time.Time
	}{
		{name: "session or user missing", repositoryError: ErrNotFound},
		{name: "wrong owner", mutate: func(state *AuthenticationState) {
			state.Session.UserID = 99
			state.User.ID = 99
		}},
		{name: "revoked", mutate: func(state *AuthenticationState) { state.Session.RevokedAt = &revokedAt }},
		{name: "expired", mutate: func(state *AuthenticationState) { state.Session.ExpiresAt = authenticateNow.Add(-time.Second) }},
		{name: "expires exactly now", mutate: func(state *AuthenticationState) { state.Session.ExpiresAt = authenticateNow }},
		{name: "subsecond expiry normalizes to current second", clockNow: authenticateNow.Add(800 * time.Millisecond), mutate: func(state *AuthenticationState) {
			state.Session.ExpiresAt = authenticateNow.Add(900 * time.Millisecond)
		}},
		{name: "banned user", mutate: func(state *AuthenticationState) { state.User.Status = domain.StatusBanned }},
		{name: "deleted status", mutate: func(state *AuthenticationState) {
			state.User.Status = domain.StatusDeleted
			state.User.DeletedAt = &deletedAt
		}},
		{name: "deleted marker", mutate: func(state *AuthenticationState) { state.User.DeletedAt = &deletedAt }},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			state := validAuthenticationState(authenticateNow, domain.StatusActive)
			if tt.mutate != nil {
				tt.mutate(&state)
			}
			repository := &authenticateRepositoryFake{state: state, err: tt.repositoryError}
			clockNow := tt.clockNow
			if clockNow.IsZero() {
				clockNow = authenticateNow
			}
			service := &Service{repository: repository, clock: &authenticateClockSpy{now: clockNow}}

			result, err := service.Authenticate(context.Background(), AuthenticateInput{
				UserID:    authenticateUserID,
				SessionID: authenticateSessionID,
			})

			if err != ErrSessionInvalid {
				t.Fatalf("Authenticate() error type = %T, want exact ErrSessionInvalid", err)
			}
			if result != (AuthenticateResult{}) {
				t.Fatal("Authenticate() returned a non-zero result on session-invalid failure")
			}
			assertAuthenticateErrorSafe(t, err)
			if repository.authenticationCalls != 1 || repository.unexpectedCalls != 0 {
				t.Fatalf("repository calls: auth=%d unexpected=%d", repository.authenticationCalls, repository.unexpectedCalls)
			}
		})
	}
}

func TestAuthenticateTreatsDamagedReadModelsAsInternal(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*AuthenticationState)
	}{
		{name: "zero session ID", mutate: func(state *AuthenticationState) { state.Session.ID = 0 }},
		{name: "wrong returned session ID", mutate: func(state *AuthenticationState) { state.Session.ID++ }},
		{name: "zero session user ID", mutate: func(state *AuthenticationState) { state.Session.UserID = 0 }},
		{name: "zero session expiry", mutate: func(state *AuthenticationState) { state.Session.ExpiresAt = time.Time{} }},
		{name: "unencodable session expiry", mutate: func(state *AuthenticationState) {
			state.Session.ExpiresAt = time.Date(10000, time.January, 1, 0, 0, 0, 0, time.UTC)
		}},
		{name: "zero session creation", mutate: func(state *AuthenticationState) { state.Session.CreatedAt = time.Time{} }},
		{name: "expiry does not follow creation", mutate: func(state *AuthenticationState) { state.Session.ExpiresAt = state.Session.CreatedAt }},
		{name: "zero user ID", mutate: func(state *AuthenticationState) { state.User.ID = 0 }},
		{name: "wrong returned user ID", mutate: func(state *AuthenticationState) { state.User.ID++ }},
		{name: "empty user role", mutate: func(state *AuthenticationState) { state.User.Role = "" }},
		{name: "unknown user role", mutate: func(state *AuthenticationState) { state.User.Role = domain.Role("secret-role") }},
		{name: "password hash in safe user model", mutate: func(state *AuthenticationState) {
			state.User.PasswordHash = "password-hash-do-not-log"
		}},
		{name: "unknown user status", mutate: func(state *AuthenticationState) { state.User.Status = domain.Status("secret-status") }},
		{name: "muted user missing muted until", mutate: func(state *AuthenticationState) {
			state.User.Status = domain.StatusMuted
			state.User.MutedUntil = nil
		}},
		{name: "non-muted user has muted until", mutate: func(state *AuthenticationState) {
			mutedUntil := authenticateNow.Add(time.Hour)
			state.User.MutedUntil = &mutedUntil
		}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			state := validAuthenticationState(authenticateNow, domain.StatusActive)
			tt.mutate(&state)
			service := &Service{
				repository: &authenticateRepositoryFake{state: state},
				clock:      &authenticateClockSpy{now: authenticateNow},
			}

			result, err := service.Authenticate(context.Background(), AuthenticateInput{
				UserID:    authenticateUserID,
				SessionID: authenticateSessionID,
			})

			if !errors.Is(err, ErrInternal) {
				t.Fatalf("Authenticate() error type = %T, want ErrInternal", err)
			}
			if result != (AuthenticateResult{}) {
				t.Fatal("Authenticate() returned a non-zero result on internal failure")
			}
			assertAuthenticateErrorSafe(t, err)
		})
	}
}

func TestAuthenticationLookupErrorPrioritizesContextAndInternalOverNotFound(t *testing.T) {
	privateCause := errors.New("private database token hash")
	tests := []struct {
		name        string
		repository  error
		wantContext error
	}{
		{
			name:        "joined canceled and not found",
			repository:  errors.Join(ErrNotFound, context.Canceled),
			wantContext: context.Canceled,
		},
		{
			name:        "joined deadline and not found",
			repository:  errors.Join(ErrNotFound, context.DeadlineExceeded),
			wantContext: context.DeadlineExceeded,
		},
		{
			name:       "joined internal and not found",
			repository: errors.Join(ErrNotFound, newInternalError(privateCause)),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			service := &Service{
				repository: &authenticateRepositoryFake{err: tt.repository},
				clock:      &authenticateClockSpy{now: authenticateNow},
			}

			result, err := service.Authenticate(context.Background(), AuthenticateInput{
				UserID:    authenticateUserID,
				SessionID: authenticateSessionID,
			})

			assertAuthenticateInternalFailure(t, result, err, tt.wantContext)
			if errors.Is(err, privateCause) || strings.Contains(err.Error(), privateCause.Error()) {
				t.Fatal("Authenticate() exposed a private joined lookup cause")
			}
		})
	}

	t.Run("ordinary wrapped not found remains exact session invalid", func(t *testing.T) {
		service := &Service{
			repository: &authenticateRepositoryFake{err: fmt.Errorf("lookup wrapper: %w", ErrNotFound)},
			clock:      &authenticateClockSpy{now: authenticateNow},
		}

		result, err := service.Authenticate(context.Background(), AuthenticateInput{
			UserID:    authenticateUserID,
			SessionID: authenticateSessionID,
		})

		if err != ErrSessionInvalid || result != (AuthenticateResult{}) {
			t.Fatalf("Authenticate(wrapped not found) returned result/error %#v/%T, want zero/exact ErrSessionInvalid", result, err)
		}
	})
}

func TestAuthenticateFoldsRepositoryClockAndContextFailuresToInternal(t *testing.T) {
	secretCause := errors.New("database secret token hash do-not-log")
	t.Run("nil context", func(t *testing.T) {
		repository := &authenticateRepositoryFake{state: validAuthenticationState(authenticateNow, domain.StatusActive)}
		clock := &authenticateClockSpy{now: authenticateNow}
		service := &Service{repository: repository, clock: clock}

		result, err := service.Authenticate(nil, AuthenticateInput{UserID: authenticateUserID, SessionID: authenticateSessionID})

		assertAuthenticateInternalFailure(t, result, err, nil)
		if repository.authenticationCalls != 0 || clock.calls != 0 {
			t.Fatalf("nil context called repository=%d clock=%d", repository.authenticationCalls, clock.calls)
		}
	})

	t.Run("pre-canceled context", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		repository := &authenticateRepositoryFake{state: validAuthenticationState(authenticateNow, domain.StatusActive)}
		clock := &authenticateClockSpy{now: authenticateNow}
		service := &Service{repository: repository, clock: clock}

		result, err := service.Authenticate(ctx, AuthenticateInput{UserID: authenticateUserID, SessionID: authenticateSessionID})

		assertAuthenticateInternalFailure(t, result, err, context.Canceled)
		if repository.authenticationCalls != 0 || clock.calls != 0 {
			t.Fatalf("canceled context called repository=%d clock=%d", repository.authenticationCalls, clock.calls)
		}
	})

	t.Run("repository error", func(t *testing.T) {
		service := &Service{
			repository: &authenticateRepositoryFake{err: secretCause},
			clock:      &authenticateClockSpy{now: authenticateNow},
		}

		result, err := service.Authenticate(context.Background(), AuthenticateInput{UserID: authenticateUserID, SessionID: authenticateSessionID})

		assertAuthenticateInternalFailure(t, result, err, nil)
		if errors.Is(err, secretCause) {
			t.Fatal("Authenticate() exposed repository cause through errors.Is")
		}
	})

	t.Run("context canceled by repository", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		repository := &authenticateRepositoryFake{
			state:  validAuthenticationState(authenticateNow, domain.StatusActive),
			onRead: cancel,
		}
		clock := &authenticateClockSpy{now: authenticateNow}
		service := &Service{repository: repository, clock: clock}

		result, err := service.Authenticate(ctx, AuthenticateInput{UserID: authenticateUserID, SessionID: authenticateSessionID})

		assertAuthenticateInternalFailure(t, result, err, context.Canceled)
		if clock.calls != 0 {
			t.Fatalf("Clock.Now() calls = %d, want 0", clock.calls)
		}
	})

	t.Run("context canceled by clock", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		clock := &authenticateClockSpy{now: authenticateNow, onNow: cancel}
		service := &Service{
			repository: &authenticateRepositoryFake{state: validAuthenticationState(authenticateNow, domain.StatusActive)},
			clock:      clock,
		}

		result, err := service.Authenticate(ctx, AuthenticateInput{UserID: authenticateUserID, SessionID: authenticateSessionID})

		assertAuthenticateInternalFailure(t, result, err, context.Canceled)
		if clock.calls != 1 {
			t.Fatalf("Clock.Now() calls = %d, want 1", clock.calls)
		}
	})

	for _, tt := range []struct {
		name string
		now  time.Time
	}{
		{name: "zero clock", now: time.Time{}},
		{name: "negative year clock", now: time.Date(-1, time.January, 1, 0, 0, 0, 0, time.UTC)},
		{name: "out of range clock", now: time.Date(10000, time.January, 1, 0, 0, 0, 0, time.UTC)},
	} {
		t.Run(tt.name, func(t *testing.T) {
			service := &Service{
				repository: &authenticateRepositoryFake{state: validAuthenticationState(authenticateNow, domain.StatusActive)},
				clock:      &authenticateClockSpy{now: tt.now},
			}

			result, err := service.Authenticate(context.Background(), AuthenticateInput{UserID: authenticateUserID, SessionID: authenticateSessionID})

			assertAuthenticateInternalFailure(t, result, err, nil)
		})
	}
}

func TestAuthenticateAcceptsNonZeroYearZeroClock(t *testing.T) {
	now := time.Date(0, time.June, 1, 12, 0, 0, 999, time.UTC)
	state := validAuthenticationState(authenticateNow, domain.StatusActive)
	state.Session.CreatedAt = time.Date(0, time.May, 1, 12, 0, 0, 0, time.UTC)
	state.Session.ExpiresAt = time.Date(0, time.July, 1, 12, 0, 0, 0, time.UTC)
	service := &Service{
		repository: &authenticateRepositoryFake{state: state},
		clock:      &authenticateClockSpy{now: now},
	}

	result, err := service.Authenticate(context.Background(), AuthenticateInput{UserID: authenticateUserID, SessionID: authenticateSessionID})

	if err != nil || result.User != state.User {
		t.Fatalf("Authenticate(year zero) returned matching user=%t error type=%T", result.User == state.User, err)
	}
}

func validAuthenticationState(now time.Time, status domain.Status) AuthenticationState {
	mutedUntil := now.Add(time.Hour)
	user := domain.User{
		ID:             authenticateUserID,
		Email:          "latest@example.com",
		DisplayName:    "Latest User",
		Bio:            "latest bio",
		Role:           domain.RoleUser,
		Status:         status,
		ViolationCount: 3,
		CreatedAt:      now.Add(-24 * time.Hour),
		UpdatedAt:      now.Add(-time.Minute),
	}
	if status == domain.StatusMuted {
		user.MutedUntil = &mutedUntil
	}
	return AuthenticationState{
		Session: AuthenticationSession{
			ID:        authenticateSessionID,
			UserID:    authenticateUserID,
			ExpiresAt: now.Add(time.Hour),
			CreatedAt: now.Add(-time.Hour),
		},
		User: user,
	}
}

func assertAuthenticateInternalFailure(t *testing.T, result AuthenticateResult, err error, contextErr error) {
	t.Helper()
	if !errors.Is(err, ErrInternal) {
		t.Fatalf("Authenticate() error type = %T, want ErrInternal", err)
	}
	if contextErr != nil && !errors.Is(err, contextErr) {
		t.Fatalf("Authenticate() error type = %T, want context classification %v", err, contextErr)
	}
	if result != (AuthenticateResult{}) {
		t.Fatal("Authenticate() returned a non-zero result on internal failure")
	}
	assertAuthenticateErrorSafe(t, err)
}

func assertAuthenticateErrorSafe(t *testing.T, err error) {
	t.Helper()
	for _, forbidden := range []string{"secret", "token", "hash", "database", "do-not-log", "latest@example.com"} {
		if strings.Contains(strings.ToLower(err.Error()), forbidden) {
			t.Fatalf("Authenticate() error type %T exposed %q", err, forbidden)
		}
	}
}

type authenticateRepositoryFake struct {
	state               AuthenticationState
	err                 error
	onRead              func()
	authenticationCalls int
	sessionID           int64
	unexpectedCalls     int
}

func (r *authenticateRepositoryFake) FindAuthenticationState(_ context.Context, sessionID int64) (AuthenticationState, error) {
	r.authenticationCalls++
	r.sessionID = sessionID
	if r.onRead != nil {
		r.onRead()
	}
	return r.state, r.err
}

func (r *authenticateRepositoryFake) CreateUser(context.Context, CreateUserRecord) (domain.User, error) {
	r.unexpectedCalls++
	return domain.User{}, nil
}

func (r *authenticateRepositoryFake) FindLoginCredential(context.Context, string) (LoginCredential, error) {
	r.unexpectedCalls++
	return LoginCredential{}, nil
}

func (r *authenticateRepositoryFake) FindUser(context.Context, int64) (domain.User, error) {
	r.unexpectedCalls++
	return domain.User{}, nil
}

func (r *authenticateRepositoryFake) FindSessionOwner(context.Context, int64) (int64, error) {
	r.unexpectedCalls++
	return 0, nil
}

func (r *authenticateRepositoryFake) RevokeSession(context.Context, RevokeSessionRequest) error {
	r.unexpectedCalls++
	return nil
}

func (r *authenticateRepositoryFake) WithinTx(context.Context, func(context.Context, Tx) error) error {
	r.unexpectedCalls++
	return nil
}

type authenticateClockSpy struct {
	now   time.Time
	onNow func()
	calls int
}

func (c *authenticateClockSpy) Now() time.Time {
	c.calls++
	if c.onNow != nil {
		c.onNow()
	}
	return c.now
}
