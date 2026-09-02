package service

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/Free-sp1rit/content-platform/internal/identity/domain"
	infrapassword "github.com/Free-sp1rit/content-platform/internal/infra/password"
	"golang.org/x/crypto/bcrypt"
)

const (
	loginEmail          = "user@example.com"
	loginPassword       = "correct horse battery staple"
	loginPasswordHash   = "$2b$12$opaque-login-hash"
	loginDummyHash      = "$2b$12$opaque-dummy-hash"
	loginDummyCandidate = "opaque-dummy-candidate"
	loginAccessToken    = "opaque-access-token"
	loginRefreshToken   = "901.opaque-refresh-token"
	loginRefreshSecret  = "opaque-refresh-secret"
	loginJWTID          = "opaque-jwt-id"

	loginAccessTTL  = 15 * time.Minute
	loginRefreshTTL = 30 * 24 * time.Hour
)

var loginNow = time.Date(2026, time.September, 2, 11, 20, 21, 0, time.UTC)

func TestLoginComparesExactlyOnceAcrossFailurePaths(t *testing.T) {
	privateRepositoryCause := &loginPrivateError{}
	privateCompareCause := &loginPrivateError{}
	privateTransactionCause := &loginPrivateError{}

	tests := []struct {
		name         string
		context      func(*loginFixture) context.Context
		input        LoginInput
		setup        func(*loginFixture)
		wantError    error
		contextMark  error
		wantFind     int
		wantTx       int
		wantDummy    bool
		privateCause error
		wantEvents   []string
	}{
		{
			name:      "invalid email",
			input:     LoginInput{Email: "not-an-email", Password: loginPassword},
			wantError: ErrInvalidCredentials,
			wantDummy: true,
		},
		{
			name:      "empty password",
			input:     LoginInput{Email: loginEmail, Password: ""},
			wantError: ErrInvalidCredentials,
			wantDummy: true,
		},
		{
			name:      "password below registration boundary",
			input:     LoginInput{Email: loginEmail, Password: "short"},
			wantError: ErrInvalidCredentials,
			wantDummy: true,
		},
		{
			name:      "password above bcrypt boundary",
			input:     LoginInput{Email: loginEmail, Password: strings.Repeat("p", 73)},
			wantError: ErrInvalidCredentials,
			wantDummy: true,
		},
		{
			name: "nil context",
			context: func(*loginFixture) context.Context {
				return nil
			},
			input:     validLoginInput(),
			wantError: ErrInternal,
			wantDummy: true,
		},
		{
			name: "already canceled context",
			context: func(*loginFixture) context.Context {
				ctx, cancel := context.WithCancel(context.Background())
				cancel()
				return ctx
			},
			input:       validLoginInput(),
			wantError:   ErrInternal,
			contextMark: context.Canceled,
			wantDummy:   true,
		},
		{
			name: "expired context deadline",
			context: func(*loginFixture) context.Context {
				ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
				t.Cleanup(cancel)
				return ctx
			},
			input:       validLoginInput(),
			wantError:   ErrInternal,
			contextMark: context.DeadlineExceeded,
			wantDummy:   true,
		},
		{
			name:  "missing user",
			input: validLoginInput(),
			setup: func(fixture *loginFixture) {
				fixture.repository.findErr = ErrNotFound
			},
			wantError: ErrInvalidCredentials,
			wantFind:  1,
			wantDummy: true,
		},
		{
			name:  "repository read failure",
			input: validLoginInput(),
			setup: func(fixture *loginFixture) {
				fixture.repository.findErr = privateRepositoryCause
			},
			wantError: ErrInternal,
			wantFind:  1,
			wantDummy: true,
		},
		{
			name:  "repository read cancellation",
			input: validLoginInput(),
			setup: func(fixture *loginFixture) {
				fixture.repository.findErr = errors.Join(privateRepositoryCause, context.Canceled)
			},
			wantError:   ErrInternal,
			contextMark: context.Canceled,
			wantFind:    1,
			wantDummy:   true,
		},
		{
			name:  "repository cancellation wins over not found",
			input: validLoginInput(),
			setup: func(fixture *loginFixture) {
				fixture.repository.findErr = errors.Join(ErrNotFound, context.Canceled)
			},
			wantError:   ErrInternal,
			contextMark: context.Canceled,
			wantFind:    1,
			wantDummy:   true,
		},
		{
			name:  "bad password",
			input: validLoginInput(),
			setup: func(fixture *loginFixture) {
				fixture.hasher.matched = false
			},
			wantError: ErrInvalidCredentials,
			wantFind:  1,
		},
		{
			name:  "banned credential",
			input: validLoginInput(),
			setup: func(fixture *loginFixture) {
				fixture.repository.credential.Status = domain.StatusBanned
				fixture.repository.user.Status = domain.StatusBanned
			},
			wantError: ErrInvalidCredentials,
			wantFind:  1,
		},
		{
			name:  "deleted credential status",
			input: validLoginInput(),
			setup: func(fixture *loginFixture) {
				fixture.repository.credential.Status = domain.StatusDeleted
				fixture.repository.user.Status = domain.StatusDeleted
			},
			wantError: ErrInvalidCredentials,
			wantFind:  1,
		},
		{
			name:  "soft deleted credential",
			input: validLoginInput(),
			setup: func(fixture *loginFixture) {
				deletedAt := loginNow.Add(-time.Hour)
				fixture.repository.credential.DeletedAt = &deletedAt
				fixture.repository.user.DeletedAt = &deletedAt
			},
			wantError: ErrInvalidCredentials,
			wantFind:  1,
		},
		{
			name:  "malformed stored hash",
			input: validLoginInput(),
			setup: func(fixture *loginFixture) {
				fixture.hasher.compareErr = privateCompareCause
			},
			wantError: ErrInternal,
			wantFind:  1,
		},
		{
			name:  "locked password hash changed",
			input: validLoginInput(),
			setup: func(fixture *loginFixture) {
				fixture.repository.user.PasswordHash = "$2b$12$changed-after-read"
			},
			wantError: ErrInvalidCredentials,
			wantFind:  1,
			wantTx:    1,
		},
		{
			name:  "locked status banned",
			input: validLoginInput(),
			setup: func(fixture *loginFixture) {
				fixture.repository.user.Status = domain.StatusBanned
			},
			wantError: ErrInvalidCredentials,
			wantFind:  1,
			wantTx:    1,
		},
		{
			name:  "locked user soft deleted",
			input: validLoginInput(),
			setup: func(fixture *loginFixture) {
				deletedAt := loginNow
				fixture.repository.user.DeletedAt = &deletedAt
			},
			wantError: ErrInvalidCredentials,
			wantFind:  1,
			wantTx:    1,
		},
		{
			name:  "locked row missing",
			input: validLoginInput(),
			setup: func(fixture *loginFixture) {
				fixture.repository.lockRowsSet = true
				fixture.repository.lockRows = []LockedUser{}
			},
			wantError: ErrInvalidCredentials,
			wantFind:  1,
			wantTx:    1,
		},
		{
			name:  "duplicate locked rows",
			input: validLoginInput(),
			setup: func(fixture *loginFixture) {
				fixture.repository.lockRowsSet = true
				fixture.repository.lockRows = []LockedUser{fixture.repository.user, fixture.repository.user}
			},
			wantError: ErrInternal,
			wantFind:  1,
			wantTx:    1,
		},
		{
			name:  "wrong locked row",
			input: validLoginInput(),
			setup: func(fixture *loginFixture) {
				wrong := fixture.repository.user
				wrong.ID++
				fixture.repository.lockRowsSet = true
				fixture.repository.lockRows = []LockedUser{wrong}
			},
			wantError: ErrInternal,
			wantFind:  1,
			wantTx:    1,
		},
		{
			name:  "lock repository failure",
			input: validLoginInput(),
			setup: func(fixture *loginFixture) {
				fixture.repository.lockErr = privateTransactionCause
			},
			wantError: ErrInternal,
			wantFind:  1,
			wantTx:    1,
		},
		{
			name:  "muted row missing muted until",
			input: validLoginInput(),
			setup: func(fixture *loginFixture) {
				fixture.repository.user.Status = domain.StatusMuted
				fixture.repository.user.MutedUntil = nil
			},
			wantError: ErrInternal,
			wantFind:  1,
			wantTx:    1,
		},
		{
			name:  "conditional mute recovery lost",
			input: validLoginInput(),
			setup: func(fixture *loginFixture) {
				fixture.setExpiredMute(loginNow.Add(-time.Minute))
				changed := false
				fixture.repository.recoverChanged = &changed
			},
			wantError: ErrInternal,
			wantFind:  1,
			wantTx:    1,
		},
		{
			name:  "mute recovery repository failure",
			input: validLoginInput(),
			setup: func(fixture *loginFixture) {
				fixture.setExpiredMute(loginNow.Add(-time.Minute))
				fixture.repository.recoverErr = privateTransactionCause
			},
			wantError:    ErrInternal,
			wantFind:     1,
			wantTx:       1,
			privateCause: privateTransactionCause,
			wantEvents: []string{
				"find", "compare", "begin_tx", "lock_users", "clock", "recover_mute", "rollback",
			},
		},
		{
			name:  "refresh random failure",
			input: validLoginInput(),
			setup: func(fixture *loginFixture) {
				fixture.setExpiredMute(loginNow.Add(-time.Minute))
				fixture.refresh.generateErr = privateTransactionCause
			},
			wantError: ErrInternal,
			wantFind:  1,
			wantTx:    1,
		},
		{
			name:  "session insert failure",
			input: validLoginInput(),
			setup: func(fixture *loginFixture) {
				fixture.setExpiredMute(loginNow.Add(-time.Minute))
				fixture.repository.createSessionErr = privateTransactionCause
			},
			wantError: ErrInternal,
			wantFind:  1,
			wantTx:    1,
		},
		{
			name:  "jwt id random failure",
			input: validLoginInput(),
			setup: func(fixture *loginFixture) {
				fixture.setExpiredMute(loginNow.Add(-time.Minute))
				fixture.access.generateErr = privateTransactionCause
			},
			wantError: ErrInternal,
			wantFind:  1,
			wantTx:    1,
		},
		{
			name:  "jwt signing failure",
			input: validLoginInput(),
			setup: func(fixture *loginFixture) {
				fixture.setExpiredMute(loginNow.Add(-time.Minute))
				fixture.access.signErr = privateTransactionCause
			},
			wantError: ErrInternal,
			wantFind:  1,
			wantTx:    1,
		},
		{
			name:  "refresh formatting failure",
			input: validLoginInput(),
			setup: func(fixture *loginFixture) {
				fixture.setExpiredMute(loginNow.Add(-time.Minute))
				fixture.refresh.formatErr = privateTransactionCause
			},
			wantError: ErrInternal,
			wantFind:  1,
			wantTx:    1,
		},
		{
			name:  "audit insert failure",
			input: validLoginInput(),
			setup: func(fixture *loginFixture) {
				fixture.setExpiredMute(loginNow.Add(-time.Minute))
				fixture.repository.insertAuditErr = privateTransactionCause
			},
			wantError: ErrInternal,
			wantFind:  1,
			wantTx:    1,
		},
		{
			name:  "commit failure",
			input: validLoginInput(),
			setup: func(fixture *loginFixture) {
				fixture.setExpiredMute(loginNow.Add(-time.Minute))
				fixture.repository.commitErr = privateTransactionCause
			},
			wantError: ErrInternal,
			wantFind:  1,
			wantTx:    1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fixture := newLoginFixture(t, domain.StatusActive)
			if tt.setup != nil {
				tt.setup(fixture)
			}
			ctx := context.Background()
			if tt.context != nil {
				ctx = tt.context(fixture)
			}
			beforeUser := cloneLoginUser(fixture.repository.user)

			got, err := fixture.service.Login(ctx, tt.input)

			assertLoginFailure(t, got, err, tt.wantError, tt.contextMark)
			if fixture.hasher.compareCalls != 1 {
				t.Fatalf("PasswordHasher.Compare() calls = %d, want 1", fixture.hasher.compareCalls)
			}
			if fixture.repository.findCalls != tt.wantFind {
				t.Fatalf("Repository.FindLoginCredential() calls = %d, want %d", fixture.repository.findCalls, tt.wantFind)
			}
			if fixture.repository.withinTxCalls != tt.wantTx {
				t.Fatalf("Repository.WithinTx() calls = %d, want %d", fixture.repository.withinTxCalls, tt.wantTx)
			}
			if tt.privateCause != nil {
				if errors.Is(err, tt.privateCause) || strings.Contains(err.Error(), tt.privateCause.Error()) {
					t.Fatal("Login() exposed a private dependency cause")
				}
			}
			if tt.wantEvents != nil && !reflect.DeepEqual(fixture.events, tt.wantEvents) {
				t.Fatalf("Login() dependency order = %v", fixture.events)
			}
			assertLoginComparePath(t, fixture, tt.wantDummy)
			assertLoginCommittedStateUnchanged(t, fixture, beforeUser)
		})
	}
}

func TestLoginSucceedsForEveryLoginCapableStatus(t *testing.T) {
	tests := []struct {
		name       string
		status     domain.Status
		mutedUntil *time.Time
	}{
		{name: "pending", status: domain.StatusPending},
		{name: "active", status: domain.StatusActive},
		{name: "muted", status: domain.StatusMuted, mutedUntil: loginTimePointer(loginNow.Add(time.Hour))},
		{name: "frozen", status: domain.StatusFrozen},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fixture := newLoginFixture(t, tt.status)
			fixture.repository.user.MutedUntil = cloneLoginTime(tt.mutedUntil)

			got, err := fixture.service.Login(context.Background(), LoginInput{
				Email:    " User@Example.COM ",
				Password: loginPassword,
			})

			if err != nil {
				t.Fatalf("Login() returned error type %T", err)
			}
			assertSuccessfulLoginResult(t, got, tt.status, tt.mutedUntil, loginNow.Add(loginRefreshTTL), loginAccessTTL)
			assertSuccessfulLoginCalls(t, fixture)
			if fixture.repository.findEmail != loginEmail {
				t.Fatal("Login() did not normalize the email before repository lookup")
			}
			if fixture.repository.recoverCalls != 0 || fixture.repository.insertAuditCalls != 0 {
				t.Fatal("Login() recovered or audited a non-expired mute")
			}
			if gotEvents := fixture.events; !reflect.DeepEqual(gotEvents, []string{
				"find", "compare", "begin_tx", "lock_users", "clock", "refresh_generate",
				"create_session", "jti_generate", "sign", "refresh_format", "commit",
			}) {
				t.Fatalf("Login() dependency order = %v", gotEvents)
			}
		})
	}
}

func TestLoginRecoversExpiredMuteAndInsertsExactAuditLast(t *testing.T) {
	tests := []struct {
		name       string
		mutedUntil time.Time
		requestID  string
	}{
		{name: "expired before now", mutedUntil: loginNow.Add(-time.Minute), requestID: "request-42"},
		{name: "expires exactly now with empty request id", mutedUntil: loginNow},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fixture := newLoginFixture(t, domain.StatusMuted)
			fixture.setExpiredMute(tt.mutedUntil)

			got, err := fixture.service.Login(context.Background(), LoginInput{
				Email:     loginEmail,
				Password:  loginPassword,
				RequestID: tt.requestID,
			})

			if err != nil {
				t.Fatalf("Login() returned error type %T", err)
			}
			assertSuccessfulLoginResult(t, got, domain.StatusActive, nil, loginNow.Add(loginRefreshTTL), loginAccessTTL)
			assertSuccessfulLoginCalls(t, fixture)
			if fixture.repository.recoverCalls != 1 {
				t.Fatalf("Tx.RecoverExpiredMute() calls = %d, want 1", fixture.repository.recoverCalls)
			}
			if fixture.repository.insertAuditCalls != 1 || len(fixture.repository.audits) != 1 {
				t.Fatal("Login() did not commit exactly one mute recovery audit")
			}
			if fixture.repository.user.Status != domain.StatusActive || fixture.repository.user.MutedUntil != nil {
				t.Fatal("Login() did not commit the expired mute recovery")
			}
			assertExactMuteRecoveryAudit(t, fixture.repository.audits[0], fixture.repository.user.ID, tt.mutedUntil, tt.requestID)
			if gotEvents := fixture.events; !reflect.DeepEqual(gotEvents, []string{
				"find", "compare", "begin_tx", "lock_users", "clock", "recover_mute",
				"refresh_generate", "create_session", "jti_generate", "sign", "refresh_format",
				"insert_audit", "commit",
			}) {
				t.Fatalf("Login() dependency order = %v", gotEvents)
			}
		})
	}
}

func TestLoginCapsAccessExpiryAtCreatedSessionExpiry(t *testing.T) {
	tests := []struct {
		name          string
		sessionExpiry time.Time
		wantAccessTTL time.Duration
	}{
		{
			name:          "normal access ttl",
			sessionExpiry: loginNow.Add(loginRefreshTTL),
			wantAccessTTL: loginAccessTTL,
		},
		{
			name:          "session expires before access ttl",
			sessionExpiry: loginNow.Add(5 * time.Minute),
			wantAccessTTL: 5 * time.Minute,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fixture := newLoginFixture(t, domain.StatusActive)
			fixture.repository.sessionResult = func(_ CreateSessionRecord, session domain.UserSession) domain.UserSession {
				session.ExpiresAt = tt.sessionExpiry
				return session
			}

			got, err := fixture.service.Login(context.Background(), validLoginInput())

			if err != nil {
				t.Fatalf("Login() returned error type %T", err)
			}
			assertSuccessfulLoginResult(t, got, domain.StatusActive, nil, tt.sessionExpiry, tt.wantAccessTTL)
			if !fixture.access.signedExpiresAt.Equal(loginNow.Add(tt.wantAccessTTL)) {
				t.Fatal("Login() signed the access token with the wrong capped expiration")
			}
			if !fixture.access.signedIssuedAt.Equal(loginNow) {
				t.Fatal("Login() did not use the normalized login time as access iat")
			}
		})
	}
}

func TestLoginRejectsMalformedCreatedSessionAndRollsBack(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*domain.UserSession)
	}{
		{name: "non-positive id", mutate: func(session *domain.UserSession) { session.ID = 0 }},
		{name: "wrong owner", mutate: func(session *domain.UserSession) { session.UserID++ }},
		{name: "expired", mutate: func(session *domain.UserSession) { session.ExpiresAt = loginNow }},
		{name: "extends requested lifetime by subsecond", mutate: func(session *domain.UserSession) {
			session.ExpiresAt = loginNow.Add(loginRefreshTTL + 500*time.Millisecond)
		}},
		{name: "extends requested lifetime", mutate: func(session *domain.UserSession) { session.ExpiresAt = loginNow.Add(loginRefreshTTL + time.Second) }},
		{name: "revoked", mutate: func(session *domain.UserSession) { session.RevokedAt = loginTimePointer(loginNow) }},
		{name: "wrong token hash", mutate: func(session *domain.UserSession) { session.TokenHash[0] ^= 0xff }},
		{name: "short token hash", mutate: func(session *domain.UserSession) { session.TokenHash = session.TokenHash[:31] }},
		{name: "wrong created at", mutate: func(session *domain.UserSession) { session.CreatedAt = loginNow.Add(time.Second) }},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fixture := newLoginFixture(t, domain.StatusMuted)
			fixture.setExpiredMute(loginNow.Add(-time.Minute))
			beforeUser := cloneLoginUser(fixture.repository.user)
			fixture.repository.sessionResult = func(_ CreateSessionRecord, session domain.UserSession) domain.UserSession {
				tt.mutate(&session)
				return session
			}

			got, err := fixture.service.Login(context.Background(), validLoginInput())

			assertLoginFailure(t, got, err, ErrInternal, nil)
			if fixture.hasher.compareCalls != 1 {
				t.Fatalf("PasswordHasher.Compare() calls = %d, want 1", fixture.hasher.compareCalls)
			}
			if fixture.access.totalCalls() != 0 || fixture.refresh.formatCalls != 0 {
				t.Fatal("Login() generated access material after a malformed session result")
			}
			assertLoginCommittedStateUnchanged(t, fixture, beforeUser)
		})
	}
}

func TestLoginContextGateRunsAfterTheSingleCompare(t *testing.T) {
	t.Run("canceled while repository returns credential", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		fixture := newLoginFixture(t, domain.StatusActive)
		fixture.repository.beforeFindReturn = cancel

		got, err := fixture.service.Login(ctx, validLoginInput())

		assertLoginFailure(t, got, err, ErrInternal, context.Canceled)
		if fixture.hasher.compareCalls != 1 || fixture.repository.withinTxCalls != 0 {
			t.Fatal("Login() did not finish exactly one compare before stopping on query-time cancellation")
		}
		if gotEvents := fixture.events; !reflect.DeepEqual(gotEvents, []string{"find", "compare"}) {
			t.Fatalf("Login() dependency order = %v", gotEvents)
		}
	})

	t.Run("canceled during compare", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		fixture := newLoginFixture(t, domain.StatusActive)
		fixture.hasher.afterCompare = cancel

		got, err := fixture.service.Login(ctx, validLoginInput())

		assertLoginFailure(t, got, err, ErrInternal, context.Canceled)
		if fixture.hasher.compareCalls != 1 || fixture.repository.withinTxCalls != 0 {
			t.Fatal("Login() did not stop after the compare-time context gate")
		}
	})

	t.Run("cancellation after compare gate does not rewrite mismatch", func(t *testing.T) {
		ctx := &loginBarrierContext{Context: context.Background(), cancelAfterCalls: 2}
		fixture := newLoginFixture(t, domain.StatusActive)
		fixture.hasher.matched = false

		got, err := fixture.service.Login(ctx, validLoginInput())

		assertLoginFailure(t, got, err, ErrInvalidCredentials, nil)
		if ctx.errCalls != 2 {
			t.Fatalf("context.Err() calls = %d, want 2 linearization checks", ctx.errCalls)
		}
		if fixture.hasher.compareCalls != 1 || fixture.repository.withinTxCalls != 0 {
			t.Fatal("Login() changed the fixed compare or transaction path after credential mismatch")
		}
	})
}

func TestLoginSamplesClockAfterUserLock(t *testing.T) {
	postLockNow := loginNow.Add(2 * time.Minute)
	mutedUntil := loginNow.Add(time.Minute)
	fixture := newLoginFixture(t, domain.StatusMuted)
	fixture.repository.user.MutedUntil = loginTimePointer(mutedUntil)
	fixture.repository.beforeLockReturn = func() {
		fixture.clock.now = postLockNow
	}

	got, err := fixture.service.Login(context.Background(), validLoginInput())

	if err != nil {
		t.Fatalf("Login() returned error type %T", err)
	}
	if got.User.Status != domain.StatusActive || got.User.MutedUntil != nil {
		t.Fatal("Login() did not recover a mute that expired while waiting for the user lock")
	}
	if fixture.repository.recoverCalls != 1 || len(fixture.repository.audits) != 1 {
		t.Fatal("Login() did not recover and audit the post-lock expired mute exactly once")
	}
	if !fixture.repository.createSessionRecord.CreatedAt.Equal(postLockNow) ||
		!fixture.repository.createSessionRecord.ExpiresAt.Equal(postLockNow.Add(loginRefreshTTL)) {
		t.Fatal("Login() did not derive session times from the post-lock clock sample")
	}
	if !fixture.access.signedIssuedAt.Equal(postLockNow) ||
		!fixture.access.signedExpiresAt.Equal(postLockNow.Add(loginAccessTTL)) {
		t.Fatal("Login() did not derive access claims from the post-lock clock sample")
	}
	if gotEvents := fixture.events; !reflect.DeepEqual(gotEvents, []string{
		"find", "compare", "begin_tx", "lock_users", "clock", "recover_mute",
		"refresh_generate", "create_session", "jti_generate", "sign", "refresh_format",
		"insert_audit", "commit",
	}) {
		t.Fatalf("Login() dependency order = %v", gotEvents)
	}
}

func TestLoginClockFailureOccursAfterLockAndRollsBack(t *testing.T) {
	fixture := newLoginFixture(t, domain.StatusActive)
	fixture.clock.now = time.Time{}
	beforeUser := cloneLoginUser(fixture.repository.user)

	got, err := fixture.service.Login(context.Background(), validLoginInput())

	assertLoginFailure(t, got, err, ErrInternal, nil)
	if fixture.hasher.compareCalls != 1 {
		t.Fatalf("PasswordHasher.Compare() calls = %d, want 1", fixture.hasher.compareCalls)
	}
	if fixture.repository.withinTxCalls != 1 || fixture.repository.lockCalls != 1 || fixture.clock.calls != 1 {
		t.Fatal("Login() did not sample the failing clock exactly once after entering the locked transaction")
	}
	if gotEvents := fixture.events; !reflect.DeepEqual(gotEvents, []string{
		"find", "compare", "begin_tx", "lock_users", "clock", "rollback",
	}) {
		t.Fatalf("Login() dependency order = %v", gotEvents)
	}
	assertLoginCommittedStateUnchanged(t, fixture, beforeUser)
}

func TestLoginErrorsAndResultDoNotExposeCredentialOrTokenInternals(t *testing.T) {
	privateCause := &loginPrivateError{}
	fixture := newLoginFixture(t, domain.StatusActive)
	fixture.hasher.compareErr = privateCause

	got, err := fixture.service.Login(context.Background(), validLoginInput())

	assertLoginFailure(t, got, err, ErrInternal, nil)
	if errors.Is(err, privateCause) {
		t.Fatal("Login() exposed a private compare cause through errors.Is")
	}
	for _, forbidden := range []string{loginEmail, loginPassword, loginPasswordHash, loginDummyHash, loginDummyCandidate, privateCause.Error()} {
		if strings.Contains(err.Error(), forbidden) {
			t.Fatal("Login() error exposed private credential or dependency data")
		}
	}

	fixture = newLoginFixture(t, domain.StatusActive)
	result, err := fixture.service.Login(context.Background(), validLoginInput())
	if err != nil {
		t.Fatalf("Login() returned error type %T", err)
	}
	encoded, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("json.Marshal(LoginResult) returned error type %T", err)
	}
	for _, forbidden := range []string{loginPassword, loginPasswordHash, loginJWTID, loginRefreshSecret} {
		if strings.Contains(string(encoded), forbidden) {
			t.Fatal("LoginResult exposed password, hash, refresh secret, or JWT id internals")
		}
	}

	typeOfResult := reflect.TypeOf(LoginResult{})
	wantFields := []string{"TokenType", "AccessToken", "ExpiresIn", "RefreshToken", "RefreshExpiresAt", "User"}
	if typeOfResult.NumField() != len(wantFields) {
		t.Fatalf("LoginResult field count = %d, want %d", typeOfResult.NumField(), len(wantFields))
	}
	for index, want := range wantFields {
		field := typeOfResult.Field(index)
		if field.Name != want || field.Tag.Get("json") != "" {
			t.Fatal("LoginResult contains an unexpected field or transport tag")
		}
	}
}

func TestLoginConfiguredBcryptCostMismatchMatchesMissingCredentialFailure(t *testing.T) {
	storedHash, err := bcrypt.GenerateFromPassword([]byte(loginPassword), 10)
	if err != nil {
		t.Fatalf("GenerateFromPassword(cost 10) error = %v", err)
	}
	configuredHasher, err := infrapassword.New(12)
	if err != nil {
		t.Fatalf("password.New(12) error = %v", err)
	}

	tests := []struct {
		name    string
		missing bool
	}{
		{name: "stored hash uses different cost"},
		{name: "missing credential", missing: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fixture := newLoginFixture(t, domain.StatusActive)
			fixture.repository.credential.PasswordHash = string(storedHash)
			fixture.repository.user.PasswordHash = string(storedHash)
			if tt.missing {
				fixture.repository.findErr = ErrNotFound
			}
			countingHasher := &loginCountingPasswordHasher{PasswordHasher: configuredHasher}
			fixture.service.passwordHasher = countingHasher

			got, err := fixture.service.Login(context.Background(), validLoginInput())

			assertLoginFailure(t, got, err, ErrInvalidCredentials, nil)
			if countingHasher.compareCalls != 1 {
				t.Fatalf("PasswordHasher.Compare() calls = %d, want 1", countingHasher.compareCalls)
			}
			if fixture.repository.withinTxCalls != 0 {
				t.Fatal("Login() opened a transaction after bcrypt cost mismatch or missing credential")
			}
		})
	}
}

func validLoginInput() LoginInput {
	return LoginInput{Email: loginEmail, Password: loginPassword}
}

func assertLoginFailure(t *testing.T, got LoginResult, err, want, contextMark error) {
	t.Helper()

	if got != (LoginResult{}) {
		t.Fatal("Login() returned a non-zero result after failure")
	}
	if err == nil {
		t.Fatal("Login() succeeded")
	}
	if !errors.Is(err, want) {
		t.Fatalf("Login() error type = %T, want stable service error", err)
	}
	var validationError *ValidationError
	if errors.As(err, &validationError) || errors.Is(err, ErrValidationFailed) {
		t.Fatal("Login() returned a validation error")
	}
	if want == ErrInvalidCredentials {
		if err != ErrInvalidCredentials || err.Error() != ErrInvalidCredentials.Error() {
			t.Fatal("Login() did not return the exact stable invalid-credentials sentinel")
		}
		if errors.Is(err, ErrInternal) {
			t.Fatal("Login() classified a credential failure as internal")
		}
	}
	if want == ErrInternal {
		if err.Error() != ErrInternal.Error() {
			t.Fatal("Login() internal error message is not stable and safe")
		}
		if errors.Is(err, ErrInvalidCredentials) {
			t.Fatal("Login() classified an internal failure as invalid credentials")
		}
	}
	if contextMark != nil && !errors.Is(err, contextMark) {
		t.Fatal("Login() did not preserve the safe context classification")
	}
}

func assertLoginComparePath(t *testing.T, fixture *loginFixture, wantDummy bool) {
	t.Helper()

	if wantDummy {
		if fixture.hasher.dummyHashCalls != 1 || fixture.hasher.dummyCandidateCalls != 1 {
			t.Fatal("Login() did not select exactly one complete dummy credential pair")
		}
		if fixture.hasher.comparedHash != loginDummyHash || fixture.hasher.comparedCandidate != loginDummyCandidate {
			t.Fatal("Login() did not compare the selected dummy hash and candidate")
		}
		return
	}
	if fixture.hasher.dummyHashCalls != 0 || fixture.hasher.dummyCandidateCalls != 0 {
		t.Fatal("Login() selected dummy credential material for a found user")
	}
	if fixture.hasher.comparedHash != loginPasswordHash || fixture.hasher.comparedCandidate != loginPassword {
		t.Fatal("Login() did not compare the stored hash with the original password")
	}
}

func assertLoginCommittedStateUnchanged(t *testing.T, fixture *loginFixture, beforeUser domain.User) {
	t.Helper()

	if !reflect.DeepEqual(fixture.repository.user, beforeUser) {
		t.Fatal("Login() committed a user mutation after failure")
	}
	if len(fixture.repository.sessions) != 0 {
		t.Fatal("Login() committed a session after failure")
	}
	if len(fixture.repository.audits) != 0 {
		t.Fatal("Login() committed an audit after failure")
	}
}

func assertSuccessfulLoginResult(
	t *testing.T,
	got LoginResult,
	wantStatus domain.Status,
	wantMutedUntil *time.Time,
	wantRefreshExpiry time.Time,
	wantAccessTTL time.Duration,
) {
	t.Helper()

	if got.TokenType != "Bearer" || got.AccessToken != loginAccessToken || got.RefreshToken != loginRefreshToken {
		t.Fatal("Login() returned unexpected token metadata")
	}
	if got.ExpiresIn != int64(wantAccessTTL/time.Second) {
		t.Fatalf("LoginResult.ExpiresIn = %d, want %d", got.ExpiresIn, int64(wantAccessTTL/time.Second))
	}
	if !got.RefreshExpiresAt.Equal(wantRefreshExpiry) {
		t.Fatal("LoginResult.RefreshExpiresAt did not use the created session absolute expiry")
	}
	if got.User.ID != 73 || got.User.Email != loginEmail || got.User.Status != wantStatus || got.User.DeletedAt != nil {
		t.Fatal("LoginResult.User did not contain the expected safe user view")
	}
	if !loginOptionalTimesEqual(got.User.MutedUntil, wantMutedUntil) {
		t.Fatal("LoginResult.User.MutedUntil mismatch")
	}
}

func assertSuccessfulLoginCalls(t *testing.T, fixture *loginFixture) {
	t.Helper()

	if fixture.hasher.compareCalls != 1 {
		t.Fatalf("PasswordHasher.Compare() calls = %d, want 1", fixture.hasher.compareCalls)
	}
	assertLoginComparePath(t, fixture, false)
	if fixture.repository.findCalls != 1 || fixture.repository.withinTxCalls != 1 || fixture.repository.lockCalls != 1 {
		t.Fatal("Login() did not perform the expected lookup, transaction, and single-user lock")
	}
	if !reflect.DeepEqual(fixture.repository.lockIDs, []int64{73}) {
		t.Fatal("Login() did not lock exactly the credential user ID")
	}
	if fixture.clock.calls != 1 || fixture.repository.createSessionCalls != 1 {
		t.Fatal("Login() did not read the clock and create exactly one session")
	}
	if fixture.refresh.generateCalls != 1 || fixture.refresh.formatCalls != 1 || fixture.access.generateCalls != 1 || fixture.access.signCalls != 1 {
		t.Fatal("Login() did not generate and format each token component exactly once")
	}
	if len(fixture.repository.sessions) != 1 {
		t.Fatal("Login() did not commit exactly one session")
	}
	record := fixture.repository.createSessionRecord
	if record.UserID != 73 || record.TokenHash != loginRefreshHash() || !record.CreatedAt.Equal(loginNow) || !record.ExpiresAt.Equal(loginNow.Add(loginRefreshTTL)) {
		t.Fatal("Login() created the session with unexpected owner, hash, or absolute timestamps")
	}
	if fixture.access.signedUserID != 73 || fixture.access.signedSessionID != 901 || fixture.access.signedJWTID != loginJWTID {
		t.Fatal("Login() signed access claims with unexpected identifiers")
	}
	if fixture.refresh.formattedSessionID != 901 || fixture.refresh.formattedSecret != loginRefreshSecret {
		t.Fatal("Login() formatted the refresh token from unexpected material")
	}
}

func assertExactMuteRecoveryAudit(t *testing.T, got AuditEntry, userID int64, oldMutedUntil time.Time, requestID string) {
	t.Helper()

	if got.ActorType != AuditActorSystem || got.ActorID != nil || got.Action != "user.mute_expired" ||
		got.TargetType != "user" || got.TargetID != userID || !got.CreatedAt.Equal(loginNow) {
		t.Fatal("Login() produced incorrect mute recovery audit metadata")
	}
	wantDetail := map[string]any{
		"old_status":      domain.StatusMuted,
		"new_status":      domain.StatusActive,
		"old_muted_until": oldMutedUntil,
		"new_muted_until": nil,
		"request_id":      requestID,
	}
	if !reflect.DeepEqual(got.Detail, wantDetail) {
		t.Fatal("Login() produced incorrect mute recovery audit detail")
	}
}

func loginRefreshHash() [32]byte {
	var value [32]byte
	for index := range value {
		value[index] = byte(index + 1)
	}
	return value
}

func loginTimePointer(value time.Time) *time.Time {
	return &value
}

func cloneLoginTime(value *time.Time) *time.Time {
	if value == nil {
		return nil
	}
	cloned := *value
	return &cloned
}

func loginOptionalTimesEqual(left, right *time.Time) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	return left.Equal(*right)
}

func cloneLoginUser(user domain.User) domain.User {
	user.MutedUntil = cloneLoginTime(user.MutedUntil)
	user.DeletedAt = cloneLoginTime(user.DeletedAt)
	return user
}

func cloneLoginSession(session domain.UserSession) domain.UserSession {
	session.TokenHash = append([]byte(nil), session.TokenHash...)
	session.RevokedAt = cloneLoginTime(session.RevokedAt)
	return session
}

func cloneLoginAudit(entry AuditEntry) AuditEntry {
	if entry.ActorID != nil {
		actorID := *entry.ActorID
		entry.ActorID = &actorID
	}
	detail := entry.Detail
	entry.Detail = make(map[string]any, len(detail))
	for key, value := range detail {
		entry.Detail[key] = value
	}
	return entry
}

type loginPrivateError struct{}

func (*loginPrivateError) Error() string {
	return "private login dependency failure"
}

type loginCountingPasswordHasher struct {
	PasswordHasher
	compareCalls int
}

func (h *loginCountingPasswordHasher) Compare(hash, candidate string) (bool, error) {
	h.compareCalls++
	return h.PasswordHasher.Compare(hash, candidate)
}

type loginBarrierContext struct {
	context.Context
	cancelAfterCalls int
	errCalls         int
}

func (c *loginBarrierContext) Err() error {
	c.errCalls++
	if c.errCalls > c.cancelAfterCalls {
		return context.Canceled
	}
	return nil
}

type loginFixture struct {
	service    *Service
	events     []string
	repository *loginRepositoryFake
	hasher     *loginPasswordHasherSpy
	clock      *loginClockSpy
	access     *loginAccessTokenSpy
	refresh    *loginRefreshTokenSpy
}

func newLoginFixture(t *testing.T, status domain.Status) *loginFixture {
	t.Helper()

	fixture := &loginFixture{}
	user := domain.User{
		ID:             73,
		Email:          loginEmail,
		PasswordHash:   loginPasswordHash,
		DisplayName:    "Alice",
		Bio:            "profile",
		Role:           domain.RoleUser,
		Status:         status,
		ViolationCount: 2,
		CreatedAt:      loginNow.Add(-24 * time.Hour),
		UpdatedAt:      loginNow.Add(-time.Hour),
	}
	fixture.repository = &loginRepositoryFake{
		events: &fixture.events,
		credential: LoginCredential{
			UserID:       user.ID,
			PasswordHash: user.PasswordHash,
			Status:       status,
		},
		user:          user,
		nextSessionID: 901,
	}
	fixture.hasher = &loginPasswordHasherSpy{
		events:  &fixture.events,
		matched: true,
	}
	fixture.clock = &loginClockSpy{events: &fixture.events, now: loginNow}
	fixture.access = &loginAccessTokenSpy{
		events:      &fixture.events,
		jwtID:       loginJWTID,
		accessToken: loginAccessToken,
	}
	fixture.refresh = &loginRefreshTokenSpy{
		events:     &fixture.events,
		secret:     loginRefreshSecret,
		secretHash: loginRefreshHash(),
		formatted:  loginRefreshToken,
	}

	service, err := New(Dependencies{
		Repository:            fixture.repository,
		PasswordHasher:        fixture.hasher,
		AccessTokenManager:    fixture.access,
		RefreshTokenGenerator: fixture.refresh,
		Clock:                 fixture.clock,
	}, Config{
		AccessTokenTTL:  loginAccessTTL,
		RefreshTokenTTL: loginRefreshTTL,
	})
	if err != nil {
		t.Fatalf("New() returned error type %T for valid login fixture", err)
	}
	fixture.service = service
	return fixture
}

func (f *loginFixture) setExpiredMute(mutedUntil time.Time) {
	f.repository.credential.Status = domain.StatusMuted
	f.repository.user.Status = domain.StatusMuted
	f.repository.user.MutedUntil = loginTimePointer(mutedUntil)
}

type loginRepositoryFake struct {
	repositoryPortStub
	events              *[]string
	credential          LoginCredential
	findErr             error
	findCalls           int
	findEmail           string
	beforeFindReturn    func()
	withinTxCalls       int
	commitErr           error
	user                domain.User
	sessions            []domain.UserSession
	audits              []AuditEntry
	nextSessionID       int64
	lockCalls           int
	lockIDs             []int64
	lockRowsSet         bool
	lockRows            []LockedUser
	lockErr             error
	beforeLockReturn    func()
	recoverCalls        int
	recoverChanged      *bool
	recoverErr          error
	createSessionCalls  int
	createSessionRecord CreateSessionRecord
	createSessionErr    error
	sessionResult       func(CreateSessionRecord, domain.UserSession) domain.UserSession
	insertAuditCalls    int
	insertAuditErr      error
}

func (r *loginRepositoryFake) FindLoginCredential(_ context.Context, email string) (LoginCredential, error) {
	r.findCalls++
	r.findEmail = email
	*r.events = append(*r.events, "find")
	if r.beforeFindReturn != nil {
		r.beforeFindReturn()
	}
	if r.findErr != nil {
		return LoginCredential{}, r.findErr
	}
	credential := r.credential
	credential.DeletedAt = cloneLoginTime(credential.DeletedAt)
	return credential, nil
}

func (r *loginRepositoryFake) WithinTx(ctx context.Context, callback func(context.Context, Tx) error) error {
	r.withinTxCalls++
	*r.events = append(*r.events, "begin_tx")
	tx := &loginTransactionFake{
		repository:     r,
		stagedUser:     cloneLoginUser(r.user),
		stagedSessions: cloneLoginSessions(r.sessions),
		stagedAudits:   cloneLoginAudits(r.audits),
	}
	if err := callback(ctx, tx); err != nil {
		*r.events = append(*r.events, "rollback")
		return err
	}
	*r.events = append(*r.events, "commit")
	if r.commitErr != nil {
		return r.commitErr
	}
	r.user = cloneLoginUser(tx.stagedUser)
	r.sessions = cloneLoginSessions(tx.stagedSessions)
	r.audits = cloneLoginAudits(tx.stagedAudits)
	return nil
}

type loginTransactionFake struct {
	transactionPortStub
	repository     *loginRepositoryFake
	stagedUser     domain.User
	stagedSessions []domain.UserSession
	stagedAudits   []AuditEntry
}

func (tx *loginTransactionFake) LockUsers(_ context.Context, ids []int64) ([]LockedUser, error) {
	repository := tx.repository
	repository.lockCalls++
	repository.lockIDs = append([]int64(nil), ids...)
	*repository.events = append(*repository.events, "lock_users")
	if repository.lockErr != nil {
		return nil, repository.lockErr
	}
	if repository.beforeLockReturn != nil {
		repository.beforeLockReturn()
	}
	if repository.lockRowsSet {
		rows := make([]LockedUser, len(repository.lockRows))
		for index, user := range repository.lockRows {
			rows[index] = cloneLoginUser(user)
		}
		return rows, nil
	}
	return []LockedUser{cloneLoginUser(tx.stagedUser)}, nil
}

func (tx *loginTransactionFake) RecoverExpiredMute(_ context.Context, userID int64, now time.Time) (domain.User, bool, error) {
	repository := tx.repository
	repository.recoverCalls++
	*repository.events = append(*repository.events, "recover_mute")
	if repository.recoverErr != nil {
		return domain.User{}, false, repository.recoverErr
	}
	if repository.recoverChanged != nil && !*repository.recoverChanged {
		return domain.User{}, false, nil
	}
	if tx.stagedUser.ID != userID || tx.stagedUser.Status != domain.StatusMuted ||
		tx.stagedUser.MutedUntil == nil || tx.stagedUser.MutedUntil.After(now) {
		return domain.User{}, false, nil
	}
	tx.stagedUser.Status = domain.StatusActive
	tx.stagedUser.MutedUntil = nil
	tx.stagedUser.UpdatedAt = now
	return cloneLoginUser(tx.stagedUser), true, nil
}

func (tx *loginTransactionFake) CreateSession(_ context.Context, record CreateSessionRecord) (domain.UserSession, error) {
	repository := tx.repository
	repository.createSessionCalls++
	repository.createSessionRecord = record
	*repository.events = append(*repository.events, "create_session")
	if repository.createSessionErr != nil {
		return domain.UserSession{}, repository.createSessionErr
	}
	session := domain.UserSession{
		ID:        repository.nextSessionID,
		UserID:    record.UserID,
		TokenHash: append([]byte(nil), record.TokenHash[:]...),
		ExpiresAt: record.ExpiresAt,
		CreatedAt: record.CreatedAt,
	}
	if repository.sessionResult != nil {
		session = repository.sessionResult(record, session)
	}
	tx.stagedSessions = append(tx.stagedSessions, cloneLoginSession(session))
	return cloneLoginSession(session), nil
}

func (tx *loginTransactionFake) InsertAudit(_ context.Context, entry AuditEntry) error {
	repository := tx.repository
	repository.insertAuditCalls++
	*repository.events = append(*repository.events, "insert_audit")
	if repository.insertAuditErr != nil {
		return repository.insertAuditErr
	}
	tx.stagedAudits = append(tx.stagedAudits, cloneLoginAudit(entry))
	return nil
}

func cloneLoginSessions(sessions []domain.UserSession) []domain.UserSession {
	cloned := make([]domain.UserSession, len(sessions))
	for index, session := range sessions {
		cloned[index] = cloneLoginSession(session)
	}
	return cloned
}

func cloneLoginAudits(audits []AuditEntry) []AuditEntry {
	cloned := make([]AuditEntry, len(audits))
	for index, entry := range audits {
		cloned[index] = cloneLoginAudit(entry)
	}
	return cloned
}

type loginPasswordHasherSpy struct {
	events              *[]string
	compareCalls        int
	comparedHash        string
	comparedCandidate   string
	matched             bool
	compareErr          error
	afterCompare        func()
	dummyHashCalls      int
	dummyCandidateCalls int
}

func (*loginPasswordHasherSpy) Hash(string) (string, error) {
	return "", nil
}

func (h *loginPasswordHasherSpy) Compare(hash, candidate string) (bool, error) {
	h.compareCalls++
	h.comparedHash = hash
	h.comparedCandidate = candidate
	*h.events = append(*h.events, "compare")
	if h.afterCompare != nil {
		h.afterCompare()
	}
	return h.matched, h.compareErr
}

func (h *loginPasswordHasherSpy) DummyHash() string {
	h.dummyHashCalls++
	return loginDummyHash
}

func (h *loginPasswordHasherSpy) DummyCandidate() string {
	h.dummyCandidateCalls++
	return loginDummyCandidate
}

type loginClockSpy struct {
	events *[]string
	calls  int
	now    time.Time
}

func (c *loginClockSpy) Now() time.Time {
	c.calls++
	*c.events = append(*c.events, "clock")
	return c.now
}

type loginAccessTokenSpy struct {
	events          *[]string
	generateCalls   int
	generateErr     error
	jwtID           string
	signCalls       int
	signErr         error
	accessToken     string
	signedUserID    int64
	signedSessionID int64
	signedIssuedAt  time.Time
	signedExpiresAt time.Time
	signedJWTID     string
}

func (m *loginAccessTokenSpy) GenerateJWTID() (string, error) {
	m.generateCalls++
	*m.events = append(*m.events, "jti_generate")
	return m.jwtID, m.generateErr
}

func (m *loginAccessTokenSpy) Sign(userID, sessionID int64, issuedAt, expiresAt time.Time, jwtID string) (string, error) {
	m.signCalls++
	m.signedUserID = userID
	m.signedSessionID = sessionID
	m.signedIssuedAt = issuedAt
	m.signedExpiresAt = expiresAt
	m.signedJWTID = jwtID
	*m.events = append(*m.events, "sign")
	return m.accessToken, m.signErr
}

func (m *loginAccessTokenSpy) totalCalls() int {
	return m.generateCalls + m.signCalls
}

type loginRefreshTokenSpy struct {
	events             *[]string
	generateCalls      int
	generateErr        error
	secret             string
	secretHash         [32]byte
	formatCalls        int
	formatErr          error
	formatted          string
	formattedSessionID int64
	formattedSecret    string
}

func (g *loginRefreshTokenSpy) Generate() (string, [32]byte, error) {
	g.generateCalls++
	*g.events = append(*g.events, "refresh_generate")
	return g.secret, g.secretHash, g.generateErr
}

func (g *loginRefreshTokenSpy) Format(sessionID int64, secret string) (string, error) {
	g.formatCalls++
	g.formattedSessionID = sessionID
	g.formattedSecret = secret
	*g.events = append(*g.events, "refresh_format")
	return g.formatted, g.formatErr
}

func (*loginRefreshTokenSpy) Parse(string) (int64, [32]byte, error) {
	return 0, [32]byte{}, nil
}

func (*loginRefreshTokenSpy) Match([32]byte, [32]byte) bool {
	return false
}
