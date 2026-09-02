package service

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Free-sp1rit/content-platform/internal/identity/domain"
)

const (
	refreshRawToken    = "901.AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8"
	refreshNewToken    = "901.ICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8"
	refreshNewSecret   = "ICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8"
	refreshAccessToken = "opaque-rotated-access-token"
	refreshJWTID       = "opaque-refresh-jwt-id"

	refreshUserID    int64 = 73
	refreshSessionID int64 = 901

	refreshAccessTTL  = 15 * time.Minute
	refreshSessionTTL = 24 * time.Hour
)

var refreshNow = time.Date(2026, time.September, 2, 14, 15, 16, 0, time.UTC)

func TestRefreshHasExactServiceShape(t *testing.T) {
	method, ok := reflect.TypeOf((*Service)(nil)).MethodByName("Refresh")
	if !ok {
		t.Fatal("Service.Refresh method is missing")
	}

	contextType := reflect.TypeOf((*context.Context)(nil)).Elem()
	errorType := reflect.TypeOf((*error)(nil)).Elem()
	if method.Type.NumIn() != 3 || method.Type.In(1) != contextType {
		t.Fatal("Service.Refresh must accept context.Context and one input value")
	}
	assertRefreshStructShape(t, method.Type.In(2), []refreshFieldShape{
		{name: "RefreshToken", typ: reflect.TypeOf("")},
		{name: "RequestID", typ: reflect.TypeOf("")},
	})

	if method.Type.NumOut() != 2 || method.Type.Out(1) != errorType {
		t.Fatal("Service.Refresh must return one result value and error")
	}
	assertRefreshStructShape(t, method.Type.Out(0), []refreshFieldShape{
		{name: "TokenType", typ: reflect.TypeOf("")},
		{name: "AccessToken", typ: reflect.TypeOf("")},
		{name: "ExpiresIn", typ: reflect.TypeOf(int64(0))},
		{name: "RefreshToken", typ: reflect.TypeOf("")},
		{name: "RefreshExpiresAt", typ: reflect.TypeOf(time.Time{})},
	})
}

func TestRefreshRejectsMalformedTokenWithoutLookup(t *testing.T) {
	privateCause := &refreshPrivateError{}
	fixture := newRefreshFixture(t)
	fixture.refresh.parseErr = privateCause

	got, err := fixture.service.Refresh(context.Background(), RefreshInput{
		RefreshToken: "malformed-private-refresh-token",
		RequestID:    "request-malformed",
	})

	assertRefreshFailure(t, got, err, ErrInvalidRefreshToken, nil, privateCause)
	if fixture.repository.findOwnerCalls != 0 || fixture.repository.withinTxCalls != 0 {
		t.Fatal("Refresh() performed repository work after token parsing failed")
	}
	if events := fixture.events.snapshot(); !reflect.DeepEqual(events, []string{"parse"}) {
		t.Fatalf("Refresh() dependency order = %v", events)
	}
}

func TestRefreshRejectsNonPositiveParsedSessionIDAsInvalidToken(t *testing.T) {
	fixture := newRefreshFixture(t)
	fixture.refresh.parsedSessionID = 0

	got, err := fixture.service.Refresh(context.Background(), RefreshInput{
		RefreshToken: "0.AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8",
	})

	assertRefreshFailure(t, got, err, ErrInvalidRefreshToken, nil, nil)
	if fixture.repository.findOwnerCalls != 0 || fixture.repository.withinTxCalls != 0 {
		t.Fatal("Refresh() performed repository work for a non-positive parsed session ID")
	}
	if events := fixture.events.snapshot(); !reflect.DeepEqual(events, []string{"parse"}) {
		t.Fatalf("Refresh() dependency order = %v", events)
	}
}

func TestRefreshClassifiesSessionOwnerPreReadFailures(t *testing.T) {
	privateCause := &refreshPrivateError{}
	tests := []struct {
		name        string
		ownerID     int64
		ownerErr    error
		wantError   error
		contextMark error
		cause       error
	}{
		{name: "session missing", ownerID: refreshUserID, ownerErr: ErrNotFound, wantError: ErrInvalidRefreshToken},
		{
			name:        "not found wrapped with cancellation remains internal",
			ownerID:     refreshUserID,
			ownerErr:    errors.Join(ErrNotFound, context.Canceled),
			wantError:   ErrInternal,
			contextMark: context.Canceled,
		},
		{
			name:      "not found wrapped with internal remains internal",
			ownerID:   refreshUserID,
			ownerErr:  errors.Join(ErrNotFound, ErrInternal),
			wantError: ErrInternal,
		},
		{name: "repository failure", ownerID: refreshUserID, ownerErr: privateCause, wantError: ErrInternal, cause: privateCause},
		{name: "non-positive repository owner", ownerID: 0, wantError: ErrInternal},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fixture := newRefreshFixture(t)
			fixture.repository.ownerID = tt.ownerID
			fixture.repository.ownerErr = tt.ownerErr

			got, err := fixture.service.Refresh(context.Background(), validRefreshInput())

			assertRefreshFailure(t, got, err, tt.wantError, tt.contextMark, tt.cause)
			if fixture.repository.findOwnerCalls != 1 || fixture.repository.findOwnerSessionID != refreshSessionID {
				t.Fatal("Refresh() did not pre-read exactly the parsed session owner")
			}
			if fixture.repository.withinTxCalls != 0 {
				t.Fatal("Refresh() opened a transaction after owner pre-read failed")
			}
			if events := fixture.events.snapshot(); !reflect.DeepEqual(events, []string{"parse", "find_owner"}) {
				t.Fatalf("Refresh() dependency order = %v", events)
			}
		})
	}
}

func TestRefreshRevalidatesLockedUserSessionAndOwner(t *testing.T) {
	privateCause := &refreshPrivateError{}
	tests := []struct {
		name        string
		setup       func(*refreshFixture)
		wantError   error
		contextMark error
		cause       error
		wantEvents  []string
	}{
		{
			name: "user lock failure",
			setup: func(f *refreshFixture) {
				f.repository.lockUsersErr = privateCause
			},
			wantError:  ErrInternal,
			cause:      privateCause,
			wantEvents: []string{"parse", "find_owner", "begin_tx", "lock_users", "rollback"},
		},
		{
			name: "locked user missing",
			setup: func(f *refreshFixture) {
				f.repository.lockUsersRowsSet = true
				f.repository.lockUsersRows = []LockedUser{}
			},
			wantError:  ErrInvalidRefreshToken,
			wantEvents: []string{"parse", "find_owner", "begin_tx", "lock_users", "rollback"},
		},
		{
			name: "locked user does not match pre-read owner",
			setup: func(f *refreshFixture) {
				wrong := cloneLoginUser(f.repository.user)
				wrong.ID++
				f.repository.lockUsersRowsSet = true
				f.repository.lockUsersRows = []LockedUser{wrong}
			},
			wantError:  ErrInvalidRefreshToken,
			wantEvents: []string{"parse", "find_owner", "begin_tx", "lock_users", "rollback"},
		},
		{
			name: "session lock failure",
			setup: func(f *refreshFixture) {
				f.repository.lockSessionErr = privateCause
			},
			wantError:  ErrInternal,
			cause:      privateCause,
			wantEvents: []string{"parse", "find_owner", "begin_tx", "lock_users", "lock_session", "rollback"},
		},
		{
			name: "locked session missing",
			setup: func(f *refreshFixture) {
				f.repository.lockSessionErr = ErrNotFound
			},
			wantError:  ErrInvalidRefreshToken,
			wantEvents: []string{"parse", "find_owner", "begin_tx", "lock_users", "lock_session", "rollback"},
		},
		{
			name: "session missing wrapped with deadline remains internal",
			setup: func(f *refreshFixture) {
				f.repository.lockSessionErr = errors.Join(ErrNotFound, context.DeadlineExceeded)
			},
			wantError:   ErrInternal,
			contextMark: context.DeadlineExceeded,
			wantEvents:  []string{"parse", "find_owner", "begin_tx", "lock_users", "lock_session", "rollback"},
		},
		{
			name: "locked session id mismatch",
			setup: func(f *refreshFixture) {
				wrong := cloneLoginSession(f.repository.session)
				wrong.ID++
				f.repository.lockSessionResultSet = true
				f.repository.lockSessionResult = wrong
			},
			wantError:  ErrInvalidRefreshToken,
			wantEvents: []string{"parse", "find_owner", "begin_tx", "lock_users", "lock_session", "rollback"},
		},
		{
			name: "pre-read owner is not authorization when locked session owner changed",
			setup: func(f *refreshFixture) {
				wrong := cloneLoginSession(f.repository.session)
				wrong.UserID++
				f.repository.lockSessionResultSet = true
				f.repository.lockSessionResult = wrong
			},
			wantError:  ErrInvalidRefreshToken,
			wantEvents: []string{"parse", "find_owner", "begin_tx", "lock_users", "lock_session", "rollback"},
		},
		{
			name: "revoked session",
			setup: func(f *refreshFixture) {
				f.repository.session.RevokedAt = refreshTimePointer(refreshNow.Add(-time.Minute))
			},
			wantError:  ErrInvalidRefreshToken,
			wantEvents: []string{"parse", "find_owner", "begin_tx", "lock_users", "lock_session", "rollback"},
		},
		{
			name: "malformed stored token hash",
			setup: func(f *refreshFixture) {
				f.repository.session.TokenHash = append([]byte(nil), f.repository.session.TokenHash[:31]...)
			},
			wantError:  ErrInvalidRefreshToken,
			wantEvents: []string{"parse", "find_owner", "begin_tx", "lock_users", "lock_session", "rollback"},
		},
		{
			name: "refresh hash mismatch",
			setup: func(f *refreshFixture) {
				matched := false
				f.refresh.matchResult = &matched
			},
			wantError: ErrInvalidRefreshToken,
			wantEvents: []string{
				"parse", "find_owner", "begin_tx", "lock_users", "lock_session", "match_hash", "rollback",
			},
		},
		{
			name: "banned user",
			setup: func(f *refreshFixture) {
				f.repository.user.Status = domain.StatusBanned
			},
			wantError: ErrInvalidRefreshToken,
			wantEvents: []string{
				"parse", "find_owner", "begin_tx", "lock_users", "lock_session", "match_hash", "rollback",
			},
		},
		{
			name: "deleted status",
			setup: func(f *refreshFixture) {
				f.repository.user.Status = domain.StatusDeleted
				f.repository.user.DeletedAt = refreshTimePointer(refreshNow.Add(-time.Hour))
			},
			wantError: ErrInvalidRefreshToken,
			wantEvents: []string{
				"parse", "find_owner", "begin_tx", "lock_users", "lock_session", "match_hash", "rollback",
			},
		},
		{
			name: "soft deleted user",
			setup: func(f *refreshFixture) {
				f.repository.user.DeletedAt = refreshTimePointer(refreshNow.Add(-time.Hour))
			},
			wantError: ErrInvalidRefreshToken,
			wantEvents: []string{
				"parse", "find_owner", "begin_tx", "lock_users", "lock_session", "match_hash", "rollback",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fixture := newRefreshFixture(t)
			tt.setup(fixture)
			beforeUser, beforeSession, beforeAudits := fixture.repository.snapshot()

			got, err := fixture.service.Refresh(context.Background(), validRefreshInput())

			assertRefreshFailure(t, got, err, tt.wantError, tt.contextMark, tt.cause)
			if events := fixture.events.snapshot(); !reflect.DeepEqual(events, tt.wantEvents) {
				t.Fatalf("Refresh() dependency order = %v, want %v", events, tt.wantEvents)
			}
			if fixture.repository.lockUsersCalls != 1 || !reflect.DeepEqual(fixture.repository.lockUserIDs, []int64{refreshUserID}) {
				t.Fatal("Refresh() did not lock exactly the pre-read owner first")
			}
			if fixture.repository.lockSessionCalls > 0 && fixture.repository.lockSessionID != refreshSessionID {
				t.Fatal("Refresh() did not lock exactly the parsed session after the user")
			}
			if fixture.clock.calls != 0 || fixture.repository.recoverCalls != 0 || fixture.repository.rotateCalls != 0 ||
				fixture.refresh.generateCalls != 0 || fixture.access.generateCalls != 0 || fixture.access.signCalls != 0 {
				t.Fatal("Refresh() performed time, mute, token, or rotation work after a locked fact failed")
			}
			assertRefreshRepositoryState(t, fixture.repository, beforeUser, beforeSession, beforeAudits)
		})
	}
}

func TestRefreshSamplesClockAfterLocksAndRejectsAbsoluteExpiry(t *testing.T) {
	tests := []struct {
		name          string
		sessionExpiry time.Time
		clockNow      time.Time
		advanceAtLock bool
		wantError     error
	}{
		{
			name:          "zero session expiry",
			sessionExpiry: time.Time{},
			clockNow:      refreshNow,
			wantError:     ErrInvalidRefreshToken,
		},
		{
			name:          "session expired before now",
			sessionExpiry: refreshNow.Add(-time.Second),
			clockNow:      refreshNow,
			wantError:     ErrInvalidRefreshToken,
		},
		{
			name:          "session expires exactly now",
			sessionExpiry: refreshNow,
			clockNow:      refreshNow,
			wantError:     ErrInvalidRefreshToken,
		},
		{
			name:          "subsecond lifetime cannot produce a valid integer-second access token",
			sessionExpiry: refreshNow.Add(500 * time.Millisecond),
			clockNow:      refreshNow,
			wantError:     ErrInvalidRefreshToken,
		},
		{
			name:          "session expires while waiting for locks",
			sessionExpiry: refreshNow.Add(time.Minute),
			clockNow:      refreshNow.Add(2 * time.Minute),
			advanceAtLock: true,
			wantError:     ErrInvalidRefreshToken,
		},
		{
			name:          "uninitialized clock",
			sessionExpiry: refreshNow.Add(time.Hour),
			clockNow:      time.Time{},
			wantError:     ErrInternal,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fixture := newRefreshFixture(t)
			fixture.repository.session.ExpiresAt = tt.sessionExpiry
			if tt.advanceAtLock {
				fixture.repository.beforeLockSessionReturn = func() {
					fixture.clock.set(tt.clockNow)
				}
			} else {
				fixture.clock.set(tt.clockNow)
			}
			beforeUser, beforeSession, beforeAudits := fixture.repository.snapshot()

			got, err := fixture.service.Refresh(context.Background(), validRefreshInput())

			assertRefreshFailure(t, got, err, tt.wantError, nil, nil)
			if fixture.clock.calls != 1 {
				t.Fatalf("Clock.Now() calls = %d, want 1", fixture.clock.calls)
			}
			if events := fixture.events.snapshot(); !reflect.DeepEqual(events, []string{
				"parse", "find_owner", "begin_tx", "lock_users", "lock_session", "match_hash", "clock", "rollback",
			}) {
				t.Fatalf("Refresh() dependency order = %v", events)
			}
			if fixture.repository.recoverCalls != 0 || fixture.refresh.generateCalls != 0 || fixture.repository.rotateCalls != 0 {
				t.Fatal("Refresh() mutated state or generated tokens after absolute expiry failed")
			}
			assertRefreshRepositoryState(t, fixture.repository, beforeUser, beforeSession, beforeAudits)
		})
	}
}

func TestRefreshRejectsSessionExpiryOutsideRFC3339BeforeMutation(t *testing.T) {
	fixture := newRefreshFixture(t)
	fixture.repository.session.ExpiresAt = time.Date(10000, time.January, 1, 0, 0, 0, 0, time.UTC)
	fixture.repository.user.Status = domain.StatusMuted
	fixture.repository.user.MutedUntil = refreshTimePointer(refreshNow.Add(-time.Minute))
	beforeUser, beforeSession, beforeAudits := fixture.repository.snapshot()

	got, err := fixture.service.Refresh(context.Background(), validRefreshInput())

	assertRefreshFailure(t, got, err, ErrInvalidRefreshToken, nil, nil)
	if fixture.clock.calls != 1 {
		t.Fatalf("Clock.Now() calls = %d, want 1", fixture.clock.calls)
	}
	if events := fixture.events.snapshot(); !reflect.DeepEqual(events, []string{
		"parse", "find_owner", "begin_tx", "lock_users", "lock_session", "match_hash", "clock", "rollback",
	}) {
		t.Fatalf("Refresh() dependency order = %v", events)
	}
	if fixture.repository.recoverCalls != 0 || fixture.refresh.generateCalls != 0 ||
		fixture.access.generateCalls != 0 || fixture.access.signCalls != 0 || fixture.refresh.formatCalls != 0 ||
		fixture.repository.rotateCalls != 0 || fixture.repository.insertAuditCalls != 0 {
		t.Fatal("Refresh() performed mute, token, rotation, or audit work for an unencodable session expiry")
	}
	assertRefreshRepositoryState(t, fixture.repository, beforeUser, beforeSession, beforeAudits)
}

func TestRefreshRotatesTokenWithoutExtendingSessionAndCapsAccessExpiry(t *testing.T) {
	tests := []struct {
		name          string
		sessionExpiry time.Time
		wantAccessTTL time.Duration
	}{
		{
			name:          "access ttl is shorter",
			sessionExpiry: refreshNow.Add(refreshSessionTTL),
			wantAccessTTL: refreshAccessTTL,
		},
		{
			name:          "existing session expires first",
			sessionExpiry: refreshNow.Add(5 * time.Minute),
			wantAccessTTL: 5 * time.Minute,
		},
		{
			name:          "subsecond session expiry is capped downward",
			sessionExpiry: refreshNow.Add(5*time.Minute + 500*time.Millisecond),
			wantAccessTTL: 5 * time.Minute,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fixture := newRefreshFixture(t)
			fixture.repository.session.ExpiresAt = tt.sessionExpiry
			beforeUser, beforeSession, beforeAudits := fixture.repository.snapshot()

			got, err := fixture.service.Refresh(context.Background(), validRefreshInput())

			if err != nil {
				t.Fatalf("Refresh() returned error type %T", err)
			}
			if got.TokenType != "Bearer" || got.AccessToken != refreshAccessToken || got.RefreshToken != refreshNewToken {
				t.Fatal("Refresh() returned unexpected token metadata")
			}
			if _, err := json.Marshal(got); err != nil {
				t.Fatalf("json.Marshal(RefreshResult) returned error type %T", err)
			}
			if got.ExpiresIn != int64(tt.wantAccessTTL/time.Second) {
				t.Fatalf("RefreshResult.ExpiresIn = %d, want %d", got.ExpiresIn, int64(tt.wantAccessTTL/time.Second))
			}
			if !got.RefreshExpiresAt.Equal(domain.NormalizeTime(tt.sessionExpiry)) {
				t.Fatal("Refresh() did not return the existing absolute session expiry")
			}
			if events := fixture.events.snapshot(); !reflect.DeepEqual(events, []string{
				"parse", "find_owner", "begin_tx", "lock_users", "lock_session", "match_hash", "clock",
				"refresh_generate", "jti_generate", "sign", "refresh_format", "rotate_hash", "commit",
			}) {
				t.Fatalf("Refresh() dependency order = %v", events)
			}
			if fixture.clock.calls != 1 || fixture.refresh.generateCalls != 1 || fixture.refresh.formatCalls != 1 ||
				fixture.access.generateCalls != 1 || fixture.access.signCalls != 1 || fixture.repository.rotateCalls != 1 {
				t.Fatal("Refresh() did not generate, sign, format, and rotate exactly once")
			}
			if fixture.refresh.formattedID != refreshSessionID || fixture.refresh.formattedSecret != refreshNewSecret {
				t.Fatal("Refresh() did not format the new secret for the locked session")
			}
			if fixture.access.signedUserID != refreshUserID || fixture.access.signedSessionID != refreshSessionID ||
				fixture.access.signedJWTID != refreshJWTID || !fixture.access.signedIssuedAt.Equal(refreshNow) ||
				!fixture.access.signedExpiresAt.Equal(refreshNow.Add(tt.wantAccessTTL)) {
				t.Fatal("Refresh() signed unexpected access token claims")
			}
			if fixture.access.signedExpiresAt.After(tt.sessionExpiry) {
				t.Fatal("Refresh() extended access expiry beyond a subsecond absolute session expiry")
			}
			if fixture.repository.rotateSessionID != refreshSessionID || fixture.repository.rotateHash != fixture.refresh.generatedHash {
				t.Fatal("Refresh() did not persist only the newly generated refresh hash")
			}
			gotUser, gotSession, gotAudits := fixture.repository.snapshot()
			if !reflect.DeepEqual(gotUser, beforeUser) || !reflect.DeepEqual(gotAudits, beforeAudits) {
				t.Fatal("Refresh() unexpectedly changed the user or audit state")
			}
			wantSession := cloneLoginSession(beforeSession)
			wantSession.TokenHash = append([]byte(nil), fixture.refresh.generatedHash[:]...)
			if !reflect.DeepEqual(gotSession, wantSession) {
				t.Fatal("Refresh() changed session fields other than token_hash")
			}
			if !gotSession.ExpiresAt.Equal(beforeSession.ExpiresAt) {
				t.Fatal("Refresh() extended or otherwise changed session.expires_at")
			}
		})
	}
}

func TestRefreshHandlesMutedUserOnlyAfterTokenFactsAreValid(t *testing.T) {
	tests := []struct {
		name          string
		mutedUntil    time.Time
		hashMismatch  bool
		wantRecovered bool
		wantError     error
		wantEvents    []string
	}{
		{
			name:          "mute expired before now",
			mutedUntil:    refreshNow.Add(-time.Minute),
			wantRecovered: true,
			wantEvents: []string{
				"parse", "find_owner", "begin_tx", "lock_users", "lock_session", "match_hash", "clock",
				"recover_mute", "refresh_generate", "jti_generate", "sign", "refresh_format", "rotate_hash",
				"insert_audit", "commit",
			},
		},
		{
			name:          "mute expires exactly now",
			mutedUntil:    refreshNow,
			wantRecovered: true,
			wantEvents: []string{
				"parse", "find_owner", "begin_tx", "lock_users", "lock_session", "match_hash", "clock",
				"recover_mute", "refresh_generate", "jti_generate", "sign", "refresh_format", "rotate_hash",
				"insert_audit", "commit",
			},
		},
		{
			name:       "future mute remains muted",
			mutedUntil: refreshNow.Add(time.Minute),
			wantEvents: []string{
				"parse", "find_owner", "begin_tx", "lock_users", "lock_session", "match_hash", "clock",
				"refresh_generate", "jti_generate", "sign", "refresh_format", "rotate_hash", "commit",
			},
		},
		{
			name:         "invalid old token cannot recover expired mute",
			mutedUntil:   refreshNow.Add(-time.Minute),
			hashMismatch: true,
			wantError:    ErrInvalidRefreshToken,
			wantEvents: []string{
				"parse", "find_owner", "begin_tx", "lock_users", "lock_session", "match_hash", "rollback",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fixture := newRefreshFixture(t)
			fixture.repository.user.Status = domain.StatusMuted
			fixture.repository.user.MutedUntil = refreshTimePointer(tt.mutedUntil)
			if tt.hashMismatch {
				matched := false
				fixture.refresh.matchResult = &matched
			}
			beforeUser, beforeSession, beforeAudits := fixture.repository.snapshot()

			got, err := fixture.service.Refresh(context.Background(), RefreshInput{
				RefreshToken: refreshRawToken,
				RequestID:    "mute-request-42",
			})

			if tt.wantError != nil {
				assertRefreshFailure(t, got, err, tt.wantError, nil, nil)
				assertRefreshRepositoryState(t, fixture.repository, beforeUser, beforeSession, beforeAudits)
			} else {
				if err != nil {
					t.Fatalf("Refresh() returned error type %T", err)
				}
				gotUser, gotSession, gotAudits := fixture.repository.snapshot()
				if tt.wantRecovered {
					if gotUser.Status != domain.StatusActive || gotUser.MutedUntil != nil || !gotUser.UpdatedAt.Equal(refreshNow) {
						t.Fatal("Refresh() did not commit the expired mute recovery with the shared now")
					}
					if len(gotAudits) != 1 {
						t.Fatalf("Refresh() committed %d mute recovery audits, want 1", len(gotAudits))
					}
					assertExactRefreshMuteAudit(t, gotAudits[0], tt.mutedUntil, "mute-request-42")
				} else {
					if !reflect.DeepEqual(gotUser, beforeUser) || len(gotAudits) != 0 {
						t.Fatal("Refresh() changed or audited an unexpired mute")
					}
				}
				wantSession := cloneLoginSession(beforeSession)
				wantSession.TokenHash = append([]byte(nil), fixture.refresh.generatedHash[:]...)
				if !reflect.DeepEqual(gotSession, wantSession) {
					t.Fatal("Refresh() did not atomically combine mute handling with hash rotation")
				}
			}
			if events := fixture.events.snapshot(); !reflect.DeepEqual(events, tt.wantEvents) {
				t.Fatalf("Refresh() dependency order = %v, want %v", events, tt.wantEvents)
			}
		})
	}
}

func TestRefreshRejectsInvalidContextAfterParsing(t *testing.T) {
	tests := []struct {
		name        string
		context     func() context.Context
		contextMark error
	}{
		{
			name: "nil context",
			context: func() context.Context {
				return nil
			},
		},
		{
			name: "canceled context",
			context: func() context.Context {
				ctx, cancel := context.WithCancel(context.Background())
				cancel()
				return ctx
			},
			contextMark: context.Canceled,
		},
		{
			name: "expired deadline",
			context: func() context.Context {
				ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
				t.Cleanup(cancel)
				return ctx
			},
			contextMark: context.DeadlineExceeded,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fixture := newRefreshFixture(t)

			got, err := fixture.service.Refresh(tt.context(), validRefreshInput())

			assertRefreshFailure(t, got, err, ErrInternal, tt.contextMark, nil)
			if fixture.repository.findOwnerCalls != 0 || fixture.repository.withinTxCalls != 0 {
				t.Fatal("Refresh() performed repository work after its post-parse context gate failed")
			}
			if events := fixture.events.snapshot(); !reflect.DeepEqual(events, []string{"parse"}) {
				t.Fatalf("Refresh() dependency order = %v", events)
			}
		})
	}
}

func TestRefreshStopsWhenContextIsCanceledDuringOwnerPreRead(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	fixture := newRefreshFixture(t)
	fixture.repository.beforeFindOwnerReturn = cancel

	got, err := fixture.service.Refresh(ctx, validRefreshInput())

	assertRefreshFailure(t, got, err, ErrInternal, context.Canceled, nil)
	if fixture.repository.withinTxCalls != 0 {
		t.Fatal("Refresh() opened a transaction after owner pre-read canceled the context")
	}
	if events := fixture.events.snapshot(); !reflect.DeepEqual(events, []string{"parse", "find_owner"}) {
		t.Fatalf("Refresh() dependency order = %v", events)
	}
}

func TestRefreshRollsBackEveryInternalFailure(t *testing.T) {
	privateCause := &refreshPrivateError{}
	tests := []struct {
		name       string
		setup      func(*refreshFixture)
		cause      error
		wantEvents []string
	}{
		{
			name: "begin transaction failure",
			setup: func(f *refreshFixture) {
				f.repository.beginErr = privateCause
			},
			cause:      privateCause,
			wantEvents: []string{"parse", "find_owner", "begin_tx"},
		},
		{
			name: "mute recovery failure",
			setup: func(f *refreshFixture) {
				f.repository.recoverErr = privateCause
			},
			cause: privateCause,
			wantEvents: []string{
				"parse", "find_owner", "begin_tx", "lock_users", "lock_session", "match_hash", "clock",
				"recover_mute", "rollback",
			},
		},
		{
			name: "mute conditional update unexpectedly loses",
			setup: func(f *refreshFixture) {
				changed := false
				f.repository.recoverChanged = &changed
			},
			wantEvents: []string{
				"parse", "find_owner", "begin_tx", "lock_users", "lock_session", "match_hash", "clock",
				"recover_mute", "rollback",
			},
		},
		{
			name: "refresh secret random failure",
			setup: func(f *refreshFixture) {
				f.refresh.generateErr = privateCause
			},
			cause: privateCause,
			wantEvents: []string{
				"parse", "find_owner", "begin_tx", "lock_users", "lock_session", "match_hash", "clock",
				"recover_mute", "refresh_generate", "rollback",
			},
		},
		{
			name: "jwt id random failure",
			setup: func(f *refreshFixture) {
				f.access.generateErr = privateCause
			},
			cause: privateCause,
			wantEvents: []string{
				"parse", "find_owner", "begin_tx", "lock_users", "lock_session", "match_hash", "clock",
				"recover_mute", "refresh_generate", "jti_generate", "rollback",
			},
		},
		{
			name: "jwt signing failure",
			setup: func(f *refreshFixture) {
				f.access.signErr = privateCause
			},
			cause: privateCause,
			wantEvents: []string{
				"parse", "find_owner", "begin_tx", "lock_users", "lock_session", "match_hash", "clock",
				"recover_mute", "refresh_generate", "jti_generate", "sign", "rollback",
			},
		},
		{
			name: "refresh formatting failure",
			setup: func(f *refreshFixture) {
				f.refresh.formatErr = privateCause
			},
			cause: privateCause,
			wantEvents: []string{
				"parse", "find_owner", "begin_tx", "lock_users", "lock_session", "match_hash", "clock",
				"recover_mute", "refresh_generate", "jti_generate", "sign", "refresh_format", "rollback",
			},
		},
		{
			name: "hash rotation failure",
			setup: func(f *refreshFixture) {
				f.repository.rotateErr = privateCause
			},
			cause: privateCause,
			wantEvents: []string{
				"parse", "find_owner", "begin_tx", "lock_users", "lock_session", "match_hash", "clock",
				"recover_mute", "refresh_generate", "jti_generate", "sign", "refresh_format", "rotate_hash", "rollback",
			},
		},
		{
			name: "mute audit failure after rotation",
			setup: func(f *refreshFixture) {
				f.repository.insertAuditErr = privateCause
			},
			cause: privateCause,
			wantEvents: []string{
				"parse", "find_owner", "begin_tx", "lock_users", "lock_session", "match_hash", "clock",
				"recover_mute", "refresh_generate", "jti_generate", "sign", "refresh_format", "rotate_hash",
				"insert_audit", "rollback",
			},
		},
		{
			name: "commit failure",
			setup: func(f *refreshFixture) {
				f.repository.commitErr = privateCause
			},
			cause: privateCause,
			wantEvents: []string{
				"parse", "find_owner", "begin_tx", "lock_users", "lock_session", "match_hash", "clock",
				"recover_mute", "refresh_generate", "jti_generate", "sign", "refresh_format", "rotate_hash",
				"insert_audit", "commit",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fixture := newRefreshFixture(t)
			fixture.repository.user.Status = domain.StatusMuted
			fixture.repository.user.MutedUntil = refreshTimePointer(refreshNow.Add(-time.Minute))
			tt.setup(fixture)
			beforeUser, beforeSession, beforeAudits := fixture.repository.snapshot()

			got, err := fixture.service.Refresh(context.Background(), validRefreshInput())

			assertRefreshFailure(t, got, err, ErrInternal, nil, tt.cause)
			if events := fixture.events.snapshot(); !reflect.DeepEqual(events, tt.wantEvents) {
				t.Fatalf("Refresh() dependency order = %v, want %v", events, tt.wantEvents)
			}
			assertRefreshRepositoryState(t, fixture.repository, beforeUser, beforeSession, beforeAudits)
		})
	}
}

func TestRefreshSucceedsForEveryRefreshCapableStatus(t *testing.T) {
	tests := []struct {
		name       string
		status     domain.Status
		mutedUntil *time.Time
	}{
		{name: "pending", status: domain.StatusPending},
		{name: "active", status: domain.StatusActive},
		{name: "muted", status: domain.StatusMuted, mutedUntil: refreshTimePointer(refreshNow.Add(time.Hour))},
		{name: "frozen", status: domain.StatusFrozen},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fixture := newRefreshFixture(t)
			fixture.repository.user.Status = tt.status
			fixture.repository.user.MutedUntil = cloneLoginTime(tt.mutedUntil)
			beforeUser, beforeSession, _ := fixture.repository.snapshot()

			got, err := fixture.service.Refresh(context.Background(), validRefreshInput())

			if err != nil {
				t.Fatalf("Refresh() returned error type %T for refresh-capable status %q", err, tt.status)
			}
			if got.RefreshToken != refreshNewToken || got.AccessToken != refreshAccessToken {
				t.Fatal("Refresh() did not return rotated tokens")
			}
			gotUser, gotSession, gotAudits := fixture.repository.snapshot()
			if !reflect.DeepEqual(gotUser, beforeUser) || len(gotAudits) != 0 {
				t.Fatal("Refresh() changed a refresh-capable user without an expired mute")
			}
			wantSession := cloneLoginSession(beforeSession)
			wantSession.TokenHash = append([]byte(nil), fixture.refresh.generatedHash[:]...)
			if !reflect.DeepEqual(gotSession, wantSession) {
				t.Fatal("Refresh() did not rotate exactly the token hash")
			}
		})
	}
}

func TestRefreshRejectsOldTokenReuse(t *testing.T) {
	fixture := newRefreshFixture(t)

	first, err := fixture.service.Refresh(context.Background(), validRefreshInput())
	if err != nil {
		t.Fatalf("first Refresh() returned error type %T", err)
	}
	if first.RefreshToken != refreshNewToken {
		t.Fatal("first Refresh() did not return the rotated token")
	}
	userAfterFirst, sessionAfterFirst, auditsAfterFirst := fixture.repository.snapshot()

	second, err := fixture.service.Refresh(context.Background(), validRefreshInput())

	assertRefreshFailure(t, second, err, ErrInvalidRefreshToken, nil, nil)
	assertRefreshRepositoryState(t, fixture.repository, userAfterFirst, sessionAfterFirst, auditsAfterFirst)
	if fixture.refresh.generateCalls != 1 || fixture.repository.rotateCalls != 1 {
		t.Fatal("Refresh() generated or rotated again while rejecting old-token reuse")
	}
	if fixture.refresh.matchCalls != 2 {
		t.Fatalf("RefreshTokenGenerator.Match() calls = %d, want 2", fixture.refresh.matchCalls)
	}
}

func TestRefreshConcurrentOldTokenAllowsAtMostOneSuccess(t *testing.T) {
	fixture := newRefreshFixture(t)
	start := make(chan struct{})
	ownerReadsReleased := make(chan struct{})
	var ownerReads sync.WaitGroup
	ownerReads.Add(2)
	fixture.repository.beforeFindOwnerReturn = func() {
		ownerReads.Done()
		<-ownerReadsReleased
	}
	type outcome struct {
		result RefreshResult
		err    error
	}
	outcomes := make(chan outcome, 2)
	var workers sync.WaitGroup
	for worker := 0; worker < 2; worker++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			<-start
			result, err := fixture.service.Refresh(context.Background(), validRefreshInput())
			outcomes <- outcome{result: result, err: err}
		}()
	}
	close(start)
	ownerReads.Wait()
	close(ownerReadsReleased)
	workers.Wait()
	close(outcomes)

	successes := 0
	invalid := 0
	for got := range outcomes {
		switch {
		case got.err == nil:
			successes++
			if got.result.RefreshToken != refreshNewToken {
				t.Fatal("successful concurrent Refresh() returned an unexpected token")
			}
		case got.err == ErrInvalidRefreshToken && got.result == (RefreshResult{}):
			invalid++
		default:
			t.Fatalf("concurrent Refresh() returned result/error types %T/%T", got.result, got.err)
		}
	}
	if successes != 1 || invalid != 1 {
		t.Fatalf("concurrent Refresh() outcomes = %d success, %d invalid; want 1 and 1", successes, invalid)
	}
	if fixture.refresh.generateCalls != 1 || fixture.repository.rotateCalls != 1 {
		t.Fatal("concurrent Refresh() generated or committed more than one rotation")
	}
	_, gotSession, gotAudits := fixture.repository.snapshot()
	if !reflect.DeepEqual(gotSession.TokenHash, fixture.refresh.generatedHash[:]) || len(gotAudits) != 0 {
		t.Fatal("concurrent Refresh() committed an unexpected final session or audit state")
	}
}

func assertExactRefreshMuteAudit(t *testing.T, got AuditEntry, oldMutedUntil time.Time, requestID string) {
	t.Helper()
	if got.ActorType != AuditActorSystem || got.ActorID != nil || got.Action != "user.mute_expired" ||
		got.TargetType != "user" || got.TargetID != refreshUserID || !got.CreatedAt.Equal(refreshNow) {
		t.Fatal("Refresh() produced incorrect mute recovery audit metadata")
	}
	wantDetail := map[string]any{
		"old_status":      domain.StatusMuted,
		"new_status":      domain.StatusActive,
		"old_muted_until": oldMutedUntil,
		"new_muted_until": nil,
		"request_id":      requestID,
	}
	if !reflect.DeepEqual(got.Detail, wantDetail) {
		t.Fatal("Refresh() produced incorrect mute recovery audit detail")
	}
}

type refreshFieldShape struct {
	name string
	typ  reflect.Type
}

func assertRefreshStructShape(t *testing.T, got reflect.Type, want []refreshFieldShape) {
	t.Helper()
	if got.Kind() != reflect.Struct || got.NumField() != len(want) {
		t.Fatal("Refresh input or result has an unexpected public shape")
	}
	for index, expected := range want {
		field := got.Field(index)
		if field.Name != expected.name || field.Type != expected.typ || field.Tag.Get("json") != "" {
			t.Fatal("Refresh input or result has an unexpected public field")
		}
	}
}

func validRefreshInput() RefreshInput {
	return RefreshInput{RefreshToken: refreshRawToken, RequestID: "request-42"}
}

func assertRefreshFailure(t *testing.T, got RefreshResult, err, want, contextMark, privateCause error) {
	t.Helper()
	if got != (RefreshResult{}) {
		t.Fatal("Refresh() returned a non-zero result after failure")
	}
	if err == nil {
		t.Fatal("Refresh() unexpectedly succeeded")
	}
	if !errors.Is(err, want) {
		t.Fatalf("Refresh() error type = %T, want stable service error", err)
	}
	if want == ErrInvalidRefreshToken {
		if err != ErrInvalidRefreshToken || err.Error() != ErrInvalidRefreshToken.Error() {
			t.Fatal("Refresh() did not return the exact invalid-refresh sentinel")
		}
		if errors.Is(err, ErrInternal) {
			t.Fatal("Refresh() classified a caller-visible refresh failure as internal")
		}
	}
	if want == ErrInternal {
		if err.Error() != ErrInternal.Error() || errors.Is(err, ErrInvalidRefreshToken) {
			t.Fatal("Refresh() did not return a safe internal error")
		}
	}
	if contextMark != nil && !errors.Is(err, contextMark) {
		t.Fatal("Refresh() did not preserve the safe context classification")
	}
	if privateCause != nil {
		if errors.Is(err, privateCause) || strings.Contains(err.Error(), privateCause.Error()) {
			t.Fatal("Refresh() exposed a private dependency cause")
		}
	}
	for _, forbidden := range []string{refreshRawToken, refreshNewToken, refreshNewSecret} {
		if strings.Contains(err.Error(), forbidden) {
			t.Fatal("Refresh() error exposed refresh token material")
		}
	}
}

func refreshHash(seed byte) [32]byte {
	var value [32]byte
	for index := range value {
		value[index] = seed + byte(index)
	}
	return value
}

func refreshTimePointer(value time.Time) *time.Time {
	return &value
}

type refreshPrivateError struct{}

func (*refreshPrivateError) Error() string {
	return "private refresh dependency failure"
}

type refreshEventLog struct {
	mu     sync.Mutex
	values []string
}

func (l *refreshEventLog) add(value string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.values = append(l.values, value)
}

func (l *refreshEventLog) snapshot() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]string(nil), l.values...)
}

type refreshFixture struct {
	service    *Service
	events     *refreshEventLog
	repository *refreshRepositoryFake
	clock      *refreshClockSpy
	access     *refreshAccessTokenSpy
	refresh    *refreshTokenSpy
}

func newRefreshFixture(t *testing.T) *refreshFixture {
	t.Helper()
	events := &refreshEventLog{}
	user := domain.User{
		ID:             refreshUserID,
		Email:          "refresh-user@example.com",
		PasswordHash:   "$2b$12$opaque-refresh-user-hash",
		DisplayName:    "Refresh User",
		Bio:            "profile",
		Role:           domain.RoleUser,
		Status:         domain.StatusActive,
		ViolationCount: 2,
		CreatedAt:      refreshNow.Add(-30 * 24 * time.Hour),
		UpdatedAt:      refreshNow.Add(-time.Hour),
	}
	oldHash := refreshHash(1)
	session := domain.UserSession{
		ID:        refreshSessionID,
		UserID:    refreshUserID,
		TokenHash: append([]byte(nil), oldHash[:]...),
		ExpiresAt: refreshNow.Add(refreshSessionTTL),
		CreatedAt: refreshNow.Add(-time.Hour),
	}
	repository := &refreshRepositoryFake{
		events:  events,
		ownerID: refreshUserID,
		user:    user,
		session: session,
	}
	clock := &refreshClockSpy{events: events, now: refreshNow}
	access := &refreshAccessTokenSpy{
		events:      events,
		jwtID:       refreshJWTID,
		accessToken: refreshAccessToken,
	}
	refreshGenerator := &refreshTokenSpy{
		events:          events,
		parsedSessionID: refreshSessionID,
		parsedHash:      oldHash,
		generatedSecret: refreshNewSecret,
		generatedHash:   refreshHash(101),
		formattedToken:  refreshNewToken,
	}
	service, err := New(Dependencies{
		Repository:            repository,
		PasswordHasher:        refreshUnusedPasswordHasher{},
		AccessTokenManager:    access,
		RefreshTokenGenerator: refreshGenerator,
		Clock:                 clock,
	}, Config{
		AccessTokenTTL:  refreshAccessTTL,
		RefreshTokenTTL: 30 * 24 * time.Hour,
	})
	if err != nil {
		t.Fatalf("New() returned error type %T for valid refresh fixture", err)
	}
	return &refreshFixture{
		service:    service,
		events:     events,
		repository: repository,
		clock:      clock,
		access:     access,
		refresh:    refreshGenerator,
	}
}

type refreshUnusedPasswordHasher struct{}

func (refreshUnusedPasswordHasher) Hash(string) (string, error)          { return "", nil }
func (refreshUnusedPasswordHasher) Compare(string, string) (bool, error) { return false, nil }
func (refreshUnusedPasswordHasher) DummyHash() string                    { return "unused" }
func (refreshUnusedPasswordHasher) DummyCandidate() string               { return "unused" }

type refreshRepositoryFake struct {
	repositoryPortStub
	events *refreshEventLog
	txMu   sync.Mutex
	mu     sync.Mutex

	ownerID                 int64
	ownerErr                error
	findOwnerCalls          int
	findOwnerSessionID      int64
	beforeFindOwnerReturn   func()
	withinTxCalls           int
	beginErr                error
	commitErr               error
	user                    domain.User
	session                 domain.UserSession
	audits                  []AuditEntry
	lockUsersCalls          int
	lockUserIDs             []int64
	lockUsersErr            error
	lockUsersRowsSet        bool
	lockUsersRows           []LockedUser
	beforeLockUsersReturn   func()
	lockSessionCalls        int
	lockSessionID           int64
	lockSessionErr          error
	lockSessionResultSet    bool
	lockSessionResult       domain.UserSession
	beforeLockSessionReturn func()
	recoverCalls            int
	recoverErr              error
	recoverChanged          *bool
	rotateCalls             int
	rotateSessionID         int64
	rotateHash              [32]byte
	rotateErr               error
	insertAuditCalls        int
	insertAuditErr          error
}

func (r *refreshRepositoryFake) FindSessionOwner(_ context.Context, sessionID int64) (int64, error) {
	r.events.add("find_owner")
	r.mu.Lock()
	r.findOwnerCalls++
	r.findOwnerSessionID = sessionID
	ownerID := r.ownerID
	err := r.ownerErr
	beforeReturn := r.beforeFindOwnerReturn
	r.mu.Unlock()
	if beforeReturn != nil {
		beforeReturn()
	}
	return ownerID, err
}

func (r *refreshRepositoryFake) WithinTx(ctx context.Context, callback func(context.Context, Tx) error) error {
	r.txMu.Lock()
	defer r.txMu.Unlock()
	r.events.add("begin_tx")
	r.mu.Lock()
	r.withinTxCalls++
	if r.beginErr != nil {
		err := r.beginErr
		r.mu.Unlock()
		return err
	}
	tx := &refreshTransactionFake{
		repository:    r,
		stagedUser:    cloneLoginUser(r.user),
		stagedSession: cloneLoginSession(r.session),
		stagedAudits:  cloneLoginAudits(r.audits),
	}
	r.mu.Unlock()

	if err := callback(ctx, tx); err != nil {
		r.events.add("rollback")
		return err
	}
	r.events.add("commit")
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.commitErr != nil {
		return r.commitErr
	}
	r.user = cloneLoginUser(tx.stagedUser)
	r.session = cloneLoginSession(tx.stagedSession)
	r.audits = cloneLoginAudits(tx.stagedAudits)
	return nil
}

func (r *refreshRepositoryFake) snapshot() (domain.User, domain.UserSession, []AuditEntry) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return cloneLoginUser(r.user), cloneLoginSession(r.session), cloneLoginAudits(r.audits)
}

func assertRefreshRepositoryState(
	t *testing.T,
	repository *refreshRepositoryFake,
	wantUser domain.User,
	wantSession domain.UserSession,
	wantAudits []AuditEntry,
) {
	t.Helper()
	gotUser, gotSession, gotAudits := repository.snapshot()
	if !reflect.DeepEqual(gotUser, wantUser) || !reflect.DeepEqual(gotSession, wantSession) || !reflect.DeepEqual(gotAudits, wantAudits) {
		t.Fatal("Refresh() committed partial user, session, or audit state after failure")
	}
}

type refreshTransactionFake struct {
	transactionPortStub
	repository    *refreshRepositoryFake
	stagedUser    domain.User
	stagedSession domain.UserSession
	stagedAudits  []AuditEntry
}

func (tx *refreshTransactionFake) LockUsers(_ context.Context, ids []int64) ([]LockedUser, error) {
	r := tx.repository
	r.events.add("lock_users")
	r.mu.Lock()
	r.lockUsersCalls++
	r.lockUserIDs = append([]int64(nil), ids...)
	err := r.lockUsersErr
	rowsSet := r.lockUsersRowsSet
	rows := append([]LockedUser(nil), r.lockUsersRows...)
	beforeReturn := r.beforeLockUsersReturn
	r.mu.Unlock()
	if err != nil {
		return nil, err
	}
	if beforeReturn != nil {
		beforeReturn()
	}
	if rowsSet {
		for index := range rows {
			rows[index] = cloneLoginUser(rows[index])
		}
		return rows, nil
	}
	return []LockedUser{cloneLoginUser(tx.stagedUser)}, nil
}

func (tx *refreshTransactionFake) LockSession(_ context.Context, sessionID int64) (domain.UserSession, error) {
	r := tx.repository
	r.events.add("lock_session")
	r.mu.Lock()
	r.lockSessionCalls++
	r.lockSessionID = sessionID
	err := r.lockSessionErr
	resultSet := r.lockSessionResultSet
	result := cloneLoginSession(r.lockSessionResult)
	beforeReturn := r.beforeLockSessionReturn
	r.mu.Unlock()
	if err != nil {
		return domain.UserSession{}, err
	}
	if beforeReturn != nil {
		beforeReturn()
	}
	if resultSet {
		return result, nil
	}
	return cloneLoginSession(tx.stagedSession), nil
}

func (tx *refreshTransactionFake) RecoverExpiredMute(_ context.Context, userID int64, now time.Time) (domain.User, bool, error) {
	r := tx.repository
	r.events.add("recover_mute")
	r.mu.Lock()
	r.recoverCalls++
	err := r.recoverErr
	changed := r.recoverChanged
	r.mu.Unlock()
	if err != nil {
		return domain.User{}, false, err
	}
	if changed != nil && !*changed {
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

func (tx *refreshTransactionFake) RotateSessionToken(_ context.Context, sessionID int64, tokenHash [32]byte) error {
	r := tx.repository
	r.events.add("rotate_hash")
	r.mu.Lock()
	r.rotateCalls++
	r.rotateSessionID = sessionID
	r.rotateHash = tokenHash
	err := r.rotateErr
	r.mu.Unlock()
	if err != nil {
		return err
	}
	if tx.stagedSession.ID != sessionID {
		return ErrNotFound
	}
	tx.stagedSession.TokenHash = append([]byte(nil), tokenHash[:]...)
	return nil
}

func (tx *refreshTransactionFake) InsertAudit(_ context.Context, entry AuditEntry) error {
	r := tx.repository
	r.events.add("insert_audit")
	r.mu.Lock()
	r.insertAuditCalls++
	err := r.insertAuditErr
	r.mu.Unlock()
	if err != nil {
		return err
	}
	tx.stagedAudits = append(tx.stagedAudits, cloneLoginAudit(entry))
	return nil
}

type refreshClockSpy struct {
	events *refreshEventLog
	mu     sync.Mutex
	calls  int
	now    time.Time
}

func (c *refreshClockSpy) Now() time.Time {
	c.events.add("clock")
	c.mu.Lock()
	defer c.mu.Unlock()
	c.calls++
	return c.now
}

func (c *refreshClockSpy) set(value time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = value
}

type refreshAccessTokenSpy struct {
	events *refreshEventLog
	mu     sync.Mutex

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

func (m *refreshAccessTokenSpy) GenerateJWTID() (string, error) {
	m.events.add("jti_generate")
	m.mu.Lock()
	defer m.mu.Unlock()
	m.generateCalls++
	return m.jwtID, m.generateErr
}

func (m *refreshAccessTokenSpy) Sign(userID, sessionID int64, issuedAt, expiresAt time.Time, jwtID string) (string, error) {
	m.events.add("sign")
	m.mu.Lock()
	defer m.mu.Unlock()
	m.signCalls++
	m.signedUserID = userID
	m.signedSessionID = sessionID
	m.signedIssuedAt = issuedAt
	m.signedExpiresAt = expiresAt
	m.signedJWTID = jwtID
	return m.accessToken, m.signErr
}

type refreshTokenSpy struct {
	events *refreshEventLog
	mu     sync.Mutex

	parseCalls       int
	parseRaw         string
	parseErr         error
	parsedSessionID  int64
	parsedHash       [32]byte
	matchCalls       int
	matchedStored    [32]byte
	matchedCandidate [32]byte
	matchResult      *bool
	generateCalls    int
	generateErr      error
	generatedSecret  string
	generatedHash    [32]byte
	formatCalls      int
	formatErr        error
	formattedToken   string
	formattedID      int64
	formattedSecret  string
}

func (g *refreshTokenSpy) Parse(raw string) (int64, [32]byte, error) {
	g.events.add("parse")
	g.mu.Lock()
	defer g.mu.Unlock()
	g.parseCalls++
	g.parseRaw = raw
	return g.parsedSessionID, g.parsedHash, g.parseErr
}

func (g *refreshTokenSpy) Match(stored, candidate [32]byte) bool {
	g.events.add("match_hash")
	g.mu.Lock()
	defer g.mu.Unlock()
	g.matchCalls++
	g.matchedStored = stored
	g.matchedCandidate = candidate
	if g.matchResult != nil {
		return *g.matchResult
	}
	return stored == candidate
}

func (g *refreshTokenSpy) Generate() (string, [32]byte, error) {
	g.events.add("refresh_generate")
	g.mu.Lock()
	defer g.mu.Unlock()
	g.generateCalls++
	return g.generatedSecret, g.generatedHash, g.generateErr
}

func (g *refreshTokenSpy) Format(sessionID int64, secret string) (string, error) {
	g.events.add("refresh_format")
	g.mu.Lock()
	defer g.mu.Unlock()
	g.formatCalls++
	g.formattedID = sessionID
	g.formattedSecret = secret
	return g.formattedToken, g.formatErr
}
