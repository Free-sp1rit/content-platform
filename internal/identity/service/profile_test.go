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
	profileUserID    int64 = 142
	profileSessionID int64 = 284
	profileSecret          = "profile-password-hash-do-not-expose"
)

var profileNow = time.Date(2026, time.September, 2, 10, 11, 12, 0, time.UTC)

func TestMeReturnsSafeLatestViewForReadableStatuses(t *testing.T) {
	for _, status := range []domain.Status{
		domain.StatusPending,
		domain.StatusActive,
		domain.StatusMuted,
		domain.StatusFrozen,
	} {
		t.Run(string(status), func(t *testing.T) {
			user := validProfileUser(status)
			repository := newProfileRepository(user)
			clock := &profileClockSpy{now: profileNow}
			service := &Service{repository: repository, clock: clock}

			got, err := service.Me(context.Background(), MeInput{
				UserID:    profileUserID,
				SessionID: profileSessionID,
				RequestID: "request-me",
			})

			if err != nil {
				t.Fatalf("Me() error type = %T, want nil", err)
			}
			want := safeProfileUser(user).View()
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("Me() = %#v, want %#v", got, want)
			}
			assertProfileJSONOmitsSecrets(t, got)
			if repository.authenticationCalls != 1 || repository.findUserCalls != 0 || repository.withinTxCalls != 0 {
				t.Fatalf("Me() repository calls auth/find/tx = %d/%d/%d", repository.authenticationCalls, repository.findUserCalls, repository.withinTxCalls)
			}
			if clock.calls != 1 {
				t.Fatalf("Clock.Now() calls = %d, want 1", clock.calls)
			}
		})
	}
}

func TestFutureSubsecondMuteDoesNotOpenRecoveryTransaction(t *testing.T) {
	user := validProfileUser(domain.StatusMuted)
	user.MutedUntil = profileTimePointer(profileNow.Add(500 * time.Millisecond))
	repository := newProfileRepository(user)
	clock := &profileClockSpy{now: profileNow.Add(900 * time.Millisecond)}
	service := &Service{repository: repository, clock: clock}

	got, err := service.Me(context.Background(), MeInput{
		UserID:    profileUserID,
		SessionID: profileSessionID,
		RequestID: "request-me",
	})

	wantMutedUntil := domain.NormalizeTime(*user.MutedUntil)
	if err != nil || got.Status != domain.StatusMuted || got.MutedUntil == nil || !got.MutedUntil.Equal(wantMutedUntil) {
		t.Fatalf("Me(future subsecond mute) = %#v/%T, want unchanged muted success", got, err)
	}
	if repository.withinTxCalls != 0 || repository.lockCalls != 0 || repository.recoverCalls != 0 || repository.insertAuditCalls != 0 {
		t.Fatalf("future subsecond mute opened recovery tx/lock/update/audit = %d/%d/%d/%d", repository.withinTxCalls, repository.lockCalls, repository.recoverCalls, repository.insertAuditCalls)
	}
	if clock.calls != 1 {
		t.Fatalf("Clock.Now() calls = %d, want 1", clock.calls)
	}
}

func TestMePropagatesStrictAuthenticationFailuresWithZeroSafeResult(t *testing.T) {
	privateCause := errors.New("private database email token hash")
	revokedAt := profileNow.Add(-time.Minute)
	tests := []struct {
		name      string
		configure func(*profileRepositoryFake)
		want      error
	}{
		{
			name: "missing session or user",
			configure: func(repository *profileRepositoryFake) {
				repository.authenticationErr = ErrNotFound
			},
			want: ErrSessionInvalid,
		},
		{
			name: "revoked session",
			configure: func(repository *profileRepositoryFake) {
				repository.session.RevokedAt = &revokedAt
			},
			want: ErrSessionInvalid,
		},
		{
			name: "banned latest user",
			configure: func(repository *profileRepositoryFake) {
				repository.user.Status = domain.StatusBanned
			},
			want: ErrSessionInvalid,
		},
		{
			name: "repository failure",
			configure: func(repository *profileRepositoryFake) {
				repository.authenticationErr = privateCause
			},
			want: ErrInternal,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			repository := newProfileRepository(validProfileUser(domain.StatusActive))
			tt.configure(repository)
			service := &Service{repository: repository, clock: &profileClockSpy{now: profileNow}}

			got, err := service.Me(context.Background(), MeInput{
				UserID:    profileUserID,
				SessionID: profileSessionID,
				RequestID: "request-me",
			})

			if got != (domain.UserView{}) {
				t.Fatal("Me() returned a non-zero result on strict-auth failure")
			}
			if tt.want == ErrSessionInvalid {
				if err != ErrSessionInvalid {
					t.Fatalf("Me() error type = %T, want exact ErrSessionInvalid", err)
				}
			} else if !errors.Is(err, tt.want) {
				t.Fatalf("Me() error type = %T, want %v", err, tt.want)
			}
			assertProfileErrorSafe(t, err, privateCause)
		})
	}
}

func TestPublicUserReturnsCurrentAndDeletedViews(t *testing.T) {
	for _, status := range []domain.Status{
		domain.StatusPending,
		domain.StatusActive,
		domain.StatusMuted,
		domain.StatusFrozen,
		domain.StatusBanned,
		domain.StatusDeleted,
	} {
		t.Run(string(status), func(t *testing.T) {
			user := validProfileUser(status)
			repository := newProfileRepository(user)
			clock := &profileClockSpy{now: profileNow}
			service := &Service{repository: repository, clock: clock}

			got, err := service.PublicUser(context.Background(), PublicUserInput{
				UserID:    profileUserID,
				RequestID: "request-public",
			})

			if err != nil {
				t.Fatalf("PublicUser() error type = %T, want nil", err)
			}
			want := safeProfileUser(user).PublicView()
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("PublicUser() = %#v, want %#v", got, want)
			}
			if status == domain.StatusDeleted && (got.DisplayName != "Deleted User" || got.Bio != "" || got.Role != domain.RoleUser || got.Status != domain.StatusDeleted) {
				t.Fatal("PublicUser() did not return the stable deleted-user anonymization")
			}
			assertProfileJSONOmitsSecrets(t, got)
			if repository.findUserCalls != 1 || repository.authenticationCalls != 0 || repository.withinTxCalls != 0 {
				t.Fatalf("PublicUser() repository calls find/auth/tx = %d/%d/%d", repository.findUserCalls, repository.authenticationCalls, repository.withinTxCalls)
			}
			if clock.calls != 1 {
				t.Fatalf("Clock.Now() calls = %d, want 1", clock.calls)
			}
		})
	}
}

func TestPublicUserClassifiesInvalidMissingAndRepositoryFailures(t *testing.T) {
	privateCause := errors.New("private user lookup email hash")

	t.Run("invalid user ID", func(t *testing.T) {
		repository := newProfileRepository(validProfileUser(domain.StatusActive))
		clock := &profileClockSpy{now: profileNow}
		service := &Service{repository: repository, clock: clock}

		got, err := service.PublicUser(context.Background(), PublicUserInput{UserID: 0})

		if got != (domain.PublicUserView{}) || !errors.Is(err, ErrInternal) {
			t.Fatalf("PublicUser(invalid ID) = %#v/%T, want zero/ErrInternal", got, err)
		}
		if repository.findUserCalls != 0 || clock.calls != 0 {
			t.Fatal("PublicUser(invalid ID) called dependencies")
		}
	})

	t.Run("missing user", func(t *testing.T) {
		repository := newProfileRepository(validProfileUser(domain.StatusActive))
		repository.findUserErr = ErrNotFound
		service := &Service{repository: repository, clock: &profileClockSpy{now: profileNow}}

		got, err := service.PublicUser(context.Background(), PublicUserInput{UserID: profileUserID})

		if got != (domain.PublicUserView{}) || err != ErrUserNotFound {
			t.Fatalf("PublicUser(missing) = %#v/%T, want zero/exact ErrUserNotFound", got, err)
		}
	})

	t.Run("repository failure", func(t *testing.T) {
		repository := newProfileRepository(validProfileUser(domain.StatusActive))
		repository.findUserErr = privateCause
		service := &Service{repository: repository, clock: &profileClockSpy{now: profileNow}}

		got, err := service.PublicUser(context.Background(), PublicUserInput{UserID: profileUserID})

		if got != (domain.PublicUserView{}) || !errors.Is(err, ErrInternal) {
			t.Fatalf("PublicUser(repository failure) = %#v/%T, want zero/ErrInternal", got, err)
		}
		assertProfileErrorSafe(t, err, privateCause)
	})
}

func TestMuteRecoveryAppliesToAuthenticateMeAndPublicUser(t *testing.T) {
	tests := []struct {
		name           string
		mutedUntil     time.Time
		requestID      string
		invoke         func(*Service) (domain.Status, *time.Time, error)
		firstReadEvent string
	}{
		{
			name:           "authenticate before now",
			mutedUntil:     profileNow.Add(-time.Second),
			requestID:      "",
			firstReadEvent: "find_authentication",
			invoke: func(service *Service) (domain.Status, *time.Time, error) {
				result, err := service.Authenticate(context.Background(), AuthenticateInput{UserID: profileUserID, SessionID: profileSessionID})
				return result.User.Status, result.User.MutedUntil, err
			},
		},
		{
			name:           "me exactly now",
			mutedUntil:     profileNow,
			requestID:      "request-me",
			firstReadEvent: "find_authentication",
			invoke: func(service *Service) (domain.Status, *time.Time, error) {
				result, err := service.Me(context.Background(), MeInput{UserID: profileUserID, SessionID: profileSessionID, RequestID: "request-me"})
				return result.Status, result.MutedUntil, err
			},
		},
		{
			name:           "public before now",
			mutedUntil:     profileNow.Add(-time.Second),
			requestID:      "request-public",
			firstReadEvent: "find_user",
			invoke: func(service *Service) (domain.Status, *time.Time, error) {
				result, err := service.PublicUser(context.Background(), PublicUserInput{UserID: profileUserID, RequestID: "request-public"})
				return result.Status, nil, err
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			user := validProfileUser(domain.StatusMuted)
			user.MutedUntil = profileTimePointer(tt.mutedUntil)
			repository := newProfileRepository(user)
			clock := &profileClockSpy{
				now:  time.Date(2026, time.September, 2, 18, 11, 12, 987654321, time.FixedZone("UTC+8", 8*60*60)),
				repo: repository,
			}
			service := &Service{repository: repository, clock: clock}

			status, mutedUntil, err := tt.invoke(service)

			if err != nil {
				t.Fatalf("profile recovery error type = %T, want nil", err)
			}
			if status != domain.StatusActive || mutedUntil != nil {
				t.Fatalf("profile recovery returned status/muted_until = %q/%v, want active/nil", status, mutedUntil)
			}
			storedUser, audits := repository.snapshot()
			if storedUser.Status != domain.StatusActive || storedUser.MutedUntil != nil || !storedUser.UpdatedAt.Equal(profileNow) {
				t.Fatal("profile recovery did not commit the exact active user state")
			}
			if len(audits) != 1 {
				t.Fatalf("profile recovery audit count = %d, want 1", len(audits))
			}
			assertExactProfileMuteAudit(t, audits[0], tt.mutedUntil, tt.requestID)
			wantEvents := []string{tt.firstReadEvent, "clock", "begin_tx", "lock_users", "recover_mute", "insert_audit", "commit"}
			if got := repository.eventSnapshot(); !reflect.DeepEqual(got, wantEvents) {
				t.Fatalf("profile recovery events = %v, want %v", got, wantEvents)
			}
			if clock.calls != 1 || repository.recoverCalls != 1 || repository.insertAuditCalls != 1 {
				t.Fatalf("profile recovery calls clock/recover/audit = %d/%d/%d", clock.calls, repository.recoverCalls, repository.insertAuditCalls)
			}
		})
	}
}

func TestPublicUserRejectsDamagedReadModelsAndPreservesSafeFailureClassifications(t *testing.T) {
	privateCause := errors.New("private profile repository SQL token")

	t.Run("damaged user structures", func(t *testing.T) {
		tests := []struct {
			name   string
			mutate func(*domain.User)
		}{
			{name: "wrong ID", mutate: func(user *domain.User) { user.ID++ }},
			{name: "unknown role", mutate: func(user *domain.User) { user.Role = domain.Role("owner") }},
			{name: "unknown status", mutate: func(user *domain.User) { user.Status = domain.Status("hidden") }},
			{name: "password hash in safe read", mutate: func(user *domain.User) { user.PasswordHash = profileSecret }},
			{name: "negative violations", mutate: func(user *domain.User) { user.ViolationCount = -1 }},
			{name: "zero creation time", mutate: func(user *domain.User) { user.CreatedAt = time.Time{} }},
			{name: "updated before creation", mutate: func(user *domain.User) { user.UpdatedAt = user.CreatedAt.Add(-time.Second) }},
			{name: "muted missing deadline", mutate: func(user *domain.User) {
				user.Status = domain.StatusMuted
				user.MutedUntil = nil
			}},
			{name: "active carries mute deadline", mutate: func(user *domain.User) {
				user.MutedUntil = profileTimePointer(profileNow.Add(time.Hour))
			}},
			{name: "deleted missing marker", mutate: func(user *domain.User) {
				user.Status = domain.StatusDeleted
				user.DeletedAt = nil
			}},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				user := safeProfileUser(validProfileUser(domain.StatusActive))
				tt.mutate(&user)
				repository := newProfileRepository(validProfileUser(domain.StatusActive))
				repository.findUserResultSet = true
				repository.findUserResult = user
				if tt.name == "password hash in safe read" {
					repository.preserveReadPasswordHash = true
				}
				clock := &profileClockSpy{now: profileNow}
				service := &Service{repository: repository, clock: clock}

				got, err := service.PublicUser(context.Background(), PublicUserInput{UserID: profileUserID})

				if got != (domain.PublicUserView{}) || !errors.Is(err, ErrInternal) {
					t.Fatalf("PublicUser(damaged row) = %#v/%T, want zero/ErrInternal", got, err)
				}
				assertProfileErrorSafe(t, err, nil)
				if clock.calls != 0 {
					t.Fatal("PublicUser() sampled the clock before rejecting a damaged read model")
				}
			})
		}
	})

	t.Run("nil and canceled contexts", func(t *testing.T) {
		for _, tt := range []struct {
			name string
			ctx  func() context.Context
			want error
		}{
			{name: "nil", ctx: func() context.Context { return nil }, want: nil},
			{name: "canceled", ctx: func() context.Context {
				ctx, cancel := context.WithCancel(context.Background())
				cancel()
				return ctx
			}, want: context.Canceled},
		} {
			t.Run(tt.name, func(t *testing.T) {
				repository := newProfileRepository(validProfileUser(domain.StatusActive))
				clock := &profileClockSpy{now: profileNow}
				service := &Service{repository: repository, clock: clock}

				got, err := service.PublicUser(tt.ctx(), PublicUserInput{UserID: profileUserID})

				if got != (domain.PublicUserView{}) || !errors.Is(err, ErrInternal) {
					t.Fatalf("PublicUser(%s context) = %#v/%T, want zero/ErrInternal", tt.name, got, err)
				}
				if tt.want != nil && !errors.Is(err, tt.want) {
					t.Fatalf("PublicUser(%s context) lost %v classification", tt.name, tt.want)
				}
				if repository.findUserCalls != 0 || clock.calls != 0 {
					t.Fatal("PublicUser() called dependencies after an initial context failure")
				}
			})
		}
	})

	t.Run("joined lookup classifications prefer context and internal", func(t *testing.T) {
		for _, repositoryErr := range []error{
			errors.Join(ErrNotFound, context.Canceled),
			errors.Join(ErrNotFound, newInternalError(privateCause)),
		} {
			repository := newProfileRepository(validProfileUser(domain.StatusActive))
			repository.findUserErr = repositoryErr
			service := &Service{repository: repository, clock: &profileClockSpy{now: profileNow}}

			got, err := service.PublicUser(context.Background(), PublicUserInput{UserID: profileUserID})

			if got != (domain.PublicUserView{}) || !errors.Is(err, ErrInternal) || errors.Is(err, ErrUserNotFound) {
				t.Fatalf("PublicUser(joined lookup) = %#v/%T, want zero/internal precedence", got, err)
			}
			assertProfileErrorSafe(t, err, privateCause)
		}
	})

	t.Run("invalid clock", func(t *testing.T) {
		repository := newProfileRepository(validProfileUser(domain.StatusActive))
		service := &Service{repository: repository, clock: &profileClockSpy{now: time.Time{}}}

		got, err := service.PublicUser(context.Background(), PublicUserInput{UserID: profileUserID})

		if got != (domain.PublicUserView{}) || !errors.Is(err, ErrInternal) {
			t.Fatalf("PublicUser(invalid clock) = %#v/%T, want zero/ErrInternal", got, err)
		}
	})
}

func TestMuteRecoveryRechecksLatestLockedState(t *testing.T) {
	t.Run("Me uses latest readable states and rejects latest unavailable states", func(t *testing.T) {
		for _, status := range []domain.Status{
			domain.StatusActive,
			domain.StatusPending,
			domain.StatusFrozen,
			domain.StatusBanned,
			domain.StatusDeleted,
		} {
			t.Run(string(status), func(t *testing.T) {
				observed := validProfileUser(domain.StatusMuted)
				observed.MutedUntil = profileTimePointer(profileNow.Add(-time.Second))
				latest := validProfileUser(status)
				repository := newProfileRepository(observed)
				repository.lockRowsSet = true
				repository.lockRows = []LockedUser{latest}
				service := &Service{repository: repository, clock: &profileClockSpy{now: profileNow}}

				got, err := service.Me(context.Background(), MeInput{UserID: profileUserID, SessionID: profileSessionID, RequestID: "request-me"})

				if status == domain.StatusBanned || status == domain.StatusDeleted {
					if got != (domain.UserView{}) || err != ErrSessionInvalid {
						t.Fatalf("Me(latest %s) = %#v/%T, want zero/exact ErrSessionInvalid", status, got, err)
					}
				} else {
					if err != nil || got.Status != status {
						t.Fatalf("Me(latest %s) = %#v/%T, want latest readable status", status, got, err)
					}
				}
				_, audits := repository.snapshot()
				if repository.recoverCalls != 0 || repository.insertAuditCalls != 0 || len(audits) != 0 {
					t.Fatal("Me() recovered or audited after the locked row had already changed state")
				}
			})
		}
	})

	t.Run("PublicUser returns latest public state including deleted anonymization", func(t *testing.T) {
		for _, status := range []domain.Status{
			domain.StatusActive,
			domain.StatusPending,
			domain.StatusFrozen,
			domain.StatusBanned,
			domain.StatusDeleted,
			domain.StatusMuted,
		} {
			t.Run(string(status), func(t *testing.T) {
				observed := validProfileUser(domain.StatusMuted)
				observed.MutedUntil = profileTimePointer(profileNow.Add(-time.Second))
				latest := validProfileUser(status)
				if status == domain.StatusMuted {
					latest.MutedUntil = profileTimePointer(profileNow.Add(time.Second))
				}
				repository := newProfileRepository(observed)
				repository.lockRowsSet = true
				repository.lockRows = []LockedUser{latest}
				service := &Service{repository: repository, clock: &profileClockSpy{now: profileNow}}

				got, err := service.PublicUser(context.Background(), PublicUserInput{UserID: profileUserID, RequestID: "request-public"})

				if err != nil {
					t.Fatalf("PublicUser(latest %s) error type = %T", status, err)
				}
				if want := latest.PublicView(); !reflect.DeepEqual(got, want) {
					t.Fatalf("PublicUser(latest %s) = %#v, want %#v", status, got, want)
				}
				_, audits := repository.snapshot()
				if repository.recoverCalls != 0 || repository.insertAuditCalls != 0 || len(audits) != 0 {
					t.Fatal("PublicUser() recovered or audited after the locked row no longer needed recovery")
				}
			})
		}
	})
}

func TestMuteRecoveryFailuresRollbackUserAndAudit(t *testing.T) {
	privateCause := errors.New("private recovery database detail")
	changedFalse := false
	tests := []struct {
		name      string
		configure func(*profileRepositoryFake)
	}{
		{name: "update failure", configure: func(repository *profileRepositoryFake) { repository.recoverErr = privateCause }},
		{name: "conditional changed false", configure: func(repository *profileRepositoryFake) { repository.recoverChanged = &changedFalse }},
		{name: "audit failure", configure: func(repository *profileRepositoryFake) { repository.insertAuditErr = privateCause }},
		{name: "commit failure", configure: func(repository *profileRepositoryFake) { repository.commitErr = privateCause }},
		{name: "invalid changed row", configure: func(repository *profileRepositoryFake) {
			invalid := validProfileUser(domain.StatusActive)
			invalid.Role = domain.Role("owner")
			invalid.UpdatedAt = profileNow
			repository.recoverResultSet = true
			repository.recoverResult = invalid
		}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			user := validProfileUser(domain.StatusMuted)
			user.MutedUntil = profileTimePointer(profileNow.Add(-time.Second))
			repository := newProfileRepository(user)
			tt.configure(repository)
			beforeUser, beforeAudits := repository.snapshot()
			service := &Service{repository: repository, clock: &profileClockSpy{now: profileNow}}

			got, err := service.PublicUser(context.Background(), PublicUserInput{UserID: profileUserID, RequestID: "request-public"})

			if got != (domain.PublicUserView{}) || !errors.Is(err, ErrInternal) {
				t.Fatalf("PublicUser(%s) = %#v/%T, want zero/ErrInternal", tt.name, got, err)
			}
			assertProfileErrorSafe(t, err, privateCause)
			afterUser, afterAudits := repository.snapshot()
			if !reflect.DeepEqual(afterUser, beforeUser) || !reflect.DeepEqual(afterAudits, beforeAudits) {
				t.Fatal("mute recovery failure committed partial user or audit state")
			}
		})
	}
}

func TestPublicUserConcurrentMuteRecoveryCommitsAtMostOneAudit(t *testing.T) {
	user := validProfileUser(domain.StatusMuted)
	oldMutedUntil := profileNow.Add(-time.Second)
	user.MutedUntil = profileTimePointer(oldMutedUntil)
	repository := newProfileRepository(user)
	var staleReads sync.WaitGroup
	staleReads.Add(2)
	releaseReads := make(chan struct{})
	repository.beforeFindUserReturn = func() {
		staleReads.Done()
		<-releaseReads
	}
	var lockAttempts sync.WaitGroup
	lockAttempts.Add(2)
	releaseLockAttempts := make(chan struct{})
	repository.beforeLockAttempt = func() {
		lockAttempts.Done()
		<-releaseLockAttempts
	}
	clock := &profileClockSpy{now: profileNow}
	service := &Service{repository: repository, clock: clock}

	type outcome struct {
		view domain.PublicUserView
		err  error
	}
	outcomes := make(chan outcome, 2)
	var workers sync.WaitGroup
	for worker := 0; worker < 2; worker++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			view, err := service.PublicUser(context.Background(), PublicUserInput{UserID: profileUserID, RequestID: "request-concurrent"})
			outcomes <- outcome{view: view, err: err}
		}()
	}
	staleReads.Wait()
	close(releaseReads)
	lockAttempts.Wait()
	close(releaseLockAttempts)
	workers.Wait()
	close(outcomes)

	for got := range outcomes {
		if got.err != nil || got.view.Status != domain.StatusActive {
			t.Fatalf("concurrent PublicUser() = %#v/%T, want active success", got.view, got.err)
		}
	}
	storedUser, audits := repository.snapshot()
	if storedUser.Status != domain.StatusActive || storedUser.MutedUntil != nil || !storedUser.UpdatedAt.Equal(profileNow) {
		t.Fatal("concurrent recovery did not commit the active user exactly once")
	}
	if len(audits) != 1 || repository.recoverCalls != 1 || repository.insertAuditCalls != 1 {
		t.Fatalf("concurrent recovery audit/recover/insert counts = %d/%d/%d, want 1/1/1", len(audits), repository.recoverCalls, repository.insertAuditCalls)
	}
	assertExactProfileMuteAudit(t, audits[0], oldMutedUntil, "request-concurrent")
	if repository.withinTxCalls != 2 || repository.lockCalls != 2 {
		t.Fatalf("concurrent recovery transaction/lock calls = %d/%d, want 2/2 stale attempts", repository.withinTxCalls, repository.lockCalls)
	}
}

func validProfileUser(status domain.Status) domain.User {
	user := domain.User{
		ID:             profileUserID,
		Email:          "profile@example.com",
		PasswordHash:   profileSecret,
		DisplayName:    "Profile User",
		Bio:            "public profile bio",
		Role:           domain.RoleUser,
		Status:         status,
		ViolationCount: 4,
		CreatedAt:      profileNow.Add(-30 * 24 * time.Hour),
		UpdatedAt:      profileNow.Add(-time.Hour),
	}
	switch status {
	case domain.StatusMuted:
		user.MutedUntil = profileTimePointer(profileNow.Add(time.Hour))
	case domain.StatusDeleted:
		user.DeletedAt = profileTimePointer(profileNow.Add(-time.Minute))
	}
	return user
}

func newProfileRepository(user domain.User) *profileRepositoryFake {
	return &profileRepositoryFake{
		user: user,
		session: AuthenticationSession{
			ID:        profileSessionID,
			UserID:    profileUserID,
			ExpiresAt: profileNow.Add(time.Hour),
			CreatedAt: profileNow.Add(-time.Hour),
		},
	}
}

func safeProfileUser(user domain.User) domain.User {
	user = cloneProfileUser(user)
	user.PasswordHash = ""
	return user
}

func assertProfileJSONOmitsSecrets(t *testing.T, value any) {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("json.Marshal(profile result) error = %v", err)
	}
	text := strings.ToLower(string(encoded))
	for _, forbidden := range []string{"email" + ":\"profile@example.com\"" + profileSecret, "password", "hash", "token", "audit", profileSecret} {
		if strings.Contains(text, strings.ToLower(forbidden)) {
			t.Fatalf("profile JSON exposed forbidden material %q", forbidden)
		}
	}
}

func assertProfileErrorSafe(t *testing.T, err error, privateCause error) {
	t.Helper()
	if err == nil {
		t.Fatal("profile operation unexpectedly returned nil error")
	}
	if privateCause != nil && (errors.Is(err, privateCause) || strings.Contains(err.Error(), privateCause.Error())) {
		t.Fatal("profile operation exposed a private cause")
	}
	for _, forbidden := range []string{"profile@example.com", profileSecret, "password", "hash", "token", "database"} {
		if strings.Contains(strings.ToLower(err.Error()), strings.ToLower(forbidden)) {
			t.Fatalf("profile error exposed %q", forbidden)
		}
	}
}

func assertExactProfileMuteAudit(t *testing.T, got AuditEntry, oldMutedUntil time.Time, requestID string) {
	t.Helper()
	if got.ActorType != AuditActorSystem || got.ActorID != nil || got.Action != "user.mute_expired" ||
		got.TargetType != "user" || got.TargetID != profileUserID || !got.CreatedAt.Equal(profileNow) {
		t.Fatalf("mute recovery audit metadata = %#v", got)
	}
	wantDetail := map[string]any{
		"old_status":      domain.StatusMuted,
		"new_status":      domain.StatusActive,
		"old_muted_until": oldMutedUntil,
		"new_muted_until": nil,
		"request_id":      requestID,
	}
	if !reflect.DeepEqual(got.Detail, wantDetail) {
		t.Fatalf("mute recovery detail = %#v, want %#v", got.Detail, wantDetail)
	}
}

func profileTimePointer(value time.Time) *time.Time {
	return &value
}

func cloneProfileUser(user domain.User) domain.User {
	if user.MutedUntil != nil {
		mutedUntil := *user.MutedUntil
		user.MutedUntil = &mutedUntil
	}
	if user.DeletedAt != nil {
		deletedAt := *user.DeletedAt
		user.DeletedAt = &deletedAt
	}
	return user
}

func cloneProfileAudit(entry AuditEntry) AuditEntry {
	if entry.ActorID != nil {
		actorID := *entry.ActorID
		entry.ActorID = &actorID
	}
	entry.Detail = mapsClone(entry.Detail)
	return entry
}

func mapsClone(values map[string]any) map[string]any {
	if values == nil {
		return nil
	}
	cloned := make(map[string]any, len(values))
	for key, value := range values {
		cloned[key] = value
	}
	return cloned
}

type profileRepositoryFake struct {
	repositoryPortStub

	txMu sync.Mutex
	mu   sync.Mutex

	user                     domain.User
	session                  AuthenticationSession
	audits                   []AuditEntry
	authenticationErr        error
	findUserErr              error
	findUserResultSet        bool
	findUserResult           domain.User
	preserveReadPasswordHash bool
	beforeFindUserReturn     func()
	beginErr                 error
	commitErr                error
	lockErr                  error
	lockRowsSet              bool
	lockRows                 []LockedUser
	beforeLockAttempt        func()
	recoverErr               error
	recoverChanged           *bool
	recoverResultSet         bool
	recoverResult            domain.User
	insertAuditErr           error

	authenticationCalls int
	findUserCalls       int
	withinTxCalls       int
	lockCalls           int
	recoverCalls        int
	insertAuditCalls    int
	events              []string
}

func (r *profileRepositoryFake) FindAuthenticationState(_ context.Context, sessionID int64) (AuthenticationState, error) {
	r.addEvent("find_authentication")
	r.mu.Lock()
	defer r.mu.Unlock()
	r.authenticationCalls++
	if r.authenticationErr != nil {
		return AuthenticationState{}, r.authenticationErr
	}
	session := r.session
	if sessionID != session.ID {
		return AuthenticationState{}, ErrNotFound
	}
	return AuthenticationState{Session: session, User: safeProfileUser(r.user)}, nil
}

func (r *profileRepositoryFake) FindUser(_ context.Context, userID int64) (domain.User, error) {
	r.addEvent("find_user")
	r.mu.Lock()
	r.findUserCalls++
	if r.findUserErr != nil {
		err := r.findUserErr
		r.mu.Unlock()
		return domain.User{}, err
	}
	result := r.user
	if r.findUserResultSet {
		result = r.findUserResult
	}
	if userID != profileUserID && !r.findUserResultSet {
		r.mu.Unlock()
		return domain.User{}, ErrNotFound
	}
	preservePasswordHash := r.preserveReadPasswordHash
	beforeReturn := r.beforeFindUserReturn
	r.mu.Unlock()
	result = cloneProfileUser(result)
	if !preservePasswordHash {
		result.PasswordHash = ""
	}
	if beforeReturn != nil {
		beforeReturn()
	}
	return result, nil
}

func (r *profileRepositoryFake) WithinTx(ctx context.Context, callback func(context.Context, Tx) error) error {
	r.addEvent("begin_tx")

	r.mu.Lock()
	r.withinTxCalls++
	if r.beginErr != nil {
		err := r.beginErr
		r.mu.Unlock()
		return err
	}
	tx := &profileTransactionFake{repository: r}
	r.mu.Unlock()
	defer tx.releaseUserLock()

	if err := callback(ctx, tx); err != nil {
		r.addEvent("rollback")
		return err
	}
	r.addEvent("commit")
	r.mu.Lock()
	if r.commitErr != nil {
		err := r.commitErr
		r.mu.Unlock()
		return err
	}
	if !tx.userLocked {
		r.mu.Unlock()
		return errors.New("profile transaction committed without a user lock")
	}
	r.user = cloneProfileUser(tx.stagedUser)
	r.audits = make([]AuditEntry, len(tx.stagedAudits))
	for index := range tx.stagedAudits {
		r.audits[index] = cloneProfileAudit(tx.stagedAudits[index])
	}
	r.mu.Unlock()
	return nil
}

func (r *profileRepositoryFake) addEvent(event string) {
	r.mu.Lock()
	r.events = append(r.events, event)
	r.mu.Unlock()
}

func (r *profileRepositoryFake) eventSnapshot() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.events...)
}

func (r *profileRepositoryFake) snapshot() (domain.User, []AuditEntry) {
	r.mu.Lock()
	defer r.mu.Unlock()
	audits := make([]AuditEntry, len(r.audits))
	for index := range r.audits {
		audits[index] = cloneProfileAudit(r.audits[index])
	}
	return cloneProfileUser(r.user), audits
}

type profileTransactionFake struct {
	transactionPortStub
	repository   *profileRepositoryFake
	stagedUser   domain.User
	stagedAudits []AuditEntry
	userLocked   bool
}

func (tx *profileTransactionFake) LockUsers(_ context.Context, userIDs []int64) ([]LockedUser, error) {
	r := tx.repository
	r.addEvent("lock_users")
	if r.beforeLockAttempt != nil {
		r.beforeLockAttempt()
	}
	if tx.userLocked {
		return nil, errors.New("profile transaction locked users more than once")
	}
	r.txMu.Lock()
	tx.userLocked = true
	r.mu.Lock()
	r.lockCalls++
	err := r.lockErr
	rowsSet := r.lockRowsSet
	rows := append([]LockedUser(nil), r.lockRows...)
	tx.stagedUser = cloneProfileUser(r.user)
	tx.stagedAudits = make([]AuditEntry, len(r.audits))
	for index := range r.audits {
		tx.stagedAudits[index] = cloneProfileAudit(r.audits[index])
	}
	r.mu.Unlock()
	if err != nil {
		return nil, err
	}
	if !reflect.DeepEqual(userIDs, []int64{profileUserID}) {
		return nil, errors.New("unexpected profile lock IDs")
	}
	if rowsSet {
		for index := range rows {
			rows[index] = cloneProfileUser(rows[index])
		}
		if len(rows) == 1 {
			tx.stagedUser = cloneProfileUser(rows[0])
		}
		return rows, nil
	}
	return []LockedUser{cloneProfileUser(tx.stagedUser)}, nil
}

func (tx *profileTransactionFake) releaseUserLock() {
	if !tx.userLocked {
		return
	}
	tx.userLocked = false
	tx.repository.txMu.Unlock()
}

func (tx *profileTransactionFake) RecoverExpiredMute(_ context.Context, userID int64, now time.Time) (domain.User, bool, error) {
	r := tx.repository
	r.addEvent("recover_mute")
	r.mu.Lock()
	r.recoverCalls++
	err := r.recoverErr
	changed := r.recoverChanged
	resultSet := r.recoverResultSet
	result := cloneProfileUser(r.recoverResult)
	r.mu.Unlock()
	if err != nil {
		return domain.User{}, false, err
	}
	if changed != nil && !*changed {
		return domain.User{}, false, nil
	}
	if tx.stagedUser.ID != userID || tx.stagedUser.Status != domain.StatusMuted || tx.stagedUser.MutedUntil == nil || tx.stagedUser.MutedUntil.After(now) {
		return domain.User{}, false, nil
	}
	tx.stagedUser.Status = domain.StatusActive
	tx.stagedUser.MutedUntil = nil
	tx.stagedUser.UpdatedAt = now
	if resultSet {
		tx.stagedUser = cloneProfileUser(result)
		return result, true, nil
	}
	return cloneProfileUser(tx.stagedUser), true, nil
}

func (tx *profileTransactionFake) InsertAudit(_ context.Context, entry AuditEntry) error {
	r := tx.repository
	r.addEvent("insert_audit")
	r.mu.Lock()
	r.insertAuditCalls++
	err := r.insertAuditErr
	r.mu.Unlock()
	if err != nil {
		return err
	}
	tx.stagedAudits = append(tx.stagedAudits, cloneProfileAudit(entry))
	return nil
}

type profileClockSpy struct {
	mu    sync.Mutex
	now   time.Time
	calls int
	repo  *profileRepositoryFake
}

func (c *profileClockSpy) Now() time.Time {
	if c.repo != nil {
		c.repo.addEvent("clock")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.calls++
	return c.now
}
