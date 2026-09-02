//go:build integration

package identity_test

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/Free-sp1rit/content-platform/internal/identity/domain"
	identityservice "github.com/Free-sp1rit/content-platform/internal/identity/service"
	infrapassword "github.com/Free-sp1rit/content-platform/internal/infra/password"
	identitypostgres "github.com/Free-sp1rit/content-platform/internal/infra/postgres/identity"
	"github.com/Free-sp1rit/content-platform/internal/infra/token"
	"github.com/Free-sp1rit/content-platform/internal/testkit"
)

const (
	postgresInvariantTestTimeout    = 45 * time.Second
	postgresInvariantRaceTimeout    = 15 * time.Second
	postgresInvariantQueryTimeout   = 3 * time.Second
	postgresInvariantPassword       = "correct horse battery staple"
	postgresInvariantAccessSecret   = "0123456789abcdef0123456789abcdef"
	postgresInvariantAccessIssuer   = "identity-postgres-integration"
	postgresInvariantAccessAudience = "identity-postgres-tests"
)

var (
	postgresInvariantNow       = time.Date(2026, time.September, 2, 12, 0, 0, 0, time.UTC)
	errInjectedTransactionStep = errors.New("injected identity transaction failure")
	errInjectedAccessTokenSign = errors.New("injected access token signing failure")
)

func TestPostgresIdentityRollbackInvariants(t *testing.T) {
	// Do not call t.Parallel: each subtest runs schema-local migrations through goose.
	t.Run("DeleteMe second session revoke", func(t *testing.T) {
		harness := newPostgresInvariantHarness(t)
		user := harness.createUser(t, "delete-revoke", domain.RoleUser, domain.StatusActive, nil)
		first, _ := harness.createRefreshSession(t, user.ID)
		second, _ := harness.createRefreshSession(t, user.ID)
		service := harness.serviceWith(t, &hookedRepository{
			Repository: harness.repository,
			hooks: transactionHooks{
				failSecondSessionRevoke: errInjectedTransactionStep,
			},
		}, nil)

		_, err := service.DeleteMe(harness.Context(), identityservice.DeleteMeInput{
			UserID: user.ID, SessionID: first.ID, RequestID: "delete-revoke-failure",
		})
		assertIdentityError(t, err, identityservice.ErrInternal)

		state := harness.readState(t, user.ID)
		assertUserState(t, state.User, domain.StatusActive, nil, nil, user.DisplayName)
		assertPersistedUserUnchanged(t, state.User, user)
		assertPersistedSessionUnchanged(t, state, first)
		assertPersistedSessionUnchanged(t, state, second)
		assertSessionActive(t, state, first.ID)
		assertSessionActive(t, state, second.ID)
		assertAuditCount(t, state, "", 0)
	})

	t.Run("DeleteMe final mute recovery audit", func(t *testing.T) {
		harness := newPostgresInvariantHarness(t)
		mutedUntil := harness.now.Add(-time.Minute)
		user := harness.createUser(t, "delete-audit", domain.RoleUser, domain.StatusMuted, &mutedUntil)
		first, _ := harness.createRefreshSession(t, user.ID)
		second, _ := harness.createRefreshSession(t, user.ID)
		service := harness.serviceWith(t, &hookedRepository{
			Repository: harness.repository,
			hooks:      transactionHooks{insertAuditError: errInjectedTransactionStep},
		}, nil)

		_, err := service.DeleteMe(harness.Context(), identityservice.DeleteMeInput{
			UserID: user.ID, SessionID: first.ID, RequestID: "delete-audit-failure",
		})
		assertIdentityError(t, err, identityservice.ErrInternal)

		state := harness.readState(t, user.ID)
		assertUserState(t, state.User, domain.StatusMuted, &mutedUntil, nil, user.DisplayName)
		assertPersistedUserUnchanged(t, state.User, user)
		assertPersistedSessionUnchanged(t, state, first)
		assertPersistedSessionUnchanged(t, state, second)
		assertSessionActive(t, state, first.ID)
		assertSessionActive(t, state, second.ID)
		assertAuditCount(t, state, "", 0)
	})

	t.Run("UpdateMe recovery patch and audit", func(t *testing.T) {
		harness := newPostgresInvariantHarness(t)
		mutedUntil := harness.now.Add(-time.Minute)
		user := harness.createUser(t, "update-audit", domain.RoleUser, domain.StatusMuted, &mutedUntil)
		session, _ := harness.createRefreshSession(t, user.ID)
		service := harness.serviceWith(t, &hookedRepository{
			Repository: harness.repository,
			hooks:      transactionHooks{insertAuditError: errInjectedTransactionStep},
		}, nil)

		_, err := service.UpdateMe(harness.Context(), identityservice.UpdateMeInput{
			UserID: user.ID, SessionID: session.ID, RequestID: "update-audit-failure",
			DisplayName: identityservice.SetField("Changed but rolled back"),
		})
		assertIdentityError(t, err, identityservice.ErrInternal)

		state := harness.readState(t, user.ID)
		assertUserState(t, state.User, domain.StatusMuted, &mutedUntil, nil, user.DisplayName)
		assertPersistedUserUnchanged(t, state.User, user)
		assertPersistedSessionUnchanged(t, state, session)
		assertSessionActive(t, state, session.ID)
		assertAuditCount(t, state, "", 0)
	})

	t.Run("admin ban audit", func(t *testing.T) {
		harness := newPostgresInvariantHarness(t)
		admin := harness.createUser(t, "ban-admin", domain.RoleAdmin, domain.StatusActive, nil)
		target := harness.createUser(t, "ban-target", domain.RoleUser, domain.StatusActive, nil)
		adminSession, _ := harness.createRefreshSession(t, admin.ID)
		targetFirst, _ := harness.createRefreshSession(t, target.ID)
		targetSecond, _ := harness.createRefreshSession(t, target.ID)
		service := harness.serviceWith(t, &hookedRepository{
			Repository: harness.repository,
			hooks:      transactionHooks{insertAuditError: errInjectedTransactionStep},
		}, nil)

		_, err := service.ChangeUserStatus(harness.Context(), identityservice.ChangeUserStatusInput{
			ActorID: admin.ID, ActorSessionID: adminSession.ID, TargetID: target.ID,
			NewStatus: domain.StatusBanned, Reason: "rollback", RequestID: "ban-audit-failure",
		})
		assertIdentityError(t, err, identityservice.ErrInternal)

		targetState := harness.readState(t, target.ID)
		assertUserState(t, targetState.User, domain.StatusActive, nil, nil, target.DisplayName)
		assertPersistedUserUnchanged(t, targetState.User, target)
		assertPersistedSessionUnchanged(t, targetState, targetFirst)
		assertPersistedSessionUnchanged(t, targetState, targetSecond)
		assertSessionActive(t, targetState, targetFirst.ID)
		assertSessionActive(t, targetState, targetSecond.ID)
		assertAuditCount(t, targetState, "", 0)
		adminState := harness.readState(t, admin.ID)
		assertUserState(t, adminState.User, domain.StatusActive, nil, nil, admin.DisplayName)
		assertPersistedUserUnchanged(t, adminState.User, admin)
		assertPersistedSessionUnchanged(t, adminState, adminSession)
		assertSessionActive(t, adminState, adminSession.ID)
		assertAuditCount(t, adminState, "", 0)
	})

	t.Run("Login JWT signing", func(t *testing.T) {
		harness := newPostgresInvariantHarness(t)
		mutedUntil := harness.now.Add(-time.Minute)
		user := harness.createUser(t, "login-sign", domain.RoleUser, domain.StatusMuted, &mutedUntil)
		failingAccess := failingAccessTokenManager{
			delegate: harness.access,
			err:      errInjectedAccessTokenSign,
		}
		service := harness.serviceWith(t, harness.repository, failingAccess)

		_, err := service.Login(harness.Context(), identityservice.LoginInput{
			Email: user.Email, Password: postgresInvariantPassword, RequestID: "login-sign-failure",
		})
		assertIdentityError(t, err, identityservice.ErrInternal)

		state := harness.readState(t, user.ID)
		assertUserState(t, state.User, domain.StatusMuted, &mutedUntil, nil, user.DisplayName)
		assertPersistedUserUnchanged(t, state.User, user)
		if len(state.Sessions) != 0 {
			t.Fatalf("persisted login sessions = %d, want 0", len(state.Sessions))
		}
		assertAuditCount(t, state, "", 0)
	})

	t.Run("Refresh JWT signing", func(t *testing.T) {
		harness := newPostgresInvariantHarness(t)
		mutedUntil := harness.now.Add(-time.Minute)
		user := harness.createUser(t, "refresh-sign", domain.RoleUser, domain.StatusMuted, &mutedUntil)
		session, oldRefresh := harness.createRefreshSession(t, user.ID)
		originalHash := append([]byte(nil), session.TokenHash...)
		failingAccess := failingAccessTokenManager{
			delegate: harness.access,
			err:      errInjectedAccessTokenSign,
		}
		service := harness.serviceWith(t, harness.repository, failingAccess)

		_, err := service.Refresh(harness.Context(), identityservice.RefreshInput{
			RefreshToken: oldRefresh, RequestID: "refresh-sign-failure",
		})
		assertIdentityError(t, err, identityservice.ErrInternal)

		rolledBack := harness.readState(t, user.ID)
		assertUserState(t, rolledBack.User, domain.StatusMuted, &mutedUntil, nil, user.DisplayName)
		assertPersistedUserUnchanged(t, rolledBack.User, user)
		assertPersistedSessionUnchanged(t, rolledBack, session)
		assertSessionActive(t, rolledBack, session.ID)
		assertSessionHash(t, rolledBack, session.ID, originalHash)
		assertAuditCount(t, rolledBack, "", 0)

		if _, err := harness.service.Refresh(harness.Context(), identityservice.RefreshInput{
			RefreshToken: oldRefresh, RequestID: "refresh-after-sign-failure",
		}); err != nil {
			t.Fatalf("old refresh token was not reusable after rollback: %v", err)
		}
		committed := harness.readState(t, user.ID)
		assertUserState(t, committed.User, domain.StatusActive, nil, nil, user.DisplayName)
		assertAuditCount(t, committed, "user.mute_expired", 1)
		if bytes.Equal(persistedSession(t, committed, session.ID).TokenHash, originalHash) {
			t.Fatal("successful refresh did not rotate token hash after signing rollback")
		}
		assertRefreshRejected(t, harness, oldRefresh)
	})

	t.Run("Refresh audit", func(t *testing.T) {
		harness := newPostgresInvariantHarness(t)
		mutedUntil := harness.now.Add(-time.Minute)
		user := harness.createUser(t, "refresh-audit", domain.RoleUser, domain.StatusMuted, &mutedUntil)
		session, oldRefresh := harness.createRefreshSession(t, user.ID)
		originalHash := append([]byte(nil), session.TokenHash...)
		service := harness.serviceWith(t, &hookedRepository{
			Repository: harness.repository,
			hooks:      transactionHooks{insertAuditError: errInjectedTransactionStep},
		}, nil)

		_, err := service.Refresh(harness.Context(), identityservice.RefreshInput{
			RefreshToken: oldRefresh, RequestID: "refresh-audit-failure",
		})
		assertIdentityError(t, err, identityservice.ErrInternal)

		rolledBack := harness.readState(t, user.ID)
		assertUserState(t, rolledBack.User, domain.StatusMuted, &mutedUntil, nil, user.DisplayName)
		assertPersistedUserUnchanged(t, rolledBack.User, user)
		assertPersistedSessionUnchanged(t, rolledBack, session)
		assertSessionActive(t, rolledBack, session.ID)
		assertSessionHash(t, rolledBack, session.ID, originalHash)
		assertAuditCount(t, rolledBack, "", 0)

		if _, err := harness.service.Refresh(harness.Context(), identityservice.RefreshInput{
			RefreshToken: oldRefresh, RequestID: "refresh-after-audit-failure",
		}); err != nil {
			t.Fatalf("old refresh token was not reusable after audit rollback: %v", err)
		}
		committed := harness.readState(t, user.ID)
		assertUserState(t, committed.User, domain.StatusActive, nil, nil, user.DisplayName)
		assertAuditCount(t, committed, "user.mute_expired", 1)
		if bytes.Equal(persistedSession(t, committed, session.ID).TokenHash, originalHash) {
			t.Fatal("successful refresh did not rotate token hash after audit rollback")
		}
		assertRefreshRejected(t, harness, oldRefresh)
	})
}

func TestPostgresIdentityAuthenticationRaces(t *testing.T) {
	// Do not call t.Parallel: each subtest runs schema-local migrations through goose.
	t.Run("two refreshes using one old token", func(t *testing.T) {
		harness := newPostgresInvariantHarness(t)
		ctx := harness.raceContext(t)
		user := harness.createUser(t, "refresh-refresh", domain.RoleUser, domain.StatusActive, nil)
		session, oldRefresh := harness.createRefreshSession(t, user.ID)
		barrier := newTransactionBarrier()
		t.Cleanup(barrier.Release)
		defer barrier.Release()
		holder := harness.serviceWith(t, &hookedRepository{
			Repository: harness.repository,
			hooks:      transactionHooks{afterLockSession: barrier.hold},
		}, nil)
		applicationName := "identity_refresh_refresh_" + randomRepositoryTestSuffix(t)
		contender := harness.additionalService(t, applicationName, transactionHooks{})

		holderDone := startServiceCall(t, func() (identityservice.RefreshResult, error) {
			return holder.Refresh(ctx, identityservice.RefreshInput{
				RefreshToken: oldRefresh, RequestID: "refresh-refresh-holder",
			})
		})
		awaitTransactionBarrier(t, ctx, barrier, holderDone)
		contenderDone := startServiceCall(t, func() (identityservice.RefreshResult, error) {
			return contender.Refresh(ctx, identityservice.RefreshInput{
				RefreshToken: oldRefresh, RequestID: "refresh-refresh-contender",
			})
		})
		awaitPostgresLockWait(t, ctx, harness.fixture.DB, applicationName, contenderDone)
		barrier.Release()

		holderResult := finishServiceCall(t, ctx, "first refresh", holderDone)
		contenderResult := finishServiceCall(t, ctx, "second refresh", contenderDone)
		if holderResult.Err != nil {
			t.Fatalf("first refresh error = %v", holderResult.Err)
		}
		assertIdentityError(t, contenderResult.Err, identityservice.ErrInvalidRefreshToken)

		state := harness.readState(t, user.ID)
		assertUserState(t, state.User, domain.StatusActive, nil, nil, user.DisplayName)
		assertSessionActive(t, state, session.ID)
		assertSessionExpiry(t, state, session.ID, session.ExpiresAt)
		assertRefreshHash(t, harness, state, session.ID, holderResult.Value.RefreshToken)
		assertAuditCount(t, state, "", 0)
		assertRefreshRejected(t, harness, oldRefresh)
	})

	t.Run("refresh then logout", func(t *testing.T) {
		harness := newPostgresInvariantHarness(t)
		ctx := harness.raceContext(t)
		user := harness.createUser(t, "refresh-logout", domain.RoleUser, domain.StatusActive, nil)
		session, oldRefresh := harness.createRefreshSession(t, user.ID)
		barrier := newTransactionBarrier()
		t.Cleanup(barrier.Release)
		defer barrier.Release()
		holder := harness.serviceWith(t, &hookedRepository{
			Repository: harness.repository,
			hooks:      transactionHooks{afterLockSession: barrier.hold},
		}, nil)
		applicationName := "identity_refresh_logout_" + randomRepositoryTestSuffix(t)
		logoutService := harness.additionalService(t, applicationName, transactionHooks{})

		refreshDone := startServiceCall(t, func() (identityservice.RefreshResult, error) {
			return holder.Refresh(ctx, identityservice.RefreshInput{
				RefreshToken: oldRefresh, RequestID: "refresh-logout-refresh",
			})
		})
		awaitTransactionBarrier(t, ctx, barrier, refreshDone)
		logoutDone := startServiceCall(t, func() (identityservice.LogoutResult, error) {
			return logoutService.Logout(ctx, identityservice.LogoutInput{
				UserID: user.ID, SessionID: session.ID,
			})
		})
		awaitPostgresLockWait(t, ctx, harness.fixture.DB, applicationName, logoutDone)
		barrier.Release()

		refreshResult := finishServiceCall(t, ctx, "refresh", refreshDone)
		logoutResult := finishServiceCall(t, ctx, "logout", logoutDone)
		if refreshResult.Err != nil {
			t.Fatalf("refresh error = %v", refreshResult.Err)
		}
		if logoutResult.Err != nil || !logoutResult.Value.LoggedOut {
			t.Fatalf("logout result = %+v, error = %v", logoutResult.Value, logoutResult.Err)
		}

		state := harness.readState(t, user.ID)
		assertUserState(t, state.User, domain.StatusActive, nil, nil, user.DisplayName)
		assertSessionRevoked(t, state, session.ID)
		assertSessionExpiry(t, state, session.ID, session.ExpiresAt)
		assertRefreshHash(t, harness, state, session.ID, refreshResult.Value.RefreshToken)
		assertAuditCount(t, state, "", 0)
		assertRefreshRejected(t, harness, oldRefresh)
		assertRefreshRejected(t, harness, refreshResult.Value.RefreshToken)
	})

	t.Run("refresh then ban", func(t *testing.T) {
		harness := newPostgresInvariantHarness(t)
		ctx := harness.raceContext(t)
		admin := harness.createUser(t, "refresh-ban-admin", domain.RoleAdmin, domain.StatusActive, nil)
		target := harness.createUser(t, "refresh-ban-target", domain.RoleUser, domain.StatusActive, nil)
		adminSession, _ := harness.createRefreshSession(t, admin.ID)
		targetSession, oldRefresh := harness.createRefreshSession(t, target.ID)
		barrier := newTransactionBarrier()
		t.Cleanup(barrier.Release)
		defer barrier.Release()
		holder := harness.serviceWith(t, &hookedRepository{
			Repository: harness.repository,
			hooks:      transactionHooks{afterLockSession: barrier.hold},
		}, nil)
		applicationName := "identity_refresh_ban_" + randomRepositoryTestSuffix(t)
		adminService := harness.additionalService(t, applicationName, transactionHooks{})

		refreshDone := startServiceCall(t, func() (identityservice.RefreshResult, error) {
			return holder.Refresh(ctx, identityservice.RefreshInput{
				RefreshToken: oldRefresh, RequestID: "refresh-ban-refresh",
			})
		})
		awaitTransactionBarrier(t, ctx, barrier, refreshDone)
		banDone := startServiceCall(t, func() (domain.UserView, error) {
			return adminService.ChangeUserStatus(ctx, identityservice.ChangeUserStatusInput{
				ActorID: admin.ID, ActorSessionID: adminSession.ID, TargetID: target.ID,
				NewStatus: domain.StatusBanned, Reason: "concurrent refresh", RequestID: "refresh-ban-admin",
			})
		})
		awaitPostgresLockWait(t, ctx, harness.fixture.DB, applicationName, banDone)
		barrier.Release()

		refreshResult := finishServiceCall(t, ctx, "refresh", refreshDone)
		banResult := finishServiceCall(t, ctx, "ban", banDone)
		if refreshResult.Err != nil {
			t.Fatalf("refresh error = %v", refreshResult.Err)
		}
		if banResult.Err != nil || banResult.Value.Status != domain.StatusBanned {
			t.Fatalf("ban result = %+v, error = %v", banResult.Value, banResult.Err)
		}

		targetState := harness.readState(t, target.ID)
		assertUserState(t, targetState.User, domain.StatusBanned, nil, nil, target.DisplayName)
		assertSessionRevoked(t, targetState, targetSession.ID)
		assertSessionExpiry(t, targetState, targetSession.ID, targetSession.ExpiresAt)
		assertRefreshHash(t, harness, targetState, targetSession.ID, refreshResult.Value.RefreshToken)
		if activeSessionCount(targetState) != 0 {
			t.Fatal("banned target retained an active session")
		}
		assertAuditCount(t, targetState, "user.status_changed", 1)
		adminState := harness.readState(t, admin.ID)
		assertUserState(t, adminState.User, domain.StatusActive, nil, nil, admin.DisplayName)
		assertSessionActive(t, adminState, adminSession.ID)
		assertAuditCount(t, adminState, "", 0)
		assertRefreshRejected(t, harness, oldRefresh)
		assertRefreshRejected(t, harness, refreshResult.Value.RefreshToken)
	})

	t.Run("refresh then delete", func(t *testing.T) {
		harness := newPostgresInvariantHarness(t)
		ctx := harness.raceContext(t)
		user := harness.createUser(t, "refresh-delete", domain.RoleUser, domain.StatusActive, nil)
		session, oldRefresh := harness.createRefreshSession(t, user.ID)
		barrier := newTransactionBarrier()
		t.Cleanup(barrier.Release)
		defer barrier.Release()
		holder := harness.serviceWith(t, &hookedRepository{
			Repository: harness.repository,
			hooks:      transactionHooks{afterLockSession: barrier.hold},
		}, nil)
		applicationName := "identity_refresh_delete_" + randomRepositoryTestSuffix(t)
		deleteService := harness.additionalService(t, applicationName, transactionHooks{})

		refreshDone := startServiceCall(t, func() (identityservice.RefreshResult, error) {
			return holder.Refresh(ctx, identityservice.RefreshInput{
				RefreshToken: oldRefresh, RequestID: "refresh-delete-refresh",
			})
		})
		awaitTransactionBarrier(t, ctx, barrier, refreshDone)
		deleteDone := startServiceCall(t, func() (identityservice.DeleteMeResult, error) {
			return deleteService.DeleteMe(ctx, identityservice.DeleteMeInput{
				UserID: user.ID, SessionID: session.ID, RequestID: "refresh-delete-delete",
			})
		})
		awaitPostgresLockWait(t, ctx, harness.fixture.DB, applicationName, deleteDone)
		barrier.Release()

		refreshResult := finishServiceCall(t, ctx, "refresh", refreshDone)
		deleteResult := finishServiceCall(t, ctx, "delete", deleteDone)
		if refreshResult.Err != nil {
			t.Fatalf("refresh error = %v", refreshResult.Err)
		}
		if deleteResult.Err != nil || !deleteResult.Value.Deleted {
			t.Fatalf("delete result = %+v, error = %v", deleteResult.Value, deleteResult.Err)
		}

		state := harness.readState(t, user.ID)
		deletedAt := harness.now
		assertUserState(t, state.User, domain.StatusDeleted, nil, &deletedAt, user.DisplayName)
		assertSessionRevoked(t, state, session.ID)
		assertSessionExpiry(t, state, session.ID, session.ExpiresAt)
		assertRefreshHash(t, harness, state, session.ID, refreshResult.Value.RefreshToken)
		if activeSessionCount(state) != 0 {
			t.Fatal("deleted user retained an active session")
		}
		assertAuditCount(t, state, "", 0)
		assertRefreshRejected(t, harness, oldRefresh)
		assertRefreshRejected(t, harness, refreshResult.Value.RefreshToken)
	})

	t.Run("login then ban", func(t *testing.T) {
		harness := newPostgresInvariantHarness(t)
		ctx := harness.raceContext(t)
		admin := harness.createUser(t, "login-ban-admin", domain.RoleAdmin, domain.StatusActive, nil)
		target := harness.createUser(t, "login-ban-target", domain.RoleUser, domain.StatusActive, nil)
		adminSession, _ := harness.createRefreshSession(t, admin.ID)
		barrier := newTransactionBarrier()
		t.Cleanup(barrier.Release)
		defer barrier.Release()
		holder := harness.serviceWith(t, &hookedRepository{
			Repository: harness.repository,
			hooks:      transactionHooks{afterLockUsers: barrier.hold},
		}, nil)
		applicationName := "identity_login_ban_" + randomRepositoryTestSuffix(t)
		adminService := harness.additionalService(t, applicationName, transactionHooks{})

		loginDone := startServiceCall(t, func() (identityservice.LoginResult, error) {
			return holder.Login(ctx, identityservice.LoginInput{
				Email: target.Email, Password: postgresInvariantPassword, RequestID: "login-ban-login",
			})
		})
		awaitTransactionBarrier(t, ctx, barrier, loginDone)
		banDone := startServiceCall(t, func() (domain.UserView, error) {
			return adminService.ChangeUserStatus(ctx, identityservice.ChangeUserStatusInput{
				ActorID: admin.ID, ActorSessionID: adminSession.ID, TargetID: target.ID,
				NewStatus: domain.StatusBanned, Reason: "concurrent login", RequestID: "login-ban-admin",
			})
		})
		awaitPostgresLockWait(t, ctx, harness.fixture.DB, applicationName, banDone)
		barrier.Release()

		loginResult := finishServiceCall(t, ctx, "login", loginDone)
		banResult := finishServiceCall(t, ctx, "ban", banDone)
		if loginResult.Err != nil {
			t.Fatalf("login error = %v", loginResult.Err)
		}
		if banResult.Err != nil || banResult.Value.Status != domain.StatusBanned {
			t.Fatalf("ban result = %+v, error = %v", banResult.Value, banResult.Err)
		}
		loginSessionID := refreshSessionID(t, harness.refresh, loginResult.Value.RefreshToken)

		targetState := harness.readState(t, target.ID)
		assertUserState(t, targetState.User, domain.StatusBanned, nil, nil, target.DisplayName)
		assertSessionRevoked(t, targetState, loginSessionID)
		if activeSessionCount(targetState) != 0 {
			t.Fatal("banned target retained the concurrently created login session")
		}
		assertAuditCount(t, targetState, "user.status_changed", 1)
		adminState := harness.readState(t, admin.ID)
		assertUserState(t, adminState.User, domain.StatusActive, nil, nil, admin.DisplayName)
		assertSessionActive(t, adminState, adminSession.ID)
		assertAuditCount(t, adminState, "", 0)
	})

	t.Run("login then delete", func(t *testing.T) {
		harness := newPostgresInvariantHarness(t)
		ctx := harness.raceContext(t)
		user := harness.createUser(t, "login-delete", domain.RoleUser, domain.StatusActive, nil)
		currentSession, _ := harness.createRefreshSession(t, user.ID)
		barrier := newTransactionBarrier()
		t.Cleanup(barrier.Release)
		defer barrier.Release()
		holder := harness.serviceWith(t, &hookedRepository{
			Repository: harness.repository,
			hooks:      transactionHooks{afterLockUsers: barrier.hold},
		}, nil)
		applicationName := "identity_login_delete_" + randomRepositoryTestSuffix(t)
		deleteService := harness.additionalService(t, applicationName, transactionHooks{})

		loginDone := startServiceCall(t, func() (identityservice.LoginResult, error) {
			return holder.Login(ctx, identityservice.LoginInput{
				Email: user.Email, Password: postgresInvariantPassword, RequestID: "login-delete-login",
			})
		})
		awaitTransactionBarrier(t, ctx, barrier, loginDone)
		deleteDone := startServiceCall(t, func() (identityservice.DeleteMeResult, error) {
			return deleteService.DeleteMe(ctx, identityservice.DeleteMeInput{
				UserID: user.ID, SessionID: currentSession.ID, RequestID: "login-delete-delete",
			})
		})
		awaitPostgresLockWait(t, ctx, harness.fixture.DB, applicationName, deleteDone)
		barrier.Release()

		loginResult := finishServiceCall(t, ctx, "login", loginDone)
		deleteResult := finishServiceCall(t, ctx, "delete", deleteDone)
		if loginResult.Err != nil {
			t.Fatalf("login error = %v", loginResult.Err)
		}
		if deleteResult.Err != nil || !deleteResult.Value.Deleted {
			t.Fatalf("delete result = %+v, error = %v", deleteResult.Value, deleteResult.Err)
		}
		loginSessionID := refreshSessionID(t, harness.refresh, loginResult.Value.RefreshToken)

		state := harness.readState(t, user.ID)
		deletedAt := harness.now
		assertUserState(t, state.User, domain.StatusDeleted, nil, &deletedAt, user.DisplayName)
		assertSessionRevoked(t, state, currentSession.ID)
		assertSessionRevoked(t, state, loginSessionID)
		if activeSessionCount(state) != 0 {
			t.Fatal("deleted user retained a concurrently created login session")
		}
		assertAuditCount(t, state, "", 0)
	})
}

func TestPostgresIdentityMuteRecoveryRaces(t *testing.T) {
	// Do not call t.Parallel: each subtest runs schema-local migrations through goose.
	t.Run("two readers restore one expired mute", func(t *testing.T) {
		harness := newPostgresInvariantHarness(t)
		ctx := harness.raceContext(t)
		mutedUntil := harness.now.Add(-time.Minute)
		user := harness.createUser(t, "mute-readers", domain.RoleUser, domain.StatusMuted, &mutedUntil)
		barrier := newTransactionBarrier()
		t.Cleanup(barrier.Release)
		defer barrier.Release()
		holder := harness.serviceWith(t, &hookedRepository{
			Repository: harness.repository,
			hooks:      transactionHooks{afterLockUsers: barrier.hold},
		}, nil)
		applicationName := "identity_mute_readers_" + randomRepositoryTestSuffix(t)
		contender := harness.additionalService(t, applicationName, transactionHooks{})

		holderDone := startServiceCall(t, func() (domain.PublicUserView, error) {
			return holder.PublicUser(ctx, identityservice.PublicUserInput{
				UserID: user.ID, RequestID: "mute-readers-holder",
			})
		})
		awaitTransactionBarrier(t, ctx, barrier, holderDone)
		contenderDone := startServiceCall(t, func() (domain.PublicUserView, error) {
			return contender.PublicUser(ctx, identityservice.PublicUserInput{
				UserID: user.ID, RequestID: "mute-readers-contender",
			})
		})
		awaitPostgresLockWait(t, ctx, harness.fixture.DB, applicationName, contenderDone)
		barrier.Release()

		holderResult := finishServiceCall(t, ctx, "first mute recovery", holderDone)
		contenderResult := finishServiceCall(t, ctx, "second mute recovery", contenderDone)
		if holderResult.Err != nil || holderResult.Value.Status != domain.StatusActive {
			t.Fatalf("first mute recovery result = %+v, error = %v", holderResult.Value, holderResult.Err)
		}
		if contenderResult.Err != nil || contenderResult.Value.Status != domain.StatusActive {
			t.Fatalf("second mute recovery result = %+v, error = %v", contenderResult.Value, contenderResult.Err)
		}

		state := harness.readState(t, user.ID)
		assertUserState(t, state.User, domain.StatusActive, nil, nil, user.DisplayName)
		if len(state.Sessions) != 0 {
			t.Fatalf("mute reader sessions = %d, want 0", len(state.Sessions))
		}
		assertAuditCount(t, state, "user.mute_expired", 1)
		assertAuditCount(t, state, "", 1)
	})

	t.Run("refresh and reader restore one expired mute", func(t *testing.T) {
		harness := newPostgresInvariantHarness(t)
		ctx := harness.raceContext(t)
		mutedUntil := harness.now.Add(-time.Minute)
		user := harness.createUser(t, "refresh-mute", domain.RoleUser, domain.StatusMuted, &mutedUntil)
		session, oldRefresh := harness.createRefreshSession(t, user.ID)
		barrier := newTransactionBarrier()
		t.Cleanup(barrier.Release)
		defer barrier.Release()
		holder := harness.serviceWith(t, &hookedRepository{
			Repository: harness.repository,
			hooks:      transactionHooks{afterLockUsers: barrier.hold},
		}, nil)
		applicationName := "identity_refresh_mute_" + randomRepositoryTestSuffix(t)
		reader := harness.additionalService(t, applicationName, transactionHooks{})

		refreshDone := startServiceCall(t, func() (identityservice.RefreshResult, error) {
			return holder.Refresh(ctx, identityservice.RefreshInput{
				RefreshToken: oldRefresh, RequestID: "refresh-mute-refresh",
			})
		})
		awaitTransactionBarrier(t, ctx, barrier, refreshDone)
		readerDone := startServiceCall(t, func() (domain.PublicUserView, error) {
			return reader.PublicUser(ctx, identityservice.PublicUserInput{
				UserID: user.ID, RequestID: "refresh-mute-reader",
			})
		})
		awaitPostgresLockWait(t, ctx, harness.fixture.DB, applicationName, readerDone)
		barrier.Release()

		refreshResult := finishServiceCall(t, ctx, "refresh mute recovery", refreshDone)
		readerResult := finishServiceCall(t, ctx, "reader mute recovery", readerDone)
		if refreshResult.Err != nil {
			t.Fatalf("refresh mute recovery error = %v", refreshResult.Err)
		}
		if readerResult.Err != nil || readerResult.Value.Status != domain.StatusActive {
			t.Fatalf("reader mute recovery result = %+v, error = %v", readerResult.Value, readerResult.Err)
		}

		state := harness.readState(t, user.ID)
		assertUserState(t, state.User, domain.StatusActive, nil, nil, user.DisplayName)
		assertSessionActive(t, state, session.ID)
		assertSessionExpiry(t, state, session.ID, session.ExpiresAt)
		assertRefreshHash(t, harness, state, session.ID, refreshResult.Value.RefreshToken)
		assertAuditCount(t, state, "user.mute_expired", 1)
		assertAuditCount(t, state, "", 1)
		assertRefreshRejected(t, harness, oldRefresh)
	})

	t.Run("login and reader restore one expired mute", func(t *testing.T) {
		harness := newPostgresInvariantHarness(t)
		ctx := harness.raceContext(t)
		mutedUntil := harness.now.Add(-time.Minute)
		user := harness.createUser(t, "login-mute", domain.RoleUser, domain.StatusMuted, &mutedUntil)
		barrier := newTransactionBarrier()
		t.Cleanup(barrier.Release)
		defer barrier.Release()
		holder := harness.serviceWith(t, &hookedRepository{
			Repository: harness.repository,
			hooks:      transactionHooks{afterLockUsers: barrier.hold},
		}, nil)
		applicationName := "identity_login_mute_" + randomRepositoryTestSuffix(t)
		reader := harness.additionalService(t, applicationName, transactionHooks{})

		loginDone := startServiceCall(t, func() (identityservice.LoginResult, error) {
			return holder.Login(ctx, identityservice.LoginInput{
				Email: user.Email, Password: postgresInvariantPassword, RequestID: "login-mute-login",
			})
		})
		awaitTransactionBarrier(t, ctx, barrier, loginDone)
		readerDone := startServiceCall(t, func() (domain.PublicUserView, error) {
			return reader.PublicUser(ctx, identityservice.PublicUserInput{
				UserID: user.ID, RequestID: "login-mute-reader",
			})
		})
		awaitPostgresLockWait(t, ctx, harness.fixture.DB, applicationName, readerDone)
		barrier.Release()

		loginResult := finishServiceCall(t, ctx, "login mute recovery", loginDone)
		readerResult := finishServiceCall(t, ctx, "reader mute recovery", readerDone)
		if loginResult.Err != nil || loginResult.Value.User.Status != domain.StatusActive {
			t.Fatalf("login mute recovery result = %+v, error = %v", loginResult.Value, loginResult.Err)
		}
		if readerResult.Err != nil || readerResult.Value.Status != domain.StatusActive {
			t.Fatalf("reader mute recovery result = %+v, error = %v", readerResult.Value, readerResult.Err)
		}
		loginSessionID := refreshSessionID(t, harness.refresh, loginResult.Value.RefreshToken)

		state := harness.readState(t, user.ID)
		assertUserState(t, state.User, domain.StatusActive, nil, nil, user.DisplayName)
		assertSessionActive(t, state, loginSessionID)
		if activeSessionCount(state) != 1 {
			t.Fatalf("active login sessions = %d, want 1", activeSessionCount(state))
		}
		assertAuditCount(t, state, "user.mute_expired", 1)
		assertAuditCount(t, state, "", 1)
	})
}

func TestPostgresIdentityProfileSessionRaces(t *testing.T) {
	// Do not call t.Parallel: each subtest runs schema-local migrations through goose.
	t.Run("UpdateMe then refresh", func(t *testing.T) {
		harness := newPostgresInvariantHarness(t)
		ctx := harness.raceContext(t)
		user := harness.createUser(t, "update-refresh", domain.RoleUser, domain.StatusActive, nil)
		session, oldRefresh := harness.createRefreshSession(t, user.ID)
		const updatedName = "Updated before refresh"
		barrier := newTransactionBarrier()
		t.Cleanup(barrier.Release)
		defer barrier.Release()
		holder := harness.serviceWith(t, &hookedRepository{
			Repository: harness.repository,
			hooks:      transactionHooks{afterLockSession: barrier.hold},
		}, nil)
		applicationName := "identity_update_refresh_" + randomRepositoryTestSuffix(t)
		refreshService := harness.additionalService(t, applicationName, transactionHooks{})

		updateDone := startServiceCall(t, func() (domain.UserView, error) {
			return holder.UpdateMe(ctx, identityservice.UpdateMeInput{
				UserID: user.ID, SessionID: session.ID, RequestID: "update-refresh-update",
				DisplayName: identityservice.SetField(updatedName),
			})
		})
		awaitTransactionBarrier(t, ctx, barrier, updateDone)
		refreshDone := startServiceCall(t, func() (identityservice.RefreshResult, error) {
			return refreshService.Refresh(ctx, identityservice.RefreshInput{
				RefreshToken: oldRefresh, RequestID: "update-refresh-refresh",
			})
		})
		awaitPostgresLockWait(t, ctx, harness.fixture.DB, applicationName, refreshDone)
		barrier.Release()

		updateResult := finishServiceCall(t, ctx, "profile update", updateDone)
		refreshResult := finishServiceCall(t, ctx, "refresh after update", refreshDone)
		if updateResult.Err != nil || updateResult.Value.DisplayName != updatedName {
			t.Fatalf("profile update result = %+v, error = %v", updateResult.Value, updateResult.Err)
		}
		if refreshResult.Err != nil {
			t.Fatalf("refresh after update error = %v", refreshResult.Err)
		}

		state := harness.readState(t, user.ID)
		assertUserState(t, state.User, domain.StatusActive, nil, nil, updatedName)
		assertSessionActive(t, state, session.ID)
		assertSessionExpiry(t, state, session.ID, session.ExpiresAt)
		assertRefreshHash(t, harness, state, session.ID, refreshResult.Value.RefreshToken)
		assertAuditCount(t, state, "", 0)
		assertRefreshRejected(t, harness, oldRefresh)
	})

	t.Run("DeleteMe then refresh", func(t *testing.T) {
		harness := newPostgresInvariantHarness(t)
		ctx := harness.raceContext(t)
		user := harness.createUser(t, "delete-refresh", domain.RoleUser, domain.StatusActive, nil)
		session, oldRefresh := harness.createRefreshSession(t, user.ID)
		barrier := newTransactionBarrier()
		t.Cleanup(barrier.Release)
		defer barrier.Release()
		holder := harness.serviceWith(t, &hookedRepository{
			Repository: harness.repository,
			hooks:      transactionHooks{afterLockActiveSessions: barrier.hold},
		}, nil)
		applicationName := "identity_delete_refresh_" + randomRepositoryTestSuffix(t)
		refreshService := harness.additionalService(t, applicationName, transactionHooks{})

		deleteDone := startServiceCall(t, func() (identityservice.DeleteMeResult, error) {
			return holder.DeleteMe(ctx, identityservice.DeleteMeInput{
				UserID: user.ID, SessionID: session.ID, RequestID: "delete-refresh-delete",
			})
		})
		awaitTransactionBarrier(t, ctx, barrier, deleteDone)
		refreshDone := startServiceCall(t, func() (identityservice.RefreshResult, error) {
			return refreshService.Refresh(ctx, identityservice.RefreshInput{
				RefreshToken: oldRefresh, RequestID: "delete-refresh-refresh",
			})
		})
		awaitPostgresLockWait(t, ctx, harness.fixture.DB, applicationName, refreshDone)
		barrier.Release()

		deleteResult := finishServiceCall(t, ctx, "delete before refresh", deleteDone)
		refreshResult := finishServiceCall(t, ctx, "refresh after delete", refreshDone)
		if deleteResult.Err != nil || !deleteResult.Value.Deleted {
			t.Fatalf("delete result = %+v, error = %v", deleteResult.Value, deleteResult.Err)
		}
		assertIdentityError(t, refreshResult.Err, identityservice.ErrInvalidRefreshToken)

		state := harness.readState(t, user.ID)
		deletedAt := harness.now
		assertUserState(t, state.User, domain.StatusDeleted, nil, &deletedAt, user.DisplayName)
		assertSessionRevoked(t, state, session.ID)
		assertSessionHash(t, state, session.ID, session.TokenHash)
		assertSessionExpiry(t, state, session.ID, session.ExpiresAt)
		if activeSessionCount(state) != 0 {
			t.Fatal("deleted user retained an active session")
		}
		assertAuditCount(t, state, "", 0)
		assertRefreshRejected(t, harness, oldRefresh)
	})

	t.Run("UpdateMe then logout", func(t *testing.T) {
		harness := newPostgresInvariantHarness(t)
		ctx := harness.raceContext(t)
		user := harness.createUser(t, "update-logout", domain.RoleUser, domain.StatusActive, nil)
		session, oldRefresh := harness.createRefreshSession(t, user.ID)
		const updatedName = "Updated before logout"
		barrier := newTransactionBarrier()
		t.Cleanup(barrier.Release)
		defer barrier.Release()
		holder := harness.serviceWith(t, &hookedRepository{
			Repository: harness.repository,
			hooks:      transactionHooks{afterLockSession: barrier.hold},
		}, nil)
		applicationName := "identity_update_logout_" + randomRepositoryTestSuffix(t)
		logoutService := harness.additionalService(t, applicationName, transactionHooks{})

		updateDone := startServiceCall(t, func() (domain.UserView, error) {
			return holder.UpdateMe(ctx, identityservice.UpdateMeInput{
				UserID: user.ID, SessionID: session.ID, RequestID: "update-logout-update",
				DisplayName: identityservice.SetField(updatedName),
			})
		})
		awaitTransactionBarrier(t, ctx, barrier, updateDone)
		logoutDone := startServiceCall(t, func() (identityservice.LogoutResult, error) {
			return logoutService.Logout(ctx, identityservice.LogoutInput{
				UserID: user.ID, SessionID: session.ID,
			})
		})
		awaitPostgresLockWait(t, ctx, harness.fixture.DB, applicationName, logoutDone)
		barrier.Release()

		updateResult := finishServiceCall(t, ctx, "profile update", updateDone)
		logoutResult := finishServiceCall(t, ctx, "logout after update", logoutDone)
		if updateResult.Err != nil || updateResult.Value.DisplayName != updatedName {
			t.Fatalf("profile update result = %+v, error = %v", updateResult.Value, updateResult.Err)
		}
		if logoutResult.Err != nil || !logoutResult.Value.LoggedOut {
			t.Fatalf("logout result = %+v, error = %v", logoutResult.Value, logoutResult.Err)
		}

		state := harness.readState(t, user.ID)
		assertUserState(t, state.User, domain.StatusActive, nil, nil, updatedName)
		assertSessionRevoked(t, state, session.ID)
		assertAuditCount(t, state, "", 0)
		assertRefreshRejected(t, harness, oldRefresh)
	})

	t.Run("DeleteMe then logout", func(t *testing.T) {
		harness := newPostgresInvariantHarness(t)
		ctx := harness.raceContext(t)
		user := harness.createUser(t, "delete-logout", domain.RoleUser, domain.StatusActive, nil)
		session, oldRefresh := harness.createRefreshSession(t, user.ID)
		barrier := newTransactionBarrier()
		t.Cleanup(barrier.Release)
		defer barrier.Release()
		holder := harness.serviceWith(t, &hookedRepository{
			Repository: harness.repository,
			hooks:      transactionHooks{afterLockActiveSessions: barrier.hold},
		}, nil)
		applicationName := "identity_delete_logout_" + randomRepositoryTestSuffix(t)
		logoutService := harness.additionalService(t, applicationName, transactionHooks{})

		deleteDone := startServiceCall(t, func() (identityservice.DeleteMeResult, error) {
			return holder.DeleteMe(ctx, identityservice.DeleteMeInput{
				UserID: user.ID, SessionID: session.ID, RequestID: "delete-logout-delete",
			})
		})
		awaitTransactionBarrier(t, ctx, barrier, deleteDone)
		logoutDone := startServiceCall(t, func() (identityservice.LogoutResult, error) {
			return logoutService.Logout(ctx, identityservice.LogoutInput{
				UserID: user.ID, SessionID: session.ID,
			})
		})
		awaitPostgresLockWait(t, ctx, harness.fixture.DB, applicationName, logoutDone)
		barrier.Release()

		deleteResult := finishServiceCall(t, ctx, "delete before logout", deleteDone)
		logoutResult := finishServiceCall(t, ctx, "logout after delete", logoutDone)
		if deleteResult.Err != nil || !deleteResult.Value.Deleted {
			t.Fatalf("delete result = %+v, error = %v", deleteResult.Value, deleteResult.Err)
		}
		if logoutResult.Err != nil || !logoutResult.Value.LoggedOut {
			t.Fatalf("logout result = %+v, error = %v", logoutResult.Value, logoutResult.Err)
		}

		state := harness.readState(t, user.ID)
		deletedAt := harness.now
		assertUserState(t, state.User, domain.StatusDeleted, nil, &deletedAt, user.DisplayName)
		assertSessionRevoked(t, state, session.ID)
		if activeSessionCount(state) != 0 {
			t.Fatal("deleted user retained an active session")
		}
		assertAuditCount(t, state, "", 0)
		assertRefreshRejected(t, harness, oldRefresh)
	})
}

func TestPostgresIdentityLogoutFirstRaces(t *testing.T) {
	// Logout is one autocommitted conditional UPDATE. The post-delegate gate
	// holds the service call open only after PostgreSQL has committed the revoke.
	t.Run("logout then refresh", func(t *testing.T) {
		harness := newPostgresInvariantHarness(t)
		ctx := harness.raceContext(t)
		user := harness.createUser(t, "logout-refresh", domain.RoleUser, domain.StatusActive, nil)
		session, oldRefresh := harness.createRefreshSession(t, user.ID)
		barrier := newTransactionBarrier()
		t.Cleanup(barrier.Release)
		defer barrier.Release()
		logoutService := harness.serviceWith(t, &hookedRepository{
			Repository: harness.repository,
			hooks:      transactionHooks{afterRevokeSession: barrier.hold},
		}, nil)
		refreshService := harness.additionalService(t, "identity_logout_refresh_"+randomRepositoryTestSuffix(t), transactionHooks{})

		logoutDone := startServiceCall(t, func() (identityservice.LogoutResult, error) {
			return logoutService.Logout(ctx, identityservice.LogoutInput{
				UserID: user.ID, SessionID: session.ID,
			})
		})
		awaitTransactionBarrier(t, ctx, barrier, logoutDone)
		refreshDone := startServiceCall(t, func() (identityservice.RefreshResult, error) {
			return refreshService.Refresh(ctx, identityservice.RefreshInput{
				RefreshToken: oldRefresh, RequestID: "logout-refresh-refresh",
			})
		})
		refreshResult := finishServiceCall(t, ctx, "refresh after committed logout update", refreshDone)
		barrier.Release()
		logoutResult := finishServiceCall(t, ctx, "logout", logoutDone)
		if logoutResult.Err != nil || !logoutResult.Value.LoggedOut {
			t.Fatalf("logout result = %+v, error = %v", logoutResult.Value, logoutResult.Err)
		}
		assertIdentityError(t, refreshResult.Err, identityservice.ErrInvalidRefreshToken)

		state := harness.readState(t, user.ID)
		assertUserState(t, state.User, domain.StatusActive, nil, nil, user.DisplayName)
		assertSessionRevoked(t, state, session.ID)
		assertPersistedSessionUnchangedExceptRevocation(t, state, session)
		assertAuditCount(t, state, "", 0)
		assertRefreshRejected(t, harness, oldRefresh)
	})

	t.Run("logout then UpdateMe", func(t *testing.T) {
		harness := newPostgresInvariantHarness(t)
		ctx := harness.raceContext(t)
		user := harness.createUser(t, "logout-update", domain.RoleUser, domain.StatusActive, nil)
		session, _ := harness.createRefreshSession(t, user.ID)
		barrier := newTransactionBarrier()
		t.Cleanup(barrier.Release)
		defer barrier.Release()
		logoutService := harness.serviceWith(t, &hookedRepository{
			Repository: harness.repository,
			hooks:      transactionHooks{afterRevokeSession: barrier.hold},
		}, nil)
		updateService := harness.additionalService(t, "identity_logout_update_"+randomRepositoryTestSuffix(t), transactionHooks{})

		logoutDone := startServiceCall(t, func() (identityservice.LogoutResult, error) {
			return logoutService.Logout(ctx, identityservice.LogoutInput{
				UserID: user.ID, SessionID: session.ID,
			})
		})
		awaitTransactionBarrier(t, ctx, barrier, logoutDone)
		updateDone := startServiceCall(t, func() (domain.UserView, error) {
			return updateService.UpdateMe(ctx, identityservice.UpdateMeInput{
				UserID: user.ID, SessionID: session.ID, RequestID: "logout-update-update",
				DisplayName: identityservice.SetField("Must not be persisted"),
			})
		})
		updateResult := finishServiceCall(t, ctx, "profile update after committed logout update", updateDone)
		barrier.Release()
		logoutResult := finishServiceCall(t, ctx, "logout", logoutDone)
		if logoutResult.Err != nil || !logoutResult.Value.LoggedOut {
			t.Fatalf("logout result = %+v, error = %v", logoutResult.Value, logoutResult.Err)
		}
		assertIdentityError(t, updateResult.Err, identityservice.ErrSessionInvalid)

		state := harness.readState(t, user.ID)
		assertPersistedUserUnchanged(t, state.User, user)
		assertSessionRevoked(t, state, session.ID)
		assertPersistedSessionUnchangedExceptRevocation(t, state, session)
		assertAuditCount(t, state, "", 0)
	})

	t.Run("logout then DeleteMe", func(t *testing.T) {
		harness := newPostgresInvariantHarness(t)
		ctx := harness.raceContext(t)
		user := harness.createUser(t, "logout-delete", domain.RoleUser, domain.StatusActive, nil)
		session, _ := harness.createRefreshSession(t, user.ID)
		barrier := newTransactionBarrier()
		t.Cleanup(barrier.Release)
		defer barrier.Release()
		logoutService := harness.serviceWith(t, &hookedRepository{
			Repository: harness.repository,
			hooks:      transactionHooks{afterRevokeSession: barrier.hold},
		}, nil)
		deleteService := harness.additionalService(t, "identity_logout_delete_"+randomRepositoryTestSuffix(t), transactionHooks{})

		logoutDone := startServiceCall(t, func() (identityservice.LogoutResult, error) {
			return logoutService.Logout(ctx, identityservice.LogoutInput{
				UserID: user.ID, SessionID: session.ID,
			})
		})
		awaitTransactionBarrier(t, ctx, barrier, logoutDone)
		deleteDone := startServiceCall(t, func() (identityservice.DeleteMeResult, error) {
			return deleteService.DeleteMe(ctx, identityservice.DeleteMeInput{
				UserID: user.ID, SessionID: session.ID, RequestID: "logout-delete-delete",
			})
		})
		deleteResult := finishServiceCall(t, ctx, "delete after committed logout update", deleteDone)
		barrier.Release()
		logoutResult := finishServiceCall(t, ctx, "logout", logoutDone)
		if logoutResult.Err != nil || !logoutResult.Value.LoggedOut {
			t.Fatalf("logout result = %+v, error = %v", logoutResult.Value, logoutResult.Err)
		}
		assertIdentityError(t, deleteResult.Err, identityservice.ErrSessionInvalid)

		state := harness.readState(t, user.ID)
		assertPersistedUserUnchanged(t, state.User, user)
		assertSessionRevoked(t, state, session.ID)
		assertPersistedSessionUnchangedExceptRevocation(t, state, session)
		assertAuditCount(t, state, "", 0)
	})
}

func TestPostgresIdentityTerminalStatusWinsAuthenticationRaces(t *testing.T) {
	// Do not call t.Parallel: each subtest runs schema-local migrations through goose.
	t.Run("ban then refresh revalidates locked user", func(t *testing.T) {
		harness := newPostgresInvariantHarness(t)
		ctx := harness.raceContext(t)
		admin := harness.createUser(t, "ban-refresh-admin", domain.RoleAdmin, domain.StatusActive, nil)
		target := harness.createUser(t, "ban-refresh-target", domain.RoleUser, domain.StatusActive, nil)
		adminSession, _ := harness.createRefreshSession(t, admin.ID)
		targetSession, oldRefresh := harness.createRefreshSession(t, target.ID)
		barrier := newTransactionBarrier()
		t.Cleanup(barrier.Release)
		defer barrier.Release()
		holder := harness.serviceWith(t, &hookedRepository{
			Repository: harness.repository,
			hooks:      transactionHooks{afterLockUsers: barrier.hold},
		}, nil)
		applicationName := "identity_ban_refresh_" + randomRepositoryTestSuffix(t)
		refreshService := harness.additionalService(t, applicationName, transactionHooks{})

		banDone := startServiceCall(t, func() (domain.UserView, error) {
			return holder.ChangeUserStatus(ctx, identityservice.ChangeUserStatusInput{
				ActorID: admin.ID, ActorSessionID: adminSession.ID, TargetID: target.ID,
				NewStatus: domain.StatusBanned, Reason: "terminal first", RequestID: "ban-refresh-ban",
			})
		})
		awaitTransactionBarrier(t, ctx, barrier, banDone)
		refreshDone := startServiceCall(t, func() (identityservice.RefreshResult, error) {
			return refreshService.Refresh(ctx, identityservice.RefreshInput{
				RefreshToken: oldRefresh, RequestID: "ban-refresh-refresh",
			})
		})
		awaitPostgresLockWait(t, ctx, harness.fixture.DB, applicationName, refreshDone)
		barrier.Release()

		banResult := finishServiceCall(t, ctx, "ban before refresh", banDone)
		refreshResult := finishServiceCall(t, ctx, "refresh after ban", refreshDone)
		if banResult.Err != nil || banResult.Value.Status != domain.StatusBanned {
			t.Fatalf("ban result = %+v, error = %v", banResult.Value, banResult.Err)
		}
		assertIdentityError(t, refreshResult.Err, identityservice.ErrInvalidRefreshToken)

		targetState := harness.readState(t, target.ID)
		assertUserState(t, targetState.User, domain.StatusBanned, nil, nil, target.DisplayName)
		assertPersistedSessionUnchangedExceptRevocation(t, targetState, targetSession)
		if activeSessionCount(targetState) != 0 {
			t.Fatal("banned user retained an active session")
		}
		assertAuditCount(t, targetState, "user.status_changed", 1)
		adminState := harness.readState(t, admin.ID)
		assertUserState(t, adminState.User, domain.StatusActive, nil, nil, admin.DisplayName)
		assertSessionActive(t, adminState, adminSession.ID)
		assertAuditCount(t, adminState, "", 0)
		assertRefreshRejected(t, harness, oldRefresh)
	})

	t.Run("delete then refresh revalidates locked user", func(t *testing.T) {
		harness := newPostgresInvariantHarness(t)
		ctx := harness.raceContext(t)
		user := harness.createUser(t, "delete-refresh-revalidate", domain.RoleUser, domain.StatusActive, nil)
		session, oldRefresh := harness.createRefreshSession(t, user.ID)
		barrier := newTransactionBarrier()
		t.Cleanup(barrier.Release)
		defer barrier.Release()
		holder := harness.serviceWith(t, &hookedRepository{
			Repository: harness.repository,
			hooks:      transactionHooks{afterLockUsers: barrier.hold},
		}, nil)
		applicationName := "identity_delete_refresh_revalidate_" + randomRepositoryTestSuffix(t)
		refreshService := harness.additionalService(t, applicationName, transactionHooks{})

		deleteDone := startServiceCall(t, func() (identityservice.DeleteMeResult, error) {
			return holder.DeleteMe(ctx, identityservice.DeleteMeInput{
				UserID: user.ID, SessionID: session.ID, RequestID: "delete-refresh-delete",
			})
		})
		awaitTransactionBarrier(t, ctx, barrier, deleteDone)
		refreshDone := startServiceCall(t, func() (identityservice.RefreshResult, error) {
			return refreshService.Refresh(ctx, identityservice.RefreshInput{
				RefreshToken: oldRefresh, RequestID: "delete-refresh-refresh",
			})
		})
		awaitPostgresLockWait(t, ctx, harness.fixture.DB, applicationName, refreshDone)
		barrier.Release()

		deleteResult := finishServiceCall(t, ctx, "delete before refresh", deleteDone)
		refreshResult := finishServiceCall(t, ctx, "refresh after delete", refreshDone)
		if deleteResult.Err != nil || !deleteResult.Value.Deleted {
			t.Fatalf("delete result = %+v, error = %v", deleteResult.Value, deleteResult.Err)
		}
		assertIdentityError(t, refreshResult.Err, identityservice.ErrInvalidRefreshToken)

		state := harness.readState(t, user.ID)
		deletedAt := harness.now
		assertUserState(t, state.User, domain.StatusDeleted, nil, &deletedAt, user.DisplayName)
		assertPersistedSessionUnchangedExceptRevocation(t, state, session)
		if activeSessionCount(state) != 0 {
			t.Fatal("deleted user retained an active session")
		}
		assertAuditCount(t, state, "", 0)
		assertRefreshRejected(t, harness, oldRefresh)
	})

	t.Run("ban then login revalidates locked user", func(t *testing.T) {
		harness := newPostgresInvariantHarness(t)
		ctx := harness.raceContext(t)
		admin := harness.createUser(t, "ban-login-admin", domain.RoleAdmin, domain.StatusActive, nil)
		target := harness.createUser(t, "ban-login-target", domain.RoleUser, domain.StatusActive, nil)
		adminSession, _ := harness.createRefreshSession(t, admin.ID)
		barrier := newTransactionBarrier()
		t.Cleanup(barrier.Release)
		defer barrier.Release()
		holder := harness.serviceWith(t, &hookedRepository{
			Repository: harness.repository,
			hooks:      transactionHooks{afterLockUsers: barrier.hold},
		}, nil)
		applicationName := "identity_ban_login_" + randomRepositoryTestSuffix(t)
		loginService := harness.additionalService(t, applicationName, transactionHooks{})

		banDone := startServiceCall(t, func() (domain.UserView, error) {
			return holder.ChangeUserStatus(ctx, identityservice.ChangeUserStatusInput{
				ActorID: admin.ID, ActorSessionID: adminSession.ID, TargetID: target.ID,
				NewStatus: domain.StatusBanned, Reason: "terminal first", RequestID: "ban-login-ban",
			})
		})
		awaitTransactionBarrier(t, ctx, barrier, banDone)
		loginDone := startServiceCall(t, func() (identityservice.LoginResult, error) {
			return loginService.Login(ctx, identityservice.LoginInput{
				Email: target.Email, Password: postgresInvariantPassword, RequestID: "ban-login-login",
			})
		})
		awaitPostgresLockWait(t, ctx, harness.fixture.DB, applicationName, loginDone)
		barrier.Release()

		banResult := finishServiceCall(t, ctx, "ban before login", banDone)
		loginResult := finishServiceCall(t, ctx, "login after ban", loginDone)
		if banResult.Err != nil || banResult.Value.Status != domain.StatusBanned {
			t.Fatalf("ban result = %+v, error = %v", banResult.Value, banResult.Err)
		}
		assertIdentityError(t, loginResult.Err, identityservice.ErrInvalidCredentials)

		targetState := harness.readState(t, target.ID)
		assertUserState(t, targetState.User, domain.StatusBanned, nil, nil, target.DisplayName)
		if len(targetState.Sessions) != 0 {
			t.Fatalf("banned target sessions = %d, want 0", len(targetState.Sessions))
		}
		assertAuditCount(t, targetState, "user.status_changed", 1)
		adminState := harness.readState(t, admin.ID)
		assertUserState(t, adminState.User, domain.StatusActive, nil, nil, admin.DisplayName)
		assertSessionActive(t, adminState, adminSession.ID)
		assertAuditCount(t, adminState, "", 0)
	})

	t.Run("delete then login revalidates locked user", func(t *testing.T) {
		harness := newPostgresInvariantHarness(t)
		ctx := harness.raceContext(t)
		user := harness.createUser(t, "delete-login-revalidate", domain.RoleUser, domain.StatusActive, nil)
		session, _ := harness.createRefreshSession(t, user.ID)
		barrier := newTransactionBarrier()
		t.Cleanup(barrier.Release)
		defer barrier.Release()
		holder := harness.serviceWith(t, &hookedRepository{
			Repository: harness.repository,
			hooks:      transactionHooks{afterLockUsers: barrier.hold},
		}, nil)
		applicationName := "identity_delete_login_" + randomRepositoryTestSuffix(t)
		loginService := harness.additionalService(t, applicationName, transactionHooks{})

		deleteDone := startServiceCall(t, func() (identityservice.DeleteMeResult, error) {
			return holder.DeleteMe(ctx, identityservice.DeleteMeInput{
				UserID: user.ID, SessionID: session.ID, RequestID: "delete-login-delete",
			})
		})
		awaitTransactionBarrier(t, ctx, barrier, deleteDone)
		loginDone := startServiceCall(t, func() (identityservice.LoginResult, error) {
			return loginService.Login(ctx, identityservice.LoginInput{
				Email: user.Email, Password: postgresInvariantPassword, RequestID: "delete-login-login",
			})
		})
		awaitPostgresLockWait(t, ctx, harness.fixture.DB, applicationName, loginDone)
		barrier.Release()

		deleteResult := finishServiceCall(t, ctx, "delete before login", deleteDone)
		loginResult := finishServiceCall(t, ctx, "login after delete", loginDone)
		if deleteResult.Err != nil || !deleteResult.Value.Deleted {
			t.Fatalf("delete result = %+v, error = %v", deleteResult.Value, deleteResult.Err)
		}
		assertIdentityError(t, loginResult.Err, identityservice.ErrInvalidCredentials)

		state := harness.readState(t, user.ID)
		deletedAt := harness.now
		assertUserState(t, state.User, domain.StatusDeleted, nil, &deletedAt, user.DisplayName)
		assertSessionRevoked(t, state, session.ID)
		if activeSessionCount(state) != 0 {
			t.Fatal("deleted user retained an active session")
		}
		assertAuditCount(t, state, "", 0)
	})
}

func TestPostgresIdentityAdminRaces(t *testing.T) {
	// Do not call t.Parallel: each subtest runs schema-local migrations through goose.
	t.Run("two admins serialize changes to one ordinary user", func(t *testing.T) {
		harness := newPostgresInvariantHarness(t)
		ctx := harness.raceContext(t)
		firstAdmin := harness.createUser(t, "same-target-admin-a", domain.RoleAdmin, domain.StatusActive, nil)
		secondAdmin := harness.createUser(t, "same-target-admin-b", domain.RoleAdmin, domain.StatusActive, nil)
		target := harness.createUser(t, "same-target-user", domain.RoleUser, domain.StatusActive, nil)
		firstSession, _ := harness.createRefreshSession(t, firstAdmin.ID)
		secondSession, _ := harness.createRefreshSession(t, secondAdmin.ID)
		targetSession, _ := harness.createRefreshSession(t, target.ID)
		mutedUntil := harness.now.Add(time.Hour)
		barrier := newTransactionBarrier()
		t.Cleanup(barrier.Release)
		defer barrier.Release()
		firstService := harness.serviceWith(t, &hookedRepository{
			Repository: harness.repository,
			hooks:      transactionHooks{afterLockUsers: barrier.hold},
		}, nil)
		applicationName := "identity_admin_same_target_" + randomRepositoryTestSuffix(t)
		secondService := harness.additionalService(t, applicationName, transactionHooks{})

		firstDone := startServiceCall(t, func() (domain.UserView, error) {
			return firstService.ChangeUserStatus(ctx, identityservice.ChangeUserStatusInput{
				ActorID: firstAdmin.ID, ActorSessionID: firstSession.ID, TargetID: target.ID,
				NewStatus: domain.StatusMuted, MutedUntil: &mutedUntil,
				Reason: "first admin", RequestID: "same-target-first",
			})
		})
		awaitTransactionBarrier(t, ctx, barrier, firstDone)
		secondDone := startServiceCall(t, func() (domain.UserView, error) {
			return secondService.ChangeUserStatus(ctx, identityservice.ChangeUserStatusInput{
				ActorID: secondAdmin.ID, ActorSessionID: secondSession.ID, TargetID: target.ID,
				NewStatus: domain.StatusFrozen, Reason: "second admin", RequestID: "same-target-second",
			})
		})
		awaitPostgresLockWait(t, ctx, harness.fixture.DB, applicationName, secondDone)
		barrier.Release()

		firstResult := finishServiceCall(t, ctx, "first admin change", firstDone)
		secondResult := finishServiceCall(t, ctx, "second admin change", secondDone)
		if firstResult.Err != nil || firstResult.Value.Status != domain.StatusMuted {
			t.Fatalf("first admin result = %+v, error = %v", firstResult.Value, firstResult.Err)
		}
		if secondResult.Err != nil || secondResult.Value.Status != domain.StatusFrozen {
			t.Fatalf("second admin result = %+v, error = %v", secondResult.Value, secondResult.Err)
		}

		targetState := harness.readState(t, target.ID)
		assertUserState(t, targetState.User, domain.StatusFrozen, nil, nil, target.DisplayName)
		assertSessionActive(t, targetState, targetSession.ID)
		assertAuditCount(t, targetState, "user.status_changed", 2)
		assertStatusAuditTransition(t, targetState.Audits[0], domain.StatusActive, domain.StatusMuted, "same-target-first")
		assertStatusAuditTransition(t, targetState.Audits[1], domain.StatusMuted, domain.StatusFrozen, "same-target-second")
		firstAdminState := harness.readState(t, firstAdmin.ID)
		assertUserState(t, firstAdminState.User, domain.StatusActive, nil, nil, firstAdmin.DisplayName)
		assertSessionActive(t, firstAdminState, firstSession.ID)
		assertAuditCount(t, firstAdminState, "", 0)
		secondAdminState := harness.readState(t, secondAdmin.ID)
		assertUserState(t, secondAdminState.User, domain.StatusActive, nil, nil, secondAdmin.DisplayName)
		assertSessionActive(t, secondAdminState, secondSession.ID)
		assertAuditCount(t, secondAdminState, "", 0)
	})

	t.Run("admin action commits before actor deletes self", func(t *testing.T) {
		harness := newPostgresInvariantHarness(t)
		ctx := harness.raceContext(t)
		admin := harness.createUser(t, "action-delete-admin", domain.RoleAdmin, domain.StatusActive, nil)
		target := harness.createUser(t, "action-delete-target", domain.RoleUser, domain.StatusActive, nil)
		adminSession, _ := harness.createRefreshSession(t, admin.ID)
		targetSession, _ := harness.createRefreshSession(t, target.ID)
		barrier := newTransactionBarrier()
		t.Cleanup(barrier.Release)
		defer barrier.Release()
		actionService := harness.serviceWith(t, &hookedRepository{
			Repository: harness.repository,
			hooks:      transactionHooks{afterLockUsers: barrier.hold},
		}, nil)
		applicationName := "identity_action_actor_delete_" + randomRepositoryTestSuffix(t)
		deleteService := harness.additionalService(t, applicationName, transactionHooks{})

		actionDone := startServiceCall(t, func() (domain.UserView, error) {
			return actionService.ChangeUserStatus(ctx, identityservice.ChangeUserStatusInput{
				ActorID: admin.ID, ActorSessionID: adminSession.ID, TargetID: target.ID,
				NewStatus: domain.StatusBanned, Reason: "action first", RequestID: "action-delete-action",
			})
		})
		awaitTransactionBarrier(t, ctx, barrier, actionDone)
		deleteDone := startServiceCall(t, func() (identityservice.DeleteMeResult, error) {
			return deleteService.DeleteMe(ctx, identityservice.DeleteMeInput{
				UserID: admin.ID, SessionID: adminSession.ID, RequestID: "action-delete-self-delete",
			})
		})
		awaitPostgresLockWait(t, ctx, harness.fixture.DB, applicationName, deleteDone)
		barrier.Release()

		actionResult := finishServiceCall(t, ctx, "admin action", actionDone)
		deleteResult := finishServiceCall(t, ctx, "actor self deletion", deleteDone)
		if actionResult.Err != nil || actionResult.Value.Status != domain.StatusBanned {
			t.Fatalf("admin action result = %+v, error = %v", actionResult.Value, actionResult.Err)
		}
		if deleteResult.Err != nil || !deleteResult.Value.Deleted {
			t.Fatalf("actor deletion result = %+v, error = %v", deleteResult.Value, deleteResult.Err)
		}

		targetState := harness.readState(t, target.ID)
		assertUserState(t, targetState.User, domain.StatusBanned, nil, nil, target.DisplayName)
		assertSessionRevoked(t, targetState, targetSession.ID)
		if activeSessionCount(targetState) != 0 {
			t.Fatal("banned target retained an active session")
		}
		assertAuditCount(t, targetState, "user.status_changed", 1)
		adminState := harness.readState(t, admin.ID)
		deletedAt := harness.now
		assertUserState(t, adminState.User, domain.StatusDeleted, nil, &deletedAt, admin.DisplayName)
		assertSessionRevoked(t, adminState, adminSession.ID)
		if activeSessionCount(adminState) != 0 {
			t.Fatal("deleted admin retained an active session")
		}
		assertAuditCount(t, adminState, "", 0)
	})

	t.Run("actor deletes self before admin action revalidation", func(t *testing.T) {
		harness := newPostgresInvariantHarness(t)
		ctx := harness.raceContext(t)
		admin := harness.createUser(t, "delete-action-admin", domain.RoleAdmin, domain.StatusActive, nil)
		target := harness.createUser(t, "delete-action-target", domain.RoleUser, domain.StatusActive, nil)
		adminSession, _ := harness.createRefreshSession(t, admin.ID)
		targetSession, _ := harness.createRefreshSession(t, target.ID)
		barrier := newTransactionBarrier()
		t.Cleanup(barrier.Release)
		defer barrier.Release()
		deleteService := harness.serviceWith(t, &hookedRepository{
			Repository: harness.repository,
			hooks:      transactionHooks{afterLockActiveSessions: barrier.hold},
		}, nil)
		applicationName := "identity_actor_delete_action_" + randomRepositoryTestSuffix(t)
		actionService := harness.additionalService(t, applicationName, transactionHooks{})

		deleteDone := startServiceCall(t, func() (identityservice.DeleteMeResult, error) {
			return deleteService.DeleteMe(ctx, identityservice.DeleteMeInput{
				UserID: admin.ID, SessionID: adminSession.ID, RequestID: "delete-action-self-delete",
			})
		})
		awaitTransactionBarrier(t, ctx, barrier, deleteDone)
		actionDone := startServiceCall(t, func() (domain.UserView, error) {
			return actionService.ChangeUserStatus(ctx, identityservice.ChangeUserStatusInput{
				ActorID: admin.ID, ActorSessionID: adminSession.ID, TargetID: target.ID,
				NewStatus: domain.StatusBanned, Reason: "delete first", RequestID: "delete-action-action",
			})
		})
		awaitPostgresLockWait(t, ctx, harness.fixture.DB, applicationName, actionDone)
		barrier.Release()

		deleteResult := finishServiceCall(t, ctx, "actor self deletion", deleteDone)
		actionResult := finishServiceCall(t, ctx, "admin action after deletion", actionDone)
		if deleteResult.Err != nil || !deleteResult.Value.Deleted {
			t.Fatalf("actor deletion result = %+v, error = %v", deleteResult.Value, deleteResult.Err)
		}
		assertIdentityError(t, actionResult.Err, identityservice.ErrSessionInvalid)

		adminState := harness.readState(t, admin.ID)
		deletedAt := harness.now
		assertUserState(t, adminState.User, domain.StatusDeleted, nil, &deletedAt, admin.DisplayName)
		assertSessionRevoked(t, adminState, adminSession.ID)
		if activeSessionCount(adminState) != 0 {
			t.Fatal("deleted admin retained an active session")
		}
		assertAuditCount(t, adminState, "", 0)
		targetState := harness.readState(t, target.ID)
		assertUserState(t, targetState.User, domain.StatusActive, nil, nil, target.DisplayName)
		assertSessionActive(t, targetState, targetSession.ID)
		assertAuditCount(t, targetState, "", 0)
	})

	t.Run("two admins targeting each other fail without deadlock", func(t *testing.T) {
		harness := newPostgresInvariantHarness(t)
		ctx := harness.raceContext(t)
		firstAdmin := harness.createUser(t, "mutual-admin-a", domain.RoleAdmin, domain.StatusActive, nil)
		secondAdmin := harness.createUser(t, "mutual-admin-b", domain.RoleAdmin, domain.StatusActive, nil)
		firstSession, _ := harness.createRefreshSession(t, firstAdmin.ID)
		secondSession, _ := harness.createRefreshSession(t, secondAdmin.ID)
		barrier := newTransactionBarrier()
		t.Cleanup(barrier.Release)
		defer barrier.Release()
		firstService := harness.serviceWith(t, &hookedRepository{
			Repository: harness.repository,
			hooks:      transactionHooks{afterLockUsers: barrier.hold},
		}, nil)
		applicationName := "identity_mutual_admin_" + randomRepositoryTestSuffix(t)
		secondService := harness.additionalService(t, applicationName, transactionHooks{})

		firstDone := startServiceCall(t, func() (domain.UserView, error) {
			return firstService.ChangeUserStatus(ctx, identityservice.ChangeUserStatusInput{
				ActorID: firstAdmin.ID, ActorSessionID: firstSession.ID, TargetID: secondAdmin.ID,
				NewStatus: domain.StatusFrozen, Reason: "mutual a", RequestID: "mutual-admin-a",
			})
		})
		awaitTransactionBarrier(t, ctx, barrier, firstDone)
		secondDone := startServiceCall(t, func() (domain.UserView, error) {
			return secondService.ChangeUserStatus(ctx, identityservice.ChangeUserStatusInput{
				ActorID: secondAdmin.ID, ActorSessionID: secondSession.ID, TargetID: firstAdmin.ID,
				NewStatus: domain.StatusFrozen, Reason: "mutual b", RequestID: "mutual-admin-b",
			})
		})
		awaitPostgresLockWait(t, ctx, harness.fixture.DB, applicationName, secondDone)
		barrier.Release()

		firstResult := finishServiceCall(t, ctx, "first mutual admin action", firstDone)
		secondResult := finishServiceCall(t, ctx, "second mutual admin action", secondDone)
		assertIdentityError(t, firstResult.Err, identityservice.ErrAdminTargetForbidden)
		assertIdentityError(t, secondResult.Err, identityservice.ErrAdminTargetForbidden)

		firstState := harness.readState(t, firstAdmin.ID)
		assertUserState(t, firstState.User, domain.StatusActive, nil, nil, firstAdmin.DisplayName)
		assertSessionActive(t, firstState, firstSession.ID)
		assertAuditCount(t, firstState, "", 0)
		secondState := harness.readState(t, secondAdmin.ID)
		assertUserState(t, secondState.User, domain.StatusActive, nil, nil, secondAdmin.DisplayName)
		assertSessionActive(t, secondState, secondSession.ID)
		assertAuditCount(t, secondState, "", 0)
	})
}

type postgresInvariantHarness struct {
	fixture    *testkit.PostgresFixture
	repository *identitypostgres.Repository
	service    *identityservice.Service
	refresh    *token.RefreshCodec
	access     identityservice.AccessTokenManager
	hasher     identityservice.PasswordHasher
	clock      invariantClock
	now        time.Time
}

func newPostgresInvariantHarness(t *testing.T) *postgresInvariantHarness {
	t.Helper()
	fixture := testkit.OpenPostgresFixture(t, testkit.PostgresFixtureOptions{
		SchemaPrefix:    "identity_invariant_test",
		Timeout:         postgresInvariantTestTimeout,
		CleanupTimeout:  repositoryCleanupTimeout,
		MaxOpenConns:    12,
		MaxIdleConns:    6,
		ApplyMigrations: true,
	})
	access, err := token.NewAccessManager(
		postgresInvariantAccessSecret,
		postgresInvariantAccessIssuer,
		postgresInvariantAccessAudience,
	)
	if err != nil {
		t.Fatalf("create access token manager: %v", err)
	}
	hasher, err := infrapassword.New(10)
	if err != nil {
		t.Fatalf("create bcrypt password hasher: %v", err)
	}
	harness := &postgresInvariantHarness{
		fixture:    fixture,
		repository: identitypostgres.New(fixture.DB),
		refresh:    token.NewRefreshCodec(),
		access:     access,
		hasher:     hasher,
		clock:      invariantClock{now: postgresInvariantNow},
		now:        postgresInvariantNow,
	}
	harness.service = harness.serviceWith(t, harness.repository, nil)
	return harness
}

func (harness *postgresInvariantHarness) Context() context.Context {
	return harness.fixture.Context
}

func (harness *postgresInvariantHarness) raceContext(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(harness.fixture.Context, postgresInvariantRaceTimeout)
	t.Cleanup(cancel)
	return ctx
}

func (harness *postgresInvariantHarness) serviceWith(
	t *testing.T,
	repository identityservice.Repository,
	access identityservice.AccessTokenManager,
) *identityservice.Service {
	t.Helper()
	if access == nil {
		access = harness.access
	}
	service, err := identityservice.New(identityservice.Dependencies{
		Repository:            repository,
		PasswordHasher:        harness.hasher,
		AccessTokenManager:    access,
		RefreshTokenGenerator: harness.refresh,
		Clock:                 harness.clock,
	}, identityservice.Config{
		AccessTokenTTL:  15 * time.Minute,
		RefreshTokenTTL: 24 * time.Hour,
	})
	if err != nil {
		t.Fatalf("create identity service: %v", err)
	}
	return service
}

func (harness *postgresInvariantHarness) additionalService(
	t *testing.T,
	applicationName string,
	hooks transactionHooks,
) *identityservice.Service {
	t.Helper()
	db := harness.fixture.OpenPool(t, applicationName, 4, 2)
	var repository identityservice.Repository = identitypostgres.New(db)
	if !hooks.empty() {
		repository = &hookedRepository{Repository: repository, hooks: hooks}
	}
	return harness.serviceWith(t, repository, nil)
}

func (harness *postgresInvariantHarness) createUser(
	t *testing.T,
	label string,
	role domain.Role,
	status domain.Status,
	mutedUntil *time.Time,
) domain.User {
	t.Helper()
	passwordHash, err := harness.hasher.Hash(postgresInvariantPassword)
	if err != nil {
		t.Fatalf("hash fixture password: %v", err)
	}
	createdAt := harness.now.Add(-time.Hour)
	user, err := harness.repository.CreateUser(harness.Context(), identityservice.CreateUserRecord{
		Email:          label + "-" + randomRepositoryTestSuffix(t) + "@example.test",
		PasswordHash:   passwordHash,
		DisplayName:    "Invariant " + label,
		Bio:            "",
		Role:           role,
		Status:         status,
		MutedUntil:     mutedUntil,
		ViolationCount: 0,
		CreatedAt:      createdAt,
		UpdatedAt:      createdAt,
	})
	if err != nil {
		t.Fatalf("create %s user: %v", label, err)
	}
	return user
}

func (harness *postgresInvariantHarness) createRefreshSession(
	t *testing.T,
	userID int64,
) (domain.UserSession, string) {
	t.Helper()
	secret, tokenHash, err := harness.refresh.Generate()
	if err != nil {
		t.Fatalf("generate refresh fixture: %v", err)
	}
	var session domain.UserSession
	err = harness.repository.WithinTx(harness.Context(), func(txCtx context.Context, tx identityservice.Tx) error {
		users, err := tx.LockUsers(txCtx, []int64{userID})
		if err != nil {
			return err
		}
		if len(users) != 1 || users[0].ID != userID {
			return errors.New("fixture user was not lockable")
		}
		session, err = tx.CreateSession(txCtx, identityservice.CreateSessionRecord{
			UserID:    userID,
			TokenHash: tokenHash,
			ExpiresAt: harness.now.Add(24 * time.Hour),
			CreatedAt: harness.now,
		})
		return err
	})
	if err != nil {
		t.Fatalf("create refresh session for user %d: %v", userID, err)
	}
	raw, err := harness.refresh.Format(session.ID, secret)
	if err != nil {
		t.Fatalf("format refresh fixture: %v", err)
	}
	return session, raw
}

func (harness *postgresInvariantHarness) readState(t *testing.T, userID int64) persistedIdentityState {
	t.Helper()
	ctx, cancel := context.WithTimeout(harness.Context(), postgresInvariantQueryTimeout)
	defer cancel()

	var state persistedIdentityState
	var role, status string
	err := harness.fixture.DB.QueryRowContext(
		ctx,
		"SELECT email, password_hash, display_name, bio, role, status, muted_until, violation_count, created_at, updated_at, deleted_at FROM users WHERE id = $1",
		userID,
	).Scan(
		&state.User.Email,
		&state.User.PasswordHash,
		&state.User.DisplayName,
		&state.User.Bio,
		&role,
		&status,
		&state.User.MutedUntil,
		&state.User.ViolationCount,
		&state.User.CreatedAt,
		&state.User.UpdatedAt,
		&state.User.DeletedAt,
	)
	if err != nil {
		t.Fatalf("read persisted user %d: %v", userID, err)
	}
	state.User.ID = userID
	state.User.Role = domain.Role(role)
	state.User.Status = domain.Status(status)

	sessionRows, err := harness.fixture.DB.QueryContext(
		ctx,
		"SELECT id, user_id, token_hash, expires_at, revoked_at, created_at FROM user_sessions WHERE user_id = $1 ORDER BY id",
		userID,
	)
	if err != nil {
		t.Fatalf("query persisted sessions for user %d: %v", userID, err)
	}
	defer sessionRows.Close()
	for sessionRows.Next() {
		var session persistedSessionState
		if err := sessionRows.Scan(
			&session.ID,
			&session.UserID,
			&session.TokenHash,
			&session.ExpiresAt,
			&session.RevokedAt,
			&session.CreatedAt,
		); err != nil {
			t.Fatalf("scan persisted session for user %d: %v", userID, err)
		}
		state.Sessions = append(state.Sessions, session)
	}
	if err := sessionRows.Err(); err != nil {
		t.Fatalf("iterate persisted sessions for user %d: %v", userID, err)
	}

	auditRows, err := harness.fixture.DB.QueryContext(
		ctx,
		"SELECT id, actor_type, actor_id, action, target_type, target_id, detail::text, created_at FROM audit_logs WHERE target_id = $1 ORDER BY id",
		userID,
	)
	if err != nil {
		t.Fatalf("query persisted audits for user %d: %v", userID, err)
	}
	defer auditRows.Close()
	for auditRows.Next() {
		var audit persistedAuditState
		if err := auditRows.Scan(
			&audit.ID,
			&audit.ActorType,
			&audit.ActorID,
			&audit.Action,
			&audit.TargetType,
			&audit.TargetID,
			&audit.Detail,
			&audit.CreatedAt,
		); err != nil {
			t.Fatalf("scan persisted audit for user %d: %v", userID, err)
		}
		state.Audits = append(state.Audits, audit)
	}
	if err := auditRows.Err(); err != nil {
		t.Fatalf("iterate persisted audits for user %d: %v", userID, err)
	}
	return state
}

type persistedIdentityState struct {
	User     persistedUserState
	Sessions []persistedSessionState
	Audits   []persistedAuditState
}

type persistedUserState struct {
	ID             int64
	Email          string
	PasswordHash   string
	DisplayName    string
	Bio            string
	Role           domain.Role
	Status         domain.Status
	MutedUntil     sql.NullTime
	ViolationCount int
	CreatedAt      time.Time
	UpdatedAt      time.Time
	DeletedAt      sql.NullTime
}

type persistedSessionState struct {
	ID        int64
	UserID    int64
	TokenHash []byte
	ExpiresAt time.Time
	RevokedAt sql.NullTime
	CreatedAt time.Time
}

type persistedAuditState struct {
	ID         int64
	ActorType  string
	ActorID    sql.NullInt64
	Action     string
	TargetType string
	TargetID   int64
	Detail     string
	CreatedAt  time.Time
}

func assertUserState(
	t *testing.T,
	got persistedUserState,
	wantStatus domain.Status,
	wantMutedUntil *time.Time,
	wantDeletedAt *time.Time,
	wantDisplayName string,
) {
	t.Helper()
	if got.Status != wantStatus {
		t.Fatalf("persisted user status = %q, want %q", got.Status, wantStatus)
	}
	assertNullTime(t, "persisted muted_until", got.MutedUntil, wantMutedUntil)
	assertNullTime(t, "persisted deleted_at", got.DeletedAt, wantDeletedAt)
	if got.DisplayName != wantDisplayName {
		t.Fatalf("persisted display_name = %q, want %q", got.DisplayName, wantDisplayName)
	}
}

func assertNullTime(t *testing.T, label string, got sql.NullTime, want *time.Time) {
	t.Helper()
	if want == nil {
		if got.Valid {
			t.Fatalf("%s = %v, want NULL", label, got.Time)
		}
		return
	}
	if !got.Valid || !got.Time.Equal(*want) {
		t.Fatalf("%s = (%v, %t), want %v", label, got.Time, got.Valid, *want)
	}
}

func assertPersistedUserUnchanged(t *testing.T, got persistedUserState, want domain.User) {
	t.Helper()
	if got.ID != want.ID ||
		got.Email != want.Email ||
		got.PasswordHash != want.PasswordHash ||
		got.DisplayName != want.DisplayName ||
		got.Bio != want.Bio ||
		got.Role != want.Role ||
		got.Status != want.Status ||
		got.ViolationCount != want.ViolationCount ||
		!got.CreatedAt.Equal(want.CreatedAt) ||
		!got.UpdatedAt.Equal(want.UpdatedAt) {
		t.Fatal("persisted user changed after failed transaction")
	}
	assertNullTime(t, "persisted muted_until", got.MutedUntil, want.MutedUntil)
	assertNullTime(t, "persisted deleted_at", got.DeletedAt, want.DeletedAt)
}

func assertPersistedSessionUnchanged(t *testing.T, got persistedIdentityState, want domain.UserSession) {
	t.Helper()
	session := persistedSession(t, got, want.ID)
	if session.ID != want.ID ||
		session.UserID != want.UserID ||
		!bytes.Equal(session.TokenHash, want.TokenHash) ||
		!session.ExpiresAt.Equal(want.ExpiresAt) ||
		!session.CreatedAt.Equal(want.CreatedAt) {
		t.Fatalf("persisted session %d changed after failed transaction", want.ID)
	}
	assertNullTime(t, "persisted session revoked_at", session.RevokedAt, want.RevokedAt)
}

func assertPersistedSessionUnchangedExceptRevocation(
	t *testing.T,
	got persistedIdentityState,
	want domain.UserSession,
) {
	t.Helper()
	session := persistedSession(t, got, want.ID)
	if session.ID != want.ID ||
		session.UserID != want.UserID ||
		!bytes.Equal(session.TokenHash, want.TokenHash) ||
		!session.ExpiresAt.Equal(want.ExpiresAt) ||
		!session.CreatedAt.Equal(want.CreatedAt) {
		t.Fatalf("persisted session %d changed outside revoked_at", want.ID)
	}
	if !session.RevokedAt.Valid {
		t.Fatalf("persisted session %d was not revoked", want.ID)
	}
}

func persistedSession(t *testing.T, state persistedIdentityState, sessionID int64) persistedSessionState {
	t.Helper()
	for _, session := range state.Sessions {
		if session.ID == sessionID {
			return session
		}
	}
	t.Fatalf("persisted session %d not found", sessionID)
	return persistedSessionState{}
}

func assertSessionActive(t *testing.T, state persistedIdentityState, sessionID int64) {
	t.Helper()
	if session := persistedSession(t, state, sessionID); session.RevokedAt.Valid {
		t.Fatalf("session %d revoked_at = %v, want NULL", sessionID, session.RevokedAt.Time)
	}
}

func assertSessionRevoked(t *testing.T, state persistedIdentityState, sessionID int64) {
	t.Helper()
	if session := persistedSession(t, state, sessionID); !session.RevokedAt.Valid {
		t.Fatalf("session %d revoked_at is NULL, want revoked", sessionID)
	}
}

func assertSessionHash(t *testing.T, state persistedIdentityState, sessionID int64, want []byte) {
	t.Helper()
	got := persistedSession(t, state, sessionID).TokenHash
	if !bytes.Equal(got, want) {
		t.Fatalf("session %d token_hash does not match expected value", sessionID)
	}
}

func assertSessionExpiry(t *testing.T, state persistedIdentityState, sessionID int64, want time.Time) {
	t.Helper()
	got := persistedSession(t, state, sessionID).ExpiresAt
	if !got.Equal(want) {
		t.Fatalf("session %d expires_at = %v, want %v", sessionID, got, want)
	}
}

func assertRefreshHash(
	t *testing.T,
	harness *postgresInvariantHarness,
	state persistedIdentityState,
	sessionID int64,
	rawRefresh string,
) {
	t.Helper()
	parsedSessionID, hash, err := harness.refresh.Parse(rawRefresh)
	if err != nil {
		t.Fatalf("parse returned refresh token: %v", err)
	}
	if parsedSessionID != sessionID {
		t.Fatalf("returned refresh session ID = %d, want %d", parsedSessionID, sessionID)
	}
	assertSessionHash(t, state, sessionID, hash[:])
}

func refreshSessionID(t *testing.T, codec *token.RefreshCodec, rawRefresh string) int64 {
	t.Helper()
	sessionID, _, err := codec.Parse(rawRefresh)
	if err != nil {
		t.Fatalf("parse returned refresh token: %v", err)
	}
	return sessionID
}

func assertRefreshRejected(t *testing.T, harness *postgresInvariantHarness, rawRefresh string) {
	t.Helper()
	_, err := harness.service.Refresh(harness.Context(), identityservice.RefreshInput{
		RefreshToken: rawRefresh,
		RequestID:    "final-refresh-reuse-probe",
	})
	assertIdentityError(t, err, identityservice.ErrInvalidRefreshToken)
}

func activeSessionCount(state persistedIdentityState) int {
	count := 0
	for _, session := range state.Sessions {
		if !session.RevokedAt.Valid {
			count++
		}
	}
	return count
}

func assertAuditCount(t *testing.T, state persistedIdentityState, action string, want int) {
	t.Helper()
	got := 0
	for _, audit := range state.Audits {
		if action == "" || audit.Action == action {
			got++
		}
	}
	if got != want {
		t.Fatalf("persisted audit count for %q = %d, want %d", action, got, want)
	}
}

func assertStatusAuditTransition(
	t *testing.T,
	audit persistedAuditState,
	wantOld domain.Status,
	wantNew domain.Status,
	wantRequestID string,
) {
	t.Helper()
	if audit.Action != "user.status_changed" {
		t.Fatalf("audit action = %q, want user.status_changed", audit.Action)
	}
	var detail map[string]any
	if err := json.Unmarshal([]byte(audit.Detail), &detail); err != nil {
		t.Fatalf("decode status audit detail: %v", err)
	}
	if got := detail["old_status"]; got != string(wantOld) {
		t.Fatalf("audit old_status = %v, want %q", got, wantOld)
	}
	if got := detail["new_status"]; got != string(wantNew) {
		t.Fatalf("audit new_status = %v, want %q", got, wantNew)
	}
	if got := detail["request_id"]; got != wantRequestID {
		t.Fatalf("audit request_id = %v, want %q", got, wantRequestID)
	}
}

func assertIdentityError(t *testing.T, err, want error) {
	t.Helper()
	if !errors.Is(err, want) {
		t.Fatalf("identity service error = %v, want %v", err, want)
	}
}

type invariantClock struct {
	now time.Time
}

func (clock invariantClock) Now() time.Time {
	return clock.now
}

type failingAccessTokenManager struct {
	delegate identityservice.AccessTokenManager
	err      error
}

func (manager failingAccessTokenManager) GenerateJWTID() (string, error) {
	return manager.delegate.GenerateJWTID()
}

func (manager failingAccessTokenManager) Sign(
	userID, sessionID int64,
	issuedAt, expiresAt time.Time,
	jwtID string,
) (string, error) {
	return "", manager.err
}

type transactionHooks struct {
	afterLockUsers          func(context.Context) error
	afterLockSession        func(context.Context) error
	afterLockActiveSessions func(context.Context) error
	afterLockSessions       func(context.Context) error
	afterRevokeSession      func(context.Context) error
	failSecondSessionRevoke error
	insertAuditError        error
}

func (hooks transactionHooks) empty() bool {
	return hooks.afterLockUsers == nil &&
		hooks.afterLockSession == nil &&
		hooks.afterLockActiveSessions == nil &&
		hooks.afterLockSessions == nil &&
		hooks.afterRevokeSession == nil &&
		hooks.failSecondSessionRevoke == nil &&
		hooks.insertAuditError == nil
}

type hookedRepository struct {
	identityservice.Repository
	hooks transactionHooks
}

func (repository *hookedRepository) RevokeSession(
	ctx context.Context,
	request identityservice.RevokeSessionRequest,
) error {
	err := repository.Repository.RevokeSession(ctx, request)
	if err == nil && repository.hooks.afterRevokeSession != nil {
		err = repository.hooks.afterRevokeSession(ctx)
	}
	return err
}

func (repository *hookedRepository) WithinTx(
	ctx context.Context,
	callback func(context.Context, identityservice.Tx) error,
) error {
	return repository.Repository.WithinTx(ctx, func(txCtx context.Context, tx identityservice.Tx) error {
		return callback(txCtx, &hookedTransaction{Tx: tx, hooks: repository.hooks})
	})
}

type hookedTransaction struct {
	identityservice.Tx
	hooks transactionHooks
}

func (tx *hookedTransaction) LockUsers(
	ctx context.Context,
	userIDs []int64,
) ([]identityservice.LockedUser, error) {
	users, err := tx.Tx.LockUsers(ctx, userIDs)
	if err == nil && tx.hooks.afterLockUsers != nil {
		err = tx.hooks.afterLockUsers(ctx)
	}
	return users, err
}

func (tx *hookedTransaction) LockSession(
	ctx context.Context,
	sessionID int64,
) (domain.UserSession, error) {
	session, err := tx.Tx.LockSession(ctx, sessionID)
	if err == nil && tx.hooks.afterLockSession != nil {
		err = tx.hooks.afterLockSession(ctx)
	}
	return session, err
}

func (tx *hookedTransaction) LockActiveSessions(
	ctx context.Context,
	userID int64,
) ([]domain.UserSession, error) {
	sessions, err := tx.Tx.LockActiveSessions(ctx, userID)
	if err == nil && tx.hooks.afterLockActiveSessions != nil {
		err = tx.hooks.afterLockActiveSessions(ctx)
	}
	return sessions, err
}

func (tx *hookedTransaction) LockSessions(
	ctx context.Context,
	request identityservice.SessionLockRequest,
) ([]domain.UserSession, error) {
	sessions, err := tx.Tx.LockSessions(ctx, request)
	if err == nil && tx.hooks.afterLockSessions != nil {
		err = tx.hooks.afterLockSessions(ctx)
	}
	return sessions, err
}

func (tx *hookedTransaction) RevokeLockedSessions(
	ctx context.Context,
	sessionIDs []int64,
	revokedAt time.Time,
) error {
	if tx.hooks.failSecondSessionRevoke != nil && len(sessionIDs) >= 2 {
		if err := tx.Tx.RevokeLockedSessions(ctx, sessionIDs[:1], revokedAt); err != nil {
			return err
		}
		return tx.hooks.failSecondSessionRevoke
	}
	return tx.Tx.RevokeLockedSessions(ctx, sessionIDs, revokedAt)
}

func (tx *hookedTransaction) InsertAudit(ctx context.Context, entry identityservice.AuditEntry) error {
	if tx.hooks.insertAuditError != nil {
		if err := tx.Tx.InsertAudit(ctx, entry); err != nil {
			return err
		}
		return tx.hooks.insertAuditError
	}
	return tx.Tx.InsertAudit(ctx, entry)
}

type transactionBarrier struct {
	entered     chan struct{}
	release     chan struct{}
	enteredOnce sync.Once
	releaseOnce sync.Once
}

func newTransactionBarrier() *transactionBarrier {
	return &transactionBarrier{
		entered: make(chan struct{}),
		release: make(chan struct{}),
	}
}

func (barrier *transactionBarrier) hold(ctx context.Context) error {
	barrier.enteredOnce.Do(func() { close(barrier.entered) })
	select {
	case <-barrier.release:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (barrier *transactionBarrier) Release() {
	barrier.releaseOnce.Do(func() { close(barrier.release) })
}

type serviceCallResult[T any] struct {
	Value T
	Err   error
}

func startServiceCall[T any](t testing.TB, call func() (T, error)) <-chan serviceCallResult[T] {
	t.Helper()
	done := make(chan serviceCallResult[T], 1)
	go func() {
		defer close(done)
		value, err := call()
		done <- serviceCallResult[T]{Value: value, Err: err}
	}()
	t.Cleanup(func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), repositoryWorkerCleanupTimeout)
		defer cancel()
		select {
		case <-done:
		case <-cleanupCtx.Done():
			t.Errorf("identity service worker did not finish during bounded cleanup: %v", cleanupCtx.Err())
		}
	})
	return done
}

func awaitTransactionBarrier[T any](
	t *testing.T,
	ctx context.Context,
	barrier *transactionBarrier,
	done <-chan serviceCallResult[T],
) {
	t.Helper()
	select {
	case <-barrier.entered:
	case result := <-done:
		t.Fatalf("service call completed before transaction barrier: %v", result.Err)
	case <-ctx.Done():
		t.Fatalf("wait for transaction barrier: %v", ctx.Err())
	}
}

func awaitPostgresLockWait[T any](
	t *testing.T,
	ctx context.Context,
	db *sql.DB,
	applicationName string,
	done <-chan serviceCallResult[T],
) {
	t.Helper()
	result, completed, err := waitForApplicationLockWait(ctx, db, applicationName, done)
	if err != nil {
		t.Fatalf("observe PostgreSQL lock wait for %s: %v", applicationName, err)
	}
	if completed {
		t.Fatalf("service call for %s completed before waiting on a database lock: %v", applicationName, result.Err)
	}
}

func finishServiceCall[T any](
	t *testing.T,
	ctx context.Context,
	label string,
	done <-chan serviceCallResult[T],
) serviceCallResult[T] {
	t.Helper()
	result, err := receiveBeforeContextDone(ctx, done)
	if err != nil {
		t.Fatalf("wait for %s: %v", label, err)
	}
	return result
}
