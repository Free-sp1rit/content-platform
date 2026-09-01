//go:build integration

package identity_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/Free-sp1rit/content-platform/internal/identity/domain"
	identityservice "github.com/Free-sp1rit/content-platform/internal/identity/service"
	"github.com/Free-sp1rit/content-platform/internal/infra/config"
	"github.com/Free-sp1rit/content-platform/internal/infra/postgres"
	identitypostgres "github.com/Free-sp1rit/content-platform/internal/infra/postgres/identity"
	"github.com/Free-sp1rit/content-platform/internal/infra/postgres/migration"
	"github.com/Free-sp1rit/content-platform/internal/testkit"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/stdlib"
)

const (
	repositoryIntegrationTimeout    = 2 * time.Minute
	repositoryConcurrentTestTimeout = 15 * time.Second
	repositoryCleanupTimeout        = 30 * time.Second
	repositoryLockAttemptTimeout    = 150 * time.Millisecond
)

var _ identityservice.Repository = (*identitypostgres.Repository)(nil)

func TestRepositoryIntegration(t *testing.T) {
	// Do not call t.Parallel: this test creates schema-local DDL and exercises row locks.
	ctx, db, repository := openRepositoryDatabase(t)

	t.Run("maps only the email unique constraint", func(t *testing.T) {
		now := repositoryTestTime()
		record := repositoryUserRecord(t, "email-conflict", now)
		created, err := repository.CreateUser(ctx, record)
		if err != nil {
			t.Fatalf("CreateUser() error = %v", err)
		}
		if created.ID <= 0 {
			t.Fatalf("CreateUser() ID = %d, want positive", created.ID)
		}
		if created.Email != record.Email {
			t.Fatal("CreateUser() email did not match the persisted record")
		}
		if created.PasswordHash != record.PasswordHash {
			t.Fatal("CreateUser() password_hash did not match the persisted record")
		}

		_, err = repository.CreateUser(ctx, record)
		if !errors.Is(err, identityservice.ErrEmailExists) {
			t.Fatalf("duplicate CreateUser() error = %v, want ErrEmailExists", err)
		}
		assertSafeRepositoryError(t, err, "users_email_uidx", record.PasswordHash)

		const otherConstraint = "repository_test_display_name_uidx"
		if _, err := db.ExecContext(ctx, "CREATE UNIQUE INDEX "+quoteIdentifier(otherConstraint)+" ON users (display_name)"); err != nil {
			t.Fatalf("create test-only unique index: %v", err)
		}
		t.Cleanup(func() {
			cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), repositoryCleanupTimeout)
			defer cleanupCancel()
			if _, err := db.ExecContext(cleanupCtx, "DROP INDEX IF EXISTS "+quoteIdentifier(otherConstraint)); err != nil {
				t.Errorf("drop test-only unique index: %v", err)
			}
		})

		other := repositoryUserRecord(t, "other-conflict", now)
		other.DisplayName = record.DisplayName
		_, err = repository.CreateUser(ctx, other)
		if !errors.Is(err, identityservice.ErrInternal) {
			t.Fatalf("other unique constraint error = %v, want ErrInternal", err)
		}
		if errors.Is(err, identityservice.ErrEmailExists) {
			t.Fatalf("other unique constraint error = %v, must not map to ErrEmailExists", err)
		}
		assertSafeRepositoryError(t, err, otherConstraint, other.PasswordHash)
	})

	t.Run("finds users credentials sessions and stable not found errors", func(t *testing.T) {
		now := repositoryTestTime()
		record := repositoryUserRecord(t, "lookup", now)
		user := createRepositoryUser(t, ctx, repository, record)

		credential, err := repository.FindLoginCredential(ctx, record.Email)
		if err != nil {
			t.Fatalf("FindLoginCredential() error = %v", err)
		}
		if credential.UserID != user.ID {
			t.Fatalf("FindLoginCredential() user ID = %d, want %d", credential.UserID, user.ID)
		}
		if credential.PasswordHash != record.PasswordHash {
			t.Fatal("FindLoginCredential() password_hash did not match")
		}
		if credential.Status != record.Status {
			t.Fatalf("FindLoginCredential() status = %q, want %q", credential.Status, record.Status)
		}
		if credential.DeletedAt != nil {
			t.Fatalf("FindLoginCredential() deleted_at = %v, want nil", credential.DeletedAt)
		}

		found, err := repository.FindUser(ctx, user.ID)
		if err != nil {
			t.Fatalf("FindUser() error = %v", err)
		}
		assertUsersEqual(t, found, user)

		session := createRepositorySession(t, ctx, repository, user.ID, hashByte(0x11), now, now.Add(2*time.Hour))
		owner, err := repository.FindSessionOwner(ctx, session.ID)
		if err != nil {
			t.Fatalf("FindSessionOwner() error = %v", err)
		}
		if owner != user.ID {
			t.Fatalf("FindSessionOwner() = %d, want %d", owner, user.ID)
		}

		err = repository.WithinTx(ctx, func(txCtx context.Context, tx identityservice.Tx) error {
			locked, err := tx.LockSession(txCtx, session.ID)
			if err != nil {
				return err
			}
			if locked.ID != session.ID {
				t.Fatalf("LockSession() ID = %d, want %d", locked.ID, session.ID)
			}
			if locked.UserID != user.ID {
				t.Fatalf("LockSession() user ID = %d, want %d", locked.UserID, user.ID)
			}
			if !bytes.Equal(locked.TokenHash, session.TokenHash) {
				t.Fatal("LockSession() token_hash did not match")
			}
			return nil
		})
		if err != nil {
			t.Fatalf("WithinTx(LockSession) error = %v", err)
		}

		for name, find := range map[string]func() error{
			"credential": func() error { _, err := repository.FindLoginCredential(ctx, "missing@example.test"); return err },
			"user":       func() error { _, err := repository.FindUser(ctx, 9223372036854775807); return err },
			"owner":      func() error { _, err := repository.FindSessionOwner(ctx, 9223372036854775807); return err },
			"session": func() error {
				return repository.WithinTx(ctx, func(txCtx context.Context, tx identityservice.Tx) error {
					_, err := tx.LockSession(txCtx, 9223372036854775807)
					return err
				})
			},
		} {
			t.Run(name+" not found", func(t *testing.T) {
				err := find()
				if !errors.Is(err, identityservice.ErrNotFound) {
					t.Fatalf("error = %v, want ErrNotFound", err)
				}
				assertSafeRepositoryError(t, err, "SELECT", "user_sessions")
			})
		}
	})

	t.Run("locks users in ascending de-duplicated order", func(t *testing.T) {
		testCtx, cancelTest := context.WithTimeout(ctx, repositoryConcurrentTestTimeout)
		defer cancelTest()
		now := repositoryTestTime()
		first := createRepositoryUser(t, testCtx, repository, repositoryUserRecord(t, "lock-user-first", now))
		second := createRepositoryUser(t, testCtx, repository, repositoryUserRecord(t, "lock-user-second", now))
		third := createRepositoryUser(t, testCtx, repository, repositoryUserRecord(t, "lock-user-third", now))
		var schema string
		if err := db.QueryRowContext(testCtx, "SELECT current_schema()").Scan(&schema); err != nil {
			t.Fatalf("read current schema: %v", err)
		}
		candidateApplication := "identity_user_lock_" + randomRepositoryTestSuffix(t)
		_, candidateRepository := openAdditionalRepositoryDatabase(
			t,
			testCtx,
			testkit.DatabaseURL(t),
			schema,
			candidateApplication,
		)

		blockerLocked := make(chan struct{})
		releaseBlocker := make(chan struct{})
		blockerDone := make(chan error, 1)
		go func() {
			blockerDone <- repository.WithinTx(testCtx, func(txCtx context.Context, tx identityservice.Tx) error {
				if _, err := tx.LockUsers(txCtx, []int64{third.ID}); err != nil {
					return err
				}
				close(blockerLocked)
				select {
				case <-releaseBlocker:
					return nil
				case <-txCtx.Done():
					return txCtx.Err()
				}
			})
		}()

		blockerReleased := false
		blockerWaited := false
		candidateStarted := false
		candidateWaited := false
		var candidateDone chan error
		defer func() {
			if !blockerReleased {
				close(releaseBlocker)
			}
			if !blockerWaited {
				cleanupErrorWorker(t, "higher user blocker", blockerDone)
			}
			if candidateStarted && !candidateWaited {
				cleanupErrorWorker(t, "ordered user lock candidate", candidateDone)
			}
		}()
		blockerWaited, err := waitForWorkerReady(testCtx, blockerLocked, blockerDone)
		if err != nil {
			t.Fatalf("higher user blocker failed before acquiring its lock: %v", err)
		}

		candidateDone = make(chan error, 1)
		candidateStarted = true
		go func() {
			candidateDone <- candidateRepository.WithinTx(testCtx, func(txCtx context.Context, tx identityservice.Tx) error {
				locked, err := tx.LockUsers(txCtx, []int64{third.ID, first.ID, second.ID, first.ID, third.ID})
				if err != nil {
					return err
				}
				if got, want := lockedUserIDs(locked), []int64{first.ID, second.ID, third.ID}; !equalIDs(got, want) {
					return errors.New("user lock result was not ordered and de-duplicated")
				}
				return nil
			})
		}()

		candidateBeforeWait, candidateWaited, waitErr := waitForApplicationLockWait(testCtx, db, candidateApplication, candidateDone)
		if waitErr != nil {
			t.Fatalf("observe ordered user lock candidate: %v", waitErr)
		}
		if candidateWaited {
			if candidateBeforeWait != nil {
				t.Fatalf("ordered user lock candidate failed before entering a lock wait: %v", candidateBeforeWait)
			}
			t.Fatal("ordered user lock candidate completed before entering a lock wait")
		}
		deadlineCtx, cancelDeadline := context.WithTimeout(testCtx, repositoryLockAttemptTimeout)
		err = repository.WithinTx(deadlineCtx, func(txCtx context.Context, tx identityservice.Tx) error {
			_, err := tx.LockUsers(txCtx, []int64{first.ID})
			return err
		})
		cancelDeadline()
		if !errors.Is(err, identityservice.ErrInternal) || !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("lower user contender error = %v, want ErrInternal and context.DeadlineExceeded", err)
		}

		close(releaseBlocker)
		blockerReleased = true
		blockerErr, waitErr := receiveBeforeContextDone(testCtx, blockerDone)
		if waitErr != nil {
			t.Fatalf("wait for higher user blocker: %v", waitErr)
		}
		blockerWaited = true
		if blockerErr != nil {
			t.Fatalf("higher user blocker error = %v", blockerErr)
		}
		candidateErr, waitErr := receiveBeforeContextDone(testCtx, candidateDone)
		if waitErr != nil {
			t.Fatalf("wait for ordered user lock candidate: %v", waitErr)
		}
		candidateWaited = true
		if candidateErr != nil {
			t.Fatalf("ordered user lock error = %v", candidateErr)
		}
	})

	t.Run("locks explicit and active-user sessions in one global order", func(t *testing.T) {
		testCtx, cancelTest := context.WithTimeout(ctx, repositoryConcurrentTestTimeout)
		defer cancelTest()
		now := repositoryTestTime()
		actor := createRepositoryUser(t, testCtx, repository, repositoryUserRecord(t, "combined-lock-actor", now))
		target := createRepositoryUser(t, testCtx, repository, repositoryUserRecord(t, "combined-lock-target", now))
		targetFirst := createRepositorySession(t, testCtx, repository, target.ID, hashByte(0x15), now, now.Add(time.Hour))
		targetSecond := createRepositorySession(t, testCtx, repository, target.ID, hashByte(0x16), now, now.Add(time.Hour))
		targetRevoked := createRepositorySession(t, testCtx, repository, target.ID, hashByte(0x17), now, now.Add(time.Hour))
		if err := repository.RevokeSession(testCtx, identityservice.RevokeSessionRequest{
			UserID:    target.ID,
			SessionID: targetRevoked.ID,
			RevokedAt: now.Add(time.Minute),
		}); err != nil {
			t.Fatalf("prepare target revoked session: %v", err)
		}
		actorSession := createRepositorySession(t, testCtx, repository, actor.ID, hashByte(0x18), now, now.Add(time.Hour))
		var schema string
		if err := db.QueryRowContext(testCtx, "SELECT current_schema()").Scan(&schema); err != nil {
			t.Fatalf("read current schema: %v", err)
		}
		candidateApplication := "identity_session_lock_" + randomRepositoryTestSuffix(t)
		_, candidateRepository := openAdditionalRepositoryDatabase(
			t,
			testCtx,
			testkit.DatabaseURL(t),
			schema,
			candidateApplication,
		)

		blockerLocked := make(chan struct{})
		releaseBlocker := make(chan struct{})
		blockerDone := make(chan error, 1)
		go func() {
			blockerDone <- repository.WithinTx(testCtx, func(txCtx context.Context, tx identityservice.Tx) error {
				if _, err := tx.LockSession(txCtx, actorSession.ID); err != nil {
					return err
				}
				close(blockerLocked)
				select {
				case <-releaseBlocker:
					return nil
				case <-txCtx.Done():
					return txCtx.Err()
				}
			})
		}()

		blockerReleased := false
		blockerWaited := false
		candidateStarted := false
		candidateWaited := false
		var candidateDone chan error
		defer func() {
			if !blockerReleased {
				close(releaseBlocker)
			}
			if !blockerWaited {
				cleanupErrorWorker(t, "higher session blocker", blockerDone)
			}
			if candidateStarted && !candidateWaited {
				cleanupErrorWorker(t, "combined session lock candidate", candidateDone)
			}
		}()
		blockerWaited, err := waitForWorkerReady(testCtx, blockerLocked, blockerDone)
		if err != nil {
			t.Fatalf("higher session blocker failed before acquiring its lock: %v", err)
		}

		candidateDone = make(chan error, 1)
		candidateStarted = true
		go func() {
			candidateDone <- candidateRepository.WithinTx(testCtx, func(txCtx context.Context, tx identityservice.Tx) error {
				if _, err := tx.LockUsers(txCtx, []int64{target.ID, actor.ID}); err != nil {
					return err
				}
				locked, err := tx.LockSessions(txCtx, identityservice.SessionLockRequest{
					SessionIDs:    []int64{actorSession.ID, actorSession.ID},
					ActiveUserIDs: []int64{target.ID, target.ID},
				})
				if err != nil {
					return err
				}
				if got, want := sessionIDs(locked), []int64{targetFirst.ID, targetSecond.ID, actorSession.ID}; !equalIDs(got, want) {
					return errors.New("combined session lock result was not globally ordered and de-duplicated")
				}
				return nil
			})
		}()

		candidateBeforeWait, candidateWaited, waitErr := waitForApplicationLockWait(testCtx, db, candidateApplication, candidateDone)
		if waitErr != nil {
			t.Fatalf("observe combined session lock candidate: %v", waitErr)
		}
		if candidateWaited {
			if candidateBeforeWait != nil {
				t.Fatalf("combined session lock candidate failed before entering a lock wait: %v", candidateBeforeWait)
			}
			t.Fatal("combined session lock candidate completed before entering a lock wait")
		}
		deadlineCtx, cancelDeadline := context.WithTimeout(testCtx, repositoryLockAttemptTimeout)
		started := time.Now()
		err = repository.WithinTx(deadlineCtx, func(txCtx context.Context, tx identityservice.Tx) error {
			_, err := tx.LockSession(txCtx, targetFirst.ID)
			return err
		})
		cancelDeadline()
		if !errors.Is(err, identityservice.ErrInternal) || !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("lower session contender error = %v, want ErrInternal and context.DeadlineExceeded", err)
		}
		if elapsed := time.Since(started); elapsed > 2*time.Second {
			t.Fatalf("lower session contender ignored deadline: elapsed %v", elapsed)
		}

		close(releaseBlocker)
		blockerReleased = true
		blockerErr, waitErr := receiveBeforeContextDone(testCtx, blockerDone)
		if waitErr != nil {
			t.Fatalf("wait for higher session blocker: %v", waitErr)
		}
		blockerWaited = true
		if blockerErr != nil {
			t.Fatalf("higher session blocker error = %v", blockerErr)
		}
		candidateErr, waitErr := receiveBeforeContextDone(testCtx, candidateDone)
		if waitErr != nil {
			t.Fatalf("wait for combined session lock candidate: %v", waitErr)
		}
		candidateWaited = true
		if candidateErr != nil {
			t.Fatalf("combined session lock error = %v", candidateErr)
		}
	})

	t.Run("lock session observes a concurrent committed tuple after waiting", func(t *testing.T) {
		testCtx, cancelTest := context.WithTimeout(ctx, repositoryConcurrentTestTimeout)
		defer cancelTest()
		now := repositoryTestTime()
		user := createRepositoryUser(t, testCtx, repository, repositoryUserRecord(t, "session-eval-plan-qual", now))
		session := createRepositorySession(t, testCtx, repository, user.ID, hashByte(0x19), now, now.Add(time.Hour))
		rotatedHash := hashByte(0x1a)
		revokedAt := now.Add(time.Minute)

		var schema string
		if err := db.QueryRowContext(testCtx, "SELECT current_schema()").Scan(&schema); err != nil {
			t.Fatalf("read current schema: %v", err)
		}
		waiterApplication := "identity_session_epq_" + randomRepositoryTestSuffix(t)
		_, waiterRepository := openAdditionalRepositoryDatabase(
			t,
			testCtx,
			testkit.DatabaseURL(t),
			schema,
			waiterApplication,
		)

		type lockResult struct {
			session domain.UserSession
			err     error
		}

		updated := make(chan struct{})
		releaseUpdater := make(chan struct{})
		updaterDone := make(chan error, 1)
		go func() {
			updaterDone <- repository.WithinTx(testCtx, func(txCtx context.Context, tx identityservice.Tx) error {
				if _, err := tx.LockSession(txCtx, session.ID); err != nil {
					return err
				}
				if err := tx.RotateSessionToken(txCtx, session.ID, rotatedHash); err != nil {
					return err
				}
				if err := tx.RevokeLockedSessions(txCtx, []int64{session.ID}, revokedAt); err != nil {
					return err
				}
				close(updated)
				select {
				case <-releaseUpdater:
					return nil
				case <-txCtx.Done():
					return txCtx.Err()
				}
			})
		}()

		updaterReleased := false
		updaterWaited := false
		waiterStarted := false
		waiterWaited := false
		var waiterDone chan lockResult
		defer func() {
			if !updaterReleased {
				close(releaseUpdater)
			}
			if !updaterWaited {
				cleanupErrorWorker(t, "concurrent session updater", updaterDone)
			}
			if waiterStarted && !waiterWaited {
				cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), repositoryWorkerCleanupTimeout)
				defer cleanupCancel()
				result, waitErr := receiveBeforeContextDone(cleanupCtx, waiterDone)
				if waitErr != nil {
					t.Errorf("session lock waiter did not finish during bounded cleanup: %v", waitErr)
				} else if result.err != nil {
					t.Errorf("session lock waiter failed during cleanup: %v", result.err)
				}
			}
		}()
		updaterWaited, err := waitForWorkerReady(testCtx, updated, updaterDone)
		if err != nil {
			t.Fatalf("session updater failed before reaching the commit gate: %v", err)
		}

		waiterDone = make(chan lockResult, 1)
		waiterStarted = true
		go func() {
			var locked domain.UserSession
			err := waiterRepository.WithinTx(testCtx, func(txCtx context.Context, tx identityservice.Tx) error {
				var err error
				locked, err = tx.LockSession(txCtx, session.ID)
				return err
			})
			waiterDone <- lockResult{session: locked, err: err}
		}()

		waiterBeforeWait, waiterWaited, waitErr := waitForApplicationLockWait(testCtx, db, waiterApplication, waiterDone)
		if waitErr != nil {
			t.Fatalf("observe session lock waiter: %v", waitErr)
		}
		if waiterWaited {
			if waiterBeforeWait.err != nil {
				t.Fatalf("session lock waiter failed before entering a lock wait: %v", waiterBeforeWait.err)
			}
			t.Fatal("session lock waiter completed before entering a lock wait")
		}
		close(releaseUpdater)
		updaterReleased = true
		updaterErr, waitErr := receiveBeforeContextDone(testCtx, updaterDone)
		if waitErr != nil {
			t.Fatalf("wait for concurrent session updater: %v", waitErr)
		}
		updaterWaited = true
		if updaterErr != nil {
			t.Fatalf("commit concurrent session update: %v", updaterErr)
		}

		result, waitErr := receiveBeforeContextDone(testCtx, waiterDone)
		if waitErr != nil {
			t.Fatalf("wait for session lock waiter: %v", waitErr)
		}
		waiterWaited = true
		if result.err != nil {
			t.Fatalf("LockSession() after concurrent commit error = %v", result.err)
		}
		if !bytes.Equal(result.session.TokenHash, rotatedHash[:]) {
			t.Fatal("LockSession() returned a stale token_hash after waiting for a concurrent commit")
		}
		if result.session.RevokedAt == nil || !result.session.RevokedAt.Equal(revokedAt) {
			t.Fatalf("LockSession() revoked_at = %v, want concurrent commit time %v", result.session.RevokedAt, revokedAt)
		}
	})

	t.Run("creates and rotates a session without extending its lifetime", func(t *testing.T) {
		now := repositoryTestTime()
		user := createRepositoryUser(t, ctx, repository, repositoryUserRecord(t, "session-rotation", now))
		originalHash := hashByte(0x21)
		expiresAt := now.Add(8 * time.Hour)
		session := createRepositorySession(t, ctx, repository, user.ID, originalHash, now, expiresAt)

		rotatedHash := hashByte(0x22)
		err := repository.WithinTx(ctx, func(txCtx context.Context, tx identityservice.Tx) error {
			if _, err := tx.LockUsers(txCtx, []int64{user.ID}); err != nil {
				return err
			}
			if _, err := tx.LockSession(txCtx, session.ID); err != nil {
				return err
			}
			return tx.RotateSessionToken(txCtx, session.ID, rotatedHash)
		})
		if err != nil {
			t.Fatalf("WithinTx(RotateSessionToken) error = %v", err)
		}

		persistedHash, persistedExpiry := readSessionTokenAndExpiry(t, ctx, db, session.ID)
		if !bytes.Equal(persistedHash, rotatedHash[:]) {
			t.Fatal("RotateSessionToken() did not persist the requested token_hash")
		}
		if !persistedExpiry.Equal(expiresAt) {
			t.Fatalf("rotated expires_at = %v, want unchanged %v", persistedExpiry, expiresAt)
		}
	})

	t.Run("logout is a conditional idempotent update", func(t *testing.T) {
		now := repositoryTestTime()
		owner := createRepositoryUser(t, ctx, repository, repositoryUserRecord(t, "logout-owner", now))
		other := createRepositoryUser(t, ctx, repository, repositoryUserRecord(t, "logout-other", now))
		session := createRepositorySession(t, ctx, repository, owner.ID, hashByte(0x31), now, now.Add(time.Hour))

		if err := repository.RevokeSession(ctx, identityservice.RevokeSessionRequest{
			UserID:    other.ID,
			SessionID: session.ID,
			RevokedAt: now.Add(time.Minute),
		}); err != nil {
			t.Fatalf("RevokeSession(wrong owner) error = %v", err)
		}
		if revokedAt := readSessionRevokedAt(t, ctx, db, session.ID); revokedAt != nil {
			t.Fatalf("wrong-owner logout revoked_at = %v, want nil", revokedAt)
		}

		revokedAt := now.Add(2 * time.Minute)
		if err := repository.RevokeSession(ctx, identityservice.RevokeSessionRequest{
			UserID:    owner.ID,
			SessionID: session.ID,
			RevokedAt: revokedAt,
		}); err != nil {
			t.Fatalf("RevokeSession() error = %v", err)
		}
		if err := repository.RevokeSession(ctx, identityservice.RevokeSessionRequest{
			UserID:    owner.ID,
			SessionID: session.ID,
			RevokedAt: revokedAt.Add(time.Hour),
		}); err != nil {
			t.Fatalf("second RevokeSession() error = %v", err)
		}
		persisted := readSessionRevokedAt(t, ctx, db, session.ID)
		if persisted == nil || !persisted.Equal(revokedAt) {
			t.Fatalf("idempotent revoked_at = %v, want first timestamp %v", persisted, revokedAt)
		}
	})

	t.Run("locks active sessions in order and revokes de-duplicated locked ids", func(t *testing.T) {
		now := repositoryTestTime()
		user := createRepositoryUser(t, ctx, repository, repositoryUserRecord(t, "bulk-revoke", now))
		first := createRepositorySession(t, ctx, repository, user.ID, hashByte(0x41), now, now.Add(time.Hour))
		second := createRepositorySession(t, ctx, repository, user.ID, hashByte(0x42), now, now.Add(time.Hour))
		third := createRepositorySession(t, ctx, repository, user.ID, hashByte(0x43), now, now.Add(time.Hour))
		alreadyRevoked := createRepositorySession(t, ctx, repository, user.ID, hashByte(0x44), now, now.Add(time.Hour))
		if err := repository.RevokeSession(ctx, identityservice.RevokeSessionRequest{
			UserID:    user.ID,
			SessionID: alreadyRevoked.ID,
			RevokedAt: now.Add(time.Minute),
		}); err != nil {
			t.Fatalf("prepare revoked session: %v", err)
		}

		revokedAt := now.Add(5 * time.Minute)
		err := repository.WithinTx(ctx, func(txCtx context.Context, tx identityservice.Tx) error {
			if _, err := tx.LockUsers(txCtx, []int64{user.ID}); err != nil {
				return err
			}
			locked, err := tx.LockActiveSessions(txCtx, user.ID)
			if err != nil {
				return err
			}
			assertIDs(t, sessionIDs(locked), []int64{first.ID, second.ID, third.ID})
			return tx.RevokeLockedSessions(txCtx, []int64{third.ID, first.ID, third.ID, second.ID, first.ID}, revokedAt)
		})
		if err != nil {
			t.Fatalf("WithinTx(bulk revoke) error = %v", err)
		}

		for _, sessionID := range []int64{first.ID, second.ID, third.ID} {
			persisted := readSessionRevokedAt(t, ctx, db, sessionID)
			if persisted == nil || !persisted.Equal(revokedAt) {
				t.Fatalf("session %d revoked_at = %v, want %v", sessionID, persisted, revokedAt)
			}
		}
		persistedAlreadyRevoked := readSessionRevokedAt(t, ctx, db, alreadyRevoked.ID)
		if persistedAlreadyRevoked == nil || !persistedAlreadyRevoked.Equal(now.Add(time.Minute)) {
			t.Fatalf("previously revoked session changed to %v", persistedAlreadyRevoked)
		}
	})

	t.Run("updates only specified user fields including explicit nullable values", func(t *testing.T) {
		now := repositoryTestTime()
		record := repositoryUserRecord(t, "user-mutation", now)
		record.Bio = "original bio"
		user := createRepositoryUser(t, ctx, repository, record)

		profileUpdatedAt := now.Add(time.Minute)
		updated := updateRepositoryUser(t, ctx, repository, identityservice.UserMutation{
			UserID:      user.ID,
			DisplayName: identityservice.SetField("Changed Name"),
			UpdatedAt:   identityservice.SetField(profileUpdatedAt),
		})
		if updated.DisplayName != "Changed Name" || updated.Bio != record.Bio || updated.Status != record.Status || updated.MutedUntil != nil {
			t.Fatal("profile UpdateUser() overwrote an unspecified field")
		}

		mutedUntil := now.Add(2 * time.Hour)
		mutedUpdatedAt := now.Add(2 * time.Minute)
		updated = updateRepositoryUser(t, ctx, repository, identityservice.UserMutation{
			UserID:     user.ID,
			Status:     identityservice.SetField(domain.StatusMuted),
			MutedUntil: identityservice.SetField(&mutedUntil),
			UpdatedAt:  identityservice.SetField(mutedUpdatedAt),
		})
		if updated.Status != domain.StatusMuted || updated.MutedUntil == nil || !updated.MutedUntil.Equal(mutedUntil) {
			t.Fatal("muted UpdateUser() did not persist status and muted_until")
		}

		recoveredUpdatedAt := now.Add(3 * time.Minute)
		updated = updateRepositoryUser(t, ctx, repository, identityservice.UserMutation{
			UserID:     user.ID,
			Status:     identityservice.SetField(domain.StatusActive),
			MutedUntil: identityservice.SetField[*time.Time](nil),
			Bio:        identityservice.SetField(""),
			UpdatedAt:  identityservice.SetField(recoveredUpdatedAt),
		})
		if updated.Status != domain.StatusActive || updated.MutedUntil != nil || updated.Bio != "" || updated.DisplayName != "Changed Name" {
			t.Fatal("explicit NULL UpdateUser() did not clear only the requested nullable fields")
		}
	})

	t.Run("conditionally recovers an expired mute only once", func(t *testing.T) {
		now := repositoryTestTime()
		record := repositoryUserRecord(t, "mute-recovery", now.Add(-2*time.Hour))
		expiredAt := now.Add(-time.Minute)
		record.Status = domain.StatusMuted
		record.MutedUntil = &expiredAt
		user := createRepositoryUser(t, ctx, repository, record)

		for attempt := 1; attempt <= 2; attempt++ {
			err := repository.WithinTx(ctx, func(txCtx context.Context, tx identityservice.Tx) error {
				if _, err := tx.LockUsers(txCtx, []int64{user.ID}); err != nil {
					return err
				}
				updated, changed, err := tx.RecoverExpiredMute(txCtx, user.ID, now)
				if err != nil {
					return err
				}
				if attempt == 1 {
					if !changed {
						t.Fatal("first RecoverExpiredMute() changed = false, want true")
					}
					if updated.Status != domain.StatusActive || updated.MutedUntil != nil || !updated.UpdatedAt.Equal(now) {
						t.Fatal("first RecoverExpiredMute() did not return the recovered status and timestamps")
					}
				} else if changed {
					t.Fatalf("second RecoverExpiredMute() changed = true, want false")
				}
				if !changed {
					return nil
				}
				return tx.InsertAudit(txCtx, identityservice.AuditEntry{
					ActorType:  identityservice.AuditActorSystem,
					Action:     "user.mute_expired",
					TargetType: "user",
					TargetID:   user.ID,
					Detail: map[string]any{
						"old_status":      domain.StatusMuted,
						"new_status":      domain.StatusActive,
						"old_muted_until": expiredAt,
						"new_muted_until": nil,
						"request_id":      "repository-test",
					},
					CreatedAt: now,
				})
			})
			if err != nil {
				t.Fatalf("mute recovery attempt %d error = %v", attempt, err)
			}
		}

		if got := countAuditActions(t, ctx, db, user.ID, "user.mute_expired"); got != 1 {
			t.Fatalf("mute recovery audit count = %d, want 1", got)
		}
		var oldStatus, newStatus, requestID string
		var newMutedUntilIsNull bool
		if err := db.QueryRowContext(ctx, `
			SELECT detail->>'old_status', detail->>'new_status', detail->>'request_id',
			       detail->'new_muted_until' = 'null'::jsonb
			FROM audit_logs
			WHERE target_id = $1 AND action = 'user.mute_expired'`, user.ID,
		).Scan(&oldStatus, &newStatus, &requestID, &newMutedUntilIsNull); err != nil {
			t.Fatalf("read structured audit detail: %v", err)
		}
		if oldStatus != string(domain.StatusMuted) || newStatus != string(domain.StatusActive) || requestID != "repository-test" || !newMutedUntilIsNull {
			t.Fatalf("audit detail = (%q, %q, %q, null=%t), want structured mute recovery detail", oldStatus, newStatus, requestID, newMutedUntilIsNull)
		}
	})

	t.Run("callback and commit errors both roll back partial state", func(t *testing.T) {
		now := repositoryTestTime()
		callbackRecord := repositoryUserRecord(t, "callback-rollback", now)
		callbackUser := createRepositoryUser(t, ctx, repository, callbackRecord)

		err := repository.WithinTx(ctx, func(txCtx context.Context, tx identityservice.Tx) error {
			if _, err := tx.LockUsers(txCtx, []int64{callbackUser.ID}); err != nil {
				return err
			}
			if _, err := tx.UpdateUser(txCtx, identityservice.UserMutation{
				UserID:      callbackUser.ID,
				DisplayName: identityservice.SetField("Must Roll Back"),
				UpdatedAt:   identityservice.SetField(now.Add(time.Minute)),
			}); err != nil {
				return err
			}
			return tx.InsertAudit(txCtx, identityservice.AuditEntry{
				ActorType:  identityservice.AuditActorSystem,
				Action:     "user.mute_expired",
				TargetType: "user",
				TargetID:   callbackUser.ID,
				Detail:     map[string]any{"secret": func() {}},
				CreatedAt:  now,
			})
		})
		if !errors.Is(err, identityservice.ErrInternal) {
			t.Fatalf("callback error = %v, want ErrInternal", err)
		}
		assertSafeRepositoryError(t, err, "secret", "func")
		assertDisplayName(t, ctx, repository, callbackUser.ID, callbackRecord.DisplayName)
		if got := countAuditActions(t, ctx, db, callbackUser.ID, "user.mute_expired"); got != 0 {
			t.Fatalf("callback rollback audit count = %d, want 0", got)
		}

		commitRecord := repositoryUserRecord(t, "commit-rollback", now)
		commitUser := createRepositoryUser(t, ctx, repository, commitRecord)
		err = repository.WithinTx(ctx, func(txCtx context.Context, tx identityservice.Tx) error {
			if _, err := tx.LockUsers(txCtx, []int64{commitUser.ID}); err != nil {
				return err
			}
			if _, err := tx.UpdateUser(txCtx, identityservice.UserMutation{
				UserID:      commitUser.ID,
				DisplayName: identityservice.SetField("Commit Must Roll Back"),
				UpdatedAt:   identityservice.SetField(now.Add(2 * time.Minute)),
			}); err != nil {
				return err
			}
			// A PostgreSQL statement error aborts the transaction. Ignoring the safe
			// adapter error forces the commit path to prove it cannot persist prior writes.
			_ = tx.InsertAudit(txCtx, identityservice.AuditEntry{
				ActorType:  identityservice.AuditActorType("invalid"),
				Action:     "user.status_changed",
				TargetType: "user",
				TargetID:   commitUser.ID,
				Detail:     map[string]any{},
				CreatedAt:  now,
			})
			return nil
		})
		if !errors.Is(err, identityservice.ErrInternal) {
			t.Fatalf("commit error = %v, want ErrInternal", err)
		}
		assertSafeRepositoryError(t, err, "audit_logs", "check constraint")
		assertDisplayName(t, ctx, repository, commitUser.ID, commitRecord.DisplayName)
	})

	t.Run("context deadline bounds row lock waiting", func(t *testing.T) {
		testCtx, cancelTest := context.WithTimeout(ctx, repositoryConcurrentTestTimeout)
		defer cancelTest()
		now := repositoryTestTime()
		user := createRepositoryUser(t, testCtx, repository, repositoryUserRecord(t, "lock-deadline", now))
		locked := make(chan struct{})
		release := make(chan struct{})
		holderDone := make(chan error, 1)
		go func() {
			holderDone <- repository.WithinTx(testCtx, func(txCtx context.Context, tx identityservice.Tx) error {
				if _, err := tx.LockUsers(txCtx, []int64{user.ID}); err != nil {
					return err
				}
				close(locked)
				select {
				case <-release:
					return nil
				case <-txCtx.Done():
					return txCtx.Err()
				}
			})
		}()
		released := false
		holderWaited := false
		defer func() {
			if !released {
				close(release)
			}
			if !holderWaited {
				cleanupErrorWorker(t, "lock holder", holderDone)
			}
		}()
		holderWaited, err := waitForWorkerReady(testCtx, locked, holderDone)
		if err != nil {
			t.Fatalf("lock holder failed before acquiring its lock: %v", err)
		}

		deadlineCtx, cancelDeadline := context.WithTimeout(testCtx, repositoryLockAttemptTimeout)
		started := time.Now()
		err = repository.WithinTx(deadlineCtx, func(txCtx context.Context, tx identityservice.Tx) error {
			_, err := tx.LockUsers(txCtx, []int64{user.ID})
			return err
		})
		cancelDeadline()
		if !errors.Is(err, identityservice.ErrInternal) || !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("lock wait error = %v, want ErrInternal and context.DeadlineExceeded", err)
		}
		if elapsed := time.Since(started); elapsed > 2*time.Second {
			t.Fatalf("lock wait ignored context deadline: elapsed %v", elapsed)
		}

		close(release)
		released = true
		holderErr, waitErr := receiveBeforeContextDone(testCtx, holderDone)
		if waitErr != nil {
			t.Fatalf("wait for lock holder: %v", waitErr)
		}
		holderWaited = true
		if holderErr != nil {
			t.Fatalf("lock holder transaction error = %v", holderErr)
		}
	})
}

func openRepositoryDatabase(t *testing.T) (context.Context, *sql.DB, *identitypostgres.Repository) {
	t.Helper()
	databaseURL := testkit.DatabaseURL(t)
	ctx, cancel := context.WithTimeout(context.Background(), repositoryIntegrationTimeout)
	t.Cleanup(cancel)

	adminDB, err := postgres.Open(ctx, config.DatabaseConfig{
		URL:             databaseURL,
		MaxOpenConns:    5,
		MaxIdleConns:    2,
		ConnMaxLifetime: time.Minute,
		PingTimeout:     3 * time.Second,
	})
	if err != nil {
		t.Fatalf("postgres.Open() error = %v", err)
	}

	schema := "identity_repository_test_" + randomRepositoryTestSuffix(t)
	if _, err := adminDB.ExecContext(ctx, "CREATE SCHEMA "+quoteIdentifier(schema)); err != nil {
		_ = adminDB.Close()
		t.Fatalf("create isolated schema: %v", err)
	}
	var db *sql.DB
	t.Cleanup(func() {
		if db != nil {
			if err := db.Close(); err != nil {
				t.Errorf("close isolated PostgreSQL pool: %v", err)
			}
		}
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), repositoryCleanupTimeout)
		defer cleanupCancel()
		if _, err := adminDB.ExecContext(cleanupCtx, "DROP SCHEMA IF EXISTS "+quoteIdentifier(schema)+" CASCADE"); err != nil {
			t.Errorf("drop isolated schema: %v", err)
		}
		if err := adminDB.Close(); err != nil {
			t.Errorf("close PostgreSQL admin connection: %v", err)
		}
	})

	config, err := pgx.ParseConfig(databaseURL)
	if err != nil {
		t.Fatalf("parse isolated PostgreSQL configuration: %v", err)
	}
	config.RuntimeParams["search_path"] = schema
	db = stdlib.OpenDB(*config)
	db.SetMaxOpenConns(8)
	db.SetMaxIdleConns(4)
	db.SetConnMaxLifetime(time.Minute)
	if err := db.PingContext(ctx); err != nil {
		t.Fatalf("ping isolated PostgreSQL connection: %v", err)
	}

	if err := migration.Run(ctx, db, repositoryMigrationsDirectory(t), "up"); err != nil {
		t.Fatalf("run identity migrations: %v", err)
	}
	return ctx, db, identitypostgres.New(db)
}

func openAdditionalRepositoryDatabase(t *testing.T, ctx context.Context, databaseURL, schema, applicationName string) (*sql.DB, *identitypostgres.Repository) {
	t.Helper()
	config, err := pgx.ParseConfig(databaseURL)
	if err != nil {
		t.Fatalf("parse additional PostgreSQL configuration: %v", err)
	}
	config.RuntimeParams["search_path"] = schema
	config.RuntimeParams["application_name"] = applicationName
	db := stdlib.OpenDB(*config)
	db.SetMaxOpenConns(2)
	db.SetMaxIdleConns(1)
	db.SetConnMaxLifetime(time.Minute)
	t.Cleanup(func() {
		if err := db.Close(); err != nil {
			t.Errorf("close additional PostgreSQL pool: %v", err)
		}
	})
	pingCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	if err := db.PingContext(pingCtx); err != nil {
		t.Fatalf("ping additional PostgreSQL connection: %v", err)
	}
	return db, identitypostgres.New(db)
}

func waitForApplicationLockWait[T any](ctx context.Context, db *sql.DB, applicationName string, workerDone <-chan T) (T, bool, error) {
	var zero T
	waitCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		var waiting bool
		if err := db.QueryRowContext(waitCtx, `
			SELECT EXISTS (
				SELECT 1
				FROM pg_stat_activity
				WHERE application_name = $1
				  AND wait_event_type = 'Lock'
			)`, applicationName).Scan(&waiting); err != nil {
			return zero, false, fmt.Errorf("inspect PostgreSQL lock wait: %w", err)
		}
		if waiting {
			return zero, false, nil
		}
		select {
		case result, ok := <-workerDone:
			if !ok {
				return zero, true, errResultChannelClosed
			}
			return result, true, nil
		case <-ticker.C:
		case <-waitCtx.Done():
			return zero, false, fmt.Errorf("session lock candidate did not enter a PostgreSQL lock wait: %w", waitCtx.Err())
		}
	}
}

func repositoryMigrationsDirectory(t *testing.T) string {
	t.Helper()
	_, sourceFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller() could not locate integration test")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(sourceFile), "..", "..", "..", "..", "migrations"))
}

func repositoryUserRecord(t *testing.T, prefix string, now time.Time) identityservice.CreateUserRecord {
	t.Helper()
	suffix := randomRepositoryTestSuffix(t)
	return identityservice.CreateUserRecord{
		Email:          prefix + "-" + suffix + "@example.test",
		PasswordHash:   "$2a$10$repository-test-password-hash-" + suffix,
		DisplayName:    "Repository " + suffix,
		Bio:            "",
		Role:           domain.RoleUser,
		Status:         domain.StatusActive,
		ViolationCount: 0,
		CreatedAt:      now,
		UpdatedAt:      now,
	}
}

func createRepositoryUser(t *testing.T, ctx context.Context, repository identityservice.Repository, record identityservice.CreateUserRecord) domain.User {
	t.Helper()
	user, err := repository.CreateUser(ctx, record)
	if err != nil {
		t.Fatalf("CreateUser(%q) error = %v", record.Email, err)
	}
	return user
}

func createRepositorySession(t *testing.T, ctx context.Context, repository identityservice.Repository, userID int64, hash [32]byte, createdAt, expiresAt time.Time) domain.UserSession {
	t.Helper()
	var session domain.UserSession
	err := repository.WithinTx(ctx, func(txCtx context.Context, tx identityservice.Tx) error {
		if _, err := tx.LockUsers(txCtx, []int64{userID}); err != nil {
			return err
		}
		created, err := tx.CreateSession(txCtx, identityservice.CreateSessionRecord{
			UserID:    userID,
			TokenHash: hash,
			ExpiresAt: expiresAt,
			CreatedAt: createdAt,
		})
		if err != nil {
			return err
		}
		session = created
		return nil
	})
	if err != nil {
		t.Fatalf("create session for user %d: %v", userID, err)
	}
	return session
}

func updateRepositoryUser(t *testing.T, ctx context.Context, repository identityservice.Repository, mutation identityservice.UserMutation) domain.User {
	t.Helper()
	var updated domain.User
	err := repository.WithinTx(ctx, func(txCtx context.Context, tx identityservice.Tx) error {
		if _, err := tx.LockUsers(txCtx, []int64{mutation.UserID}); err != nil {
			return err
		}
		var err error
		updated, err = tx.UpdateUser(txCtx, mutation)
		return err
	})
	if err != nil {
		t.Fatalf("UpdateUser(%d) error = %v", mutation.UserID, err)
	}
	return updated
}

func assertUsersEqual(t *testing.T, got, want domain.User) {
	t.Helper()
	if got.ID != want.ID {
		t.Fatalf("user ID = %d, want %d", got.ID, want.ID)
	}
	if got.Email != want.Email {
		t.Fatal("user email did not match")
	}
	if got.PasswordHash != want.PasswordHash {
		t.Fatal("user password_hash did not match")
	}
	if got.DisplayName != want.DisplayName || got.Bio != want.Bio {
		t.Fatal("user profile fields did not match")
	}
	if got.Role != want.Role || got.Status != want.Status || got.ViolationCount != want.ViolationCount {
		t.Fatalf("user role/status/count = (%q, %q, %d), want (%q, %q, %d)", got.Role, got.Status, got.ViolationCount, want.Role, want.Status, want.ViolationCount)
	}
	if !got.CreatedAt.Equal(want.CreatedAt) || !got.UpdatedAt.Equal(want.UpdatedAt) {
		t.Fatal("user created_at or updated_at did not match")
	}
	if !optionalTimesEqual(got.MutedUntil, want.MutedUntil) || !optionalTimesEqual(got.DeletedAt, want.DeletedAt) {
		t.Fatal("user muted_until or deleted_at did not match")
	}
}

func optionalTimesEqual(left, right *time.Time) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	return left.Equal(*right)
}

func assertIDs(t *testing.T, got, want []int64) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("ids = %v, want %v", got, want)
	}
	for index := range want {
		if got[index] != want[index] {
			t.Fatalf("ids = %v, want %v", got, want)
		}
	}
}

func equalIDs(got, want []int64) bool {
	if len(got) != len(want) {
		return false
	}
	for index := range want {
		if got[index] != want[index] {
			return false
		}
	}
	return true
}

func lockedUserIDs(users []identityservice.LockedUser) []int64 {
	ids := make([]int64, len(users))
	for index := range users {
		ids[index] = users[index].ID
	}
	return ids
}

func sessionIDs(sessions []domain.UserSession) []int64 {
	ids := make([]int64, len(sessions))
	for index := range sessions {
		ids[index] = sessions[index].ID
	}
	return ids
}

func readSessionTokenAndExpiry(t *testing.T, ctx context.Context, db *sql.DB, sessionID int64) ([]byte, time.Time) {
	t.Helper()
	var hash []byte
	var expiresAt time.Time
	if err := db.QueryRowContext(ctx, "SELECT token_hash, expires_at FROM user_sessions WHERE id = $1", sessionID).Scan(&hash, &expiresAt); err != nil {
		t.Fatalf("read session %d: %v", sessionID, err)
	}
	return hash, expiresAt
}

func readSessionRevokedAt(t *testing.T, ctx context.Context, db *sql.DB, sessionID int64) *time.Time {
	t.Helper()
	var revokedAt sql.NullTime
	if err := db.QueryRowContext(ctx, "SELECT revoked_at FROM user_sessions WHERE id = $1", sessionID).Scan(&revokedAt); err != nil {
		t.Fatalf("read session %d revoked_at: %v", sessionID, err)
	}
	if !revokedAt.Valid {
		return nil
	}
	return &revokedAt.Time
}

func countAuditActions(t *testing.T, ctx context.Context, db *sql.DB, targetID int64, action string) int {
	t.Helper()
	var count int
	if err := db.QueryRowContext(ctx, "SELECT count(*) FROM audit_logs WHERE target_id = $1 AND action = $2", targetID, action).Scan(&count); err != nil {
		t.Fatalf("count audit logs: %v", err)
	}
	return count
}

func assertDisplayName(t *testing.T, ctx context.Context, repository identityservice.Repository, userID int64, want string) {
	t.Helper()
	user, err := repository.FindUser(ctx, userID)
	if err != nil {
		t.Fatalf("FindUser(%d) error = %v", userID, err)
	}
	if user.DisplayName != want {
		t.Fatalf("user %d display_name = %q, want %q", userID, user.DisplayName, want)
	}
}

func assertSafeRepositoryError(t *testing.T, err error, forbidden ...string) {
	t.Helper()
	if err == nil {
		t.Fatal("expected repository error")
	}
	message := strings.ToLower(err.Error())
	for _, value := range forbidden {
		if value != "" && strings.Contains(message, strings.ToLower(value)) {
			t.Fatal("repository error leaked a forbidden detail")
		}
	}
	var postgresError *pgconn.PgError
	if errors.As(err, &postgresError) {
		t.Fatalf("repository error exposed PostgreSQL driver error: %T", postgresError)
	}
}

func hashByte(value byte) [32]byte {
	var hash [32]byte
	for index := range hash {
		hash[index] = value
	}
	return hash
}

func repositoryTestTime() time.Time {
	return time.Now().UTC().Truncate(time.Microsecond)
}

func randomRepositoryTestSuffix(t *testing.T) string {
	t.Helper()
	var random [8]byte
	if _, err := rand.Read(random[:]); err != nil {
		t.Fatalf("generate isolated test identifier: %v", err)
	}
	return hex.EncodeToString(random[:])
}

func quoteIdentifier(identifier string) string {
	return `"` + strings.ReplaceAll(identifier, `"`, `""`) + `"`
}
