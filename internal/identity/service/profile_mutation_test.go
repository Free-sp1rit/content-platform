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
)

func TestUpdateMeNoOpStillAuthenticatesInTransaction(t *testing.T) {
	tests := []struct {
		name        string
		displayName Field[string]
		bio         Field[string]
	}{
		{name: "absent fields"},
		{name: "JSON null mapped to unset patches", displayName: Field[string]{Value: "ignored"}, bio: Field[string]{Value: "ignored"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			repository := newProfileMutationRepository(domain.StatusActive)
			service := &Service{repository: repository, clock: &profileMutationClock{now: profileNow, repository: repository}}

			got, err := service.UpdateMe(context.Background(), UpdateMeInput{
				UserID: profileUserID, SessionID: profileSessionID, RequestID: "update-no-op",
				DisplayName: tt.displayName, Bio: tt.bio,
			})

			if err != nil {
				t.Fatalf("UpdateMe() error = %v", err)
			}
			if !reflect.DeepEqual(got, safeProfileUser(repository.user).View()) {
				t.Fatalf("UpdateMe() = %#v, want latest safe view", got)
			}
			if repository.updateCalls != 0 {
				t.Fatalf("UpdateUser() calls = %d, want 0", repository.updateCalls)
			}
			assertMutationEvents(t, repository, "begin_tx", "lock_users", "lock_session", "clock", "commit")
		})
	}
}

func TestUpdateMeValidatesAndAppliesProfilePatch(t *testing.T) {
	t.Run("display name is normalized and empty is rejected before transaction", func(t *testing.T) {
		repository := newProfileMutationRepository(domain.StatusActive)
		service := newProfileMutationService(repository)

		got, err := service.UpdateMe(context.Background(), UpdateMeInput{
			UserID: profileUserID, SessionID: profileSessionID,
			DisplayName: SetField("   "),
		})

		if got != (domain.UserView{}) || !errors.Is(err, ErrValidationFailed) {
			t.Fatalf("UpdateMe(empty display name) = %#v/%v, want zero/validation", got, err)
		}
		var validation *ValidationError
		if !errors.As(err, &validation) || validation.Field() != ValidationFieldDisplayName {
			t.Fatalf("validation field = %v, want display_name", validation)
		}
		assertMutationEvents(t, repository)
	})

	t.Run("bio rune limit is rejected before transaction", func(t *testing.T) {
		repository := newProfileMutationRepository(domain.StatusActive)
		service := newProfileMutationService(repository)
		_, err := service.UpdateMe(context.Background(), UpdateMeInput{
			UserID: profileUserID, SessionID: profileSessionID,
			Bio: SetField(strings.Repeat("界", 1001)),
		})
		var validation *ValidationError
		if !errors.As(err, &validation) || validation.Field() != ValidationFieldBio {
			t.Fatalf("UpdateMe(long bio) error = %v, want bio validation", err)
		}
		assertMutationEvents(t, repository)
	})

	t.Run("changed fields update once with normalized shared now", func(t *testing.T) {
		repository := newProfileMutationRepository(domain.StatusPending)
		service := newProfileMutationService(repository)
		got, err := service.UpdateMe(context.Background(), UpdateMeInput{
			UserID: profileUserID, SessionID: profileSessionID, RequestID: "patch-request",
			DisplayName: SetField("  New Name  "), Bio: SetField(""),
		})
		if err != nil {
			t.Fatalf("UpdateMe(changed patch) error = %v", err)
		}
		if got.DisplayName != "New Name" || got.Bio != "" || !got.UpdatedAt.Equal(profileNow) {
			t.Fatalf("UpdateMe(changed patch) = %#v", got)
		}
		if repository.updateCalls != 1 {
			t.Fatalf("UpdateUser calls = %d, want 1", repository.updateCalls)
		}
		if repository.lastMutation.DisplayName != SetField("New Name") || repository.lastMutation.Bio != SetField("") || repository.lastMutation.UpdatedAt != SetField(profileNow) {
			t.Fatalf("mutation = %#v, want normalized profile patch at shared now", repository.lastMutation)
		}
		assertSafeMutationView(t, got)
		assertMutationEvents(t, repository, "begin_tx", "lock_users", "lock_session", "clock", "update_user", "commit")
	})

	t.Run("same normalized values are a row-version no-op", func(t *testing.T) {
		repository := newProfileMutationRepository(domain.StatusMuted)
		repository.user.MutedUntil = profileTimePointer(profileNow.Add(time.Minute))
		service := newProfileMutationService(repository)
		got, err := service.UpdateMe(context.Background(), UpdateMeInput{
			UserID: profileUserID, SessionID: profileSessionID,
			DisplayName: SetField("  Profile User  "), Bio: SetField(repository.user.Bio),
		})
		if err != nil || repository.updateCalls != 0 || !got.UpdatedAt.Equal(repository.user.UpdatedAt) {
			t.Fatalf("UpdateMe(same patch) = %#v/%v updateCalls=%d", got, err, repository.updateCalls)
		}
	})
}

func TestUpdateMeEnforcesLockedAuthenticationAndFrozenPolicy(t *testing.T) {
	revokedAt := profileNow.Add(-time.Minute)
	deletedAt := profileNow.Add(-time.Minute)
	tests := []struct {
		name      string
		configure func(*profileMutationRepositoryFake)
		want      error
	}{
		{name: "frozen", configure: func(r *profileMutationRepositoryFake) { r.user.Status = domain.StatusFrozen }, want: ErrUserFrozen},
		{name: "banned", configure: func(r *profileMutationRepositoryFake) { r.user.Status = domain.StatusBanned }, want: ErrSessionInvalid},
		{name: "deleted", configure: func(r *profileMutationRepositoryFake) {
			r.user.Status, r.user.DeletedAt = domain.StatusDeleted, &deletedAt
		}, want: ErrSessionInvalid},
		{name: "wrong owner", configure: func(r *profileMutationRepositoryFake) { r.session.UserID++ }, want: ErrSessionInvalid},
		{name: "revoked", configure: func(r *profileMutationRepositoryFake) { r.session.RevokedAt = &revokedAt }, want: ErrSessionInvalid},
		{name: "expired", configure: func(r *profileMutationRepositoryFake) { r.session.ExpiresAt = profileNow }, want: ErrSessionInvalid},
		{name: "missing session", configure: func(r *profileMutationRepositoryFake) { r.lockSessionErr = ErrNotFound }, want: ErrSessionInvalid},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			repository := newProfileMutationRepository(domain.StatusActive)
			tt.configure(repository)
			before := cloneProfileUser(repository.user)
			got, err := newProfileMutationService(repository).UpdateMe(context.Background(), UpdateMeInput{
				UserID: profileUserID, SessionID: profileSessionID, DisplayName: SetField("Changed"),
			})
			if got != (domain.UserView{}) || err != tt.want {
				t.Fatalf("UpdateMe() = %#v/%v, want zero/%v", got, err, tt.want)
			}
			if !reflect.DeepEqual(repository.user, before) || repository.updateCalls != 0 {
				t.Fatal("failed UpdateMe committed a profile mutation")
			}
		})
	}
}

func TestUpdateMeRecoversExpiredMuteBeforePatchAndAuditsLast(t *testing.T) {
	repository := newProfileMutationRepository(domain.StatusMuted)
	expiredAt := profileNow.Add(-time.Minute)
	repository.user.MutedUntil = &expiredAt
	got, err := newProfileMutationService(repository).UpdateMe(context.Background(), UpdateMeInput{
		UserID: profileUserID, SessionID: profileSessionID, RequestID: "recover-update",
		Bio: SetField("new bio"),
	})
	if err != nil {
		t.Fatalf("UpdateMe(expired mute) error = %v", err)
	}
	if got.Status != domain.StatusActive || got.MutedUntil != nil || got.Bio != "new bio" {
		t.Fatalf("UpdateMe(expired mute) = %#v", got)
	}
	if len(repository.audits) != 1 || repository.audits[0].Detail["request_id"] != "recover-update" {
		t.Fatalf("audits = %#v, want one request-scoped mute recovery", repository.audits)
	}
	assertMutationEvents(t, repository, "begin_tx", "lock_users", "lock_session", "clock", "recover_mute", "update_user", "insert_audit", "commit")
}

func TestUpdateMeNoOpMayCommitOnlyExpiredMuteRecovery(t *testing.T) {
	repository := newProfileMutationRepository(domain.StatusMuted)
	expiredAt := profileNow
	repository.user.MutedUntil = &expiredAt
	got, err := newProfileMutationService(repository).UpdateMe(context.Background(), UpdateMeInput{
		UserID: profileUserID, SessionID: profileSessionID, RequestID: "recover-only",
	})
	if err != nil || got.Status != domain.StatusActive || got.MutedUntil != nil {
		t.Fatalf("UpdateMe(recovery-only) = %#v/%v", got, err)
	}
	if repository.updateCalls != 0 || len(repository.audits) != 1 {
		t.Fatalf("recovery-only update/audit calls = %d/%d, want 0/1", repository.updateCalls, len(repository.audits))
	}
	assertMutationEvents(t, repository, "begin_tx", "lock_users", "lock_session", "clock", "recover_mute", "insert_audit", "commit")
}

func TestUpdateMeRollsBackUpdateRecoveryAndAuditFailures(t *testing.T) {
	privateCause := errors.New("private profile SQL password token")
	tests := []struct {
		name      string
		configure func(*profileMutationRepositoryFake)
	}{
		{name: "update failure", configure: func(r *profileMutationRepositoryFake) { r.updateErr = privateCause }},
		{name: "mute recovery failure", configure: func(r *profileMutationRepositoryFake) { r.recoverErr = privateCause }},
		{name: "audit failure", configure: func(r *profileMutationRepositoryFake) { r.insertAuditErr = privateCause }},
		{name: "commit failure", configure: func(r *profileMutationRepositoryFake) { r.commitErr = privateCause }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			repository := newProfileMutationRepository(domain.StatusMuted)
			expiredAt := profileNow.Add(-time.Minute)
			repository.user.MutedUntil = &expiredAt
			tt.configure(repository)
			before := cloneProfileUser(repository.user)
			got, err := newProfileMutationService(repository).UpdateMe(context.Background(), UpdateMeInput{
				UserID: profileUserID, SessionID: profileSessionID, Bio: SetField("changed"),
			})
			if got != (domain.UserView{}) || !errors.Is(err, ErrInternal) || strings.Contains(err.Error(), privateCause.Error()) {
				t.Fatalf("UpdateMe(failure) = %#v/%v, want safe zero/internal", got, err)
			}
			if !reflect.DeepEqual(repository.user, before) || len(repository.audits) != 0 {
				t.Fatal("UpdateMe failure committed partial user or audit state")
			}
		})
	}
}

func TestDeleteMeSoftDeletesAndRevokesEveryActiveSessionInOrder(t *testing.T) {
	repository := newProfileMutationRepository(domain.StatusActive)
	repository.sessions = []domain.UserSession{
		profileSession(9, profileNow.Add(3*time.Hour)),
		profileSession(profileSessionID, profileNow.Add(time.Hour)),
		profileSession(3, profileNow.Add(-30*time.Minute)),
	}
	result, err := newProfileMutationService(repository).DeleteMe(context.Background(), DeleteMeInput{
		UserID: profileUserID, SessionID: profileSessionID, RequestID: "delete-request",
	})
	if err != nil || result != (DeleteMeResult{Deleted: true}) {
		t.Fatalf("DeleteMe() = %#v/%v", result, err)
	}
	if repository.user.Status != domain.StatusDeleted || repository.user.DeletedAt == nil || !repository.user.DeletedAt.Equal(profileNow) || repository.user.MutedUntil != nil || !repository.user.UpdatedAt.Equal(profileNow) {
		t.Fatalf("deleted user = %#v", repository.user)
	}
	if !reflect.DeepEqual(repository.revokedIDs, []int64{3, 9, profileSessionID}) || !repository.revokedAt.Equal(profileNow) {
		t.Fatalf("revocation = %v at %v", repository.revokedIDs, repository.revokedAt)
	}
	for _, session := range repository.sessions {
		if session.RevokedAt == nil || !session.RevokedAt.Equal(profileNow) {
			t.Fatalf("session %d not revoked at shared now", session.ID)
		}
	}
	assertMutationEvents(t, repository, "begin_tx", "lock_users", "lock_active_sessions", "clock", "update_user", "revoke_sessions", "commit")
}

func TestDeleteMeRecoversMuteThenMutatesSessionsBeforeAudit(t *testing.T) {
	repository := newProfileMutationRepository(domain.StatusMuted)
	expiredAt := profileNow.Add(-time.Second)
	repository.user.MutedUntil = &expiredAt
	result, err := newProfileMutationService(repository).DeleteMe(context.Background(), DeleteMeInput{
		UserID: profileUserID, SessionID: profileSessionID, RequestID: "recover-delete",
	})
	if err != nil || !result.Deleted || len(repository.audits) != 1 {
		t.Fatalf("DeleteMe(recovery) = %#v/%v audits=%d", result, err, len(repository.audits))
	}
	assertMutationEvents(t, repository, "begin_tx", "lock_users", "lock_active_sessions", "clock", "recover_mute", "update_user", "revoke_sessions", "insert_audit", "commit")
}

func TestDeleteMeRejectsFrozenAndInvalidLockedState(t *testing.T) {
	deletedAt := profileNow.Add(-time.Minute)
	tests := []struct {
		name      string
		configure func(*profileMutationRepositoryFake)
		want      error
	}{
		{name: "frozen", configure: func(r *profileMutationRepositoryFake) { r.user.Status = domain.StatusFrozen }, want: ErrUserFrozen},
		{name: "banned", configure: func(r *profileMutationRepositoryFake) { r.user.Status = domain.StatusBanned }, want: ErrSessionInvalid},
		{name: "deleted", configure: func(r *profileMutationRepositoryFake) {
			r.user.Status, r.user.DeletedAt = domain.StatusDeleted, &deletedAt
		}, want: ErrSessionInvalid},
		{name: "current session missing", configure: func(r *profileMutationRepositoryFake) {
			r.sessions = []domain.UserSession{profileSession(1, profileNow.Add(time.Hour))}
		}, want: ErrSessionInvalid},
		{name: "current session wrong owner", configure: func(r *profileMutationRepositoryFake) { r.sessions[0].UserID++ }, want: ErrSessionInvalid},
		{name: "current session revoked", configure: func(r *profileMutationRepositoryFake) {
			revokedAt := profileNow.Add(-time.Minute)
			r.sessions[0].RevokedAt = &revokedAt
		}, want: ErrSessionInvalid},
		{name: "current session expired", configure: func(r *profileMutationRepositoryFake) { r.sessions[0].ExpiresAt = profileNow }, want: ErrSessionInvalid},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			repository := newProfileMutationRepository(domain.StatusActive)
			tt.configure(repository)
			before := cloneProfileUser(repository.user)
			got, err := newProfileMutationService(repository).DeleteMe(context.Background(), DeleteMeInput{UserID: profileUserID, SessionID: profileSessionID})
			if got != (DeleteMeResult{}) || err != tt.want {
				t.Fatalf("DeleteMe() = %#v/%v, want zero/%v", got, err, tt.want)
			}
			if !reflect.DeepEqual(repository.user, before) || len(repository.revokedIDs) != 0 {
				t.Fatal("failed DeleteMe committed state")
			}
		})
	}
}

func TestDeleteMeRollsBackUserSessionsAndAuditOnFailures(t *testing.T) {
	privateCause := errors.New("private revoke database URL")
	tests := []struct {
		name      string
		configure func(*profileMutationRepositoryFake)
	}{
		{name: "user update", configure: func(r *profileMutationRepositoryFake) { r.updateErr = privateCause }},
		{name: "mute recovery", configure: func(r *profileMutationRepositoryFake) { r.recoverErr = privateCause }},
		{name: "revoke", configure: func(r *profileMutationRepositoryFake) { r.revokeErr = privateCause }},
		{name: "audit", configure: func(r *profileMutationRepositoryFake) { r.insertAuditErr = privateCause }},
		{name: "commit", configure: func(r *profileMutationRepositoryFake) { r.commitErr = privateCause }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			repository := newProfileMutationRepository(domain.StatusMuted)
			expiredAt := profileNow.Add(-time.Second)
			repository.user.MutedUntil = &expiredAt
			tt.configure(repository)
			beforeUser := cloneProfileUser(repository.user)
			beforeSessions := cloneMutationSessions(repository.sessions)
			got, err := newProfileMutationService(repository).DeleteMe(context.Background(), DeleteMeInput{UserID: profileUserID, SessionID: profileSessionID})
			if got != (DeleteMeResult{}) || !errors.Is(err, ErrInternal) || strings.Contains(err.Error(), privateCause.Error()) {
				t.Fatalf("DeleteMe(failure) = %#v/%v", got, err)
			}
			if !reflect.DeepEqual(repository.user, beforeUser) || !reflect.DeepEqual(repository.sessions, beforeSessions) || len(repository.audits) != 0 {
				t.Fatal("DeleteMe failure committed partial state")
			}
		})
	}
}

func TestProfileMutationResultsDoNotExposeSecrets(t *testing.T) {
	repository := newProfileMutationRepository(domain.StatusActive)
	view, err := newProfileMutationService(repository).UpdateMe(context.Background(), UpdateMeInput{UserID: profileUserID, SessionID: profileSessionID})
	if err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(view)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{profileSecret, "secret-token-hash", "password_hash", "token_hash"} {
		if strings.Contains(string(payload), secret) {
			t.Fatalf("UpdateMe result exposed %q in %s", secret, payload)
		}
	}
}

func newProfileMutationService(repository *profileMutationRepositoryFake) *Service {
	return &Service{repository: repository, clock: &profileMutationClock{now: profileNow, repository: repository}}
}

func assertSafeMutationView(t *testing.T, view domain.UserView) {
	t.Helper()
	payload, err := json.Marshal(view)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(payload), profileSecret) || strings.Contains(string(payload), "password_hash") || strings.Contains(string(payload), "token_hash") {
		t.Fatalf("unsafe mutation view: %s", payload)
	}
}

func profileSession(id int64, expiresAt time.Time) domain.UserSession {
	return domain.UserSession{ID: id, UserID: profileUserID, TokenHash: []byte("secret-token-hash"), CreatedAt: profileNow.Add(-time.Hour), ExpiresAt: expiresAt}
}

type profileMutationRepositoryFake struct {
	repositoryPortStub
	user           domain.User
	session        domain.UserSession
	sessions       []domain.UserSession
	audits         []AuditEntry
	events         []string
	updateCalls    int
	lastMutation   UserMutation
	revokedIDs     []int64
	revokedAt      time.Time
	lockSessionErr error
	lockUsersErr   error
	lockActiveErr  error
	updateErr      error
	recoverErr     error
	revokeErr      error
	insertAuditErr error
	commitErr      error
}

type profileMutationClock struct {
	now        time.Time
	repository *profileMutationRepositoryFake
}

func (c *profileMutationClock) Now() time.Time {
	c.repository.events = append(c.repository.events, "clock")
	return c.now
}

func newProfileMutationRepository(status domain.Status) *profileMutationRepositoryFake {
	user := validProfileUser(status)
	repository := &profileMutationRepositoryFake{
		user: user,
		session: domain.UserSession{
			ID: profileSessionID, UserID: profileUserID, TokenHash: []byte("secret-token-hash"),
			CreatedAt: profileNow.Add(-time.Hour), ExpiresAt: profileNow.Add(time.Hour),
		},
	}
	repository.sessions = []domain.UserSession{repository.session}
	return repository
}

func (r *profileMutationRepositoryFake) WithinTx(ctx context.Context, callback func(context.Context, Tx) error) error {
	r.events = append(r.events, "begin_tx")
	tx := &profileMutationTxFake{
		repository: r,
		user:       cloneProfileUser(r.user),
		session:    cloneMutationSession(r.session),
		sessions:   cloneMutationSessions(r.sessions),
		audits:     cloneMutationAudits(r.audits),
	}
	if err := callback(ctx, tx); err != nil {
		r.events = append(r.events, "rollback")
		return err
	}
	r.events = append(r.events, "commit")
	if r.commitErr != nil {
		return r.commitErr
	}
	r.user = cloneProfileUser(tx.user)
	r.session = cloneMutationSession(tx.session)
	r.sessions = cloneMutationSessions(tx.sessions)
	r.audits = cloneMutationAudits(tx.audits)
	r.revokedIDs = append([]int64(nil), tx.revokedIDs...)
	r.revokedAt = tx.revokedAt
	return nil
}

type profileMutationTxFake struct {
	transactionPortStub
	repository *profileMutationRepositoryFake
	user       domain.User
	session    domain.UserSession
	sessions   []domain.UserSession
	audits     []AuditEntry
	revokedIDs []int64
	revokedAt  time.Time
}

func (tx *profileMutationTxFake) LockUsers(_ context.Context, ids []int64) ([]LockedUser, error) {
	tx.repository.events = append(tx.repository.events, "lock_users")
	if tx.repository.lockUsersErr != nil {
		return nil, tx.repository.lockUsersErr
	}
	if !reflect.DeepEqual(ids, []int64{profileUserID}) {
		return nil, errors.New("unexpected user lock IDs")
	}
	return []LockedUser{cloneProfileUser(tx.user)}, nil
}

func (tx *profileMutationTxFake) LockSession(_ context.Context, id int64) (domain.UserSession, error) {
	tx.repository.events = append(tx.repository.events, "lock_session")
	if tx.repository.lockSessionErr != nil {
		return domain.UserSession{}, tx.repository.lockSessionErr
	}
	if id != profileSessionID {
		return domain.UserSession{}, ErrNotFound
	}
	return cloneMutationSession(tx.session), nil
}

func (tx *profileMutationTxFake) LockActiveSessions(_ context.Context, userID int64) ([]domain.UserSession, error) {
	tx.repository.events = append(tx.repository.events, "lock_active_sessions")
	if tx.repository.lockActiveErr != nil {
		return nil, tx.repository.lockActiveErr
	}
	if userID != profileUserID {
		return nil, errors.New("unexpected active-session owner")
	}
	result := cloneMutationSessions(tx.sessions)
	for i := 0; i < len(result); i++ {
		for j := i + 1; j < len(result); j++ {
			if result[j].ID < result[i].ID {
				result[i], result[j] = result[j], result[i]
			}
		}
	}
	return result, nil
}

func (tx *profileMutationTxFake) UpdateUser(_ context.Context, mutation UserMutation) (domain.User, error) {
	r := tx.repository
	r.events = append(r.events, "update_user")
	r.updateCalls++
	r.lastMutation = mutation
	if r.updateErr != nil {
		return domain.User{}, r.updateErr
	}
	if mutation.UserID != tx.user.ID {
		return domain.User{}, ErrNotFound
	}
	if mutation.DisplayName.Set {
		tx.user.DisplayName = mutation.DisplayName.Value
	}
	if mutation.Bio.Set {
		tx.user.Bio = mutation.Bio.Value
	}
	if mutation.Status.Set {
		tx.user.Status = mutation.Status.Value
	}
	if mutation.MutedUntil.Set {
		tx.user.MutedUntil = cloneTimePointer(mutation.MutedUntil.Value)
	}
	if mutation.UpdatedAt.Set {
		tx.user.UpdatedAt = mutation.UpdatedAt.Value
	}
	if mutation.DeletedAt.Set {
		tx.user.DeletedAt = cloneTimePointer(mutation.DeletedAt.Value)
	}
	return cloneProfileUser(tx.user), nil
}

func (tx *profileMutationTxFake) RecoverExpiredMute(_ context.Context, userID int64, now time.Time) (domain.User, bool, error) {
	r := tx.repository
	r.events = append(r.events, "recover_mute")
	if r.recoverErr != nil {
		return domain.User{}, false, r.recoverErr
	}
	if userID != tx.user.ID || tx.user.Status != domain.StatusMuted || tx.user.MutedUntil == nil || tx.user.MutedUntil.After(now) {
		return domain.User{}, false, nil
	}
	tx.user.Status = domain.StatusActive
	tx.user.MutedUntil = nil
	tx.user.UpdatedAt = now
	return cloneProfileUser(tx.user), true, nil
}

func (tx *profileMutationTxFake) RevokeLockedSessions(_ context.Context, ids []int64, revokedAt time.Time) error {
	r := tx.repository
	r.events = append(r.events, "revoke_sessions")
	if r.revokeErr != nil {
		return r.revokeErr
	}
	tx.revokedIDs = append([]int64(nil), ids...)
	tx.revokedAt = revokedAt
	for index := range tx.sessions {
		for _, id := range ids {
			if tx.sessions[index].ID == id && tx.sessions[index].RevokedAt == nil {
				tx.sessions[index].RevokedAt = cloneTimePointer(&revokedAt)
			}
		}
	}
	return nil
}

func (tx *profileMutationTxFake) InsertAudit(_ context.Context, entry AuditEntry) error {
	r := tx.repository
	r.events = append(r.events, "insert_audit")
	if r.insertAuditErr != nil {
		return r.insertAuditErr
	}
	tx.audits = append(tx.audits, cloneProfileAudit(entry))
	return nil
}

func cloneMutationSession(session domain.UserSession) domain.UserSession {
	session.TokenHash = append([]byte(nil), session.TokenHash...)
	session.RevokedAt = cloneTimePointer(session.RevokedAt)
	return session
}

func cloneMutationSessions(sessions []domain.UserSession) []domain.UserSession {
	cloned := make([]domain.UserSession, len(sessions))
	for index := range sessions {
		cloned[index] = cloneMutationSession(sessions[index])
	}
	return cloned
}

func cloneMutationAudits(audits []AuditEntry) []AuditEntry {
	cloned := make([]AuditEntry, len(audits))
	for index := range audits {
		cloned[index] = cloneProfileAudit(audits[index])
	}
	return cloned
}

func cloneTimePointer(value *time.Time) *time.Time {
	if value == nil {
		return nil
	}
	cloned := *value
	return &cloned
}

func assertMutationEvents(t *testing.T, repository *profileMutationRepositoryFake, want ...string) {
	t.Helper()
	if !reflect.DeepEqual(repository.events, want) {
		t.Fatalf("events = %v, want %v", repository.events, want)
	}
}
