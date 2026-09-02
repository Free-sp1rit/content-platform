package service

import (
	"context"
	"errors"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Free-sp1rit/content-platform/internal/identity/domain"
)

func TestChangeUserStatusChangesActiveUserToMuted(t *testing.T) {
	now := time.Date(2026, time.September, 2, 8, 30, 45, 0, time.UTC)
	admin := statusTestUser(1, domain.RoleAdmin, domain.StatusActive)
	target := statusTestUser(2, domain.RoleUser, domain.StatusActive)
	repository := newStatusRepository(admin, target)
	service := statusTestService(repository, now)
	mutedUntil := now.Add(time.Hour)

	got, err := service.ChangeUserStatus(context.Background(), ChangeUserStatusInput{
		ActorID: 1, ActorSessionID: 10, TargetID: 2, NewStatus: domain.StatusMuted,
		MutedUntil: &mutedUntil, Reason: "  abuse  ", RequestID: "req-1",
	})
	if err != nil {
		t.Fatalf("ChangeUserStatus() error = %v", err)
	}
	if got.Status != domain.StatusMuted || got.MutedUntil == nil || got.MutedUntil.Sub(mutedUntil) != 0 {
		t.Fatalf("ChangeUserStatus() view = %#v, want muted target", got)
	}
}

func TestChangeUserStatusRejectsAuthorizationAndFieldFailuresBeforeTransaction(t *testing.T) {
	now := time.Date(2026, time.September, 2, 8, 30, 45, 0, time.UTC)
	admin := statusTestUser(1, domain.RoleAdmin, domain.StatusActive)
	target := statusTestUser(2, domain.RoleUser, domain.StatusActive)
	future := now.Add(time.Hour)
	tests := []struct {
		name  string
		input ChangeUserStatusInput
		users []domain.User
		want  error
	}{
		{name: "self target", input: ChangeUserStatusInput{ActorID: 1, ActorSessionID: 10, TargetID: 1, NewStatus: domain.StatusActive}, users: []domain.User{admin, target}, want: ErrAdminTargetForbidden},
		{name: "invalid status", input: ChangeUserStatusInput{ActorID: 1, ActorSessionID: 10, TargetID: 2, NewStatus: domain.StatusPending}, users: []domain.User{admin, target}, want: ErrValidationFailed},
		{name: "muted missing until", input: ChangeUserStatusInput{ActorID: 1, ActorSessionID: 10, TargetID: 2, NewStatus: domain.StatusMuted}, users: []domain.User{admin, target}, want: ErrValidationFailed},
		{name: "muted past until", input: ChangeUserStatusInput{ActorID: 1, ActorSessionID: 10, TargetID: 2, NewStatus: domain.StatusMuted, MutedUntil: func() *time.Time { v := now.Add(-time.Second); return &v }()}, users: []domain.User{admin, target}, want: ErrValidationFailed},
		{name: "non muted until", input: ChangeUserStatusInput{ActorID: 1, ActorSessionID: 10, TargetID: 2, NewStatus: domain.StatusActive, MutedUntil: &future}, users: []domain.User{admin, target}, want: ErrValidationFailed},
		{name: "non admin", input: ChangeUserStatusInput{ActorID: 1, ActorSessionID: 10, TargetID: 2, NewStatus: domain.StatusActive}, users: []domain.User{statusTestUser(1, domain.RoleUser, domain.StatusActive), target}, want: ErrAdminRequired},
		{name: "frozen admin", input: ChangeUserStatusInput{ActorID: 1, ActorSessionID: 10, TargetID: 2, NewStatus: domain.StatusActive}, users: []domain.User{statusTestUser(1, domain.RoleAdmin, domain.StatusFrozen), target}, want: ErrUserFrozen},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := statusTestService(newStatusRepository(tt.users...), now).ChangeUserStatus(context.Background(), tt.input)
			if !errors.Is(err, tt.want) {
				t.Fatalf("error = %v, want %v", err, tt.want)
			}
		})
	}
}

func TestChangeUserStatusNoOpAuthenticatesWithoutStatusWrites(t *testing.T) {
	now := time.Date(2026, time.September, 2, 8, 30, 45, 0, time.UTC)
	repo := newStatusRepository(statusTestUser(20, domain.RoleAdmin, domain.StatusActive), statusTestUser(9, domain.RoleUser, domain.StatusActive))
	repo.session.ID, repo.session.UserID = 31, 20
	got, err := statusTestService(repo, now).ChangeUserStatus(context.Background(), ChangeUserStatusInput{ActorID: 20, ActorSessionID: 31, TargetID: 9, NewStatus: domain.StatusActive})
	if err != nil || got.ID != 9 {
		t.Fatalf("result = %#v, %v events=%v users=%#v", got, err, repo.events, repo.users)
	}
	if len(repo.mutations) != 0 || len(repo.audits) != 0 || len(repo.revokedIDs) != 0 {
		t.Fatalf("no-op wrote state: mutations=%d audits=%d revoked=%v", len(repo.mutations), len(repo.audits), repo.revokedIDs)
	}
	if len(repo.events) < 2 || repo.events[0] != "lock-users" || repo.events[1] != "lock-session" {
		t.Fatalf("events = %v", repo.events)
	}
}

func TestChangeUserStatusRejectsInvalidActorSessionAndTargets(t *testing.T) {
	now := time.Date(2026, time.September, 2, 8, 30, 45, 0, time.UTC)
	deleted := statusTestUser(2, domain.RoleUser, domain.StatusDeleted)
	deletedAt := now.Add(-time.Hour)
	deleted.DeletedAt = &deletedAt
	tests := []struct {
		name      string
		users     []domain.User
		configure func(*statusRepositoryFake)
		want      error
	}{
		{name: "missing actor session", users: []domain.User{statusTestUser(1, domain.RoleAdmin, domain.StatusActive), statusTestUser(2, domain.RoleUser, domain.StatusActive)}, configure: func(r *statusRepositoryFake) { r.session = domain.UserSession{} }, want: ErrSessionInvalid},
		{name: "other admin", users: []domain.User{statusTestUser(1, domain.RoleAdmin, domain.StatusActive), statusTestUser(2, domain.RoleAdmin, domain.StatusActive)}, want: ErrAdminTargetForbidden},
		{name: "missing target", users: []domain.User{statusTestUser(1, domain.RoleAdmin, domain.StatusActive)}, want: ErrInvalidStatusTransition},
		{name: "deleted target", users: []domain.User{statusTestUser(1, domain.RoleAdmin, domain.StatusActive), deleted}, want: ErrInvalidStatusTransition},
		{name: "unknown target status", users: []domain.User{statusTestUser(1, domain.RoleAdmin, domain.StatusActive), statusTestUser(2, domain.RoleUser, domain.Status("secret"))}, want: ErrInvalidStatusTransition},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			repo := newStatusRepository(tt.users...)
			if tt.configure != nil {
				tt.configure(repo)
			}
			got, err := statusTestService(repo, now).ChangeUserStatus(context.Background(), ChangeUserStatusInput{ActorID: 1, ActorSessionID: 10, TargetID: 2, NewStatus: domain.StatusActive})
			if !errors.Is(err, tt.want) || got != (domain.UserView{}) {
				t.Fatalf("result=%#v err=%v", got, err)
			}
		})
	}
}

func TestChangeUserStatusAllowsApprovedTransitions(t *testing.T) {
	now := time.Date(2026, time.September, 2, 8, 30, 45, 0, time.UTC)
	tests := []struct {
		name      string
		old, next domain.Status
		until     *time.Time
	}{
		{name: "pending to active", old: domain.StatusPending, next: domain.StatusActive}, {name: "banned to active", old: domain.StatusBanned, next: domain.StatusActive},
		{name: "active to frozen", old: domain.StatusActive, next: domain.StatusFrozen}, {name: "muted to active", old: domain.StatusMuted, next: domain.StatusActive}, {name: "frozen to active", old: domain.StatusFrozen, next: domain.StatusActive},
	}
	future := now.Add(time.Hour)
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			target := statusTestUser(2, domain.RoleUser, tt.old)
			if tt.old == domain.StatusMuted {
				target.MutedUntil = &future
			}
			repo := newStatusRepository(statusTestUser(1, domain.RoleAdmin, domain.StatusActive), target)
			got, err := statusTestService(repo, now).ChangeUserStatus(context.Background(), ChangeUserStatusInput{ActorID: 1, ActorSessionID: 10, TargetID: 2, NewStatus: tt.next, MutedUntil: tt.until})
			if err != nil || got.Status != tt.next {
				t.Fatalf("result=%#v err=%v", got, err)
			}
		})
	}
}

func TestChangeUserStatusBanningLocksActorThenTargetSessionsAndRevokesAscending(t *testing.T) {
	now := time.Date(2026, time.September, 2, 8, 30, 45, 0, time.UTC)
	repo := newStatusRepository(statusTestUser(2, domain.RoleUser, domain.StatusActive), statusTestUser(1, domain.RoleAdmin, domain.StatusActive))
	repo.session.ID = 50
	repo.targetSessions = []domain.UserSession{{ID: 40, UserID: 2, CreatedAt: now.Add(-time.Hour), ExpiresAt: now.Add(time.Hour)}, {ID: 3, UserID: 2, CreatedAt: now.Add(-time.Hour), ExpiresAt: now.Add(time.Hour)}}
	got, err := statusTestService(repo, now).ChangeUserStatus(context.Background(), ChangeUserStatusInput{ActorID: 1, ActorSessionID: 50, TargetID: 2, NewStatus: domain.StatusBanned, Reason: "  severe abuse ", RequestID: "req-ban"})
	if err != nil || got.Status != domain.StatusBanned {
		t.Fatalf("result = %#v, %v", got, err)
	}
	if len(repo.events) < 3 || repo.events[1] != "lock-session" || repo.events[2] != "lock-active-sessions" {
		t.Fatalf("events = %v, want actor session then target sessions", repo.events)
	}
	wantIDs := []int64{3, 40}
	if len(repo.revokedIDs) != 2 || repo.revokedIDs[0] != wantIDs[0] || repo.revokedIDs[1] != wantIDs[1] {
		t.Fatalf("revoked = %v", repo.revokedIDs)
	}
	if len(repo.audits) != 1 || repo.audits[0].Action != "user.status_changed" || repo.audits[0].Detail["reason"] != "severe abuse" || repo.audits[0].Detail["request_id"] != "req-ban" {
		t.Fatalf("audits = %#v", repo.audits)
	}
	if repo.events[len(repo.events)-1] != "audit:user.status_changed" {
		t.Fatalf("status audit was not last: %v", repo.events)
	}
}

func TestChangeUserStatusRecoversExpiredMuteBeforeRequestedTransition(t *testing.T) {
	now := time.Date(2026, time.September, 2, 8, 30, 45, 0, time.UTC)
	admin := statusTestUser(1, domain.RoleAdmin, domain.StatusActive)
	target := statusTestUser(2, domain.RoleUser, domain.StatusMuted)
	expired := now.Add(-time.Minute)
	target.MutedUntil = &expired
	repo := newStatusRepository(admin, target)
	got, err := statusTestService(repo, now).ChangeUserStatus(context.Background(), ChangeUserStatusInput{ActorID: 1, ActorSessionID: 10, TargetID: 2, NewStatus: domain.StatusFrozen, RequestID: "req-recover"})
	if err != nil || got.Status != domain.StatusFrozen {
		t.Fatalf("result = %#v, %v", got, err)
	}
	if len(repo.audits) != 2 || repo.audits[0].Action != "user.mute_expired" || repo.audits[1].Action != "user.status_changed" {
		t.Fatalf("audits = %#v", repo.audits)
	}
	if repo.audits[1].Detail["old_status"] != domain.StatusActive {
		t.Fatalf("status audit detail = %#v", repo.audits[1].Detail)
	}
}

func TestChangeUserStatusFailuresReturnZeroViewAndRollBack(t *testing.T) {
	now := time.Date(2026, time.September, 2, 8, 30, 45, 0, time.UTC)
	tests := []struct {
		name      string
		configure func(*statusRepositoryFake)
		status    domain.Status
	}{
		{name: "update", status: domain.StatusFrozen, configure: func(r *statusRepositoryFake) { r.updateErr = errors.New("password_hash secret") }},
		{name: "revoke", status: domain.StatusBanned, configure: func(r *statusRepositoryFake) {
			r.targetSessions = []domain.UserSession{{ID: 4, UserID: 2, CreatedAt: now.Add(-time.Hour), ExpiresAt: now.Add(time.Hour)}}
			r.revokeErr = errors.New("token secret")
		}},
		{name: "audit", status: domain.StatusFrozen, configure: func(r *statusRepositoryFake) { r.auditErrAt = 1 }},
		{name: "recovery", status: domain.StatusFrozen, configure: func(r *statusRepositoryFake) { expired:=now.Add(-time.Minute); r.users[1].Status=domain.StatusMuted; r.users[1].MutedUntil=&expired; r.recoverErr=errors.New("sql secret") }},
		{name: "recovery audit", status: domain.StatusFrozen, configure: func(r *statusRepositoryFake) { expired:=now.Add(-time.Minute); r.users[1].Status=domain.StatusMuted; r.users[1].MutedUntil=&expired; r.auditErrAt=1 }},
		{name: "status audit after recovery", status: domain.StatusFrozen, configure: func(r *statusRepositoryFake) { expired:=now.Add(-time.Minute); r.users[1].Status=domain.StatusMuted; r.users[1].MutedUntil=&expired; r.auditErrAt=2 }},
		{name: "commit", status: domain.StatusFrozen, configure: func(r *statusRepositoryFake) { r.commitErr = errors.New("driver secret") }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			repo := newStatusRepository(statusTestUser(1, domain.RoleAdmin, domain.StatusActive), statusTestUser(2, domain.RoleUser, domain.StatusActive))
			tt.configure(repo)
			before := repo.users[1]
			got, err := statusTestService(repo, now).ChangeUserStatus(context.Background(), ChangeUserStatusInput{ActorID: 1, ActorSessionID: 10, TargetID: 2, NewStatus: tt.status})
			if !errors.Is(err, ErrInternal) || got != (domain.UserView{}) {
				t.Fatalf("result = %#v, %v", got, err)
			}
			if repo.users[1].Status != before.Status || len(repo.audits) != 0 || len(repo.revokedIDs) != 0 {
				t.Fatalf("failure leaked staged state: user=%#v audits=%d revoked=%v", repo.users[1], len(repo.audits), repo.revokedIDs)
			}
			if strings.Contains(err.Error(), "secret") {
				t.Fatalf("unsafe error = %q", err)
			}
		})
	}
}

func statusTestUser(id int64, role domain.Role, status domain.Status) domain.User {
	created := time.Date(2026, time.September, 1, 0, 0, 0, 0, time.UTC)
	return domain.User{ID: id, Email: "user" + strconv.FormatInt(id, 10) + "@example.com", PasswordHash: "hash", DisplayName: "User", Role: role, Status: status, CreatedAt: created, UpdatedAt: created}
}

func statusTestService(repository Repository, now time.Time) *Service {
	service, err := New(Dependencies{Repository: repository, PasswordHasher: statusPasswordStub{}, AccessTokenManager: statusTokenStub{}, RefreshTokenGenerator: statusRefreshStub{}, Clock: statusClockStub{now: now}}, Config{AccessTokenTTL: time.Minute, RefreshTokenTTL: 2 * time.Minute})
	if err != nil {
		panic(err)
	}
	return service
}

type statusClockStub struct{ now time.Time }

func (c statusClockStub) Now() time.Time { return c.now }

type statusPasswordStub struct{}

func (statusPasswordStub) Hash(string) (string, error)          { return "", nil }
func (statusPasswordStub) Compare(string, string) (bool, error) { return true, nil }
func (statusPasswordStub) DummyHash() string                    { return "" }
func (statusPasswordStub) DummyCandidate() string               { return "password" }

type statusTokenStub struct{}

func (statusTokenStub) GenerateJWTID() (string, error) { return "jti", nil }
func (statusTokenStub) Sign(int64, int64, time.Time, time.Time, string) (string, error) {
	return "token", nil
}

type statusRefreshStub struct{}

func (statusRefreshStub) Generate() (string, [32]byte, error)   { return "", [32]byte{}, nil }
func (statusRefreshStub) Format(int64, string) (string, error)  { return "", nil }
func (statusRefreshStub) Parse(string) (int64, [32]byte, error) { return 0, [32]byte{}, nil }
func (statusRefreshStub) Match([32]byte, [32]byte) bool         { return true }

type statusRepositoryFake struct {
	users          []domain.User
	session        domain.UserSession
	targetSessions []domain.UserSession
	events         []string
	audits         []AuditEntry
	mutations      []UserMutation
	revokedIDs     []int64
	txCalls        int
	updateErr      error
	revokeErr      error
	recoverErr     error
	auditErrAt     int
	commitErr      error
}

func (r *statusRepositoryFake) CreateUser(context.Context, CreateUserRecord) (domain.User, error) {
	return domain.User{}, ErrInternal
}
func (r *statusRepositoryFake) FindLoginCredential(context.Context, string) (LoginCredential, error) {
	return LoginCredential{}, ErrNotFound
}
func (r *statusRepositoryFake) FindUser(context.Context, int64) (domain.User, error) {
	return domain.User{}, ErrNotFound
}
func (r *statusRepositoryFake) FindAuthenticationState(context.Context, int64) (AuthenticationState, error) {
	return AuthenticationState{}, ErrNotFound
}
func (r *statusRepositoryFake) FindSessionOwner(context.Context, int64) (int64, error) {
	return 0, ErrNotFound
}
func (r *statusRepositoryFake) RevokeSession(context.Context, RevokeSessionRequest) error { return nil }
func (r *statusRepositoryFake) WithinTx(ctx context.Context, callback func(context.Context, Tx) error) error {
	r.txCalls++
	staged := *r
	staged.users = append([]domain.User(nil), r.users...)
	staged.audits = append([]AuditEntry(nil), r.audits...)
	staged.mutations = append([]UserMutation(nil), r.mutations...)
	staged.revokedIDs = append([]int64(nil), r.revokedIDs...)
	if err := callback(ctx, &statusTxFake{repo: &staged}); err != nil {
		r.events = staged.events
		return err
	}
	if r.commitErr != nil {
		return r.commitErr
	}
	r.users, r.events, r.audits, r.mutations, r.revokedIDs = staged.users, staged.events, staged.audits, staged.mutations, staged.revokedIDs
	return nil
}

type statusTxFake struct{ repo *statusRepositoryFake }

func (tx *statusTxFake) LockUsers(_ context.Context, ids []int64) ([]LockedUser, error) {
	tx.repo.events = append(tx.repo.events, "lock-users")
	ordered := append([]int64(nil), ids...)
	sort.Slice(ordered, func(i, j int) bool { return ordered[i] < ordered[j] })
	result := make([]domain.User, 0, len(ordered))
	for _, id := range ordered {
		for _, user := range tx.repo.users {
			if user.ID == id {
				result = append(result, user)
			}
		}
	}
	return result, nil
}
func (tx *statusTxFake) LockSession(context.Context, int64) (domain.UserSession, error) {
	tx.repo.events = append(tx.repo.events, "lock-session")
	if tx.repo.session.ID == 0 {
		return domain.UserSession{}, ErrNotFound
	}
	return tx.repo.session, nil
}
func (tx *statusTxFake) LockActiveSessions(context.Context, int64) ([]domain.UserSession, error) {
	tx.repo.events = append(tx.repo.events, "lock-active-sessions")
	result := append([]domain.UserSession(nil), tx.repo.targetSessions...)
	sort.Slice(result, func(i, j int) bool { return result[i].ID < result[j].ID })
	return result, nil
}
func (tx *statusTxFake) LockSessions(context.Context, SessionLockRequest) ([]domain.UserSession, error) {
	tx.repo.events = append(tx.repo.events, "lock-sessions")
	result := append([]domain.UserSession{tx.repo.session}, tx.repo.targetSessions...)
	sort.Slice(result, func(i, j int) bool { return result[i].ID < result[j].ID })
	return result, nil
}
func (tx *statusTxFake) CreateSession(context.Context, CreateSessionRecord) (domain.UserSession, error) {
	return domain.UserSession{}, ErrInternal
}
func (tx *statusTxFake) RotateSessionToken(context.Context, int64, [32]byte) error { return nil }
func (tx *statusTxFake) RevokeLockedSessions(_ context.Context, ids []int64, _ time.Time) error {
	tx.repo.events = append(tx.repo.events, "revoke")
	if tx.repo.revokeErr != nil {
		return tx.repo.revokeErr
	}
	tx.repo.revokedIDs = append(tx.repo.revokedIDs, ids...)
	return nil
}
func (tx *statusTxFake) UpdateUser(_ context.Context, mutation UserMutation) (domain.User, error) {
	tx.repo.events = append(tx.repo.events, "update")
	if tx.repo.updateErr != nil {
		return domain.User{}, tx.repo.updateErr
	}
	tx.repo.mutations = append(tx.repo.mutations, mutation)
	for i := range tx.repo.users {
		if tx.repo.users[i].ID == mutation.UserID {
			if mutation.Status.Set {
				tx.repo.users[i].Status = mutation.Status.Value
			}
			if mutation.MutedUntil.Set {
				tx.repo.users[i].MutedUntil = mutation.MutedUntil.Value
			}
			if mutation.UpdatedAt.Set {
				tx.repo.users[i].UpdatedAt = mutation.UpdatedAt.Value
			}
			return tx.repo.users[i], nil
		}
	}
	return domain.User{}, ErrNotFound
}
func (tx *statusTxFake) RecoverExpiredMute(_ context.Context, id int64, now time.Time) (domain.User, bool, error) {
	tx.repo.events = append(tx.repo.events, "recover")
	if tx.repo.recoverErr != nil {
		return domain.User{}, false, tx.repo.recoverErr
	}
	for i := range tx.repo.users {
		user := &tx.repo.users[i]
		if user.ID == id && user.Status == domain.StatusMuted && user.MutedUntil != nil && !user.MutedUntil.After(now) {
			user.Status, user.MutedUntil, user.UpdatedAt = domain.StatusActive, nil, now
			return *user, true, nil
		}
	}
	return domain.User{}, false, nil
}
func (tx *statusTxFake) InsertAudit(_ context.Context, entry AuditEntry) error {
	tx.repo.events = append(tx.repo.events, "audit:"+entry.Action)
	if tx.repo.auditErrAt > 0 && len(tx.repo.audits)+1 == tx.repo.auditErrAt {
		return errors.New("audit secret")
	}
	tx.repo.audits = append(tx.repo.audits, entry)
	return nil
}

func newStatusRepository(users ...domain.User) *statusRepositoryFake {
	return &statusRepositoryFake{users: users, session: domain.UserSession{ID: 10, UserID: 1, ExpiresAt: time.Date(2026, time.September, 3, 0, 0, 0, 0, time.UTC), CreatedAt: time.Date(2026, time.September, 1, 0, 0, 0, 0, time.UTC)}}
}
