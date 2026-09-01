package service

import (
	"context"
	"testing"
	"time"

	"github.com/Free-sp1rit/content-platform/internal/identity/domain"
)

var (
	_ Repository = repositoryPortStub{}
	_ Tx         = transactionPortStub{}
)

type repositoryPortStub struct{}

func (repositoryPortStub) CreateUser(context.Context, CreateUserRecord) (domain.User, error) {
	return domain.User{}, nil
}

func (repositoryPortStub) FindLoginCredential(context.Context, string) (LoginCredential, error) {
	return LoginCredential{}, nil
}

func (repositoryPortStub) FindUser(context.Context, int64) (domain.User, error) {
	return domain.User{}, nil
}

func (repositoryPortStub) FindSessionOwner(context.Context, int64) (int64, error) {
	return 0, nil
}

func (repositoryPortStub) RevokeSession(context.Context, RevokeSessionRequest) error {
	return nil
}

func (repositoryPortStub) WithinTx(context.Context, func(context.Context, Tx) error) error {
	return nil
}

type transactionPortStub struct{}

func (transactionPortStub) LockUsers(context.Context, []int64) ([]LockedUser, error) {
	return nil, nil
}

func (transactionPortStub) LockSession(context.Context, int64) (domain.UserSession, error) {
	return domain.UserSession{}, nil
}

func (transactionPortStub) LockActiveSessions(context.Context, int64) ([]domain.UserSession, error) {
	return nil, nil
}

func (transactionPortStub) LockSessions(context.Context, SessionLockRequest) ([]domain.UserSession, error) {
	return nil, nil
}

func (transactionPortStub) CreateSession(context.Context, CreateSessionRecord) (domain.UserSession, error) {
	return domain.UserSession{}, nil
}

func (transactionPortStub) RotateSessionToken(context.Context, int64, [32]byte) error {
	return nil
}

func (transactionPortStub) RevokeLockedSessions(context.Context, []int64, time.Time) error {
	return nil
}

func (transactionPortStub) UpdateUser(context.Context, UserMutation) (domain.User, error) {
	return domain.User{}, nil
}

func (transactionPortStub) RecoverExpiredMute(context.Context, int64, time.Time) (domain.User, bool, error) {
	return domain.User{}, false, nil
}

func (transactionPortStub) InsertAudit(context.Context, AuditEntry) error {
	return nil
}

func TestSetFieldDistinguishesUnsetFromExplicitZeroValue(t *testing.T) {
	var unset Field[*time.Time]
	explicitNull := SetField[*time.Time](nil)

	if unset.Set {
		t.Fatal("zero-value Field must be unset")
	}
	if !explicitNull.Set {
		t.Fatal("SetField(nil) must preserve an explicit NULL mutation")
	}
	if explicitNull.Value != nil {
		t.Fatalf("SetField(nil).Value = %v, want nil", explicitNull.Value)
	}
}

func TestRevokeSessionRequestNamesIdentityFields(t *testing.T) {
	revokedAt := time.Date(2026, time.September, 2, 9, 30, 0, 0, time.UTC)
	request := RevokeSessionRequest{
		UserID:    17,
		SessionID: 42,
		RevokedAt: revokedAt,
	}

	if request.UserID != 17 {
		t.Fatalf("RevokeSessionRequest.UserID = %d, want 17", request.UserID)
	}
	if request.SessionID != 42 {
		t.Fatalf("RevokeSessionRequest.SessionID = %d, want 42", request.SessionID)
	}
	if !request.RevokedAt.Equal(revokedAt) {
		t.Fatalf("RevokeSessionRequest.RevokedAt = %v, want %v", request.RevokedAt, revokedAt)
	}
}
