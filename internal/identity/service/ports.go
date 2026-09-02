package service

import (
	"context"
	"time"

	"github.com/Free-sp1rit/content-platform/internal/identity/domain"
)

type PasswordHasher interface {
	Hash(string) (string, error)
	Compare(string, string) (bool, error)
	DummyHash() string
	DummyCandidate() string
}

type AccessTokenManager interface {
	GenerateJWTID() (string, error)
	Sign(int64, int64, time.Time, time.Time, string) (string, error)
}

type RefreshTokenGenerator interface {
	Generate() (string, [32]byte, error)
	Format(int64, string) (string, error)
	Parse(string) (int64, [32]byte, error)
	Match([32]byte, [32]byte) bool
}

type Clock interface {
	Now() time.Time
}

type Repository interface {
	CreateUser(context.Context, CreateUserRecord) (domain.User, error)
	FindLoginCredential(context.Context, string) (LoginCredential, error)
	FindUser(context.Context, int64) (domain.User, error)
	FindAuthenticationState(context.Context, int64) (AuthenticationState, error)
	FindSessionOwner(context.Context, int64) (int64, error)
	RevokeSession(context.Context, RevokeSessionRequest) error
	WithinTx(context.Context, func(context.Context, Tx) error) error
}

type Tx interface {
	LockUsers(context.Context, []int64) ([]LockedUser, error)
	LockSession(context.Context, int64) (domain.UserSession, error)
	LockActiveSessions(context.Context, int64) ([]domain.UserSession, error)
	LockSessions(context.Context, SessionLockRequest) ([]domain.UserSession, error)
	CreateSession(context.Context, CreateSessionRecord) (domain.UserSession, error)
	RotateSessionToken(context.Context, int64, [32]byte) error
	RevokeLockedSessions(context.Context, []int64, time.Time) error
	UpdateUser(context.Context, UserMutation) (domain.User, error)
	RecoverExpiredMute(context.Context, int64, time.Time) (domain.User, bool, error)
	InsertAudit(context.Context, AuditEntry) error
}

type CreateUserRecord struct {
	Email          string
	PasswordHash   string
	DisplayName    string
	Bio            string
	Role           domain.Role
	Status         domain.Status
	MutedUntil     *time.Time
	ViolationCount int
	CreatedAt      time.Time
	UpdatedAt      time.Time
	DeletedAt      *time.Time
}

type LoginCredential struct {
	UserID       int64
	PasswordHash string
	Status       domain.Status
	DeletedAt    *time.Time
}

type AuthenticationState struct {
	Session AuthenticationSession
	User    domain.User
}

type AuthenticationSession struct {
	ID        int64
	UserID    int64
	ExpiresAt time.Time
	RevokedAt *time.Time
	CreatedAt time.Time
}

type LockedUser = domain.User

type CreateSessionRecord struct {
	UserID    int64
	TokenHash [32]byte
	ExpiresAt time.Time
	CreatedAt time.Time
}

type SessionLockRequest struct {
	SessionIDs    []int64
	ActiveUserIDs []int64
}

type RevokeSessionRequest struct {
	UserID    int64
	SessionID int64
	RevokedAt time.Time
}

type Field[T any] struct {
	Set   bool
	Value T
}

func SetField[T any](value T) Field[T] {
	return Field[T]{Set: true, Value: value}
}

type UserMutation struct {
	UserID         int64
	DisplayName    Field[string]
	Bio            Field[string]
	Status         Field[domain.Status]
	MutedUntil     Field[*time.Time]
	ViolationCount Field[int]
	UpdatedAt      Field[time.Time]
	DeletedAt      Field[*time.Time]
}

type AuditActorType string

const (
	AuditActorUser   AuditActorType = "user"
	AuditActorAdmin  AuditActorType = "admin"
	AuditActorSystem AuditActorType = "system"
)

type AuditEntry struct {
	ActorType  AuditActorType
	ActorID    *int64
	Action     string
	TargetType string
	TargetID   int64
	Detail     map[string]any
	CreatedAt  time.Time
}
