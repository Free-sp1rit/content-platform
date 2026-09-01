package service

import (
	"bytes"
	"context"
	"errors"
	"time"

	"github.com/Free-sp1rit/content-platform/internal/identity/domain"
)

type RegisterInput struct {
	Email       string
	Password    string
	DisplayName string
}

type LoginInput struct {
	Email     string
	Password  string
	RequestID string
}

type LoginResult struct {
	TokenType        string
	AccessToken      string
	ExpiresIn        int64
	RefreshToken     string
	RefreshExpiresAt time.Time
	User             domain.UserView
}

type loginCredentialOutcome uint8

const (
	loginInvalidFields loginCredentialOutcome = iota
	loginMissingCredential
	loginCredentialReadFailure
	loginFoundCredential
)

func (s *Service) Login(ctx context.Context, input LoginInput) (LoginResult, error) {
	email := domain.NormalizeEmail(input.Email)
	fieldsValid := domain.ValidateEmail(email) == nil && domain.ValidateRegistrationPassword(input.Password) == nil

	var initialContextErr error
	if ctx == nil {
		initialContextErr = newInternalError(nil)
	} else if err := ctx.Err(); err != nil {
		initialContextErr = newInternalError(err)
	}

	outcome := loginInvalidFields
	credential := LoginCredential{}
	var credentialReadErr error
	if fieldsValid && initialContextErr == nil {
		var err error
		credential, err = s.repository.FindLoginCredential(ctx, email)
		switch {
		case err == nil:
			outcome = loginFoundCredential
		case internalContextMarker(err) != nil || errors.Is(err, ErrInternal):
			outcome = loginCredentialReadFailure
			credentialReadErr = err
		case errors.Is(err, ErrNotFound):
			outcome = loginMissingCredential
		default:
			outcome = loginCredentialReadFailure
			credentialReadErr = err
		}
	}

	compareHash := credential.PasswordHash
	compareCandidate := input.Password
	if outcome != loginFoundCredential {
		compareHash = s.passwordHasher.DummyHash()
		compareCandidate = s.passwordHasher.DummyCandidate()
	}

	matched, err := s.passwordHasher.Compare(compareHash, compareCandidate)
	if err != nil {
		return LoginResult{}, newInternalError(err)
	}
	if initialContextErr != nil {
		return LoginResult{}, initialContextErr
	}
	if ctxErr := ctx.Err(); ctxErr != nil {
		return LoginResult{}, newInternalError(ctxErr)
	}
	if outcome != loginFoundCredential && !matched {
		return LoginResult{}, newInternalError(nil)
	}
	if outcome == loginCredentialReadFailure {
		return LoginResult{}, newInternalError(credentialReadErr)
	}
	if outcome == loginInvalidFields || outcome == loginMissingCredential {
		return LoginResult{}, ErrInvalidCredentials
	}
	if !matched || credential.DeletedAt != nil || !credential.Status.CanLogin() {
		return LoginResult{}, ErrInvalidCredentials
	}
	if credential.UserID <= 0 {
		return LoginResult{}, newInternalError(nil)
	}

	result := LoginResult{}
	err = s.repository.WithinTx(ctx, func(txCtx context.Context, tx Tx) error {
		lockedUsers, err := tx.LockUsers(txCtx, []int64{credential.UserID})
		if err != nil {
			return newInternalError(err)
		}
		if len(lockedUsers) == 0 {
			return ErrInvalidCredentials
		}
		if len(lockedUsers) != 1 || lockedUsers[0].ID != credential.UserID {
			return newInternalError(nil)
		}

		user := lockedUsers[0]
		if user.PasswordHash != credential.PasswordHash || user.DeletedAt != nil || !user.Status.CanLogin() {
			return ErrInvalidCredentials
		}
		now, err := s.now()
		if err != nil {
			return err
		}
		refreshExpiresAt := domain.NormalizeTime(now.Add(s.refreshTokenTTL))
		accessExpiresAt := domain.NormalizeTime(now.Add(s.accessTokenTTL))
		if !validLoginExpiry(now, refreshExpiresAt) || !validLoginExpiry(now, accessExpiresAt) {
			return newInternalError(nil)
		}

		var pendingMuteAudit *AuditEntry
		if user.Status == domain.StatusMuted {
			if user.MutedUntil == nil {
				return newInternalError(nil)
			}
			if !user.MutedUntil.After(now) {
				oldMutedUntil := *user.MutedUntil
				recovered, changed, err := tx.RecoverExpiredMute(txCtx, user.ID, now)
				if err != nil {
					return newInternalError(err)
				}
				if !changed || !validRecoveredLoginUser(recovered, user.ID, credential.PasswordHash, now) {
					return newInternalError(nil)
				}
				user = recovered
				pendingMuteAudit = &AuditEntry{
					ActorType:  AuditActorSystem,
					ActorID:    nil,
					Action:     "user.mute_expired",
					TargetType: "user",
					TargetID:   user.ID,
					Detail: map[string]any{
						"old_status":      domain.StatusMuted,
						"new_status":      domain.StatusActive,
						"old_muted_until": oldMutedUntil,
						"new_muted_until": nil,
						"request_id":      input.RequestID,
					},
					CreatedAt: now,
				}
			}
		}

		refreshSecret, refreshHash, err := s.refreshTokenGenerator.Generate()
		if err != nil {
			return newInternalError(err)
		}
		sessionRecord := CreateSessionRecord{
			UserID:    user.ID,
			TokenHash: refreshHash,
			ExpiresAt: refreshExpiresAt,
			CreatedAt: now,
		}
		session, err := tx.CreateSession(txCtx, sessionRecord)
		if err != nil {
			return newInternalError(err)
		}
		if !validCreatedLoginSession(session, sessionRecord, now) {
			return newInternalError(nil)
		}
		session.ExpiresAt = domain.NormalizeTime(session.ExpiresAt)

		actualAccessExpiry := accessExpiresAt
		if session.ExpiresAt.Before(actualAccessExpiry) {
			actualAccessExpiry = session.ExpiresAt
		}
		expiresIn := actualAccessExpiry.Unix() - now.Unix()
		if expiresIn <= 0 {
			return newInternalError(nil)
		}

		jwtID, err := s.accessTokenManager.GenerateJWTID()
		if err != nil {
			return newInternalError(err)
		}
		accessToken, err := s.accessTokenManager.Sign(user.ID, session.ID, now, actualAccessExpiry, jwtID)
		if err != nil {
			return newInternalError(err)
		}
		refreshToken, err := s.refreshTokenGenerator.Format(session.ID, refreshSecret)
		if err != nil {
			return newInternalError(err)
		}
		if pendingMuteAudit != nil {
			if err := tx.InsertAudit(txCtx, *pendingMuteAudit); err != nil {
				return newInternalError(err)
			}
		}

		result = LoginResult{
			TokenType:        "Bearer",
			AccessToken:      accessToken,
			ExpiresIn:        expiresIn,
			RefreshToken:     refreshToken,
			RefreshExpiresAt: session.ExpiresAt,
			User:             user.View(),
		}
		return nil
	})
	if err != nil {
		if err == ErrInvalidCredentials {
			return LoginResult{}, ErrInvalidCredentials
		}
		return LoginResult{}, newInternalError(err)
	}
	return result, nil
}

func validLoginExpiry(now, expiresAt time.Time) bool {
	if !expiresAt.After(now) {
		return false
	}
	year := expiresAt.Year()
	return year >= 0 && year <= 9999
}

func validRecoveredLoginUser(user domain.User, userID int64, passwordHash string, now time.Time) bool {
	return user.ID == userID &&
		user.PasswordHash == passwordHash &&
		user.Status == domain.StatusActive &&
		user.MutedUntil == nil &&
		user.DeletedAt == nil &&
		user.UpdatedAt.Equal(now)
}

func validCreatedLoginSession(session domain.UserSession, record CreateSessionRecord, now time.Time) bool {
	expiresAt := domain.NormalizeTime(session.ExpiresAt)
	return session.ID > 0 &&
		session.UserID == record.UserID &&
		session.RevokedAt == nil &&
		len(session.TokenHash) == len(record.TokenHash) &&
		bytes.Equal(session.TokenHash, record.TokenHash[:]) &&
		session.CreatedAt.Equal(record.CreatedAt) &&
		session.ExpiresAt.Nanosecond() == 0 &&
		!session.ExpiresAt.After(record.ExpiresAt) &&
		validLoginExpiry(now, expiresAt)
}

func (s *Service) Register(ctx context.Context, input RegisterInput) (domain.UserView, error) {
	email := domain.NormalizeEmail(input.Email)
	displayName := domain.NormalizeDisplayName(input.DisplayName)

	if err := domain.ValidateEmail(email); err != nil {
		return domain.UserView{}, newValidationError(ValidationFieldEmail)
	}
	if err := domain.ValidateRegistrationPassword(input.Password); err != nil {
		return domain.UserView{}, newValidationError(ValidationFieldPassword)
	}
	if err := domain.ValidateDisplayName(displayName); err != nil {
		return domain.UserView{}, newValidationError(ValidationFieldDisplayName)
	}
	if err := registrationContextError(ctx); err != nil {
		return domain.UserView{}, err
	}

	passwordHash, err := s.passwordHasher.Hash(input.Password)
	if err != nil {
		return domain.UserView{}, newInternalError(err)
	}
	if err := registrationContextError(ctx); err != nil {
		return domain.UserView{}, err
	}

	now, err := s.now()
	if err != nil {
		return domain.UserView{}, err
	}

	user, err := s.repository.CreateUser(ctx, CreateUserRecord{
		Email:          email,
		PasswordHash:   passwordHash,
		DisplayName:    displayName,
		Bio:            "",
		Role:           domain.RoleUser,
		Status:         domain.StatusActive,
		MutedUntil:     nil,
		ViolationCount: 0,
		CreatedAt:      now,
		UpdatedAt:      now,
		DeletedAt:      nil,
	})
	if err != nil {
		return domain.UserView{}, registrationRepositoryError(err)
	}

	return user.View(), nil
}

func (s *Service) now() (time.Time, error) {
	value := domain.NormalizeTime(s.clock.Now())
	// Exact zero means the injected clock is uninitialized or damaged; it is
	// distinct from the RFC3339-compatible year range checked below.
	if value.IsZero() {
		return time.Time{}, newInternalError(nil)
	}
	year := value.Year()
	if year < 0 || year > 9999 {
		return time.Time{}, newInternalError(nil)
	}
	return value, nil
}

func registrationContextError(ctx context.Context) error {
	if ctx == nil {
		return newInternalError(nil)
	}
	if err := ctx.Err(); err != nil {
		return newInternalError(err)
	}
	return nil
}

func registrationRepositoryError(err error) error {
	if internalContextMarker(err) != nil {
		return newInternalError(err)
	}
	if errors.Is(err, ErrEmailExists) {
		return ErrEmailAlreadyRegistered
	}
	return newInternalError(err)
}
