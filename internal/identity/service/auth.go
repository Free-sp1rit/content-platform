package service

import (
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
