package service

import (
	"context"
	"errors"
)

var (
	ErrEmailExists                 = errors.New("email already exists")
	ErrNotFound                    = errors.New("identity record not found")
	ErrInternal                    = errors.New("identity internal error")
	ErrInvalidServiceConfiguration = errors.New("identity service configuration is invalid")
	ErrValidationFailed            = errors.New("validation failed")
	ErrEmailAlreadyRegistered      = errors.New("email already registered")
	ErrInvalidCredentials          = errors.New("invalid credentials")
	ErrInvalidRefreshToken         = errors.New("invalid refresh token")
)

type ValidationField string

const (
	ValidationFieldEmail       ValidationField = "email"
	ValidationFieldPassword    ValidationField = "password"
	ValidationFieldDisplayName ValidationField = "display_name"
)

type ValidationError struct {
	field ValidationField
}

func newValidationError(field ValidationField) *ValidationError {
	return &ValidationError{field: field}
}

func (e *ValidationError) Error() string {
	return ErrValidationFailed.Error()
}

func (e *ValidationError) Unwrap() error {
	return ErrValidationFailed
}

func (e *ValidationError) Field() ValidationField {
	if e == nil {
		return ""
	}
	return e.field
}

type internalError struct {
	contextErr error
}

func newInternalError(cause error) error {
	return &internalError{contextErr: internalContextMarker(cause)}
}

func internalContextMarker(err error) error {
	if errors.Is(err, context.Canceled) {
		return context.Canceled
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return context.DeadlineExceeded
	}
	return nil
}

func (e *internalError) Error() string {
	return ErrInternal.Error()
}

func (e *internalError) Unwrap() error {
	return ErrInternal
}

func (e *internalError) Is(target error) bool {
	if target == ErrInternal {
		return true
	}
	if target == context.Canceled || target == context.DeadlineExceeded {
		return e.contextErr == target
	}
	return false
}
