package apperror

import "errors"

type Kind string

const (
	InvalidArgument       Kind = "invalid_argument"
	Unauthenticated       Kind = "unauthenticated"
	PermissionDenied      Kind = "permission_denied"
	NotFound              Kind = "not_found"
	MethodNotAllowed      Kind = "method_not_allowed"
	Conflict              Kind = "conflict"
	RateLimited           Kind = "rate_limited"
	Internal              Kind = "internal_error"
	DependencyUnavailable Kind = "dependency_unavailable"
)

type Error struct {
	Kind    Kind
	Code    string
	Message string
	Details any
	cause   error
}

func New(kind Kind, code, message string) *Error {
	return &Error{
		Kind:    kind,
		Code:    code,
		Message: message,
	}
}

func Wrap(kind Kind, code, message string, cause error) *Error {
	err := New(kind, code, message)
	err.cause = cause
	return err
}

func (e *Error) WithDetails(details any) *Error {
	e.Details = details
	return e
}

func (e *Error) Error() string {
	return e.Message
}

func (e *Error) Unwrap() error {
	return e.cause
}

func From(err error) (*Error, bool) {
	var appErr *Error
	if !errors.As(err, &appErr) {
		return nil, false
	}
	return appErr, true
}
