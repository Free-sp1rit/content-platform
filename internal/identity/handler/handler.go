package handler

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"reflect"

	"github.com/Free-sp1rit/content-platform/internal/identity/domain"
	identityservice "github.com/Free-sp1rit/content-platform/internal/identity/service"
	"github.com/Free-sp1rit/content-platform/internal/platform/apperror"
	"github.com/Free-sp1rit/content-platform/internal/platform/authn"
	"github.com/Free-sp1rit/content-platform/internal/platform/httpx"
)

const maxRequestBodyBytes int64 = 64 << 10

type IdentityService interface {
	Register(context.Context, identityservice.RegisterInput) (domain.UserView, error)
	Login(context.Context, identityservice.LoginInput) (identityservice.LoginResult, error)
	Logout(context.Context, identityservice.LogoutInput) (identityservice.LogoutResult, error)
	Refresh(context.Context, identityservice.RefreshInput) (identityservice.RefreshResult, error)
	Me(context.Context, identityservice.MeInput) (domain.UserView, error)
	PublicUser(context.Context, identityservice.PublicUserInput) (domain.PublicUserView, error)
	UpdateMe(context.Context, identityservice.UpdateMeInput) (domain.UserView, error)
	DeleteMe(context.Context, identityservice.DeleteMeInput) (identityservice.DeleteMeResult, error)
	ChangeUserStatus(context.Context, identityservice.ChangeUserStatusInput) (domain.UserView, error)
}

type Handler struct {
	service IdentityService
	logger  *slog.Logger
}

func New(service IdentityService, logger *slog.Logger) *Handler {
	return &Handler{service: service, logger: logger}
}

func (h *Handler) RejectAccessToken(w http.ResponseWriter, r *http.Request, err error) {
	ctx := context.Background()
	if r != nil {
		ctx = r.Context()
	}
	h.writeError(ctx, w, err)
}

func (h *Handler) decode(w http.ResponseWriter, r *http.Request, destination any) bool {
	if err := httpx.DecodeJSON(w, r, destination, maxRequestBodyBytes); err != nil {
		h.writeError(r.Context(), w, err)
		return false
	}
	return true
}

func (h *Handler) principal(r *http.Request) (authn.Principal, bool) {
	if r == nil {
		return authn.Principal{}, false
	}
	principal, ok := authn.FromContext(r.Context())
	return principal, ok && principal.UserID > 0 && principal.SessionID > 0
}

func (h *Handler) available() bool {
	if h == nil || h.service == nil {
		return false
	}
	value := reflect.ValueOf(h.service)
	switch value.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return !value.IsNil()
	default:
		return true
	}
}

func (h *Handler) writeError(ctx context.Context, w http.ResponseWriter, err error) {
	publicErr := handlerError(err)
	if appErr, ok := apperror.From(publicErr); ok && appErr.Kind == apperror.Unauthenticated {
		w.Header().Set("WWW-Authenticate", "Bearer")
	}
	var logger *slog.Logger
	if h != nil {
		logger = h.logger
	}
	httpx.WriteError(ctx, w, logger, publicErr)
}

func handlerError(err error) error {
	if appErr, ok := apperror.From(err); ok {
		return appErr
	}

	switch {
	case errors.Is(err, authn.ErrInvalidAccessToken):
		return publicError(apperror.Unauthenticated, "invalid_access_token", "access token is invalid")
	case errors.Is(err, identityservice.ErrValidationFailed):
		return publicError(apperror.InvalidArgument, "validation_failed", "request validation failed")
	case errors.Is(err, identityservice.ErrSessionInvalid):
		return publicError(apperror.Unauthenticated, "session_invalid", "session is invalid")
	case errors.Is(err, identityservice.ErrInvalidCredentials):
		return publicError(apperror.Unauthenticated, "invalid_credentials", "credentials are invalid")
	case errors.Is(err, identityservice.ErrInvalidRefreshToken):
		return publicError(apperror.Unauthenticated, "invalid_refresh_token", "refresh token is invalid")
	case errors.Is(err, identityservice.ErrUserFrozen):
		return publicError(apperror.PermissionDenied, "user_frozen", "user is frozen")
	case errors.Is(err, identityservice.ErrAdminRequired):
		return publicError(apperror.PermissionDenied, "admin_required", "administrator access is required")
	case errors.Is(err, identityservice.ErrAdminTargetForbidden):
		return publicError(apperror.PermissionDenied, "admin_target_forbidden", "administrator target is forbidden")
	case errors.Is(err, identityservice.ErrUserNotFound):
		return publicError(apperror.NotFound, "user_not_found", "user was not found")
	case errors.Is(err, identityservice.ErrEmailAlreadyRegistered):
		return publicError(apperror.Conflict, "email_already_registered", "email is already registered")
	case errors.Is(err, identityservice.ErrInvalidStatusTransition):
		return publicError(apperror.Conflict, "invalid_status_transition", "status transition is invalid")
	case errors.Is(err, identityservice.ErrInternal):
		return apperror.Wrap(apperror.Internal, "internal_error", "internal server error", err)
	default:
		return err
	}
}

func publicError(kind apperror.Kind, code, message string) error {
	return apperror.New(kind, code, message)
}

func internalHandlerError() error {
	return apperror.New(apperror.Internal, "internal_error", "internal server error")
}

func validationHandlerError() error {
	return apperror.New(apperror.InvalidArgument, "validation_failed", "request validation failed")
}
