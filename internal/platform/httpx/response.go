package httpx

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"

	"github.com/Free-sp1rit/content-platform/internal/platform/apperror"
	"github.com/Free-sp1rit/content-platform/internal/platform/requestid"
)

const contentTypeJSON = "application/json; charset=utf-8"

type responseMeta struct {
	RequestID string `json:"request_id"`
}

type successEnvelope struct {
	Data any          `json:"data"`
	Meta responseMeta `json:"meta"`
}

type errorEnvelope struct {
	Error errorBody    `json:"error"`
	Meta  responseMeta `json:"meta"`
}

type errorBody struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	Details any    `json:"details,omitempty"`
}

func WriteData(ctx context.Context, w http.ResponseWriter, status int, data any) {
	payload := successEnvelope{
		Data: data,
		Meta: responseMeta{RequestID: requestid.FromContext(ctx)},
	}
	writeJSON(w, status, payload)
}

func WriteError(ctx context.Context, w http.ResponseWriter, logger *slog.Logger, err error) {
	appErr, ok := apperror.From(err)
	status := http.StatusInternalServerError
	if !ok {
		logInternalError(ctx, logger, err)
		appErr = apperror.New(apperror.Internal, string(apperror.Internal), "internal server error")
	} else {
		var knownKind bool
		status, knownKind = statusForKind(appErr.Kind)
		if !knownKind {
			logInternalError(ctx, logger, appErr)
			appErr = apperror.New(apperror.Internal, string(apperror.Internal), "internal server error")
			status = http.StatusInternalServerError
		} else if appErr.Kind == apperror.Internal {
			cause := errors.Unwrap(appErr)
			if cause != nil {
				logInternalError(ctx, logger, cause)
			}
		}
	}

	message := appErr.Message
	if appErr.Kind == apperror.Internal {
		message = "internal server error"
	}

	code := appErr.Code
	if code == "" {
		code = string(appErr.Kind)
	}
	payload := errorEnvelope{
		Error: errorBody{
			Code:    code,
			Message: message,
			Details: appErr.Details,
		},
		Meta: responseMeta{RequestID: requestid.FromContext(ctx)},
	}
	writeJSON(w, status, payload)
}

func statusForKind(kind apperror.Kind) (int, bool) {
	switch kind {
	case apperror.InvalidArgument:
		return http.StatusBadRequest, true
	case apperror.Unauthenticated:
		return http.StatusUnauthorized, true
	case apperror.PermissionDenied:
		return http.StatusForbidden, true
	case apperror.NotFound:
		return http.StatusNotFound, true
	case apperror.MethodNotAllowed:
		return http.StatusMethodNotAllowed, true
	case apperror.Conflict:
		return http.StatusConflict, true
	case apperror.RateLimited:
		return http.StatusTooManyRequests, true
	case apperror.Internal:
		return http.StatusInternalServerError, true
	case apperror.DependencyUnavailable:
		return http.StatusServiceUnavailable, true
	default:
		return http.StatusInternalServerError, false
	}
}

func logInternalError(ctx context.Context, logger *slog.Logger, err error) {
	if logger == nil {
		return
	}
	logger.ErrorContext(ctx, "request failed",
		"request_id", requestid.FromContext(ctx),
		"error", err,
	)
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	body, err := json.Marshal(payload)
	if err != nil {
		status = http.StatusInternalServerError
		body = []byte(`{"error":{"code":"internal_error","message":"internal server error"},"meta":{"request_id":""}}`)
	}

	w.Header().Set("Content-Type", contentTypeJSON)
	w.WriteHeader(status)
	_, _ = w.Write(append(body, '\n'))
}
