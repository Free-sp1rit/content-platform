package handler

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Free-sp1rit/content-platform/internal/identity/domain"
	identityservice "github.com/Free-sp1rit/content-platform/internal/identity/service"
	"github.com/Free-sp1rit/content-platform/internal/platform/authn"
	"github.com/Free-sp1rit/content-platform/internal/platform/requestid"
)

const handlerRequestID = "req-handler-123"

func TestHandlersExposeNineSuccessContracts(t *testing.T) {
	created := time.Date(2026, 9, 1, 20, 0, 0, 987654321, time.FixedZone("CST", 8*60*60))
	updated := created.Add(time.Hour)
	user := domain.UserView{
		ID: 7, Email: "user@example.com", DisplayName: "Alice", Bio: "hello",
		Role: domain.RoleUser, Status: domain.StatusActive, ViolationCount: 2,
		CreatedAt: created, UpdatedAt: updated,
	}
	public := domain.PublicUserView{
		ID: 7, DisplayName: "Alice", Bio: "hello", Role: domain.RoleUser,
		Status: domain.StatusActive, CreatedAt: created,
	}
	refreshExpiry := updated.Add(24 * time.Hour)
	fake := &fakeIdentityService{
		registerResult: user,
		loginResult: identityservice.LoginResult{
			TokenType: "Bearer", AccessToken: "access", ExpiresIn: 900,
			RefreshToken: "7.refresh", RefreshExpiresAt: refreshExpiry, User: user,
		},
		logoutResult: identityservice.LogoutResult{LoggedOut: true},
		refreshResult: identityservice.RefreshResult{
			TokenType: "Bearer", AccessToken: "access-2", ExpiresIn: 800,
			RefreshToken: "7.refresh-2", RefreshExpiresAt: refreshExpiry,
		},
		meResult:           user,
		publicResult:       public,
		updateMeResult:     user,
		deleteMeResult:     identityservice.DeleteMeResult{Deleted: true},
		changeStatusResult: user,
	}
	h := New(fake, nil)

	t.Run("register", func(t *testing.T) {
		response := invokeHandler(t, h.Register, http.MethodPost, "/register",
			`{"email":" User@Example.com ","password":"secret-password","display_name":"Alice"}`,
			"application/json", authn.Principal{}, "")
		if response.Code != http.StatusCreated {
			t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
		}
		if fake.registerInput != (identityservice.RegisterInput{Email: " User@Example.com ", Password: "secret-password", DisplayName: "Alice"}) {
			t.Fatalf("Register input = %#v", fake.registerInput)
		}
		data := successData(t, response)
		assertExactKeys(t, data, userResponseKeys...)
		assertUserTimesAndNulls(t, data)
	})

	t.Run("login", func(t *testing.T) {
		response := invokeHandler(t, h.Login, http.MethodPost, "/login",
			`{"email":"user@example.com","password":"secret-password"}`,
			"application/json; charset=utf-8", authn.Principal{}, "")
		if response.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
		}
		if fake.loginInput != (identityservice.LoginInput{Email: "user@example.com", Password: "secret-password", RequestID: handlerRequestID}) {
			t.Fatalf("Login input = %#v", fake.loginInput)
		}
		data := successData(t, response)
		assertExactKeys(t, data, "token_type", "access_token", "expires_in", "refresh_token", "refresh_expires_at", "user")
		assertExactKeys(t, objectValue(t, data, "user"), userResponseKeys...)
		if data["refresh_expires_at"] != "2026-09-02T13:00:00Z" {
			t.Fatalf("refresh_expires_at = %#v", data["refresh_expires_at"])
		}
	})

	t.Run("logout", func(t *testing.T) {
		principal := authn.Principal{UserID: 7, SessionID: 11}
		response := invokeHandler(t, h.Logout, http.MethodPost, "/logout", "", "", principal, "")
		if response.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
		}
		if fake.logoutInput != (identityservice.LogoutInput{UserID: 7, SessionID: 11}) {
			t.Fatalf("Logout input = %#v", fake.logoutInput)
		}
		assertExactKeys(t, successData(t, response), "logged_out")
	})

	t.Run("refresh", func(t *testing.T) {
		response := invokeHandler(t, h.Refresh, http.MethodPost, "/token/refresh",
			`{"refresh_token":"7.refresh"}`, "application/json", authn.Principal{}, "")
		if response.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
		}
		if fake.refreshInput != (identityservice.RefreshInput{RefreshToken: "7.refresh", RequestID: handlerRequestID}) {
			t.Fatalf("Refresh input = %#v", fake.refreshInput)
		}
		assertExactKeys(t, successData(t, response), "token_type", "access_token", "expires_in", "refresh_token", "refresh_expires_at")
	})

	t.Run("me", func(t *testing.T) {
		response := invokeHandler(t, h.Me, http.MethodGet, "/me", "", "", authn.Principal{UserID: 7, SessionID: 11}, "")
		if response.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
		}
		if fake.meInput != (identityservice.MeInput{UserID: 7, SessionID: 11, RequestID: handlerRequestID}) {
			t.Fatalf("Me input = %#v", fake.meInput)
		}
		assertExactKeys(t, successData(t, response), userResponseKeys...)
	})

	t.Run("update me", func(t *testing.T) {
		response := invokeHandler(t, h.UpdateMe, http.MethodPut, "/me",
			`{"display_name":"","bio":""}`, "application/json", authn.Principal{UserID: 7, SessionID: 11}, "")
		if response.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
		}
		want := identityservice.UpdateMeInput{
			UserID: 7, SessionID: 11, RequestID: handlerRequestID,
			DisplayName: identityservice.SetField(""), Bio: identityservice.SetField(""),
		}
		if fake.updateMeInput != want {
			t.Fatalf("UpdateMe input = %#v, want %#v", fake.updateMeInput, want)
		}
		assertExactKeys(t, successData(t, response), userResponseKeys...)
	})

	t.Run("delete me", func(t *testing.T) {
		response := invokeHandler(t, h.DeleteMe, http.MethodDelete, "/me", "", "", authn.Principal{UserID: 7, SessionID: 11}, "")
		if response.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
		}
		if fake.deleteMeInput != (identityservice.DeleteMeInput{UserID: 7, SessionID: 11, RequestID: handlerRequestID}) {
			t.Fatalf("DeleteMe input = %#v", fake.deleteMeInput)
		}
		assertExactKeys(t, successData(t, response), "deleted")
	})

	t.Run("public user", func(t *testing.T) {
		response := invokeHandler(t, h.PublicUser, http.MethodGet, "/users/7", "", "", authn.Principal{}, "7")
		if response.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
		}
		if fake.publicInput != (identityservice.PublicUserInput{UserID: 7, RequestID: handlerRequestID}) {
			t.Fatalf("PublicUser input = %#v", fake.publicInput)
		}
		data := successData(t, response)
		assertExactKeys(t, data, "id", "display_name", "bio", "role", "status", "created_at")
		if data["created_at"] != "2026-09-01T12:00:00Z" {
			t.Fatalf("created_at = %#v", data["created_at"])
		}
	})

	t.Run("change user status", func(t *testing.T) {
		response := invokeHandler(t, h.ChangeStatus, http.MethodPut, "/admin/users/7/status",
			`{"status":"muted","reason":"  abuse  ","muted_until":"2026-09-02T20:00:00.987654321+08:00"}`,
			"application/json", authn.Principal{UserID: 99, SessionID: 111}, "7")
		if response.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
		}
		wantTime := time.Date(2026, 9, 2, 12, 0, 0, 0, time.UTC)
		want := identityservice.ChangeUserStatusInput{
			ActorID: 99, ActorSessionID: 111, TargetID: 7, NewStatus: domain.StatusMuted,
			Reason: "  abuse  ", MutedUntil: &wantTime, RequestID: handlerRequestID,
		}
		if !equalChangeStatusInput(fake.changeStatusInput, want) {
			t.Fatalf("ChangeUserStatus input = %#v, want %#v", fake.changeStatusInput, want)
		}
		assertExactKeys(t, successData(t, response), userResponseKeys...)
	})
}

func TestUpdateMeMapsAbsentAndNullToUnsetButEmptyToSet(t *testing.T) {
	tests := []struct {
		name        string
		body        string
		wantDisplay identityservice.Field[string]
		wantBio     identityservice.Field[string]
	}{
		{name: "empty object", body: `{}`},
		{name: "both null", body: `{"display_name":null,"bio":null}`},
		{name: "display absent bio null", body: `{"bio":null}`},
		{name: "explicit empty", body: `{"display_name":"","bio":""}`, wantDisplay: identityservice.SetField(""), wantBio: identityservice.SetField("")},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fake := &fakeIdentityService{updateMeResult: sampleUserView()}
			h := New(fake, nil)
			response := invokeHandler(t, h.UpdateMe, http.MethodPut, "/me", tt.body, "application/json", authn.Principal{UserID: 4, SessionID: 5}, "")
			if response.Code != http.StatusOK {
				t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
			}
			if fake.updateCalls != 1 {
				t.Fatalf("UpdateMe calls = %d", fake.updateCalls)
			}
			if fake.updateMeInput.DisplayName != tt.wantDisplay || fake.updateMeInput.Bio != tt.wantBio {
				t.Fatalf("patch = %#v %#v", fake.updateMeInput.DisplayName, fake.updateMeInput.Bio)
			}
		})
	}
}

func TestLoginDoesNotPrevalidateDecodedCredentials(t *testing.T) {
	fake := &fakeIdentityService{loginErr: identityservice.ErrInvalidCredentials}
	h := New(fake, nil)
	response := invokeHandler(t, h.Login, http.MethodPost, "/login", `{"email":"","password":""}`, "application/json", authn.Principal{}, "")

	assertErrorResponse(t, response, http.StatusUnauthorized, "invalid_credentials")
	if fake.loginCalls != 1 || fake.loginInput.Email != "" || fake.loginInput.Password != "" {
		t.Fatalf("Login call = %d input = %#v", fake.loginCalls, fake.loginInput)
	}
	if response.Header().Get("WWW-Authenticate") != "Bearer" {
		t.Fatalf("WWW-Authenticate = %q", response.Header().Get("WWW-Authenticate"))
	}
}

func TestBodyHandlersRejectCaseVariantJSONFieldsBeforeCallingService(t *testing.T) {
	tests := []struct {
		name      string
		method    string
		path      string
		body      string
		principal authn.Principal
		pathID    string
		handler   func(*Handler) http.HandlerFunc
		calls     func(*fakeIdentityService) int
	}{
		{
			name: "register EMAIL", method: http.MethodPost, path: "/register",
			body:    `{"EMAIL":"user@example.com","password":"password-123","display_name":"Alice"}`,
			handler: func(h *Handler) http.HandlerFunc { return h.Register },
			calls:   func(fake *fakeIdentityService) int { return fake.registerCalls },
		},
		{
			name: "login Password", method: http.MethodPost, path: "/login",
			body:    `{"email":"user@example.com","Password":"password-123"}`,
			handler: func(h *Handler) http.HandlerFunc { return h.Login },
			calls:   func(fake *fakeIdentityService) int { return fake.loginCalls },
		},
		{
			name: "update DISPLAY_NAME", method: http.MethodPut, path: "/me",
			body: `{"DISPLAY_NAME":"Alias"}`, principal: authn.Principal{UserID: 2, SessionID: 3},
			handler: func(h *Handler) http.HandlerFunc { return h.UpdateMe },
			calls:   func(fake *fakeIdentityService) int { return fake.updateCalls },
		},
		{
			name: "status MUTED_UNTIL", method: http.MethodPut, path: "/admin/users/8/status",
			body: `{"status":"active","MUTED_UNTIL":null}`, principal: authn.Principal{UserID: 2, SessionID: 3}, pathID: "8",
			handler: func(h *Handler) http.HandlerFunc { return h.ChangeStatus },
			calls:   func(fake *fakeIdentityService) int { return fake.changeStatusCalls },
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fake := &fakeIdentityService{}
			h := New(fake, nil)

			response := invokeHandler(t, tt.handler(h), tt.method, tt.path, tt.body, "application/json", tt.principal, tt.pathID)

			assertErrorResponse(t, response, http.StatusBadRequest, "invalid_request")
			if calls := tt.calls(fake); calls != 0 {
				t.Fatalf("service calls = %d", calls)
			}
		})
	}
}

func TestChangeStatusClassifiesNullableAndInvalidTimes(t *testing.T) {
	t.Run("absent nullable fields", func(t *testing.T) {
		fake := &fakeIdentityService{changeStatusResult: sampleUserView()}
		h := New(fake, nil)
		response := invokeHandler(t, h.ChangeStatus, http.MethodPut, "/admin/users/8/status", `{"status":"active"}`, "application/json", authn.Principal{UserID: 2, SessionID: 3}, "8")
		if response.Code != http.StatusOK {
			t.Fatalf("status = %d body = %s", response.Code, response.Body.String())
		}
		if fake.changeStatusInput.Reason != "" || fake.changeStatusInput.MutedUntil != nil {
			t.Fatalf("input = %#v", fake.changeStatusInput)
		}
	})

	t.Run("null nullable fields", func(t *testing.T) {
		fake := &fakeIdentityService{changeStatusResult: sampleUserView()}
		h := New(fake, nil)
		response := invokeHandler(t, h.ChangeStatus, http.MethodPut, "/admin/users/8/status", `{"status":"active","reason":null,"muted_until":null}`, "application/json", authn.Principal{UserID: 2, SessionID: 3}, "8")
		if response.Code != http.StatusOK || fake.changeStatusInput.Reason != "" || fake.changeStatusInput.MutedUntil != nil {
			t.Fatalf("status = %d input = %#v body = %s", response.Code, fake.changeStatusInput, response.Body.String())
		}
	})

	invalidTimes := []string{
		"tomorrow",
		"2026-09-02T1:02:03Z",
		"2026-09-02T01:02:03,5Z",
		"2026-09-02T01:02:03+24:00",
		"2026-09-02T01:02:03+00:60",
	}
	for _, raw := range invalidTimes {
		t.Run("invalid RFC3339 string "+raw, func(t *testing.T) {
			fake := &fakeIdentityService{}
			h := New(fake, nil)
			body := `{"status":"muted","muted_until":` + fmt.Sprintf("%q", raw) + `}`
			response := invokeHandler(t, h.ChangeStatus, http.MethodPut, "/admin/users/8/status", body, "application/json", authn.Principal{UserID: 2, SessionID: 3}, "8")
			assertErrorResponse(t, response, http.StatusBadRequest, "validation_failed")
			if fake.changeStatusCalls != 0 {
				t.Fatalf("ChangeUserStatus calls = %d", fake.changeStatusCalls)
			}
		})
	}

	for _, body := range []string{
		`{"status":"muted","muted_until":123}`,
		`{"status":"muted","muted_until":{}}`,
		`{"status":"muted","muted_until":[]}`,
		`{"status":"muted","reason":123}`,
	} {
		t.Run("wrong JSON type "+body, func(t *testing.T) {
			fake := &fakeIdentityService{}
			h := New(fake, nil)
			response := invokeHandler(t, h.ChangeStatus, http.MethodPut, "/admin/users/8/status", body, "application/json", authn.Principal{UserID: 2, SessionID: 3}, "8")
			assertErrorResponse(t, response, http.StatusBadRequest, "invalid_request")
			if fake.changeStatusCalls != 0 {
				t.Fatalf("ChangeUserStatus calls = %d", fake.changeStatusCalls)
			}
		})
	}
}

func TestPathIDMustBeCanonicalPositiveInt64(t *testing.T) {
	valid := []string{"1", fmt.Sprintf("%d", int64(math.MaxInt64))}
	for _, raw := range valid {
		t.Run("valid "+raw, func(t *testing.T) {
			fake := &fakeIdentityService{publicResult: samplePublicUserView()}
			h := New(fake, nil)
			response := invokeHandler(t, h.PublicUser, http.MethodGet, "/users/id", "", "", authn.Principal{}, raw)
			if response.Code != http.StatusOK || fake.publicCalls != 1 {
				t.Fatalf("status = %d calls = %d body = %s", response.Code, fake.publicCalls, response.Body.String())
			}
		})
	}

	invalid := []string{"", "0", "-1", "+1", "01", " 1", "1 ", "１", "abc", "9223372036854775808"}
	for _, raw := range invalid {
		t.Run("invalid "+raw, func(t *testing.T) {
			fake := &fakeIdentityService{}
			h := New(fake, nil)
			response := invokeHandler(t, h.PublicUser, http.MethodGet, "/users/id", "", "", authn.Principal{}, raw)
			assertErrorResponse(t, response, http.StatusBadRequest, "validation_failed")
			if fake.publicCalls != 0 {
				t.Fatalf("PublicUser calls = %d", fake.publicCalls)
			}
		})
	}
}

func TestHandlersMapErrorsWithErrorsIsAndSafeBodies(t *testing.T) {
	tests := []struct {
		name   string
		err    error
		invoke func(*Handler, http.ResponseWriter, *http.Request)
		status int
		code   string
	}{
		{name: "validation", err: fmt.Errorf("wrapped: %w", identityservice.ErrValidationFailed), invoke: (*Handler).Register, status: 400, code: "validation_failed"},
		{name: "invalid credentials", err: fmt.Errorf("wrapped: %w", identityservice.ErrInvalidCredentials), invoke: (*Handler).Login, status: 401, code: "invalid_credentials"},
		{name: "invalid refresh", err: identityservice.ErrInvalidRefreshToken, invoke: (*Handler).Refresh, status: 401, code: "invalid_refresh_token"},
		{name: "session invalid", err: identityservice.ErrSessionInvalid, invoke: (*Handler).Me, status: 401, code: "session_invalid"},
		{name: "frozen", err: identityservice.ErrUserFrozen, invoke: (*Handler).Me, status: 403, code: "user_frozen"},
		{name: "admin required", err: identityservice.ErrAdminRequired, invoke: (*Handler).ChangeStatus, status: 403, code: "admin_required"},
		{name: "admin target forbidden", err: identityservice.ErrAdminTargetForbidden, invoke: (*Handler).ChangeStatus, status: 403, code: "admin_target_forbidden"},
		{name: "user not found", err: identityservice.ErrUserNotFound, invoke: (*Handler).PublicUser, status: 404, code: "user_not_found"},
		{name: "email conflict", err: identityservice.ErrEmailAlreadyRegistered, invoke: (*Handler).Register, status: 409, code: "email_already_registered"},
		{name: "status conflict", err: identityservice.ErrInvalidStatusTransition, invoke: (*Handler).ChangeStatus, status: 409, code: "invalid_status_transition"},
		{name: "internal", err: identityservice.ErrInternal, invoke: (*Handler).Register, status: 500, code: "internal_error"},
		{name: "unexpected repository", err: errors.New("postgres constraint secret-password /tmp/private jwt-secret"), invoke: (*Handler).Register, status: 500, code: "internal_error"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fake := &fakeIdentityService{allErr: tt.err}
			h := New(fake, slog.New(slog.NewTextHandler(io.Discard, nil)))
			method, path, body, contentType, principal, pathID := requestForHandler(tt.invoke)
			request := handlerRequest(method, path, body, contentType, principal, pathID)
			response := httptest.NewRecorder()
			tt.invoke(h, response, request)
			assertErrorResponse(t, response, tt.status, tt.code)
			if tt.status == http.StatusUnauthorized && response.Header().Get("WWW-Authenticate") != "Bearer" {
				t.Fatalf("WWW-Authenticate = %q", response.Header().Get("WWW-Authenticate"))
			}
			for _, secret := range []string{"secret-password", "constraint", "/tmp/private", "jwt-secret"} {
				if strings.Contains(response.Body.String(), secret) {
					t.Fatalf("response leaked %q: %s", secret, response.Body.String())
				}
			}
		})
	}
}

func TestMissingPrincipalIsInternalAndDoesNotCallService(t *testing.T) {
	fake := &fakeIdentityService{}
	h := New(fake, nil)
	request := handlerRequest(http.MethodGet, "/me", "", "", authn.Principal{}, "")
	request = request.WithContext(requestid.WithContext(context.Background(), handlerRequestID))
	response := httptest.NewRecorder()

	h.Me(response, request)

	assertErrorResponse(t, response, http.StatusInternalServerError, "internal_error")
	if fake.meCalls != 0 {
		t.Fatalf("Me calls = %d", fake.meCalls)
	}
}

func TestRejectAccessTokenHandlesNilRequestAsJSON(t *testing.T) {
	h := New(&fakeIdentityService{}, nil)
	response := httptest.NewRecorder()

	defer func() {
		if recovered := recover(); recovered != nil {
			t.Fatalf("RejectAccessToken panicked: %v", recovered)
		}
	}()
	h.RejectAccessToken(response, nil, authn.ErrInvalidAccessToken)

	assertErrorResponse(t, response, http.StatusUnauthorized, "invalid_access_token")
	if response.Header().Get("WWW-Authenticate") != "Bearer" {
		t.Fatalf("WWW-Authenticate = %q", response.Header().Get("WWW-Authenticate"))
	}
}

var userResponseKeys = []string{
	"id", "email", "display_name", "bio", "role", "status", "muted_until",
	"violation_count", "created_at", "updated_at", "deleted_at",
}

func invokeHandler(
	t *testing.T,
	handler http.HandlerFunc,
	method, path, body, contentType string,
	principal authn.Principal,
	pathID string,
) *httptest.ResponseRecorder {
	t.Helper()
	request := handlerRequest(method, path, body, contentType, principal, pathID)
	response := httptest.NewRecorder()
	handler(response, request)
	if response.Header().Get("Content-Type") != "application/json; charset=utf-8" {
		t.Fatalf("Content-Type = %q", response.Header().Get("Content-Type"))
	}
	return response
}

func handlerRequest(method, path, body, contentType string, principal authn.Principal, pathID string) *http.Request {
	var reader io.Reader
	if body != "" {
		reader = strings.NewReader(body)
	}
	request := httptest.NewRequest(method, path, reader)
	if contentType != "" {
		request.Header.Set("Content-Type", contentType)
	}
	if pathID != "" {
		request.SetPathValue("id", pathID)
	}
	ctx := requestid.WithContext(request.Context(), handlerRequestID)
	if principal.UserID != 0 || principal.SessionID != 0 {
		ctx = authn.WithContext(ctx, principal)
	}
	return request.WithContext(ctx)
}

func successData(t *testing.T, response *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var envelope struct {
		Data map[string]any `json:"data"`
		Meta struct {
			RequestID string `json:"request_id"`
		} `json:"meta"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &envelope); err != nil {
		t.Fatalf("decode response: %v body=%s", err, response.Body.String())
	}
	if envelope.Meta.RequestID != handlerRequestID {
		t.Fatalf("request_id = %q", envelope.Meta.RequestID)
	}
	if envelope.Data == nil {
		t.Fatalf("missing data: %s", response.Body.String())
	}
	return envelope.Data
}

func assertErrorResponse(t *testing.T, response *httptest.ResponseRecorder, status int, code string) {
	t.Helper()
	if response.Code != status {
		t.Fatalf("status = %d, want %d, body = %s", response.Code, status, response.Body.String())
	}
	var envelope struct {
		Error map[string]any `json:"error"`
		Meta  struct {
			RequestID string `json:"request_id"`
		} `json:"meta"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &envelope); err != nil {
		t.Fatalf("decode response: %v body=%s", err, response.Body.String())
	}
	if envelope.Error["code"] != code {
		t.Fatalf("error code = %#v, want %q, body = %s", envelope.Error["code"], code, response.Body.String())
	}
	if envelope.Meta.RequestID != "" && envelope.Meta.RequestID != handlerRequestID {
		t.Fatalf("request_id = %q", envelope.Meta.RequestID)
	}
}

func assertExactKeys(t *testing.T, value map[string]any, keys ...string) {
	t.Helper()
	if len(value) != len(keys) {
		t.Fatalf("keys = %v, want %v", mapKeys(value), keys)
	}
	for _, key := range keys {
		if _, ok := value[key]; !ok {
			t.Fatalf("missing key %q in %v", key, mapKeys(value))
		}
	}
}

func assertUserTimesAndNulls(t *testing.T, data map[string]any) {
	t.Helper()
	if data["created_at"] != "2026-09-01T12:00:00Z" || data["updated_at"] != "2026-09-01T13:00:00Z" {
		t.Fatalf("times = %#v %#v", data["created_at"], data["updated_at"])
	}
	if data["muted_until"] != nil || data["deleted_at"] != nil {
		t.Fatalf("nullable times = %#v %#v", data["muted_until"], data["deleted_at"])
	}
}

func objectValue(t *testing.T, value map[string]any, key string) map[string]any {
	t.Helper()
	object, ok := value[key].(map[string]any)
	if !ok {
		t.Fatalf("%s = %#v, want object", key, value[key])
	}
	return object
}

func mapKeys(value map[string]any) []string {
	keys := make([]string, 0, len(value))
	for key := range value {
		keys = append(keys, key)
	}
	return keys
}

func equalChangeStatusInput(left, right identityservice.ChangeUserStatusInput) bool {
	if left.ActorID != right.ActorID || left.ActorSessionID != right.ActorSessionID || left.TargetID != right.TargetID ||
		left.NewStatus != right.NewStatus || left.Reason != right.Reason || left.RequestID != right.RequestID {
		return false
	}
	if left.MutedUntil == nil || right.MutedUntil == nil {
		return left.MutedUntil == nil && right.MutedUntil == nil
	}
	return left.MutedUntil.Equal(*right.MutedUntil)
}

func sampleUserView() domain.UserView {
	return domain.UserView{
		ID: 4, Email: "user@example.com", DisplayName: "Alice", Role: domain.RoleUser,
		Status: domain.StatusActive, CreatedAt: time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC),
		UpdatedAt: time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC),
	}
}

func samplePublicUserView() domain.PublicUserView {
	return domain.PublicUserView{
		ID: 1, DisplayName: "Alice", Role: domain.RoleUser, Status: domain.StatusActive,
		CreatedAt: time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC),
	}
}

func requestForHandler(invoke func(*Handler, http.ResponseWriter, *http.Request)) (string, string, string, string, authn.Principal, string) {
	name := fmt.Sprintf("%p", invoke)
	switch name {
	case fmt.Sprintf("%p", (*Handler).Login):
		return http.MethodPost, "/login", `{"email":"a","password":"b"}`, "application/json", authn.Principal{}, ""
	case fmt.Sprintf("%p", (*Handler).Refresh):
		return http.MethodPost, "/token/refresh", `{"refresh_token":"x"}`, "application/json", authn.Principal{}, ""
	case fmt.Sprintf("%p", (*Handler).Me):
		return http.MethodGet, "/me", "", "", authn.Principal{UserID: 2, SessionID: 3}, ""
	case fmt.Sprintf("%p", (*Handler).PublicUser):
		return http.MethodGet, "/users/8", "", "", authn.Principal{}, "8"
	case fmt.Sprintf("%p", (*Handler).ChangeStatus):
		return http.MethodPut, "/admin/users/8/status", `{"status":"active"}`, "application/json", authn.Principal{UserID: 2, SessionID: 3}, "8"
	default:
		return http.MethodPost, "/register", `{"email":"a","password":"b","display_name":"c"}`, "application/json", authn.Principal{}, ""
	}
}

type fakeIdentityService struct {
	allErr error

	registerResult domain.UserView
	registerErr    error
	registerInput  identityservice.RegisterInput
	registerCalls  int

	loginResult identityservice.LoginResult
	loginErr    error
	loginInput  identityservice.LoginInput
	loginCalls  int

	logoutResult identityservice.LogoutResult
	logoutErr    error
	logoutInput  identityservice.LogoutInput
	logoutCalls  int

	refreshResult identityservice.RefreshResult
	refreshErr    error
	refreshInput  identityservice.RefreshInput
	refreshCalls  int

	meResult domain.UserView
	meErr    error
	meInput  identityservice.MeInput
	meCalls  int

	publicResult domain.PublicUserView
	publicErr    error
	publicInput  identityservice.PublicUserInput
	publicCalls  int

	updateMeResult domain.UserView
	updateMeErr    error
	updateMeInput  identityservice.UpdateMeInput
	updateCalls    int

	deleteMeResult identityservice.DeleteMeResult
	deleteMeErr    error
	deleteMeInput  identityservice.DeleteMeInput
	deleteCalls    int

	changeStatusResult domain.UserView
	changeStatusErr    error
	changeStatusInput  identityservice.ChangeUserStatusInput
	changeStatusCalls  int
}

func (f *fakeIdentityService) Register(_ context.Context, input identityservice.RegisterInput) (domain.UserView, error) {
	f.registerCalls++
	f.registerInput = input
	return f.registerResult, firstError(f.registerErr, f.allErr)
}

func (f *fakeIdentityService) Login(_ context.Context, input identityservice.LoginInput) (identityservice.LoginResult, error) {
	f.loginCalls++
	f.loginInput = input
	return f.loginResult, firstError(f.loginErr, f.allErr)
}

func (f *fakeIdentityService) Logout(_ context.Context, input identityservice.LogoutInput) (identityservice.LogoutResult, error) {
	f.logoutCalls++
	f.logoutInput = input
	return f.logoutResult, firstError(f.logoutErr, f.allErr)
}

func (f *fakeIdentityService) Refresh(_ context.Context, input identityservice.RefreshInput) (identityservice.RefreshResult, error) {
	f.refreshCalls++
	f.refreshInput = input
	return f.refreshResult, firstError(f.refreshErr, f.allErr)
}

func (f *fakeIdentityService) Me(_ context.Context, input identityservice.MeInput) (domain.UserView, error) {
	f.meCalls++
	f.meInput = input
	return f.meResult, firstError(f.meErr, f.allErr)
}

func (f *fakeIdentityService) PublicUser(_ context.Context, input identityservice.PublicUserInput) (domain.PublicUserView, error) {
	f.publicCalls++
	f.publicInput = input
	return f.publicResult, firstError(f.publicErr, f.allErr)
}

func (f *fakeIdentityService) UpdateMe(_ context.Context, input identityservice.UpdateMeInput) (domain.UserView, error) {
	f.updateCalls++
	f.updateMeInput = input
	return f.updateMeResult, firstError(f.updateMeErr, f.allErr)
}

func (f *fakeIdentityService) DeleteMe(_ context.Context, input identityservice.DeleteMeInput) (identityservice.DeleteMeResult, error) {
	f.deleteCalls++
	f.deleteMeInput = input
	return f.deleteMeResult, firstError(f.deleteMeErr, f.allErr)
}

func (f *fakeIdentityService) ChangeUserStatus(_ context.Context, input identityservice.ChangeUserStatusInput) (domain.UserView, error) {
	f.changeStatusCalls++
	f.changeStatusInput = input
	return f.changeStatusResult, firstError(f.changeStatusErr, f.allErr)
}

func firstError(specific, all error) error {
	if specific != nil {
		return specific
	}
	return all
}
