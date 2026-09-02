package app

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Free-sp1rit/content-platform/internal/identity/domain"
	identityhandler "github.com/Free-sp1rit/content-platform/internal/identity/handler"
	identityservice "github.com/Free-sp1rit/content-platform/internal/identity/service"
	"github.com/Free-sp1rit/content-platform/internal/platform/authn"
	"github.com/Free-sp1rit/content-platform/internal/platform/requestid"
	systemhandler "github.com/Free-sp1rit/content-platform/internal/system/handler"
	systemservice "github.com/Free-sp1rit/content-platform/internal/system/service"
)

const routeToken = "compact.JWT_token-~+/="

func TestRoutesExposeHealthEndpoints(t *testing.T) {
	routes, _ := testRoutes(systemservice.Ready, nil)

	for _, method := range []string{http.MethodGet, http.MethodHead} {
		for _, path := range []string{"/healthz", "/readyz"} {
			response := httptest.NewRecorder()
			routes.ServeHTTP(response, httptest.NewRequest(method, path, nil))
			if response.Code != http.StatusOK {
				t.Fatalf("%s %s status = %d, body = %s", method, path, response.Code, response.Body.String())
			}
			if response.Header().Get("Content-Type") != "application/json; charset=utf-8" {
				t.Fatalf("%s %s Content-Type = %q", method, path, response.Header().Get("Content-Type"))
			}
			if response.Header().Get(requestid.Header) == "" {
				t.Fatalf("%s %s missing request ID header", method, path)
			}
			if method == http.MethodGet && !strings.Contains(response.Body.String(), `"request_id":`) {
				t.Fatalf("GET %s missing request ID body: %s", path, response.Body.String())
			}
		}
	}
}

func TestRoutesExposeAllNineIdentityEndpoints(t *testing.T) {
	routes, service := testRoutes(systemservice.Ready, nil)
	tests := []struct {
		name   string
		method string
		path   string
		body   string
		auth   bool
		status int
	}{
		{name: "register", method: http.MethodPost, path: "/register", body: `{"email":"user@example.com","password":"password-123","display_name":"Alice"}`, status: http.StatusCreated},
		{name: "login", method: http.MethodPost, path: "/login", body: `{"email":"user@example.com","password":"password-123"}`, status: http.StatusOK},
		{name: "logout", method: http.MethodPost, path: "/logout", auth: true, status: http.StatusOK},
		{name: "refresh", method: http.MethodPost, path: "/token/refresh", body: `{"refresh_token":"3.secret"}`, status: http.StatusOK},
		{name: "me", method: http.MethodGet, path: "/me", auth: true, status: http.StatusOK},
		{name: "update me", method: http.MethodPut, path: "/me", body: `{}`, auth: true, status: http.StatusOK},
		{name: "delete me", method: http.MethodDelete, path: "/me", auth: true, status: http.StatusOK},
		{name: "public user", method: http.MethodGet, path: "/users/7", status: http.StatusOK},
		{name: "admin status", method: http.MethodPut, path: "/admin/users/7/status", body: `{"status":"active"}`, auth: true, status: http.StatusOK},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var body io.Reader
			if tt.body != "" {
				body = strings.NewReader(tt.body)
			}
			request := httptest.NewRequest(tt.method, tt.path, body)
			request.Header.Set(requestid.Header, "route-request-id")
			if tt.body != "" {
				request.Header.Set("Content-Type", "application/json")
			}
			if tt.auth {
				request.Header.Set("Authorization", "Bearer "+routeToken)
			}
			response := httptest.NewRecorder()

			routes.ServeHTTP(response, request)

			if response.Code != tt.status {
				t.Fatalf("status = %d, want %d, body = %s", response.Code, tt.status, response.Body.String())
			}
			if response.Header().Get(requestid.Header) != "route-request-id" || !strings.Contains(response.Body.String(), `"request_id":"route-request-id"`) {
				t.Fatalf("request ID regression: headers=%v body=%s", response.Header(), response.Body.String())
			}
		})
	}

	if service.registerCalls != 1 || service.loginCalls != 1 || service.logoutCalls != 1 || service.refreshCalls != 1 ||
		service.meCalls != 1 || service.updateCalls != 1 || service.deleteCalls != 1 || service.publicCalls != 1 || service.statusCalls != 1 {
		t.Fatalf("identity call counts = %#v", service)
	}
}

func TestIdentityWrongMethodsBypassAuthenticationAndUseCanonicalAllow(t *testing.T) {
	routes, service := testRoutes(systemservice.Ready, nil)
	tests := []struct {
		method string
		path   string
		allow  string
	}{
		{method: http.MethodGet, path: "/register", allow: "POST"},
		{method: http.MethodGet, path: "/login", allow: "POST"},
		{method: http.MethodGet, path: "/logout", allow: "POST"},
		{method: http.MethodGet, path: "/token/refresh", allow: "POST"},
		{method: http.MethodPost, path: "/me", allow: "GET, PUT, DELETE"},
		{method: http.MethodHead, path: "/me", allow: "GET, PUT, DELETE"},
		{method: http.MethodPost, path: "/users/7", allow: "GET"},
		{method: http.MethodHead, path: "/users/7", allow: "GET"},
		{method: http.MethodGet, path: "/admin/users/7/status", allow: "PUT"},
	}

	for _, tt := range tests {
		t.Run(tt.method+" "+tt.path, func(t *testing.T) {
			request := httptest.NewRequest(tt.method, tt.path, nil)
			response := httptest.NewRecorder()
			routes.ServeHTTP(response, request)

			if response.Code != http.StatusMethodNotAllowed || !strings.Contains(response.Body.String(), `"code":"method_not_allowed"`) {
				t.Fatalf("status = %d body = %s", response.Code, response.Body.String())
			}
			if values := response.Header().Values("Allow"); len(values) != 1 || values[0] != tt.allow {
				t.Fatalf("Allow values = %#v, want [%q]", values, tt.allow)
			}
			if strings.Contains(response.Body.String(), "invalid_access_token") {
				t.Fatalf("wrong method passed through auth: %s", response.Body.String())
			}
		})
	}

	if service.totalCalls() != 0 {
		t.Fatalf("service calls = %d", service.totalCalls())
	}
}

func TestRoutesDistinguishInvalidJWTFromInvalidSession(t *testing.T) {
	t.Run("invalid JWT", func(t *testing.T) {
		routes, service := testRoutes(systemservice.Ready, nil)
		response := httptest.NewRecorder()
		routes.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/me", nil))
		assertRouteUnauthorized(t, response, "invalid_access_token")
		if service.meCalls != 0 {
			t.Fatalf("Me calls = %d", service.meCalls)
		}
	})

	t.Run("invalid server session", func(t *testing.T) {
		routes, service := testRoutes(systemservice.Ready, identityservice.ErrSessionInvalid)
		request := httptest.NewRequest(http.MethodGet, "/me", nil)
		request.Header.Set("Authorization", "Bearer "+routeToken)
		response := httptest.NewRecorder()
		routes.ServeHTTP(response, request)
		assertRouteUnauthorized(t, response, "session_invalid")
		if service.meCalls != 1 {
			t.Fatalf("Me calls = %d", service.meCalls)
		}
	})
}

func TestLogoutUsesJWTOnlyAndAcceptsToken68Characters(t *testing.T) {
	routes, service := testRoutes(systemservice.Ready, nil)
	request := httptest.NewRequest(http.MethodPost, "/logout", nil)
	request.Header.Set("Authorization", "Bearer "+routeToken)
	response := httptest.NewRecorder()

	routes.ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d body = %s", response.Code, response.Body.String())
	}
	if service.logoutCalls != 1 || service.meCalls != 0 {
		t.Fatalf("logout calls = %d strict calls = %d", service.logoutCalls, service.meCalls)
	}
}

func TestRoutesReturnUniformNotFoundAndSystemMethodNotAllowed(t *testing.T) {
	routes, _ := testRoutes(systemservice.Ready, nil)
	tests := []struct {
		method string
		path   string
		status int
		code   string
	}{
		{method: http.MethodGet, path: "/missing", status: http.StatusNotFound, code: "not_found"},
		{method: http.MethodPost, path: "/healthz", status: http.StatusMethodNotAllowed, code: "method_not_allowed"},
	}

	for _, tt := range tests {
		response := httptest.NewRecorder()
		routes.ServeHTTP(response, httptest.NewRequest(tt.method, tt.path, nil))
		if response.Code != tt.status || !strings.Contains(response.Body.String(), `"code":"`+tt.code+`"`) {
			t.Fatalf("%s %s = %d %s", tt.method, tt.path, response.Code, response.Body.String())
		}
		if tt.status == http.StatusMethodNotAllowed && response.Header().Get("Allow") != http.MethodGet {
			t.Fatalf("Allow header = %q", response.Header().Get("Allow"))
		}
	}
}

func testRoutes(status systemservice.Status, meErr error) (http.Handler, *routeIdentityService) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	health := systemhandler.New(routeHealthService{status: status})
	identityService := newRouteIdentityService()
	identityService.meErr = meErr
	identity := identityhandler.New(identityService, logger)
	verifier := &routeVerifier{token: routeToken, principal: authn.Principal{UserID: 5, SessionID: 6}}
	authenticate := authn.Middleware(verifier, routeClock{}, identity.RejectAccessToken)
	return Routes(logger, health, identity, authenticate), identityService
}

func assertRouteUnauthorized(t *testing.T, response *httptest.ResponseRecorder, code string) {
	t.Helper()
	if response.Code != http.StatusUnauthorized || !strings.Contains(response.Body.String(), `"code":"`+code+`"`) {
		t.Fatalf("status = %d body = %s", response.Code, response.Body.String())
	}
	if response.Header().Get("WWW-Authenticate") != "Bearer" {
		t.Fatalf("WWW-Authenticate = %q", response.Header().Get("WWW-Authenticate"))
	}
}

type routeHealthService struct {
	status systemservice.Status
}

func (routeHealthService) Liveness(context.Context) systemservice.Liveness {
	return systemservice.Liveness{Status: "ok"}
}

func (s routeHealthService) Readiness(context.Context) systemservice.Readiness {
	return systemservice.Readiness{
		Status: s.status,
		Checks: map[string]systemservice.DependencyState{
			"postgres": systemservice.Up,
			"redis":    systemservice.Up,
		},
	}
}

type routeVerifier struct {
	token     string
	principal authn.Principal
}

func (v *routeVerifier) Verify(raw string, _ time.Time) (authn.Principal, error) {
	if raw != v.token {
		return authn.Principal{}, errors.New("invalid token")
	}
	return v.principal, nil
}

type routeClock struct{}

func (routeClock) Now() time.Time {
	return time.Date(2026, 9, 2, 0, 0, 0, 0, time.UTC)
}

type routeIdentityService struct {
	registerCalls int
	loginCalls    int
	logoutCalls   int
	refreshCalls  int
	meCalls       int
	updateCalls   int
	deleteCalls   int
	publicCalls   int
	statusCalls   int
	meErr         error
}

func newRouteIdentityService() *routeIdentityService {
	return &routeIdentityService{}
}

func (s *routeIdentityService) Register(context.Context, identityservice.RegisterInput) (domain.UserView, error) {
	s.registerCalls++
	return routeUser(), nil
}

func (s *routeIdentityService) Login(context.Context, identityservice.LoginInput) (identityservice.LoginResult, error) {
	s.loginCalls++
	return identityservice.LoginResult{
		TokenType: "Bearer", AccessToken: "access", ExpiresIn: 900, RefreshToken: "3.refresh",
		RefreshExpiresAt: time.Date(2026, 9, 3, 0, 0, 0, 0, time.UTC), User: routeUser(),
	}, nil
}

func (s *routeIdentityService) Logout(context.Context, identityservice.LogoutInput) (identityservice.LogoutResult, error) {
	s.logoutCalls++
	return identityservice.LogoutResult{LoggedOut: true}, nil
}

func (s *routeIdentityService) Refresh(context.Context, identityservice.RefreshInput) (identityservice.RefreshResult, error) {
	s.refreshCalls++
	return identityservice.RefreshResult{
		TokenType: "Bearer", AccessToken: "access", ExpiresIn: 900, RefreshToken: "3.refresh",
		RefreshExpiresAt: time.Date(2026, 9, 3, 0, 0, 0, 0, time.UTC),
	}, nil
}

func (s *routeIdentityService) Me(context.Context, identityservice.MeInput) (domain.UserView, error) {
	s.meCalls++
	return routeUser(), s.meErr
}

func (s *routeIdentityService) PublicUser(context.Context, identityservice.PublicUserInput) (domain.PublicUserView, error) {
	s.publicCalls++
	return domain.PublicUserView{
		ID: 7, DisplayName: "Alice", Role: domain.RoleUser, Status: domain.StatusActive,
		CreatedAt: time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC),
	}, nil
}

func (s *routeIdentityService) UpdateMe(context.Context, identityservice.UpdateMeInput) (domain.UserView, error) {
	s.updateCalls++
	return routeUser(), nil
}

func (s *routeIdentityService) DeleteMe(context.Context, identityservice.DeleteMeInput) (identityservice.DeleteMeResult, error) {
	s.deleteCalls++
	return identityservice.DeleteMeResult{Deleted: true}, nil
}

func (s *routeIdentityService) ChangeUserStatus(context.Context, identityservice.ChangeUserStatusInput) (domain.UserView, error) {
	s.statusCalls++
	return routeUser(), nil
}

func (s *routeIdentityService) totalCalls() int {
	return s.registerCalls + s.loginCalls + s.logoutCalls + s.refreshCalls + s.meCalls +
		s.updateCalls + s.deleteCalls + s.publicCalls + s.statusCalls
}

func routeUser() domain.UserView {
	now := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	return domain.UserView{
		ID: 7, Email: "user@example.com", DisplayName: "Alice", Role: domain.RoleUser,
		Status: domain.StatusActive, CreatedAt: now, UpdatedAt: now,
	}
}
