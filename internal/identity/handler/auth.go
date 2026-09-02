package handler

import (
	"net/http"

	identityservice "github.com/Free-sp1rit/content-platform/internal/identity/service"
	"github.com/Free-sp1rit/content-platform/internal/platform/httpx"
	"github.com/Free-sp1rit/content-platform/internal/platform/requestid"
)

func (h *Handler) Register(w http.ResponseWriter, r *http.Request) {
	if !h.available() {
		h.writeError(r.Context(), w, internalHandlerError())
		return
	}
	var request registerRequest
	if !h.decode(w, r, &request) {
		return
	}
	result, err := h.service.Register(r.Context(), identityservice.RegisterInput{
		Email: request.Email, Password: request.Password, DisplayName: request.DisplayName,
	})
	if err != nil {
		h.writeError(r.Context(), w, err)
		return
	}
	httpx.WriteData(r.Context(), w, http.StatusCreated, newUserResponse(result))
}

func (h *Handler) Login(w http.ResponseWriter, r *http.Request) {
	if !h.available() {
		h.writeError(r.Context(), w, internalHandlerError())
		return
	}
	var request loginRequest
	if !h.decode(w, r, &request) {
		return
	}
	result, err := h.service.Login(r.Context(), identityservice.LoginInput{
		Email: request.Email, Password: request.Password, RequestID: requestid.FromContext(r.Context()),
	})
	if err != nil {
		h.writeError(r.Context(), w, err)
		return
	}
	httpx.WriteData(r.Context(), w, http.StatusOK, newLoginResponse(result))
}

func (h *Handler) Logout(w http.ResponseWriter, r *http.Request) {
	principal, ok := h.principal(r)
	if !ok || !h.available() {
		h.writeError(r.Context(), w, internalHandlerError())
		return
	}
	result, err := h.service.Logout(r.Context(), identityservice.LogoutInput{
		UserID: principal.UserID, SessionID: principal.SessionID,
	})
	if err != nil {
		h.writeError(r.Context(), w, err)
		return
	}
	httpx.WriteData(r.Context(), w, http.StatusOK, logoutResponse{LoggedOut: result.LoggedOut})
}

func (h *Handler) Refresh(w http.ResponseWriter, r *http.Request) {
	if !h.available() {
		h.writeError(r.Context(), w, internalHandlerError())
		return
	}
	var request refreshRequest
	if !h.decode(w, r, &request) {
		return
	}
	result, err := h.service.Refresh(r.Context(), identityservice.RefreshInput{
		RefreshToken: request.RefreshToken, RequestID: requestid.FromContext(r.Context()),
	})
	if err != nil {
		h.writeError(r.Context(), w, err)
		return
	}
	httpx.WriteData(r.Context(), w, http.StatusOK, newRefreshResponse(result))
}
